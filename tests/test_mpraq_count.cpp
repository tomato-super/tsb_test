// MPA-04：`AggQuery` – `Count`（逐列 PIR 检索 → 本地布尔组合 → 数 1 的个数）测试。
//
// 覆盖（对应任务书第三步的 8 条要求）：
//   1. 单谓词全操作符（eq/neq/lt/le/gt/ge/range）与**明文基准逐记录对照 filter 向量**；
//   2. 合取（2~3 个谓词、跨 2 个属性）+ 论文的 De Morgan 形式（结果必须与扁平合取一致）；
//   3. 取反 / 边界（`neq`、阈值取在域两端与越界、`kAlignNearest` vs `kStrict`、`range` 空区间）；
//   4. 退化规模：N=1、N=100（**不是 128 的倍数** ⇒ 尾部填充位必须被忽略）、全命中、零命中；
//   5. RPC 不变量：一次 Count 后两台服务器各**恰好 +1** 次 `ServerResp`（与谓词/列数无关）；
//   6. 列去重：多个谓词引用同一列时只检索一次；
//   7. 确定性：同种子两次 `Init` 的 filter 向量逐位一致（`DeterministicPrng` + 显式种子）；
//   8. 与 `MPA-03` 的明文对照：`CountResult::filter` 与 `mpraq_baseline::Filter(...)` 逐位一致。
//
// ⚠️ 性能预算（D22-1）：`HintInit ≈ n × IF⁻¹`。常规用例 λ 取小值（4~8）加速，
//    仍留一个 λ=80 + **默认 ε=1e-10** 的验收用例并显式标注（本文件只有那一处用默认 ε）。
// ⚠️ 本文件不写 main（用 tests/support 的 TEST/EXPECT_* 宏与共享的 test_main.cpp）。
// ⚠️ **不做验证层**：`TASK_PLAN.md` §7.13 的 V1/V2 未裁决（论文的 HMAC 多集证明在共享域上
//    不成立，D24①/L9）⇒ 本文件**没有**任何"验证值/证明/完整性断言"，也不假装服务器返回的
//    数据是可信的（详见 `src/mpraq/aggquery.hpp` 的 §1）。

#include "core/random.hpp"
#include "mpraq/aggquery.hpp"
#include "mpraq/init.hpp"
#include "mpraq/lcte.hpp"
#include "mpraq/node.hpp"
#include "mpraq/predicate.hpp"
#include "test_framework.hpp"

#include "mpraq_baseline.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace tsb;
using namespace tsb::mpraq;

namespace {

// ---------------------------------------------------------------------------
// 规模常量的由来（`MPRAQ_IMPL.md` §1：`n = m_pad · ⌈N/128⌉`）
// ---------------------------------------------------------------------------
// 属性 0：R = [0, 5]、m = 6；属性 1：R = [0, 3]、m = 4 ⇒ M = Σ_a m_a = 10（真实列数）。
// `DerivePaddedGeometry` 把列数补齐到 2 的幂再挑 `(n, w)` 最优：
//   N ≤ 128 ⇒ ⌈N/128⌉ = 1 ⇒ 列数补齐 10 → 16、n = 16、w = 1、c = 16；
//   N = 256 ⇒ ⌈N/128⌉ = 2、w = 2、n = 32；
//   N = 1024 ⇒ ⌈N/128⌉ = 8、w = 8、n = 128。
// ⇒ 检索量 = 列数 × ⌈N/128⌉（不是 N，也不是"每谓词一次"）—— 用例 5/6 会把这个口径钉住。
constexpr uint32_t kAttr0M = 6;
constexpr uint32_t kAttr1M = 4;
constexpr size_t kRealColumns = kAttr0M + kAttr1M;
// 取值域与跨度：span + 2 <= m（D19-5 的无损表达条件），因此这里刻意取到上限
// 属性 0 ∈ [0, 4]（span 4 ⇒ 6 >= 6 ✔）、属性 1 ∈ [0, 2]（span 2 ⇒ 4 >= 4 ✔）。
constexpr int64_t kAttr0DomainMax = 4;
constexpr int64_t kAttr1DomainMax = 2;

// 快速用例的 ε（合法但明显更快；D22-1 的预算口径见文件头）
constexpr double kFastEps = 1e-4;
// 常规用例的 λ：既要把 2^{-λ} 的"找不到覆盖 hint"概率压小，又要留够**备份 hint**。
// ⚠️ 硬预算：`q = λw/2` 且**每个查询集消费 1 条备份 hint**（D8 不做摊销式离线）
//    ⇒ 一个用例里"累计查询集个数"必须 <= `λw/2`，否则 `CreateQueries` 直接抛
//    `PlinkoExceptions`（备份用尽）。因此 λ 是**按用例的查询集总量**选的：
//    N=100 的 15 组单谓词用例 ⇒ 16 个查询集 ⇒ λ=16；N=1 的用例 ⇒ 16 个 ⇒ λ=16。
constexpr uint32_t kFastLambda = 8;

// 报告用的全局计数器（只做输出，不参与断言）
struct ReportState {
    uint64_t count_calls = 0;
    uint64_t filter_bits_compared = 0;
    uint64_t init_calls = 0;
    size_t largest_compared_records = 0;
    double total_init_ms = 0.0;
    double total_retrieve_ms = 0.0;
    double total_combine_ms = 0.0;
    uint64_t total_queries_issued = 0;
    size_t columns_seen = 0;
    uint64_t dedup_columns_retrieved = 0;
    uint64_t dedup_queries_issued = 0;
};

ReportState& Report() {
    static ReportState s;
    return s;
}

// ---------------------------------------------------------------------------
// Schema / 记录（确定性；跨运行逐位一致）
// ---------------------------------------------------------------------------

AttributeSchema MakeAttr(uint32_t id, uint32_t m, int64_t dmin, int64_t dmax, size_t n) {
    AttributeSchema a;
    a.name = "attr" + std::to_string(id);
    a.id = id;
    a.lcte.window_size = static_cast<uint32_t>(n);
    a.lcte.range_min = dmin;
    a.lcte.range_size = m;
    a.domain_min = dmin;
    a.domain_max = dmax;
    return a;
}

// 两属性 schema：属性 0 ∈ [0, 4]（m = 6）、属性 1 ∈ [0, 2]（m = 4）
Schema MakeSchema(size_t n) {
    Schema s;
    s.AddAttribute(MakeAttr(0, kAttr0M, 0, kAttr0DomainMax, n));
    s.AddAttribute(MakeAttr(1, kAttr1M, 0, kAttr1DomainMax, n));
    return s;
}

// 确定性记录（**不是**均匀随机：要覆盖"域内每个取值都出现多轮"与边界值）：
//   attr0 = i mod 5      ∈ [0, 4]（域内满覆盖）
//   attr1 = (i / 2) mod 3 ∈ [0, 2]（周期 6，与 attr0 的周期 5 互质 ⇒ 合取不会退化成常量）
//   ⚠️ `feature` 按 `MPRAQ_IMPL.md` §1 只被保存、不参与 LCTE 编码（§7.15 语义发现 ①）⇒
//      本层的任何谓词都只能落在 `attributes` 上，这里随便填一个确定值。
std::vector<MpraqRecord> MakeRecords(size_t n) {
    std::vector<MpraqRecord> recs(n);
    for (size_t i = 0; i < n; ++i) {
        recs[i].feature = static_cast<int64_t>(i * 7 + 3);
        recs[i].attributes = {static_cast<int64_t>(i % 5),
                              static_cast<int64_t>((i / 2) % 3)};
    }
    return recs;
}

// 明文基准的数据集：**直接用客户端保存的明文属性值**构造，
// 保证"基准看到的记录"与"协议编码进 LCTE 的记录"逐条相同（否则对照无意义）。
mpraq_baseline::Dataset MakeBaseline(const std::vector<MpraqRecord>& recs) {
    mpraq_baseline::Dataset d;
    d.num_attributes = 2;
    d.domain_min = {0, 0};
    d.domain_max = {kAttr0DomainMax, kAttr1DomainMax};
    d.records.reserve(recs.size());
    for (const MpraqRecord& r : recs) d.records.push_back(r.attributes);
    return d;
}

// ---------------------------------------------------------------------------
// 谓词构造（`tsb::mpraq::Predicate` ↔ `mpraq_baseline::Pred` 的**显式转写**）
// ---------------------------------------------------------------------------

Predicate P0(PredicateOp op, int64_t v) {
    Predicate p;
    p.by_id = true;
    p.attribute_id = 0;
    p.op = op;
    p.value = v;
    return p;
}
Predicate P1(PredicateOp op, int64_t v) {
    Predicate p;
    p.by_id = true;
    p.attribute_id = 1;
    p.op = op;
    p.value = v;
    return p;
}
Predicate R0(int64_t a, int64_t b) {
    Predicate p;
    p.by_id = true;
    p.attribute_id = 0;
    p.op = PredicateOp::kRange;
    p.lower = a;
    p.upper = b;
    return p;
}
Predicate R1(int64_t a, int64_t b) {
    Predicate p;
    p.by_id = true;
    p.attribute_id = 1;
    p.op = PredicateOp::kRange;
    p.lower = a;
    p.upper = b;
    return p;
}

// 基准谓词（与上面的构造**一一对应**，刻意手写而不是模板化，便于逐条核对）
mpraq_baseline::Pred B0(mpraq_baseline::Op op, int64_t v) {
    return mpraq_baseline::Pred{0, op, v, 0, 0};
}
mpraq_baseline::Pred B1(mpraq_baseline::Op op, int64_t v) {
    return mpraq_baseline::Pred{1, op, v, 0, 0};
}
mpraq_baseline::Pred BR0(int64_t a, int64_t b) {
    return mpraq_baseline::Pred{0, mpraq_baseline::Op::kRange, 0, a, b};
}
mpraq_baseline::Pred BR1(int64_t a, int64_t b) {
    return mpraq_baseline::Pred{1, mpraq_baseline::Op::kRange, 0, a, b};
}

bool IsPowerOfTwo(uint64_t v) { return v != 0 && (v & (v - 1)) == 0; }

// (attr, column) 列表的可读渲染（`EXPECT_EQ` 的渲染器不支持 pair 容器 ⇒ 比较字符串）
std::string ColumnsText(const std::vector<std::pair<uint32_t, uint32_t>>& cols) {
    std::string s = "[";
    for (size_t i = 0; i < cols.size(); ++i) {
        if (i != 0) s += ", ";
        s += "(" + std::to_string(cols[i].first) + "," +
             std::to_string(cols[i].second) + ")";
    }
    s += "]";
    return s;
}

// ---------------------------------------------------------------------------
// 测试夹具：`Init` 一次，多个断言复用（省 HintInit 预算）
// ---------------------------------------------------------------------------

struct Fixture {
    size_t n = 0;
    Schema schema;
    std::vector<MpraqRecord> records;
    mpraq_baseline::Dataset baseline;
    std::unique_ptr<MpraqClient> client;

    // λ 可调：普通用例 8，覆盖压力大的用例上调
    static Fixture Make(size_t n, uint32_t lambda = kFastLambda, uint64_t seed = 7) {
        Fixture f;
        f.n = n;
        f.schema = MakeSchema(n);
        f.records = MakeRecords(n);
        f.baseline = MakeBaseline(f.records);
        MpraqInitParams p;
        p.lambda = lambda;
        p.prp_epsilon = kFastEps;
        p.seed = seed;
        const auto t0 = std::chrono::steady_clock::now();
        f.client = MpraqClient::Init(f.schema, f.records, p);
        Report().total_init_ms += std::chrono::duration<double, std::milli>(
                                      std::chrono::steady_clock::now() - t0)
                                      .count();
        ++Report().init_calls;
        return f;
    }

    // 几何自洽（D24④）：n = 列数 · ⌈N/128⌉、w = 2^k、c 为偶数
    void ExpectGeometrySane() const {
        const StoreParams& sp = client->store_params();
        ASSERT_EQ(sp.num_records, n);
        ASSERT_EQ(sp.words_per_column, (n + 127) / 128);
        ASSERT_EQ(sp.real_column_count, kRealColumns);
        ASSERT_TRUE(sp.column_count >= kRealColumns);
        ASSERT_EQ(sp.entry_count(),
                  static_cast<uint64_t>(sp.column_count) * sp.words_per_column);
        EXPECT_TRUE(IsPowerOfTwo(sp.plinko.w));
        EXPECT_EQ(sp.plinko.block_count() % 2, uint64_t{0});
        EXPECT_EQ(sp.entry_count(), sp.plinko.block_count() * sp.plinko.w);
    }
};

// ---------------------------------------------------------------------------
// 断言辅件
// ---------------------------------------------------------------------------

void RecordReport(const CountResult& r) {
    ++Report().count_calls;
    Report().total_retrieve_ms += r.retrieve_ms;
    Report().total_combine_ms += r.combine_ms;
    Report().total_queries_issued += r.queries_issued;
    if (r.filter.size() > Report().largest_compared_records) {
        Report().largest_compared_records = r.filter.size();
    }
}

// 把 filter 渲染成形如 "000...0 1" 的诊断串（失败时直接看出差异位置）
std::string DiffShape(const std::vector<uint8_t>& got, const std::vector<uint8_t>& want) {
    std::string s;
    for (size_t i = 0; i < got.size() && i < want.size(); ++i) {
        s.push_back(got[i] == want[i] ? '.' : 'X');
    }
    return s;
}

// **逐记录**对照 filter 向量（比值更重要：错一格必须失败）
void ExpectFilterMatchesBaseline(const CountResult& r,
                                 const std::vector<uint8_t>& want, const char* label) {
    ASSERT_EQ(r.filter.size(), want.size());
    size_t mismatched = 0;
    size_t first_bad = want.size();
    for (size_t i = 0; i < want.size(); ++i) {
        if (r.filter[i] != want[i]) {
            if (mismatched == 0) first_bad = i;
            ++mismatched;
        }
    }
    if (mismatched != 0) {
        TSB_FAIL_(std::string("filter 向量逐记录对照失败（") + label + "）：不符 " +
                  std::to_string(mismatched) + "/" + std::to_string(want.size()) +
                  " 处，首个不符下标 " + std::to_string(first_bad) +
                  "；差异图（. = 一致、X = 不符）= " + DiffShape(r.filter, want) +
                  "；实际形状 = " + mpraq_baseline::FilterShape(r.filter) +
                  "；期望形状 = " + mpraq_baseline::FilterShape(want));
    }
    Report().filter_bits_compared += want.size();
}

void ExpectCountMatchesBaseline(const CountResult& r,
                                const std::vector<uint8_t>& want, const char* label) {
    ExpectFilterMatchesBaseline(r, want, label);
    uint64_t ones = 0;
    for (uint8_t b : want) {
        if (b) ++ones;
    }
    EXPECT_EQ(r.count, ones);
}

// "一个批次 / 每台恰好 1 次 RPC"的不变量（Q5 / D24④ 的真正内容）：
//   本层把**全部列的全部 word** 放进**一个** `MpraqQueryBatch` ⇒ `RunBatch` 走
//   **一次** `ServerRespBatch` ⇒ 远程部署下每台服务器**恰好 1 次网络往返**，
//   而批内的查询集个数 = `列数 × ⌈N/128⌉`（与谓词个数无关）。
void ExpectOneBatchPerServer(const Fixture& f, const CountResult& r, const char* label) {
    EXPECT_EQ(r.queries_issued,
              static_cast<uint64_t>(r.columns.size()) * f.client->ColumnWordCount());
    EXPECT_EQ(r.server_resp_batch_calls[0], uint64_t{1});   // 每台恰好 1 次批量调用
    EXPECT_EQ(r.server_resp_batch_calls[1], uint64_t{1});
    EXPECT_EQ(r.server_resp_single_calls[0], uint64_t{0});  // 本层不碰标量接口
    EXPECT_EQ(r.server_resp_single_calls[1], uint64_t{0});
    EXPECT_EQ(r.server_resp_calls[0], uint64_t{1});         // = RPC 次数
    EXPECT_EQ(r.server_resp_calls[1], uint64_t{1});
    if (r.server_resp_calls[0] != 1 || r.server_resp_calls[1] != 1) {
        TSB_FAIL_(std::string("一次查询 = 每台恰好 1 次 RPC 的不变量失败（") + label + "）");
    }
}

void ExpectOneBatchPerServerC(const MpraqClient& c, const CountResult& r, const char* label) {
    EXPECT_EQ(r.queries_issued,
              static_cast<uint64_t>(r.columns.size()) * c.ColumnWordCount());
    EXPECT_EQ(r.server_resp_calls[0], uint64_t{1});
    EXPECT_EQ(r.server_resp_calls[1], uint64_t{1});
    EXPECT_EQ(r.server_resp_single_calls[0], uint64_t{0});
    if (r.server_resp_calls[0] != 1) {
        TSB_FAIL_(std::string("一次查询 = 每台恰好 1 次 RPC 的不变量失败（") + label + "）");
    }
}

// 跑一组**合取**谓词并与基准逐记录对照（转写关系在调用处显式给出）
CountResult RunConjunction(const Fixture& f, const std::vector<Predicate>& preds,
                           const std::vector<mpraq_baseline::Pred>& base,
                           const char* label) {
    const CountResult r = CountPredicates(*f.client, f.schema, preds);
    RecordReport(r);
    ExpectCountMatchesBaseline(r, mpraq_baseline::Filter(f.baseline, base), label);
    return r;
}

}  // namespace

// ===========================================================================
// 1. 单谓词全操作符（逐记录对照 filter 向量）
// ===========================================================================
//
// ⚠️ `gt` / `ge` 是 MPA-02 里**最容易写反**的一对（被取反的列只差一格，D19-1）；
//    这里对每个操作符都取**边界值本身**（v = 3），让"错位一格"必然被逐记录对照抓住。

TEST(MpraqCount, SinglePredicateAllOperatorsMatchBaselineRecordByRecord) {
    // ⚠️ 两个**独立**的预算（实测踩过）：
    //    ① 备份 hint 数 `q = λw/2`（D8：每个查询集消费 1 条备份 hint）；
    //    ② 🔴 **查询集总数 <= n**（Plinko 的每个查询集消耗一个 [0,n) 里的索引；
    //       `QueryGen` 对**重复索引**还会另取一个未答复的随机索引，
    //       n 个索引用完就抛"全部 n 个索引都已答复过 ⇒ 重跑离线"）。
    //    N=1024 时 n = 16 列 × 8 word = 128 ⇒ **一个 fixture 最多 128 个查询集**，
    //    而 14 组谓词的实际检索量是 160 个（实测）⇒ 必须拆到 **2 个 fixture**
    //    （这是 Plinko 的硬边界：一次离线最多 n 个查询集，与 λ 无关）。
    Fixture f = Fixture::Make(1024, 40);                 // 前 6 个谓词（56 个查询集）
    Fixture g = Fixture::Make(1024, 40, /*seed=*/11);    // 后 8 个谓词（104 个查询集）
    f.ExpectGeometrySane();

    struct Case {
        const char* name;
        Predicate pred;
        mpraq_baseline::Pred base;
    };
    const std::vector<Case> cases = {
        {"attr0 eq 3", P0(PredicateOp::kEq, 3), B0(mpraq_baseline::Op::kEq, 3)},
        {"attr0 neq 3", P0(PredicateOp::kNeq, 3), B0(mpraq_baseline::Op::kNe, 3)},
        {"attr0 lt 3", P0(PredicateOp::kLt, 3), B0(mpraq_baseline::Op::kLt, 3)},
        {"attr0 le 3", P0(PredicateOp::kLe, 3), B0(mpraq_baseline::Op::kLe, 3)},
        {"attr0 gt 3", P0(PredicateOp::kGt, 3), B0(mpraq_baseline::Op::kGt, 3)},
        {"attr0 ge 3", P0(PredicateOp::kGe, 3), B0(mpraq_baseline::Op::kGe, 3)},
        {"attr0 range[1,4)", R0(1, 4), BR0(1, 4)},
        {"attr1 eq 1", P1(PredicateOp::kEq, 1), B1(mpraq_baseline::Op::kEq, 1)},
        {"attr1 neq 1", P1(PredicateOp::kNeq, 1), B1(mpraq_baseline::Op::kNe, 1)},
        {"attr1 lt 1", P1(PredicateOp::kLt, 1), B1(mpraq_baseline::Op::kLt, 1)},
        {"attr1 le 1", P1(PredicateOp::kLe, 1), B1(mpraq_baseline::Op::kLe, 1)},
        {"attr1 gt 1", P1(PredicateOp::kGt, 1), B1(mpraq_baseline::Op::kGt, 1)},
        {"attr1 ge 1", P1(PredicateOp::kGe, 1), B1(mpraq_baseline::Op::kGe, 1)},
        {"attr1 range[0,2)", R1(0, 2), BR1(0, 2)},
    };

    size_t total_queries = 0;
    for (size_t i = 0; i < cases.size(); ++i) {
        const Fixture& fx = (i < 6) ? f : g;  // 前 6 个用 f、后 8 个用 g（n 预算见上）
        const CountResult r = CountPredicates(*fx.client, fx.schema, {cases[i].pred});
        RecordReport(r);
        ExpectCountMatchesBaseline(r, mpraq_baseline::Filter(fx.baseline, {cases[i].base}),
                                   cases[i].name);
        // ⚠️ 每个**查询集**一次 `ServerResp`（= 列数 × ⌈N/128⌉；这里的 eq/neq 占 2 列）
        ExpectOneBatchPerServer(fx, r, cases[i].name);
        total_queries += static_cast<size_t>(r.queries_issued);
    }
    // 14 组谓词的**实测**检索量：attr0 前 6 组 56 个（1~2 列 × 8 word）+ attr1 后 8 组 104 个
    EXPECT_EQ(total_queries, static_cast<size_t>(160));

    // 便利入口 `CountPredicate` 与 `CountPredicates({p})` 必须逐位一致
    const uint64_t back_before = g.client->backup_remaining();
    const CountResult via_one = CountPredicate(*g.client, g.schema, P0(PredicateOp::kGe, 2));
    RecordReport(via_one);
    // D8 的账：每个查询集消费 1 条备份 hint（不刷新 ⇒ 一次离线只支持 q 次查询）
    EXPECT_EQ(g.client->backup_remaining(), back_before - via_one.queries_issued);
    const CountResult via_list = CountPredicates(*g.client, g.schema, {P0(PredicateOp::kGe, 2)});
    RecordReport(via_list);
    EXPECT_EQ(via_one.count, via_list.count);
    ExpectFilterMatchesBaseline(via_one,
                                mpraq_baseline::Filter(
                                    g.baseline, {B0(mpraq_baseline::Op::kGe, 2)}),
                                "CountPredicate 便利入口");

    std::printf(
        "[mpa04] N=%zu 单谓词全操作符：%zu 组逐记录对照（共 %zu 个查询集，拆到 2 个 "
        "fixture）；几何 columns=%zu(真实 %zu) ⌈N/128⌉=%zu n=%llu\n",
        f.n, cases.size(), total_queries, f.client->column_count(),
        f.client->real_column_count(), f.client->ColumnWordCount(),
        static_cast<unsigned long long>(f.client->store_params().entry_count()));
}

// ===========================================================================
// 2. 合取（跨 2 个属性）+ 论文的 De Morgan 形式
// ===========================================================================

TEST(MpraqCount, ConjunctionAcrossTwoAttributesMatchesBaseline) {
    // N=256 ⇒ ⌈N/128⌉=2：2 谓词 = 2 列 ⇒ 2·2 = 4 个查询集；3 谓词 = 3 列 ⇒ 6 个
    Fixture f = Fixture::Make(256, 16);
    f.ExpectGeometrySane();

    // 2 个谓词：attr0 >= 1 ∧ attr1 < 2
    const std::vector<Predicate> two = {P0(PredicateOp::kGe, 1), P1(PredicateOp::kLt, 2)};
    const std::vector<mpraq_baseline::Pred> two_b = {B0(mpraq_baseline::Op::kGe, 1),
                                                     B1(mpraq_baseline::Op::kLt, 2)};
    const CountResult r2 = RunConjunction(f, two, two_b, "attr0>=1 AND attr1<2");
    ExpectOneBatchPerServer(f, r2, "2 谓词 2 列");

    // 3 个谓词、跨 2 个属性（attr0 两个 + attr1 一个）
    const std::vector<Predicate> three = {R0(1, 4), P1(PredicateOp::kGe, 1),
                                          P0(PredicateOp::kLe, 3)};
    const std::vector<mpraq_baseline::Pred> three_b = {
        BR0(1, 4), B1(mpraq_baseline::Op::kGe, 1), B0(mpraq_baseline::Op::kLe, 3)};
    const CountResult r3 = RunConjunction(f, three, three_b, "attr0 in [1,4) AND attr1>=1 AND attr0<=3");
    ExpectOneBatchPerServer(f, r3, "3 谓词 3 列");

    // 直接声明"结果非平凡"，避免"全 0 也通过"的假绿
    EXPECT_TRUE(r2.count > 0 && r2.count < f.n);
    EXPECT_TRUE(r3.count > 0 && r3.count < f.n);
    std::printf("[mpa04] 合取：2 谓词 count=%llu、3 谓词 count=%llu（N=%zu）\n",
                (unsigned long long)r2.count, (unsigned long long)r3.count, f.n);
}

TEST(MpraqCount, DeMorganOptimizedFormEqualsFlatConjunction) {
    // 扁平 2 列 + De Morgan 2 列 + 单区间 2 列 ⇒ 3·(2·⌈256/128⌉) = 12 个查询集 ⇒ λ=40
    Fixture f = Fixture::Make(256, 40);

    // 论文 §"Multi-Predicate Filtering Mechanism" 的形式：
    //   Φ = ¬( ∨_i P_{i0}(l_i) ) ∧ ( ∧_i P_{i1}(r_i) )
    const std::vector<Predicate> ranges = {R0(1, 4), R0(2, 5)};
    const std::vector<mpraq_baseline::Pred> ranges_b = {BR0(1, 4), BR0(2, 5)};

    const CountResult flat = CountPredicates(*f.client, f.schema, ranges);
    RecordReport(flat);
    ExpectOneBatchPerServer(f, flat, "扁平合取");
    const CountResult dm = CountRangeConjunctionDeMorgan(*f.client, f.schema, ranges);
    RecordReport(dm);
    ExpectOneBatchPerServer(f, dm, "De Morgan 形式");

    const std::vector<uint8_t> want = mpraq_baseline::Filter(f.baseline, ranges_b);
    ExpectCountMatchesBaseline(flat, want, "扁平合取 range[1,4) AND range[2,5)");
    ExpectCountMatchesBaseline(dm, want, "De Morgan 形式");
    ExpectFilterMatchesBaseline(dm, flat.filter, "De Morgan 形式 vs 扁平合取");
    EXPECT_EQ(dm.count, flat.count);
    // 列集合也必须一致（去重后升序）
    EXPECT_EQ(ColumnsText(dm.columns), ColumnsText(flat.columns));
    EXPECT_TRUE(flat.count > 0 && flat.count < f.n);

    // 两个区间有重叠 ⇒ 合取等价于 [2,4)
    const CountResult single = CountPredicates(*f.client, f.schema, {R0(2, 4)});
    RecordReport(single);
    EXPECT_EQ(single.count, flat.count);

    std::printf("[mpa04] De Morgan：count=%llu（列 %zu 个、查询集 %llu）"
                "与扁平合取逐位一致；等价单区间 count=%llu\n",
                (unsigned long long)dm.count, dm.columns.size(),
                (unsigned long long)dm.queries_issued,
                (unsigned long long)single.count);
}

// ===========================================================================
// 3. 取反 / 边界（域两端、越界、两种阈值模式）
// ===========================================================================

TEST(MpraqCount, NegationAndDomainEdgesMatchBaseline) {
    // ⚠️ 预算口径（我第一版连踩三次，留档）—— 有三条**独立**的硬预算，最小的一条说了算：
    //    ① 备份 hint 数 `q = λw/2`（每个查询集消费 1 条，D8 不做摊销式离线）；
    //    ② Plinko 的**查询集总数 <= n**（每个查询集消耗一个 [0,n) 里的索引）；
    //    ③ 🔴 更隐蔽的一条：`QueryGen` 对**重复索引**（同一列同一 word 被再次检索）
    //       会另取一个"未答复"的**随机**索引来喂服务器（`PLINKO_SPEC` §3.5 的重复查询分支），
    //       因此"同一列的第二次查询"额外吃掉一个索引 ⇒ 大量复用同一列的用例会把
    //       ② 的预算抽干得更快（实测：N=1024/n=128 时 ~30 个查询集就报
    //       "全部 n 个索引都已答复过"）。
    //    ⇒ 本用例拆成 **3 个 fixture**，让每个 fixture 内**不出现重复的 (列, word)**：
    //        f：attr0 的域端点退化      → 列 {0,1} × 8 word + 列 {0,5} × 8 = 32 个查询集
    //        g：attr1 的 eq/neq 互补     → 8 个查询集
    //        h：4 组越界阈值对齐         → 32 个查询集
    Fixture f = Fixture::Make(1024, 40);                 // 边界 1/2/3（attr0）
    Fixture g = Fixture::Make(1024, 40, /*seed=*/11);    // eq/neq 互补（attr1）
    Fixture h = Fixture::Make(1024, 40, /*seed=*/12);    // 越界阈值对齐（attr0）

    // ---- 边界 1：le 到域上界（恒真）、gt 到域上界（恒假）----
    const CountResult all = CountPredicates(*f.client, f.schema, {P0(PredicateOp::kLe, kAttr0DomainMax)});
    RecordReport(all);
    ExpectCountMatchesBaseline(
        all, mpraq_baseline::Filter(f.baseline, {B0(mpraq_baseline::Op::kLe, kAttr0DomainMax)}),
        "attr0 <= domain_max");
    EXPECT_EQ(all.count, static_cast<uint64_t>(f.n));

    const CountResult none = CountPredicates(*f.client, f.schema, {P0(PredicateOp::kGt, kAttr0DomainMax)});
    RecordReport(none);
    ExpectCountMatchesBaseline(
        none, mpraq_baseline::Filter(f.baseline, {B0(mpraq_baseline::Op::kGt, kAttr0DomainMax)}),
        "attr0 > domain_max");
    EXPECT_EQ(none.count, uint64_t{0});

    // ---- 边界 2：lt 到域下界（恒假）、ge 到域下界（恒真）----
    const CountResult none2 = CountPredicates(*f.client, f.schema, {P0(PredicateOp::kLt, 0)});
    RecordReport(none2);
    ExpectCountMatchesBaseline(none2, mpraq_baseline::Filter(f.baseline, {B0(mpraq_baseline::Op::kLt, 0)}),
                               "attr0 < domain_min");
    EXPECT_EQ(none2.count, uint64_t{0});

    const CountResult all2 = CountPredicates(*f.client, f.schema, {P0(PredicateOp::kGe, 0)});
    RecordReport(all2);
    ExpectCountMatchesBaseline(all2, mpraq_baseline::Filter(f.baseline, {B0(mpraq_baseline::Op::kGe, 0)}),
                               "attr0 >= domain_min");
    EXPECT_EQ(all2.count, static_cast<uint64_t>(f.n));

    // ---- 边界 3：半开区间的排他上界 = domain_max + 1（允许出现）----
    const CountResult upto = CountPredicates(*f.client, f.schema,
                                             {R0(0, kAttr0DomainMax + 1)});
    RecordReport(upto);
    ExpectCountMatchesBaseline(
        upto, mpraq_baseline::Filter(f.baseline, {BR0(0, kAttr0DomainMax + 1)}),
        "attr0 in [0, domain_max+1)");
    EXPECT_EQ(upto.count, static_cast<uint64_t>(f.n));

    // ---- 取反：neq 在每个取值上都要与基准逐记录一致（根节点带取反）----
    for (int64_t v = 0; v <= kAttr1DomainMax; ++v) {
        const CountResult r = CountPredicates(*g.client, g.schema, {P1(PredicateOp::kNeq, v)});
        RecordReport(r);
        ExpectCountMatchesBaseline(
            r, mpraq_baseline::Filter(g.baseline, {B1(mpraq_baseline::Op::kNe, v)}),
            "attr1 neq v");
        // eq 与 neq 互补（filter 逐位相反 ⇒ count 相加恒为 N）
        const CountResult e = CountPredicates(*g.client, g.schema, {P1(PredicateOp::kEq, v)});
        RecordReport(e);
        ExpectCountMatchesBaseline(
            e, mpraq_baseline::Filter(g.baseline, {B1(mpraq_baseline::Op::kEq, v)}),
            "attr1 eq v");
        EXPECT_EQ(r.count + e.count, static_cast<uint64_t>(g.n));
    }

    // ---- 阈值对齐（Q6）----
    // ⚠️ 重要口径（实测纠正了我第一版）：`MPA-02` 的 `RequireBoundInDomain` 会**先**把
    //    "取值域之外"的阈值拒掉（`std::out_of_range`，与 `ThresholdMode` 无关），所以
    //    **默认 schema（R 精确覆盖取值域 [0, 4] ⊂ R=[0,5]）里根本不存在"会被对齐的阈值"**：
    //    取值域内的合法阈值 0..5 全都恰好落在 R 内。
    //    ⇒ 要真正走到"对齐"分支，必须换一个 **R 不覆盖取值域** 的 schema（见下 h 与 wide）。
    //    两种模式在"阈值恰好在 R 内"时都必须给出与基准一致的答案（对齐是 no-op）。
    const CountResult at_max = CountPredicates(*h.client, h.schema, {P0(PredicateOp::kLt, 5)});
    RecordReport(at_max);
    ExpectCountMatchesBaseline(at_max,
                               mpraq_baseline::Filter(h.baseline, {B0(mpraq_baseline::Op::kLt, 5)}),
                               "阈值恰在 R 上端（对齐 no-op）");
    EXPECT_EQ(at_max.count, static_cast<uint64_t>(h.n));

    const CountResult at_min = CountPredicates(*h.client, h.schema, {P0(PredicateOp::kLe, 0)});
    RecordReport(at_min);
    ExpectCountMatchesBaseline(at_min,
                               mpraq_baseline::Filter(h.baseline, {B0(mpraq_baseline::Op::kLe, 0)}),
                               "le(0) → 阈值 1（对齐 no-op）");

    // ---- 两条模式的**可达性**结论（实测纠正了我第一版的设计假设）----
    //   想把"阈值被夹到最近有效值"这条分支跑起来，需要一个 `R 不覆盖取值域` 的 schema；
    //   但 `MpraqClient::Init` 会按 **D19-5** 直接拒绝这种 schema
    //   （`lcte.range_size = 6 < 跨度+2 = 11`）⇒ 在**合法的 MPRAQ 实例**上，
    //   `MPA-02` 的 `RequireBoundInDomain` 已经把阈值限制在 [domain_min, domain_max+1]，
    //   而这个区间**恒被 R 覆盖** ⇒ `kAlignNearest` 的"夹值"分支**不可达**，
    //   `kStrict` 也不会比它多拒绝任何东西。这里把这个结构事实**断言**下来：
    for (const AttributeSchema& a : f.schema.attributes()) {
        for (int64_t th = a.domain_min; th <= a.domain_max + 1; ++th) {
            EXPECT_TRUE(LcteContainsThreshold(a.lcte, th));
        }
        // 域外多一格就已经不合法（`RequireBoundInDomain` 直接拒绝，与 ThresholdMode 无关）
        EXPECT_FALSE(LcteContainsThreshold(a.lcte, a.domain_max + 2));
    }
    EXPECT_THROW(CountPredicates(*h.client, h.schema, {P0(PredicateOp::kLt, -3)}),
                 std::out_of_range);
    EXPECT_THROW(CountPredicates(*h.client, h.schema, {P0(PredicateOp::kGt, 9)}),
                 std::out_of_range);

    std::printf("[mpa04] 边界/取反：全命中=%llu/%zu、零命中=%llu（域两端 le/gt/lt/ge）；"
                "neq/eq 在 attr1 的 3 个取值上互补；阈值恰在 R 内时对齐为 no-op 且与基准一致；"
                "合法 schema 下 [domain_min, domain_max+1] 恒被 R 覆盖 ⇒ 对齐分支不可达"
                "（域外阈值被 MPA-02 直接拒）\n",
                (unsigned long long)all.count, f.n, (unsigned long long)none.count);
}

TEST(MpraqCount, StrictModeRejectsThresholdsOutsideLcteRangeAndRangeInversion) {
    Fixture f = Fixture::Make(100);

    // ⚠️ 关键前提（两条实测结论，纠正了我第一版的假设）：
    //   ① `MpraqClient::Init` 按 **D19-5** 要求 `m >= 跨度+2` ⇒ 合法实例里
    //      `R ⊇ [domain_min, domain_max+1]` **精确覆盖**取值域；
    //   ② `MPA-02` 的 `RequireBoundInDomain` 又把阈值限制在 [domain_min, domain_max+1]。
    //   ⇒ 在**合法 MPRAQ 实例**上，"取值域合法的阈值全部落在 R 内"，
    //      `kStrict` 因此**没有**比 `kAlignNearest` 多拒绝任何东西（它是为
    //      "R 非法/裁剪过的部署"准备的应急开关）。这里把这个结论固化成用例：
    //      `kStrict` 必须**接受** R 两端的全部合法阈值，而域外阈值两种模式都拒。
    const AttributeSchema& a0 = f.schema.ById(0);
    EXPECT_EQ(LcteMinThreshold(a0.lcte), int64_t{0});
    EXPECT_EQ(LcteMaxThreshold(a0.lcte), int64_t{5});
    EXPECT_TRUE(CoversDomainExactly(a0.lcte, a0.domain_min, a0.domain_max));
    EXPECT_THROW(CountPredicates(*f.client, f.schema, {P0(PredicateOp::kLt, 7)},
                                 ThresholdMode::kStrict),
                 std::out_of_range);
    // 阈值恰好在 R 两端 ⇒ 严格模式必须接受
    EXPECT_NO_THROW(CountPredicates(*f.client, f.schema, {P0(PredicateOp::kLt, 0)},
                                    ThresholdMode::kStrict));
    EXPECT_NO_THROW(CountPredicates(*f.client, f.schema, {P0(PredicateOp::kLt, 5)},
                                    ThresholdMode::kStrict));
    EXPECT_NO_THROW(CountPredicates(*f.client, f.schema, {P0(PredicateOp::kGe, 5)},
                                    ThresholdMode::kStrict));
    // 超出**允许边界** [domain_min, domain_max+1] ⇒ 两种模式都直接拒绝（调用方写错查询）
    EXPECT_THROW(CountPredicates(*f.client, f.schema, {P0(PredicateOp::kLt, 7)}),
                 std::out_of_range);
    EXPECT_THROW(CountPredicates(*f.client, f.schema, {P0(PredicateOp::kLt, -1)},
                                 ThresholdMode::kStrict),
                 std::out_of_range);

    // range 空区间 / 倒置被拒（`MPA-02` 负责，本层不重复实现）
    EXPECT_THROW(CountPredicates(*f.client, f.schema, {R0(3, 3)}), std::invalid_argument);
    EXPECT_THROW(CountPredicates(*f.client, f.schema, {R0(4, 1)}), std::invalid_argument);

    // 参数校验：空谓词列表、属性号越界、取值域越界
    EXPECT_THROW(CountPredicates(*f.client, f.schema, {}), std::invalid_argument);
    EXPECT_THROW(CountRangeConjunctionDeMorgan(*f.client, f.schema, {}), std::invalid_argument);
    Predicate bad_attr = P0(PredicateOp::kEq, 1);
    bad_attr.attribute_id = 99;
    EXPECT_THROW(CountPredicates(*f.client, f.schema, {bad_attr}), std::out_of_range);
    EXPECT_THROW(CountPredicates(*f.client, f.schema, {P0(PredicateOp::kEq, 9)}),
                 std::out_of_range);
    // De Morgan 形式只接受 range
    EXPECT_THROW(CountRangeConjunctionDeMorgan(*f.client, f.schema, {P0(PredicateOp::kLt, 3)}),
                 std::invalid_argument);

    // 列取回入口的越界校验（补齐列不属于任何属性 ⇒ 不可能被检索）
    EXPECT_THROW(RetrieveColumnBits(*f.client, f.schema, 5, 0), std::out_of_range);
    EXPECT_THROW(RetrieveColumnBits(*f.client, f.schema, 0, kAttr0M), std::out_of_range);
    EXPECT_THROW(RetrieveColumnBits(*f.client, f.schema, 0, kAttr0M + 5), std::out_of_range);
    EXPECT_NO_THROW(RetrieveColumnBits(*f.client, f.schema, 1, kAttr1M - 1));
}

// ===========================================================================
// 4. 退化规模：N=1、N=100（尾部填充位）、全命中 / 零命中
// ===========================================================================

TEST(MpraqCount, SingleRecordWindow) {
    // N=1 ⇒ 每列 1 个 word；eq 是 2 列 ⇒ 每个 eq 谓词 2 个查询集。本用例累计 ~10 个 ⇒ λ=40
    Fixture f = Fixture::Make(1, 40);
    f.ExpectGeometrySane();
    EXPECT_EQ(f.client->ColumnWordCount(), size_t{1});

    // 该记录的取值：attr0 = 0、attr1 = 0
    const CountResult hit = CountPredicates(*f.client, f.schema, {P0(PredicateOp::kEq, 0)});
    RecordReport(hit);
    ExpectCountMatchesBaseline(hit, mpraq_baseline::Filter(f.baseline, {B0(mpraq_baseline::Op::kEq, 0)}),
                               "N=1 eq 命中");
    EXPECT_EQ(hit.count, uint64_t{1});
    EXPECT_EQ(hit.filter, std::vector<uint8_t>{1});

    const CountResult miss = CountPredicates(*f.client, f.schema, {P0(PredicateOp::kEq, 1)});
    RecordReport(miss);
    ExpectCountMatchesBaseline(miss, mpraq_baseline::Filter(f.baseline, {B0(mpraq_baseline::Op::kEq, 1)}),
                               "N=1 eq 未命中");
    EXPECT_EQ(miss.count, uint64_t{0});
    EXPECT_EQ(miss.filter, std::vector<uint8_t>{0});

    // 跨两个属性的合取在 N=1 上同样成立
    const CountResult both = CountPredicates(*f.client, f.schema,
                                             {P0(PredicateOp::kEq, 0), P1(PredicateOp::kEq, 0)});
    RecordReport(both);
    ExpectCountMatchesBaseline(
        both, mpraq_baseline::Filter(f.baseline, {B0(mpraq_baseline::Op::kEq, 0),
                                                  B1(mpraq_baseline::Op::kEq, 0)}),
        "N=1 双属性合取");
    EXPECT_EQ(both.count, uint64_t{1});
    // attr0 eq 0 → 列 {0,1}、attr1 eq 0 → 列 {0,1} ⇒ 去重后 4 个列 × ⌈1/128⌉ = 4 个查询集
    EXPECT_EQ(both.queries_issued, uint64_t{4});
    EXPECT_EQ(ColumnsText(both.columns), std::string("[(0,0), (0,1), (1,0), (1,1)]"));
}

TEST(MpraqCount, TailPaddingBitsAreIgnoredWhenRecordCountIsNotMultipleOf128) {
    // ⚠️ 实测教训（我第一版假设错了）：`⌈100/128⌉ = 1`（不是 2）⇒ N=100 时每列只有
    //    **一个** word，其中 100 位有效、28 位是尾部填充。要真正让"每列多个 word 且最后
    //    一个 word 带填充位"成立，N 必须 > 128 且不是 128 的倍数 ⇒ 下面用 N=200 补这一档。
    const size_t n = 100;
    Fixture f = Fixture::Make(n, 40);
    f.ExpectGeometrySane();
    ASSERT_EQ(f.client->ColumnWordCount(), size_t{1});

    int checked = 0;
    for (int64_t v = 0; v <= kAttr0DomainMax; ++v) {
        const CountResult r = CountPredicates(*f.client, f.schema, {P0(PredicateOp::kEq, v)});
        RecordReport(r);
        ExpectCountMatchesBaseline(r, mpraq_baseline::Filter(f.baseline, {B0(mpraq_baseline::Op::kEq, v)}),
                                   "N=100 eq v（尾部填充位）");
        checked += static_cast<int>(r.filter.size());
        // 尾部填充位若被错误地当成"第 100 条之后的命中"，count 会**超过** N ⇒ 这里直接钉住上界
        EXPECT_TRUE(r.count <= n);
    }
    EXPECT_EQ(checked, 5 * static_cast<int>(n));

    // 两个文件的 filter 长度必须恒为 N（不是 128 的倍数向上取整）
    const CountResult r = CountPredicates(*f.client, f.schema, {P0(PredicateOp::kGe, 0)});
    RecordReport(r);
    EXPECT_EQ(r.filter.size(), n);
    EXPECT_EQ(r.count, static_cast<uint64_t>(n));

    // ---- 全命中 / 零命中（同一 N 上的两种退化）----
    const CountResult all = CountPredicates(*f.client, f.schema, {R0(0, 5)});
    RecordReport(all);
    ExpectCountMatchesBaseline(all, mpraq_baseline::Filter(f.baseline, {BR0(0, 5)}), "N=100 全命中");
    EXPECT_EQ(all.count, static_cast<uint64_t>(n));

    const CountResult zero = CountPredicates(*f.client, f.schema, {R0(4, 5)});
    RecordReport(zero);
    ExpectCountMatchesBaseline(zero, mpraq_baseline::Filter(f.baseline, {BR0(4, 5)}), "N=100 单点区间");
    std::printf("[mpa04] N=100（非 128 倍数、⌈N/128⌉=%zu）：5 组 eq + 全命中 + 单点区间"
                "全部与基准逐位一致（filter 长度恒为 %zu，尾部 28 个填充位被忽略）\n",
                f.client->ColumnWordCount(), n);

    // ---- 真正"每列 2 个 word 且最后一个 word 带填充位"的一档：N=200（⌈200/128⌉=2）----
    const size_t n2 = 200;  // 第 2 个 word 的 128 位里只有 72 位有效、56 位填充
    Fixture g = Fixture::Make(n2, 40);
    g.ExpectGeometrySane();
    ASSERT_EQ(g.client->ColumnWordCount(), size_t{2});
    const CountResult r2 = CountPredicates(*g.client, g.schema, {P0(PredicateOp::kEq, 2)});
    RecordReport(r2);
    ExpectCountMatchesBaseline(r2,
                               mpraq_baseline::Filter(g.baseline, {B0(mpraq_baseline::Op::kEq, 2)}),
                               "N=200 eq 2（第 2 个 word 带填充位）");
    EXPECT_TRUE(r2.count > 0 && r2.count < n2);
    EXPECT_EQ(r2.queries_issued, uint64_t{2} * 2);  // eq ⇒ 2 列 × ⌈200/128⌉=2
    std::printf("[mpa04] N=200（⌈N/128⌉=2、末 word 含 56 个填充位）：eq 2 ⇒ count=%llu、"
                "查询集 %llu，与基准逐位一致\n",
                (unsigned long long)r2.count, (unsigned long long)r2.queries_issued);

    // ⚠️ 由实现**证明**"尾部填充位被忽略"，而不是只靠"碰巧它们都是 0"：
    //    在两台服务器的**同一个**尾部 word 上同时翻转一个填充位（XOR 共享 ⇒ 明文翻转、
    //    parity 仍一致）⇒ 检索结果不变 ⇒ 说明展开时确实只取了 j < N。
    {
        // N=200 ⇒ 第 2 个 word 覆盖记录 128..255，其中 128..199 有效（72 位）
        // ⇒ 填充位是 j = 72..127（我第一版写成 127 是"所有填充位都在 128 之后"的错觉）
        const size_t tail_bit = 127;  // 仍然是填充位（127 >= 200-128=72）
        ASSERT_TRUE(tail_bit >= n2 - 128);
        const uint64_t flat = g.client->ColumnWordIndex(0, 2, 1);  // 列 2 的第 2 个 word
        const uint128_t flip = static_cast<uint128_t>(1) << tail_bit;
        const uint128_t s0 = g.client->node(0).FeatureWord(flat);
        const uint128_t s1 = g.client->node(1).FeatureWord(flat);
        const std::vector<uint128_t> col0 = {s0 ^ flip};
        const std::vector<uint128_t> col1 = {s1};
        g.client->node(0).UploadFeatureWords(flat, col0);
        g.client->node(1).UploadFeatureWords(flat, col1);
        // 明文第 127 个 word 的填充位现在是 1，但 filter 必须与注入前**完全一致**
        const CountResult after = CountPredicates(*g.client, g.schema, {P0(PredicateOp::kEq, 2)});
        RecordReport(after);
        EXPECT_EQ(after.count, r2.count);
        EXPECT_EQ(after.filter, r2.filter);
        const std::vector<uint8_t> bits = RetrieveColumnBits(*g.client, g.schema, 0, 2);
        EXPECT_EQ(bits, g.client->PlainColumnBits(0, 2));  // j < N 的位不受影响
        EXPECT_EQ(bits.size(), n2);
        std::printf("[mpa04] 填充位注入：翻转末 word 的第 %zu 位（< N 之外）后 "
                    "filter 逐位不变（count=%llu）⇒ 尾部填充位确实被忽略\n",
                    tail_bit, (unsigned long long)after.count);
    }
}

// ---------------------------------------------------------------------------
// 4b. 大 N（多 word 列）：本项目常规用例里能跑到的最大规模
// ---------------------------------------------------------------------------
//
// N=4096 ⇒ ⌈N/128⌉ = 32（每列 32 个 word，位展开要跨 32 个 word）；
// 真实列 M=10 ⇒ 补齐到 16 列 ⇒ n = 512、w = 32、c = 16（λ=40、ε=1e-4 加速）。
// ⚠️ 这是一次**真实的 D6 期望值测试**（与基准逐记录对照），不是"跑通就算"；
//    它也把"列 = 32 个 word 的批量检索 + 位展开"这条链路在较大规模上钉住。
//    `Init` 代价 ≈ n × IF⁻¹ ≈ 0.4 s（D22-1 的预算口径，n=512 ≤ 2¹²）。

TEST(MpraqCount, LargeWindowMultiWordColumnsMatchBaseline) {
    const size_t n = 4096;
    Fixture f = Fixture::Make(n, 40);
    f.ExpectGeometrySane();
    ASSERT_EQ(f.client->ColumnWordCount(), size_t{32});
    ASSERT_EQ(f.client->store_params().entry_count(), uint64_t{512});

    // 2 个谓词、跨 2 个属性、去重后 3 个列：attr0 range[1,4) → 列 {1,4}；attr1 ge 1 → 列 {1}
    const std::vector<Predicate> preds = {R0(1, 4), P1(PredicateOp::kGe, 1)};
    const std::vector<mpraq_baseline::Pred> base = {BR0(1, 4), B1(mpraq_baseline::Op::kGe, 1)};

    const CountResult r = CountPredicates(*f.client, f.schema, preds);
    RecordReport(r);
    ExpectCountMatchesBaseline(r, mpraq_baseline::Filter(f.baseline, base), "N=4096 双属性合取");
    ExpectOneBatchPerServer(f, r, "N=4096 双属性合取");
    EXPECT_EQ(r.columns.size(), size_t{3});
    EXPECT_EQ(r.queries_issued, static_cast<uint64_t>(3) * uint64_t{32});
    EXPECT_TRUE(r.count > 0 && r.count < n);

    std::printf(
        "[mpa04] 大 N：N=%zu M=%zu(补齐 %zu) ⌈N/128⌉=%zu n=%llu w=%llu c=%llu；"
        "3 列合取 count=%llu、查询集 %llu、每台 ServerRespBatch=%llu、"
        "retrieve=%.3f ms combine=%.3f ms\n",
        n, f.client->real_column_count(), f.client->column_count(),
        f.client->ColumnWordCount(),
        (unsigned long long)f.client->store_params().entry_count(),
        (unsigned long long)f.client->plinko_params().w,
        (unsigned long long)f.client->plinko_params().block_count(),
        (unsigned long long)r.count, (unsigned long long)r.queries_issued,
        (unsigned long long)r.server_resp_batch_calls[0], r.retrieve_ms, r.combine_ms);
}

// ===========================================================================
// 5. RPC 不变量（Q5 / D24④）
// ===========================================================================

TEST(MpraqCount, OneBatchPerServerAndRpcCountIsIndependentOfPredicateCount) {
    // λ=80 才有足够的备份 hint 支撑"多列 × ⌈N/128⌉=8"这一档（N=1024 ⇒ n=128）
    Fixture f = Fixture::Make(1024, 80);
    f.ExpectGeometrySane();

    const MpraqNode& node0 = f.client->node(0);
    EXPECT_EQ(node0.batch_rpc_count(), uint64_t{0});  // `Init`（含 HintInit）不发任何查询
    EXPECT_EQ(f.client->channel_rpc_stats(0).rpc_calls(), uint64_t{0});
    EXPECT_EQ(f.client->channel_rpc_stats(1).rpc_calls(), uint64_t{0});

    // 3 个谓词、跨 2 个属性、去重后 3 个不同的列
    const std::vector<Predicate> preds = {R0(1, 4), P1(PredicateOp::kGe, 1),
                                          P0(PredicateOp::kLe, 3)};
    const CountResult r = CountPredicates(*f.client, f.schema, preds);
    RecordReport(r);

    // ---------------------------------------------------------------
    // 🔴 Q5 / D24④ 的口径（`MPRAQ_IMPL.md` §3 的接口细节）：
    //    **一次查询 = 一个 `MpraqQueryBatch` = 每台服务器恰好 1 次 `ServerRespBatch`
    //    = 1 次网络往返**，与谓词个数、列个数、`⌈N/128⌉` **全都无关**。
    //    批内查询集个数 = 3 列 × 8 word = 24（N=1024 ⇒ ⌈N/128⌉=8）。
    //    ⚠️ 早期版本的 `RunBatch` 是"逐查询集一次标量 `ServerResp`"（此时上面的
    //       不变量不成立），`MPA-03` 已把它改成整批一次 `ServerRespBatch`；
    //       `channel_server_resp_calls()`（兼容旧名）现在只数**标量**次数 ⇒ 恒为 0，
    //       要断言 RPC 次数请用 `channel_rpc_stats()` / `CountResult::server_resp_calls`。
    // ---------------------------------------------------------------
    ExpectOneBatchPerServer(f, r, "3 谓词 3 列");
    EXPECT_EQ(f.client->channel_rpc_stats(0).server_resp_batch_calls, uint64_t{1});
    EXPECT_EQ(f.client->channel_rpc_stats(1).server_resp_batch_calls, uint64_t{1});
    EXPECT_EQ(f.client->channel_rpc_stats(0).server_resp_single_calls, uint64_t{0});
    EXPECT_EQ(f.client->channel_server_resp_calls(0), uint64_t{0});
    EXPECT_EQ(f.client->channel_rpc_stats(0).queries, r.queries_issued);  // 批内查询集个数
    EXPECT_EQ(node0.batch_rpc_count(), uint64_t{1});
    // D31：服务器侧 `queries_served()` = **查询集个数**（每条 PlinkoQuery 计 1，与
    // `grpc_mpraq` 通道同口径）；区块/word 访问量归 `words_read()`。
    EXPECT_EQ(node0.queries_served(), r.queries_issued);
    EXPECT_EQ(f.client->node(1).queries_served(), r.queries_issued);
    EXPECT_EQ(node0.words_read(), r.queries_issued * f.client->plinko_params().block_count());

    // 第 2 次查询（谓词个数不同、列数相同）⇒ 增量仍然只与"列数 × ⌈N/128⌉"有关，RPC 仍 +1
    const CountResult r2 = CountPredicates(*f.client, f.schema, {P0(PredicateOp::kLt, 2),
                                                                 P1(PredicateOp::kGt, 2),
                                                                 R0(1, 3)});
    RecordReport(r2);
    ExpectOneBatchPerServer(f, r2, "第 2 次查询");
    EXPECT_EQ(f.client->channel_rpc_stats(0).server_resp_batch_calls, uint64_t{2});
    EXPECT_EQ(node0.batch_rpc_count(), uint64_t{2});

    // ---------------------------------------------------------------
    // 反例（口径验证，**这条才是 Q5 的真正内容**）：逐列各发一次 RPC。
    // 用 `RetrieveColumnBits`（每列一个批次）显式制造 ⇒ 每次多 1 次往返
    // （RPC 次数随**列数**线性增长，而不是随批内查询集个数）。
    // ---------------------------------------------------------------
    uint64_t per_column_rpcs = 0;
    for (uint32_t c = 0; c < 3; ++c) {
        const std::vector<uint8_t> bits = RetrieveColumnBits(*f.client, f.schema, 0, c);
        EXPECT_EQ(bits.size(), f.n);
        ++per_column_rpcs;
    }
    EXPECT_EQ(f.client->channel_rpc_stats(0).server_resp_batch_calls, 2 + per_column_rpcs);
    EXPECT_EQ(f.client->channel_rpc_stats(1).server_resp_batch_calls, 2 + per_column_rpcs);

    std::printf(
        "[mpa04] RPC 不变量（N=%zu、⌈N/128⌉=%zu、λ=80）：3 谓词 3 列 ⇒ 查询集 %llu / "
        "**每台 ServerRespBatch = %llu**（= 1 次往返）、标量 ServerResp = %llu；"
        "第 2 次查询后累计 batch_calls = %llu；"
        "反例（逐列 3 次 RPC）多出 %llu 次 ⇒ '整批一次' 由本层打包保证\n",
        f.n, f.client->ColumnWordCount(), (unsigned long long)r.queries_issued,
        (unsigned long long)r.server_resp_batch_calls[0],
        (unsigned long long)r.server_resp_single_calls[0],
        (unsigned long long)f.client->channel_rpc_stats(0).server_resp_batch_calls,
        (unsigned long long)per_column_rpcs);
}

// ===========================================================================
// 6. 列去重（`PredicatePlan::columns` 的去重升序集合）
// ===========================================================================
//
// 列号（`lcte.hpp` §1：第 j 列的阈值 = range_min + j）：
//   attr0：eq 2 → 列 {2, 3}；ge 2 → 列 {2}；lt 2 → 列 {2}；
//   attr1：range[0,2) → 列 {0, 2}；lt 3 → 列 {3}。

TEST(MpraqCount, DuplicateColumnsAreRetrievedOnce) {
    // N=256 ⇒ ⌈N/128⌉=2：主要一组（3 列 ⇒ 6 个查询集）+ 恒假一组（1 列 ⇒ 2 个）
    // + eq 一组（2 列 ⇒ 4 个）⇒ λ=16 有富余
    Fixture f = Fixture::Make(256, 16);
    f.ExpectGeometrySane();

    // ---- 6 个谓词，去重后只有 3 个不同的列 ----
    const std::vector<Predicate> preds = {
        P0(PredicateOp::kEq, 2),   // attr0 列 {2, 3}
        P0(PredicateOp::kGe, 2),   // attr0 列 {2}（与上面重复）
        P0(PredicateOp::kLt, 2),   // attr0 列 {2}（再重复）
        P0(PredicateOp::kLe, 1),   // attr0 列 {2}（le(1) = [x < 2]，仍是列 2）
        P1(PredicateOp::kLe, 1),   // attr1 列 {2}（le(1) = [x < 2]）
        P1(PredicateOp::kGe, 2),   // attr1 列 {2}（ge(2) = ¬[x < 2]）
    };
    const MpraqRpcStats before0 = f.client->channel_rpc_stats(0);
    const CountResult r = CountPredicates(*f.client, f.schema, preds);
    RecordReport(r);

    // `CountResult::columns` 就是实际检索的列：去重升序
    const std::vector<std::pair<uint32_t, uint32_t>> want_columns = {{0, 2}, {0, 3}, {1, 2}};
    EXPECT_EQ(r.columns.size(), size_t{3});
    EXPECT_EQ(ColumnsText(r.columns), ColumnsText(want_columns));
    EXPECT_EQ(r.queries_issued,
              static_cast<uint64_t>(3) * f.client->ColumnWordCount());
    // Q5/D24 的真正内容：6 个谓词、3 个不同的列 ⇒ **仍然只有 1 次往返**
    // （批内查询集 = 3 列 × ⌈N/128⌉，而不是"每谓词一次"、也不是"每列一次 RPC"）
    ExpectOneBatchPerServer(f, r, "6 谓词 3 列");
    EXPECT_EQ(f.client->channel_rpc_stats(0).server_resp_batch_calls -
                  before0.server_resp_batch_calls,
              uint64_t{1});
    EXPECT_EQ(f.client->channel_rpc_stats(0).queries - before0.queries, r.queries_issued);

    // 语义仍必须与基准逐记录一致（去重不能改变结果）
    ExpectCountMatchesBaseline(
        r,
        mpraq_baseline::Filter(f.baseline,
                               {B0(mpraq_baseline::Op::kEq, 2), B0(mpraq_baseline::Op::kGe, 2),
                                B0(mpraq_baseline::Op::kLt, 2), B0(mpraq_baseline::Op::kLe, 1),
                                B1(mpraq_baseline::Op::kLe, 1), B1(mpraq_baseline::Op::kGe, 2)}),
        "6 谓词 3 列（去重）");

    // ---- 同一列 + 正反取反 = 恒假：结果必须恰好零命中（不是"去重后只剩一个字面量"）----
    const CountResult contradiction =
        CountPredicates(*f.client, f.schema, {P0(PredicateOp::kLt, 3), P0(PredicateOp::kGe, 3)});
    RecordReport(contradiction);
    EXPECT_EQ(contradiction.columns.size(), size_t{1});
    EXPECT_EQ(ColumnsText(contradiction.columns), std::string("[(0,3)]"));
    EXPECT_EQ(contradiction.count, uint64_t{0});
    for (uint8_t b : contradiction.filter) EXPECT_EQ(b, uint8_t{0});

    // ---- 单谓词两个列（eq 的 v 与 v+1）：必须是 2 个列、2·⌈N/128⌉ 个查询集 ----
    const CountResult two_cols = CountPredicates(*f.client, f.schema, {P0(PredicateOp::kEq, 2)});
    RecordReport(two_cols);
    EXPECT_EQ(ColumnsText(two_cols.columns), std::string("[(0,2), (0,3)]"));
    EXPECT_EQ(two_cols.queries_issued, static_cast<uint64_t>(2) * f.client->ColumnWordCount());

    Report().dedup_columns_retrieved += r.columns.size();
    Report().dedup_queries_issued += r.queries_issued;
    std::printf(
        "[mpa04] 列去重（N=%zu）：6 谓词 → 实际检索 %zu 列（{0,2},{0,3},{1,2}），"
        "查询集 %llu（= 3 列 × ⌈N/128⌉=%zu）、ServerResp=(%llu,%llu)；"
        "同列正反取反 = 恒假（count=0）；eq 单谓词 = 2 列\n",
        f.n, r.columns.size(), (unsigned long long)r.queries_issued,
        f.client->ColumnWordCount(), (unsigned long long)r.server_resp_batch_calls[0],
        (unsigned long long)r.server_resp_batch_calls[1]);
}

// ===========================================================================
// 7. 确定性（同种子逐位一致）
// ===========================================================================

TEST(MpraqCount, SameSeedIsBitwiseReproducibleAndMatchesPlaintextViaRetrieveColumnBits) {
    // 本用例需要 4 个 Count 查询集 + 6 个单列查询集 = 10 个 ⇒ N=100 的 n=16 够用，
    // 但为了让"检索 6 个整列"的余量更舒服，这里用 N=256（n=32）
    const size_t n = 256;
    Fixture a = Fixture::Make(n, 40, /*seed=*/20260910);
    Fixture b = Fixture::Make(n, 40, /*seed=*/20260910);

    const std::vector<Predicate> preds = {R0(1, 4), P1(PredicateOp::kGe, 1)};
    const std::vector<mpraq_baseline::Pred> base = {BR0(1, 4), B1(mpraq_baseline::Op::kGe, 1)};

    const CountResult ra = CountPredicates(*a.client, a.schema, preds);
    RecordReport(ra);
    const CountResult rb = CountPredicates(*b.client, b.schema, preds);
    RecordReport(rb);

    EXPECT_EQ(ra.count, rb.count);
    EXPECT_EQ(ColumnsText(ra.columns), ColumnsText(rb.columns));
    EXPECT_EQ(ra.filter, rb.filter);  // 逐位一致（同一个 PRNG 种子 + 显式 nonce，D23）
    ExpectCountMatchesBaseline(ra, mpraq_baseline::Filter(a.baseline, base), "同种子第一次");
    ExpectCountMatchesBaseline(rb, mpraq_baseline::Filter(b.baseline, base), "同种子第二次");

    // ---- 与 `MPA-03` 的明文对照：检索到的列比特必须等于 `PlainColumnBits` ----
    // ⚠️ 这是"PIR 检索 + word→比特展开"这条链路的**独立**对照（明文副本由 Init 直接保存），
    //    而 `CountResult::filter` 的对照是"布尔组合"的对照 —— 两者都要有。
    size_t compared = 0;
    for (uint32_t c = 0; c < kAttr0M; ++c) {
        const std::vector<uint8_t> bits = RetrieveColumnBits(*a.client, a.schema, 0, c);
        const std::vector<uint8_t> plain = a.client->PlainColumnBits(0, c);
        ASSERT_EQ(bits.size(), n);
        ASSERT_EQ(plain.size(), n);
        EXPECT_EQ(bits, plain);
        compared += bits.size();
    }
    EXPECT_EQ(compared, static_cast<size_t>(kAttr0M) * n);

    std::printf("[mpa04] 确定性：同种子两次 filter 逐位一致；"
                "RetrieveColumnBits 与 PlainColumnBits 逐位一致（attr0 全部 %u 列 × N=%zu）\n",
                kAttr0M, n);
}

// ===========================================================================
// 8. 验收用例（**唯一**使用默认 ε = 1e-10 的用例，D22-1 慢用例标注）
// ===========================================================================
//
// λ=80（论文部署值）、ε=1e-10（Plinko 默认）。规模与 `MPA-03` 的验收用例同族：
// N=1024、M=10 ⇒ 列数补齐 16、⌈N/128⌉=8、n=128、w=8、c=16。
// 本用例同时验证：多谓词 + 多列的**一次 RPC** 全链、列去重后的检索量口径、
// 以及 filter 与明文基准**逐记录**一致。

TEST(MpraqCountAcceptance, DefaultEpsilonMultiPredicateCountMatchesBaseline) {
    const size_t n = 1024;
    Schema schema = MakeSchema(n);
    auto records = MakeRecords(n);
    const mpraq_baseline::Dataset baseline = MakeBaseline(records);

    MpraqInitParams p;
    p.lambda = 80;
    p.prp_epsilon = 1e-10;  // **默认** ε，不调小
    p.seed = 20260910;

    const auto t0 = std::chrono::steady_clock::now();
    auto client = MpraqClient::Init(schema, records, p);
    const double init_ms =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0)
            .count();
    Report().total_init_ms += init_ms;
    ++Report().init_calls;
    const MpraqInitTimings& tm = client->timings();
    EXPECT_EQ(tm.words_per_column, size_t{8});
    EXPECT_EQ(tm.entry_count, uint64_t{128});

    // 覆盖率（PLINKO_SPEC §5.1：λ=80 下不应有未覆盖条目）
    const std::vector<uint8_t> mask = client->coverage_mask();
    ASSERT_EQ(mask.size(), static_cast<size_t>(tm.entry_count));
    size_t uncovered = 0;
    for (uint8_t x : mask) {
        if (!x) ++uncovered;
    }
    EXPECT_EQ(uncovered, size_t{0});

    // 3 谓词、跨 2 属性：attr0 ∈ [1, 4) ∧ attr1 >= 1 ∧ attr0 <= 3
    const std::vector<Predicate> preds = {R0(1, 4), P1(PredicateOp::kGe, 1),
                                          P0(PredicateOp::kLe, 3)};
    const std::vector<mpraq_baseline::Pred> base = {
        BR0(1, 4), B1(mpraq_baseline::Op::kGe, 1), B0(mpraq_baseline::Op::kLe, 3)};

    const MpraqRpcStats before0 = client->channel_rpc_stats(0);
    const CountResult r = CountPredicates(*client, schema, preds);
    RecordReport(r);

    ExpectCountMatchesBaseline(r, mpraq_baseline::Filter(baseline, base), "验收用例（默认 ε）");
    ExpectOneBatchPerServerC(*client, r, "验收用例（默认 ε）");
    EXPECT_EQ(client->channel_rpc_stats(0).server_resp_batch_calls -
                  before0.server_resp_batch_calls,
              uint64_t{1});
    EXPECT_EQ(client->node(0).batch_rpc_count(), uint64_t{1});
    EXPECT_EQ(r.queries_issued, static_cast<uint64_t>(r.columns.size()) * tm.words_per_column);
    EXPECT_TRUE(r.count > 0 && r.count < n);

    // 单列检索耗时（同一份 hint 表，另起一次 RPC：只用于测量，不参与上面的口径断言）
    const auto t_col = std::chrono::steady_clock::now();
    const std::vector<uint8_t> col = RetrieveColumnBits(*client, schema, 0, 3);
    const double col_ms = std::chrono::duration<double, std::milli>(
                              std::chrono::steady_clock::now() - t_col)
                              .count();
    EXPECT_EQ(col, client->PlainColumnBits(0, 3));

    std::printf(
        "[mpa04-accept] Init: N=%zu M=%zu 列(补齐 %zu→%zu) ⌈N/128⌉=%zu n=%llu w=%llu c=%llu "
        "λ=%u ε=1e-10 ⇒ %.1f ms（hint %.1f ms）\n",
        n, client->real_column_count(), tm.padding_columns, tm.column_count,
        tm.words_per_column, (unsigned long long)tm.entry_count,
        (unsigned long long)tm.block_size, (unsigned long long)tm.block_count, p.lambda,
        init_ms, tm.hint_ms);
    std::printf(
        "[mpa04-accept] Count(3 谓词、跨 2 属性): count=%llu/%zu；列 %zu 个、查询集 %llu"
        "（= %zu 列 × %zu word）⇒ 每台 ServerRespBatch = %llu/%llu（= 1 次 RPC、标量 0）；"
        "retrieve=%.3f ms combine=%.3f ms；单列 %zu word 检索=%.3f ms；未覆盖条目=%zu\n",
        (unsigned long long)r.count, n, r.columns.size(),
        (unsigned long long)r.queries_issued, r.columns.size(), tm.words_per_column,
        (unsigned long long)r.server_resp_batch_calls[0],
        (unsigned long long)r.server_resp_batch_calls[1], r.retrieve_ms, r.combine_ms,
        tm.words_per_column, col_ms, uncovered);
    std::printf(
        "[mpa04-accept] ⚠️ 本任务**不做任何验证层**（论文的 HMAC 多集证明在共享域上不成立，"
        "D24①/L9；Count 的完整性待 §7.13 的 V2 裁决）⇒ 服务器返回错值时会静默给出错结果\n");
}

// ===========================================================================
// 汇总（在所有用例之后打印，供验收报告直接引用）
// ===========================================================================

TEST(MpraqCountReport, Summary) {
    const ReportState& s = Report();
    std::printf(
        "[mpa04-summary] 成功的 Count 调用 = %llu；Init 次数 = %llu；"
        "逐记录对照的 filter 位总数 = %llu（单次最大 N = %zu）；"
        "累计 Init = %.1f ms、retrieve = %.1f ms、combine = %.1f ms；"
        "累计查询集 = %llu；去重用例：6 谓词 → %llu 列 / %llu 查询集\n",
        (unsigned long long)s.count_calls, (unsigned long long)s.init_calls,
        (unsigned long long)s.filter_bits_compared, s.largest_compared_records,
        s.total_init_ms, s.total_retrieve_ms, s.total_combine_ms,
        (unsigned long long)s.total_queries_issued,
        (unsigned long long)s.dedup_columns_retrieved,
        (unsigned long long)s.dedup_queries_issued);
    EXPECT_TRUE(s.count_calls > 30);
    EXPECT_TRUE(s.filter_bits_compared > 4000);
}
