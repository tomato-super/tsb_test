// 规模配置层（`src/mpraq/scale_config.*`）的确定性用例集（**无计时断言**，铁律 D6）。
//
// 覆盖任务书的 10 条要求 + 2 条补充：
//   ① 2 的幂校验（rows / columns_per_attribute）与可读报错；
//   ② `M = 属性数 × 每属性列数` 精确成立（属性数 1/2/3/5）；
//   ③ `m` = 补齐到 2 的幂，且 `16·m·⌈N/128⌉ + 16·N·|attrs|` 与 `Init` 后
//      `node(0).StorageBytes()` **相等**（双报 `M` 口径）；
//   ④ `k ⇒ 去重列数 = min(k, M)`、`查询集数 = 去重列数 × ⌈N/128⌉`（用 `CountPredicates`
//      的 `queries_issued` / `columns.size()` 实测对照）、每台 `server_resp_batch_calls == 1`；
//   ⑤ `k > M` ⇒ 去重列数 = M（不越界、不重复计数）；
//   ⑥ 合成数据落在取值域内、`feature == i`（D36 行标签）、同种子逐位可复现；
//   ⑦ 谓词合法（阈值在 LCTE 区间内、`ParseConjunction` 不抛）且落在互不相同的列；
//   ⑧ JSON 往返（临时文件 vs 文本；并与仓库内 `config/mpraq_scale.json` 对照）；
//   ⑨ CLI 覆盖优先于 JSON（`MpraqScaleOverrides` + `ApplyOverrides`）；
//   ⑩ L14 预算：在预算内通过；**超预算 ⇒ 拒绝并给出可读原因**；
//   ⑪ 未知字段 / 不存在的文件 ⇒ fail-loudly；
//   ⑫ 换算行与账目必须能**打印/断言**出来（Headline / Report）。

#include "test_framework.hpp"

#include "mpraq/aggquery.hpp"
#include "mpraq/scale_config.hpp"
#include "mpraq_baseline.hpp"

#include <cstdio>
#include <fstream>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

using namespace tsb;
using namespace tsb::mpraq;

namespace {

// ---------------------------------------------------------------------------
// 夹具：小规模、快（λ = 8 / 16，ε = 1e-4），但仍覆盖真实几何
// ---------------------------------------------------------------------------

// λ = 8 时 q = λw/2；下面的规模都经过核对：去重列数 × ⌈N/128⌉ ≤ min(q, n)。
MpraqScaleConfig Cfg(uint64_t rows = 256, uint32_t cols = 8, uint32_t attrs = 2,
                     uint32_t preds = 3, uint32_t lambda = 8, uint64_t seed = 7) {
    MpraqScaleConfig c;
    c.rows = rows;
    c.columns_per_attribute = cols;
    c.attributes = attrs;
    c.predicates = preds;
    c.lambda = lambda;
    c.eps = 1e-4;
    c.seed = seed;
    return c;
}

// 断言"某个表达式抛出 std::invalid_argument 且消息里含指定子串"
template <typename Fn>
void ExpectInvalidArgumentContaining(Fn&& fn, const std::string& needle,
                                     const char* what) {
    try {
        fn();
    } catch (const std::invalid_argument& e) {
        const std::string msg = e.what();
        if (msg.find(needle) == std::string::npos) {
            TSB_FAIL_(std::string(what) + "：异常消息里没有 '" + needle + "'，实际消息 = " +
                      msg);
        }
        return;
    } catch (const std::exception& e) {
        TSB_FAIL_(std::string(what) + "：抛出了非 std::invalid_argument 的异常：" +
                  e.what());
        return;
    }
    TSB_FAIL_(std::string(what) + "：期望抛 std::invalid_argument，但没有抛");
}

bool IsPow2(uint64_t v) { return v != 0 && (v & (v - 1)) == 0; }

// 谓词 → 明文基准谓词（**独立转写**：基准不复用被测代码，见 mpraq_baseline.hpp 的约定）
mpraq_baseline::Pred ToBaseline(const Predicate& p) {
    mpraq_baseline::Pred b;
    b.attr = p.attribute_id;
    switch (p.op) {
        case PredicateOp::kEq: b.op = mpraq_baseline::Op::kEq; break;
        case PredicateOp::kNeq: b.op = mpraq_baseline::Op::kNe; break;
        case PredicateOp::kLt: b.op = mpraq_baseline::Op::kLt; break;
        case PredicateOp::kLe: b.op = mpraq_baseline::Op::kLe; break;
        case PredicateOp::kGt: b.op = mpraq_baseline::Op::kGt; break;
        case PredicateOp::kGe: b.op = mpraq_baseline::Op::kGe; break;
        case PredicateOp::kRange: b.op = mpraq_baseline::Op::kRange; break;
    }
    b.value = p.value;
    b.lower = p.lower;
    b.upper = p.upper;
    return b;
}

mpraq_baseline::Dataset BaselineOf(const MpraqScaleSetup& s) {
    mpraq_baseline::Dataset d;
    d.num_attributes = s.schema.num_attributes();
    for (const AttributeSchema& a : s.schema.attributes()) {
        d.domain_min.push_back(a.domain_min);
        d.domain_max.push_back(a.domain_max);
    }
    d.records.reserve(s.records.size());
    for (const MpraqRecord& r : s.records) d.records.push_back(r.attributes);
    return d;
}

std::string TmpPath() {
    return "/tmp/mpraq_scale_config_test_" + std::to_string(::getpid()) + ".json";
}

// `PredicatePlan::columns.size()` 的实测口径：去重列数（不经过 Init，纯解析）
size_t PlannedColumns(const MpraqScaleSetup& s) {
    return ParseConjunction(s.predicates, s.schema).columns.size();
}

}  // namespace

// ---------------------------------------------------------------------------
// ① 2 的幂校验（fail-loudly，且消息里点名字段与实际值）
// ---------------------------------------------------------------------------

TEST(MpraqScaleConfig, PowerOfTwoIsEnforcedFailLoudly) {
    // rows 非 2 的幂
    ExpectInvalidArgumentContaining(
        [] { EstimateScale(Cfg(/*rows=*/1000)); }, "rows",
        "rows=1000 必须被拒绝（且消息里指出字段名）");
    ExpectInvalidArgumentContaining([] { EstimateScale(Cfg(/*rows=*/1000)); }, "1000",
                                    "rows=1000 的消息里要给出实际值");
    // 每属性列数非 2 的幂
    ExpectInvalidArgumentContaining(
        [] { EstimateScale(Cfg(/*rows=*/1024, /*cols=*/6)); }, "columns_per_attribute",
        "columns_per_attribute=6 必须被拒绝");
    ExpectInvalidArgumentContaining([] { EstimateScale(Cfg(/*rows=*/1024, /*cols=*/6)); },
                                    "不是 2 的幂", "columns_per_attribute=6 的消息要说明原因");
    // rows = 0 / 每属性列数 = 1（取值域为空）/ 属性数 = 0 / 谓词数 = 0
    ExpectInvalidArgumentContaining([] { EstimateScale(Cfg(/*rows=*/0)); }, "rows",
                                    "rows=0 必须被拒绝");
    ExpectInvalidArgumentContaining([] { EstimateScale(Cfg(1024, /*cols=*/1)); },
                                    "columns_per_attribute",
                                    "columns_per_attribute=1（取值域为空）必须被拒绝");
    ExpectInvalidArgumentContaining([] { EstimateScale(Cfg(1024, 32, /*attrs=*/0)); },
                                    "attributes", "attributes=0 必须被拒绝");
    ExpectInvalidArgumentContaining([] { EstimateScale(Cfg(1024, 32, 2, /*preds=*/0)); },
                                    "predicates", "predicates=0 必须被拒绝");
    // λ = 0 / ε 越界
    ExpectInvalidArgumentContaining([] { EstimateScale(Cfg(1024, 32, 2, 3, /*lambda=*/0)); },
                                    "lambda", "lambda=0 必须被拒绝");

    // 合法：rows=1024（2 的幂）、每属性列数=32（2 的幂）
    const MpraqScaleEstimate e = EstimateScale(Cfg(/*rows=*/1024, /*cols=*/32));
    EXPECT_TRUE(IsPow2(e.rows));
    EXPECT_TRUE(IsPow2(e.columns_per_attribute));
    EXPECT_EQ(PlannedColumns(Build(Cfg(1024, 32))), size_t{3});
}

// ---------------------------------------------------------------------------
// ② M = 属性数 × 每属性列数（多组取值，含属性数 1/2/3/5）
// ---------------------------------------------------------------------------

TEST(MpraqScaleConfig, RealColumnsEqualsAttributesTimesColumnsPerAttribute) {
    const struct {
        uint32_t attrs;
        uint32_t cols;
    } cases[] = {{1, 2}, {1, 32}, {2, 4}, {2, 8}, {3, 4}, {5, 16}};
    for (const auto& c : cases) {
        const MpraqScaleConfig cfg = Cfg(/*rows=*/128, c.cols, c.attrs, /*preds=*/2);
        const MpraqScaleEstimate e = EstimateScale(cfg);
        EXPECT_EQ(e.real_columns_M,
                  static_cast<uint64_t>(c.attrs) * static_cast<uint64_t>(c.cols));
        // 每个属性**各自**一组列（否则跨属性谓词会串列）
        const MpraqScaleSetup s = Build(cfg);
        ASSERT_EQ(s.schema.num_attributes(), static_cast<size_t>(c.attrs));
        for (const AttributeSchema& a : s.schema.attributes()) {
            EXPECT_EQ(a.lcte.range_size, c.cols);
            EXPECT_EQ(a.lcte.window_size, uint32_t{128});
            EXPECT_EQ(a.lcte.range_min, int64_t{0});
            EXPECT_EQ(a.domain_min, int64_t{0});
            EXPECT_EQ(a.domain_max, static_cast<int64_t>(c.cols) - 2);
        }
        // 所有属性同形状（同 range_size / window_size / 取值域风格）
        for (const AttributeSchema& a : s.schema.attributes()) {
            EXPECT_EQ(a.lcte.range_size, s.schema.attributes()[0].lcte.range_size);
            EXPECT_EQ(a.domain_max, s.schema.attributes()[0].domain_max);
        }
        // m 是 2 的幂且 >= M；口径双报
        EXPECT_TRUE(IsPow2(e.columns_padded_m));
        EXPECT_TRUE(e.columns_padded_m >= e.real_columns_M);
        EXPECT_EQ(e.padding_columns, e.columns_padded_m - e.real_columns_M);
        EXPECT_EQ(e.words_per_column, (cfg.rows + 127) / 128);
        EXPECT_EQ(e.entries_n, e.columns_padded_m * e.words_per_column);
        EXPECT_EQ(e.blocks_c * e.block_size_w, e.entries_n);
        EXPECT_EQ(e.blocks_c % 2, uint64_t{0});
    }
}

// ---------------------------------------------------------------------------
// ③ m 派生 + 服务器存储公式 == Init 后 node(0).StorageBytes()（双报 M 口径）
// ---------------------------------------------------------------------------

TEST(MpraqScaleConfig, PaddedColumnsAndStorageMatchInitMeasurement) {
    const MpraqScaleConfig cfgs[] = {Cfg(/*rows=*/256, /*cols=*/8, /*attrs=*/2),
                                     Cfg(/*rows=*/512, /*cols=*/4, /*attrs=*/3)};
    for (const MpraqScaleConfig& cfg : cfgs) {
        const MpraqScaleSetup s = Build(cfg);
        const MpraqScaleEstimate& e = s.estimate;

        auto client = MpraqClient::Init(s.schema, s.records, s.init);
        const StoreParams& store = client->store_params();

        // 派生口径与实测口径必须逐项一致（否则两处公式漂移）
        const std::string diff = CompareEstimateWithStore(e, store);
        if (!diff.empty()) TSB_FAIL_("预估与 Init 实测不一致：" + diff);

        EXPECT_EQ(store.num_records, cfg.rows);
        EXPECT_EQ(store.real_column_count, e.real_columns_M);
        EXPECT_EQ(store.column_count, e.columns_padded_m);
        EXPECT_EQ(store.plinko.w, e.block_size_w);
        EXPECT_EQ(store.plinko.block_count(), e.blocks_c);
        EXPECT_EQ(store.entry_count(), e.entries_n);
        EXPECT_EQ(store.plinko.backup_hints(), e.hint_cap_q);

        // 服务器存储公式（含补齐，`node.hpp` §1）
        const uint64_t formula = 16ull * store.column_count * store.words_per_column +
                                 16ull * store.num_records * store.num_attributes();
        EXPECT_EQ(formula, e.storage_bytes_padded);
        EXPECT_EQ(client->node(0).StorageBytes(), formula);
        EXPECT_EQ(client->node(1).StorageBytes(), formula);
        // 不含补齐口径（双报 M）
        const uint64_t formula_m = 16ull * store.real_column_count * store.words_per_column +
                                   16ull * store.num_records * store.num_attributes();
        EXPECT_EQ(formula_m, e.storage_bytes_unpadded);
        EXPECT_EQ(e.storage_bytes_padded - e.storage_bytes_unpadded,
                  16ull * e.padding_columns * e.words_per_column);
        // 特征表/属性表两部分也可对上
        EXPECT_EQ(client->node(0).FeatureStorageBytes(),
                  16ull * store.column_count * store.words_per_column);
        EXPECT_EQ(client->node(0).AttributeStorageBytes(),
                  16ull * store.num_records * store.num_attributes());
    }
}

// ---------------------------------------------------------------------------
// ④ k ⇒ 去重列数 = min(k, M)；查询集数 = 去重列数 × ⌈N/128⌉；每台 RPC = 1
// ---------------------------------------------------------------------------

TEST(MpraqScaleConfig, PredicateCountMapsToDedupColumnsQuerySetsAndOneRpc) {
    const MpraqScaleConfig cfg = Cfg(/*rows=*/256, /*cols=*/8, /*attrs=*/2, /*preds=*/3);
    const MpraqScaleSetup s = Build(cfg);
    const MpraqScaleEstimate& e = s.estimate;
    ASSERT_EQ(e.dedup_columns, uint64_t{3});          // min(3, 16)
    ASSERT_EQ(e.query_sets, uint64_t{6});             // 3 × ⌈256/128⌉ = 3 × 2
    EXPECT_EQ(e.rpc_per_server, uint64_t{1});
    EXPECT_EQ(PlannedColumns(s), size_t{3});

    auto client = MpraqClient::Init(s.schema, s.records, s.init);
    const CountResult r = CountPredicates(*client, s.schema, s.predicates);
    EXPECT_EQ(r.columns.size(), static_cast<size_t>(e.dedup_columns));
    EXPECT_EQ(r.queries_issued, e.query_sets);
    EXPECT_EQ(r.queries_issued,
              static_cast<uint64_t>(r.columns.size()) * e.words_per_column);
    // 每台服务器**恰好 1 次** `ServerRespBatch`（= 1 次网络往返），标量路径恒 0
    for (int sid = 0; sid < 2; ++sid) {
        const MpraqRpcStats st = client->channel_rpc_stats(sid);
        EXPECT_EQ(st.server_resp_batch_calls, uint64_t{1});
        EXPECT_EQ(st.server_resp_single_calls, uint64_t{0});
        EXPECT_EQ(st.queries, e.query_sets);
        EXPECT_EQ(r.server_resp_batch_calls[static_cast<size_t>(sid)], uint64_t{1});
    }
    // Count 与**明文基准**逐值一致（铁律 D6：不是"跑通即通过"）
    std::vector<mpraq_baseline::Pred> bp;
    for (const Predicate& p : s.predicates) bp.push_back(ToBaseline(p));
    const mpraq_baseline::Dataset d = BaselineOf(s);
    const std::vector<uint8_t> bfilter = mpraq_baseline::Filter(d, bp);
    EXPECT_EQ(r.count, mpraq_baseline::Count(d, bp));
    EXPECT_EQ(mpraq_baseline::FilterShape(r.filter), mpraq_baseline::FilterShape(bfilter));
}

// ---------------------------------------------------------------------------
// ⑤ k > M ⇒ 去重列数 = M（不越界、不重复计数）
// ---------------------------------------------------------------------------

TEST(MpraqScaleConfig, PredicatesBeyondRealColumnsDeduplicateToM) {
    // rows=128、每属性列数=4、属性数=1 ⇒ M = 4；k = 6 > M
    const MpraqScaleConfig cfg = Cfg(/*rows=*/128, /*cols=*/4, /*attrs=*/1, /*preds=*/6);
    const MpraqScaleSetup s = Build(cfg);
    const MpraqScaleEstimate& e = s.estimate;
    EXPECT_EQ(e.real_columns_M, uint64_t{4});
    EXPECT_EQ(e.dedup_columns, uint64_t{4});  // min(6, 4) = M
    EXPECT_EQ(e.query_sets, uint64_t{4});     // 4 × ⌈128/128⌉ = 4 × 1
    EXPECT_EQ(PlannedColumns(s), size_t{4});

    // 每个谓词的列都落在 [0, 每属性列数)，且 (属性, 列) 只有 M 个不同值
    std::set<std::pair<uint32_t, uint32_t>> seen;
    for (const Predicate& p : s.predicates) {
        EXPECT_TRUE(p.by_id);
        EXPECT_EQ(p.attribute_id, uint32_t{0});
        const PredicatePlan plan = ParsePredicate(p, s.schema);
        ASSERT_EQ(plan.columns.size(), size_t{1});
        EXPECT_TRUE(plan.columns[0].column < cfg.columns_per_attribute);
        seen.insert({plan.columns[0].attribute_id, plan.columns[0].column});
    }
    EXPECT_EQ(seen.size(), static_cast<size_t>(e.dedup_columns));
    // 去重列数不会超过 M，也不会有越界列（上面已逐条校验）
    EXPECT_TRUE(e.dedup_columns <= e.real_columns_M);
}

// ---------------------------------------------------------------------------
// ⑥ 合成数据：取值域内 + feature == i + 同种子逐位可复现
// ---------------------------------------------------------------------------

TEST(MpraqScaleConfig, SyntheticDataIsInDomainAndDeterministic) {
    const MpraqScaleConfig cfg = Cfg(/*rows=*/256, /*cols=*/8, /*attrs=*/3, /*preds=*/2);
    const MpraqScaleSetup a = Build(cfg);
    const MpraqScaleSetup b = Build(cfg);

    ASSERT_EQ(a.records.size(), size_t{256});
    ASSERT_EQ(b.records.size(), a.records.size());
    for (size_t i = 0; i < a.records.size(); ++i) {
        // D36：`feature` 是行标签（死字段）
        EXPECT_EQ(a.records[i].feature, static_cast<int64_t>(i));
        EXPECT_EQ(b.records[i].feature, a.records[i].feature);
        ASSERT_EQ(a.records[i].attributes.size(), size_t{3});
        for (size_t k = 0; k < a.records[i].attributes.size(); ++k) {
            const int64_t v = a.records[i].attributes[k];
            EXPECT_TRUE(v >= ScaleDomainMin(cfg) && v <= ScaleDomainMax(cfg));
            // 同种子 ⇒ 逐位可复现
            EXPECT_EQ(b.records[i].attributes[k], v);
        }
    }
    // 谓词也逐条一致
    ASSERT_EQ(a.predicates.size(), b.predicates.size());
    for (size_t j = 0; j < a.predicates.size(); ++j) {
        EXPECT_EQ(a.predicates[j].attribute_id, b.predicates[j].attribute_id);
        EXPECT_EQ(static_cast<int>(a.predicates[j].op),
                  static_cast<int>(b.predicates[j].op));
        EXPECT_EQ(a.predicates[j].value, b.predicates[j].value);
    }
    // 换种子 ⇒ 数据必须变（否则"种子"是摆设）
    const MpraqScaleSetup c = Build(Cfg(256, 8, 3, 2, 8, /*seed=*/8));
    size_t diff = 0;
    for (size_t i = 0; i < a.records.size(); ++i) {
        if (a.records[i].attributes != c.records[i].attributes) ++diff;
    }
    EXPECT_TRUE(diff > 0);
}

// ---------------------------------------------------------------------------
// ⑦ 谓词合法（阈值在 LCTE 区间内、ParseConjunction 不抛）且落在互不相同的列
// ---------------------------------------------------------------------------

TEST(MpraqScaleConfig, PredicatesAreLegalOnDistinctColumns) {
    // λ = 16 ⇒ q = λw/2 = 16；k = 5 ⇒ 查询集 = 5 × 2 = 10 ≤ min(16, n) —— 预算内
    const MpraqScaleConfig cfg = Cfg(/*rows=*/256, /*cols=*/8, /*attrs=*/2, /*preds=*/5,
                                     /*lambda=*/16);
    const MpraqScaleSetup s = Build(cfg);
    ASSERT_EQ(s.predicates.size(), size_t{5});
    EXPECT_EQ(s.estimate.dedup_columns, uint64_t{5});

    const PredicatePlan plan = ParseConjunction(s.predicates, s.schema);  // 不抛
    EXPECT_EQ(plan.columns.size(), size_t{5});
    EXPECT_EQ(plan.literals.size(), size_t{5});  // 每个谓词恰好 1 个字面量（= 1 列）
    EXPECT_TRUE(plan.IsConjunction());
    EXPECT_EQ(plan.num_records, size_t{256});

    for (size_t j = 0; j < s.predicates.size(); ++j) {
        const Predicate& p = s.predicates[j];
        const AttributeSchema& attr = s.schema.ById(p.attribute_id);
        // 期望的 (属性, 列)：a = j % 属性数、q = (j / 属性数) % 每属性列数，
        // 偶属性 = 下界 ⇒ c = (1 + q) % C；奇属性 = 上界 ⇒ c = (C − 2 − q) % C
        // （见 `scale_config.cpp` 的"同向 + 置换"规则）
        const uint32_t a = static_cast<uint32_t>(j) % cfg.attributes;
        const uint32_t C = cfg.columns_per_attribute;
        const uint32_t q = static_cast<uint32_t>(j / cfg.attributes) % C;
        const bool lower_bound = (a % 2 == 0);
        const uint32_t c = lower_bound ? (1u + q) % C : (C - 2u + C - q) % C;
        const uint32_t expect_op =
            lower_bound ? (c % 2 == 0 ? static_cast<uint32_t>(PredicateOp::kGe)
                                      : static_cast<uint32_t>(PredicateOp::kGt))
                        : (c % 2 == 0 ? static_cast<uint32_t>(PredicateOp::kLt)
                                      : static_cast<uint32_t>(PredicateOp::kLe));
        const int64_t expect_value =
            (c % 2 == 0) ? static_cast<int64_t>(c) : static_cast<int64_t>(c) - 1;
        EXPECT_EQ(static_cast<uint32_t>(p.op), expect_op);
        EXPECT_EQ(p.value, expect_value);
        EXPECT_EQ(p.attribute_id, a);
        // 阈值必须落在该属性的 LCTE 区间 [range_min, range_min + range_size − 1] 内
        EXPECT_TRUE(LcteContainsThreshold(attr.lcte, p.value));
        // 且落在取值域允许的边界内（`RequireBoundInDomain`：<= domain_max + 1）
        EXPECT_TRUE(p.value >= attr.domain_min && p.value <= attr.domain_max + 1);
        // plan 的列就是期望的列，且没有发生过阈值对齐（Q6 的 adjusted）
        ASSERT_TRUE(j < plan.literals.size());
        EXPECT_EQ(plan.literals[j].ref.attribute_id, a);
        EXPECT_EQ(plan.literals[j].ref.column, c);
        EXPECT_FALSE(plan.literals[j].adjusted);
        // 四个单列操作符都被用到（覆盖 lt/le/gt/ge，而不是只会生成一种）
    }
    // 覆盖度：5 个谓词用到的操作符 >= 2 种
    std::set<int> ops;
    for (const Predicate& p : s.predicates) ops.insert(static_cast<int>(p.op));
    EXPECT_TRUE(ops.size() >= size_t{2});
    // Sum/Avg 的属性号在范围内
    EXPECT_TRUE(s.sum_attr < s.schema.num_attributes());
    EXPECT_EQ(s.init.lambda, cfg.lambda);
    EXPECT_EQ(s.init.seed, cfg.seed);
    EXPECT_EQ(s.init.prp_epsilon, cfg.eps);
}

// ---------------------------------------------------------------------------
// ⑧ JSON 往返：临时文件 vs 同一份文本
// ---------------------------------------------------------------------------

TEST(MpraqScaleConfig, JsonRoundTripThroughFileMatchesText) {
    const MpraqScaleConfig cfg = Cfg(/*rows=*/512, /*cols=*/4, /*attrs=*/2, /*preds=*/3);
    const std::string text = ToJsonText(cfg);

    // 文本往返：字段逐项一致
    const MpraqScaleConfig from_text = MpraqScaleConfig::FromJson(text);
    EXPECT_EQ(from_text.rows, cfg.rows);
    EXPECT_EQ(from_text.columns_per_attribute, cfg.columns_per_attribute);
    EXPECT_EQ(from_text.attributes, cfg.attributes);
    EXPECT_EQ(from_text.predicates, cfg.predicates);
    EXPECT_EQ(from_text.lambda, cfg.lambda);
    EXPECT_EQ(from_text.eps, cfg.eps);
    EXPECT_EQ(from_text.seed, cfg.seed);

    // 文件往返：写到临时文件再读回，结果与文本路径**逐位一致**
    const std::string path = TmpPath();
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(out.good());
        out << text;
    }
    const MpraqScaleConfig from_file = MpraqScaleConfig::FromFile(path);

    const MpraqScaleSetup sa = Build(from_text);
    const MpraqScaleSetup sb = Build(from_file);
    ASSERT_EQ(sa.records.size(), sb.records.size());
    ASSERT_EQ(sa.predicates.size(), sb.predicates.size());
    for (size_t i = 0; i < sa.records.size(); ++i) {
        EXPECT_EQ(sb.records[i].feature, sa.records[i].feature);
        EXPECT_TRUE(sb.records[i].attributes == sa.records[i].attributes);
    }
    for (size_t j = 0; j < sa.predicates.size(); ++j) {
        EXPECT_EQ(static_cast<int>(sb.predicates[j].op),
                  static_cast<int>(sa.predicates[j].op));
        EXPECT_EQ(sb.predicates[j].value, sa.predicates[j].value);
    }
    EXPECT_EQ(sb.estimate.storage_bytes_padded, sa.estimate.storage_bytes_padded);
    EXPECT_EQ(sb.estimate.query_sets, sa.estimate.query_sets);
    std::remove(path.c_str());

    // 仓库内示例配置：必须解析成"默认值"，且与任务书给定的字段值一致
    const MpraqScaleConfig example = MpraqScaleConfig::FromFile(MPRAQ_SCALE_CONFIG_PATH);
    const MpraqScaleConfig defaults = MpraqScaleConfig::Defaults();
    EXPECT_EQ(example.rows, defaults.rows);
    EXPECT_EQ(example.columns_per_attribute, defaults.columns_per_attribute);
    EXPECT_EQ(example.attributes, defaults.attributes);
    EXPECT_EQ(example.predicates, defaults.predicates);
    EXPECT_EQ(example.lambda, defaults.lambda);
    EXPECT_EQ(example.eps, defaults.eps);
    EXPECT_EQ(example.seed, defaults.seed);
    EXPECT_EQ(example.rows, uint64_t{4096});
    EXPECT_EQ(example.columns_per_attribute, uint32_t{32});
    EXPECT_EQ(example.predicates, uint32_t{3});
    EXPECT_EQ(example.lambda, uint32_t{80});
    EXPECT_EQ(example.seed, uint64_t{7});
}

// ---------------------------------------------------------------------------
// ⑨ CLI 覆盖优先于 JSON（可测的合并逻辑）
// ---------------------------------------------------------------------------

TEST(MpraqScaleConfig, CliOverridesTakePrecedenceOverJson) {
    const std::string json =
        "{\"rows\": 512, \"columns_per_attribute\": 4, \"attributes\": 2, "
        "\"predicates\": 3, \"lambda\": 8, \"eps\": 0.001, \"seed\": 9}";
    const MpraqScaleConfig base = MpraqScaleConfig::FromJson(json);
    ASSERT_EQ(base.rows, uint64_t{512});

    EXPECT_TRUE(MpraqScaleOverrides::IsScaleFlag("--rows"));
    EXPECT_TRUE(MpraqScaleOverrides::IsScaleFlag("rows"));
    EXPECT_TRUE(MpraqScaleOverrides::IsScaleFlag("--columns"));
    EXPECT_TRUE(MpraqScaleOverrides::IsScaleFlag("--predicates"));
    EXPECT_FALSE(MpraqScaleOverrides::IsScaleFlag("--mode"));
    EXPECT_FALSE(MpraqScaleOverrides::IsScaleFlag("--json"));

    MpraqScaleOverrides ov;
    EXPECT_FALSE(ov.any());
    ov.Set("--rows", "1024");
    ov.Set("--columns", "16");
    ov.Set("--predicates", "3");
    EXPECT_TRUE(ov.any());
    // 非规模旗标 / 坏值 ⇒ 报错
    ExpectInvalidArgumentContaining(
        [&] { MpraqScaleOverrides o; o.Set("--mode", "local"); }, "--mode",
        "非规模旗标必须被拒绝");
    ExpectInvalidArgumentContaining(
        [&] { MpraqScaleOverrides o; o.Set("--rows", "abc"); }, "abc",
        "非数值的规模旗标值必须被拒绝");

    const MpraqScaleConfig merged = ApplyOverrides(base, ov);
    EXPECT_EQ(merged.rows, uint64_t{1024});              // 覆盖
    EXPECT_EQ(merged.columns_per_attribute, uint32_t{16});  // 覆盖
    EXPECT_EQ(merged.predicates, uint32_t{3});           // 覆盖（同值）
    EXPECT_EQ(merged.attributes, uint32_t{2});           // 未覆盖 ⇒ 保持 JSON
    EXPECT_EQ(merged.lambda, uint32_t{8});               // 同
    EXPECT_EQ(merged.eps, 0.001);                        // 同
    EXPECT_EQ(merged.seed, uint64_t{9});                 // 同

    // 合并结果真的被用上（并仍受 fail-loudly 校验）
    const MpraqScaleSetup s = Build(merged);
    EXPECT_EQ(s.records.size(), size_t{1024});
    EXPECT_EQ(s.estimate.real_columns_M, uint64_t{32});
    EXPECT_EQ(s.schema.attributes()[0].lcte.range_size, uint32_t{16});
    // 覆盖成非法值 ⇒ 拒绝
    MpraqScaleOverrides bad;
    bad.Set("--rows", "1000");
    ExpectInvalidArgumentContaining([&] { EstimateScale(ApplyOverrides(base, bad)); },
                                    "1000", "覆盖后的非法 rows 必须被拒绝");
}

// ---------------------------------------------------------------------------
// ⑩ L14 预算：在预算内通过；超预算**拒绝并给出可读原因**
// ---------------------------------------------------------------------------

TEST(MpraqScaleConfig, L14BudgetIsEnforcedAndOverBudgetIsRefused) {
    // 预算内：min(k, M) × ⌈N/128⌉ = 3 × 2 = 6 ≤ min(q = 8, n = 32) = 8
    const MpraqScaleSetup ok = Build(Cfg(/*rows=*/256, /*cols=*/8, /*attrs=*/2, 3));
    EXPECT_EQ(ok.estimate.dedup_columns, uint64_t{3});
    EXPECT_EQ(ok.estimate.query_sets, uint64_t{6});
    EXPECT_EQ(ok.estimate.hint_cap_q, uint64_t{8});
    EXPECT_EQ(ok.estimate.pool_cap_n, ok.estimate.entries_n);
    EXPECT_EQ(ok.estimate.budget_min, uint64_t{8});
    EXPECT_TRUE(ok.estimate.query_sets <= ok.estimate.budget_min);
    EXPECT_NO_THROW(CheckL14Budget(ok.estimate));

    // 超预算：rows=1024、每属性列数=16、属性数=2 ⇒ M=32、m=32、n=256、w=8
    //           λ=8 ⇒ q = λw/2 = 32；k=8 ⇒ 去重列数 8 ⇒ 查询集 8×8 = 64 > 32
    const MpraqScaleConfig over = Cfg(/*rows=*/1024, /*cols=*/16, /*attrs=*/2, /*preds=*/8,
                                      /*lambda=*/8);
    const MpraqScaleEstimate e = EstimateScale(over);
    EXPECT_EQ(e.dedup_columns, uint64_t{8});
    EXPECT_EQ(e.words_per_column, uint64_t{8});
    EXPECT_EQ(e.query_sets, uint64_t{64});
    EXPECT_EQ(e.hint_cap_q, uint64_t{32});
    EXPECT_TRUE(e.query_sets > e.budget_min);

    // 预算校验自身必须拒绝，并给出可读原因（含算式与上限口径）
    ExpectInvalidArgumentContaining([&] { CheckL14Budget(e); }, "L14",
                                    "超预算必须被拒绝（并指明 L14）");
    ExpectInvalidArgumentContaining([&] { CheckL14Budget(e); }, "min(q, n)",
                                    "超预算消息里要写明上限口径 min(q, n)");
    ExpectInvalidArgumentContaining([&] { CheckL14Budget(e); }, "64",
                                    "超预算消息里要给出实际查询集数");
    // `Build` 也必须**在任何 Init/查询之前**拒绝（绝不跑到一半抛 hint 用尽）
    ExpectInvalidArgumentContaining([&] { Build(over); }, "PlinkoBackupsExhausted",
                                    "Build 必须拒绝超预算规模（不推迟到运行期）");
}

// ---------------------------------------------------------------------------
// ⑪ 未知字段 / 不存在的文件 ⇒ fail-loudly
// ---------------------------------------------------------------------------

TEST(MpraqScaleConfig, UnknownFieldAndMissingFileAreRejected) {
    // 拼错的字段名会被当成"没配"⇒ 必须**直接拒绝**并点出字段名
    ExpectInvalidArgumentContaining(
        [] {
            MpraqScaleConfig::FromJson(
                "{\"rows\": 1024, \"predicatez\": 3, \"columns_per_attribute\": 32}");
        },
        "predicatez", "未知字段必须被拒绝并点名");
    ExpectInvalidArgumentContaining(
        [] { MpraqScaleConfig::FromJson("{\"row\": 1024}"); }, "row",
        "拼错的 rows 必须被拒绝");
    // 类型错误 / 根节点不是 object
    ExpectInvalidArgumentContaining(
        [] { MpraqScaleConfig::FromJson("{\"rows\": \"1024\"}"); }, "rows",
        "字段类型错误必须被拒绝");
    ExpectInvalidArgumentContaining([] { MpraqScaleConfig::FromJson("[1, 2, 3]"); },
                                    "object", "根节点必须是 object");
    // 不存在的文件
    ExpectInvalidArgumentContaining(
        [] { MpraqScaleConfig::FromFile("/nonexistent/mpraq_scale.json"); },
        "/nonexistent/mpraq_scale.json", "不存在的文件必须被拒绝并回显路径");
    // 部分配置是合法的（缺省字段取默认值）
    const MpraqScaleConfig partial = MpraqScaleConfig::FromJson("{\"rows\": 1024}");
    EXPECT_EQ(partial.rows, uint64_t{1024});
    EXPECT_EQ(partial.columns_per_attribute, uint32_t{32});
    EXPECT_EQ(partial.attributes, uint32_t{2});
    EXPECT_EQ(partial.predicates, uint32_t{3});
}

// ---------------------------------------------------------------------------
// ⑫' 自动谓词的合取**非退化**（0 < 命中数 < N）：
//     同一属性上的谓词同向 ⇒ 合取恒可满足；阈值不贴边界 ⇒ 不是恒真/恒假。
//     （这条不是"跑通"，而是把 `scale_config.cpp` 的生成规则钉住：若将来有人把方向
//      改成混向/贴边界，demo 的 Count/Sum 会静默变成 0，而 `AvgOverFilter` 会抛。）
// ---------------------------------------------------------------------------

TEST(MpraqScaleConfig, GeneratedConjunctionIsSatisfiableAndNonDegenerate) {
    const struct {
        uint32_t cols;
        uint32_t attrs;
        uint32_t preds;
        uint32_t lambda;
    } cases[] = {{8, 2, 3, 16}, {8, 2, 5, 32}, {16, 3, 6, 32}};
    for (const auto& c : cases) {
        const MpraqScaleSetup s =
            Build(Cfg(/*rows=*/256, c.cols, c.attrs, c.preds, c.lambda));
        const mpraq_baseline::Dataset d = BaselineOf(s);
        std::vector<mpraq_baseline::Pred> bp;
        for (const Predicate& p : s.predicates) bp.push_back(ToBaseline(p));
        const uint64_t count = mpraq_baseline::Count(d, bp);
        if (count == 0) {
            TSB_FAIL_("自动谓词的合取命中数为 0（退化）⇒ demo 的 Count/Sum 会恒为 0、"
                      "Avg 会抛 domain_error（cols=" + std::to_string(c.cols) +
                      "、attrs=" + std::to_string(c.attrs) +
                      "、preds=" + std::to_string(c.preds) + "）");
        }
        if (count == s.records.size()) {
            TSB_FAIL_("自动谓词的合取恒真（全命中）⇒ 对照失去意义（cols=" +
                      std::to_string(c.cols) + "、preds=" + std::to_string(c.preds) + "）");
        }
    }
}

// ---------------------------------------------------------------------------
// ⑫ 换算行与账目必须能打印/断言出来（口径不只写在注释里）
// ---------------------------------------------------------------------------

TEST(MpraqScaleConfig, HeadlineAndReportSpellOutTheConversionChain) {
    const MpraqScaleSetup s = Build(Cfg(/*rows=*/256, /*cols=*/8, /*attrs=*/2, /*preds=*/3));
    const std::string head = s.estimate.Headline();
    const char* needles[] = {"本次规模", "N=256",  "每属性列数=8", "属性数=2",
                            "M=16",     "m=16",   "谓词数=3",    "去重列数=3",
                            "查询集数=6", "每台 RPC=1"};
    for (const char* n : needles) {
        if (head.find(n) == std::string::npos) {
            TSB_FAIL_(std::string("换算行里缺少 '") + n + "'，实际 = " + head);
        }
    }
    const std::string report = s.estimate.Report();
    const char* rneedles[] = {"min(k, M)", "⌈N/128⌉", "16·m·L", "16·M·L",
                             "min(q, n)", "ServerRespBatch"};
    for (const char* n : rneedles) {
        if (report.find(n) == std::string::npos) {
            TSB_FAIL_(std::string("账目报告里缺少 '") + n + "'");
        }
    }
    // 打印出来（人工核对用；不影响断言）
    std::printf("[mpraq-scale] %s\n%s", head.c_str(), report.c_str());
    EXPECT_TRUE(!head.empty());
}
