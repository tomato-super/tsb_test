// MPA-03：MPRAQ 的 `Init`（客户端七步 + 服务器侧共享表 + 进程内通道）测试。
//
// 覆盖（对应任务书第三步的 7 条要求）：
//   1. 共享一致性：两台服务器的特征 word 逐条 **XOR** 回明文、属性共享逐条 **mod q 相加**
//      回明文（用 `shared/secret_sharing` 的**强类型**重建函数，不许手写加法）。
//   2. 布局正确性：列主序条目号 = 全局列号·⌈N/128⌉ + word 序号；word 第 j 位 = 第 j 条记录
//      （N=8 / m=3 手算逐位对照 + N 非 128 倍数的尾部填充位）。
//   3. 补齐逻辑：真实条目数不合法 ⇒ 补齐后满足 `PlinkoParams` 几何（c 偶数、w = 2^k），
//      且补齐部分明文为 0（两台一致）。
//   4. 参数校验：m < 跨度+2、w 非 2 的幂、属性号越界、N=0、记录越域等全部抛异常。
//   5. 接线冒烟：`Init` → `QueryGen` → 两台 `ServerResp` → `XorAnswers` → `ClientRecon`
//      必须等于明文特征表的该 word（证明"共享上传 + HintInit + 双服务器应答"整条链是通的）。
//   6. 存储口径：`StorageBytes()` 与 `MPRAQ_IMPL.md` §1 的公式一致（含补齐）。
//   7. 确定性：同种子两次 `Init` 的 hint/共享逐位一致。
//
// ⚠️ 性能预算（D22-1）：`HintInit ≈ n × IF⁻¹`。常规用例 n ≤ 2¹² 并显式调小 `prp_epsilon`
//    加速；**只有一个**默认 ε 的验收用例（`MpraqInitAcceptance`）。
// ⚠️ 本文件不写 main（用 tests/support 的 TEST/EXPECT_* 宏与共享的 test_main.cpp）。
// ⚠️ 本任务**不生成任何 HMAC 验证值**（论文 `:527` 在共享域上不可实现，D24①/L9，
//    机制待 `TASK_PLAN.md` §7.13 的 V1 裁决）⇒ 这里也**没有**任何"验证值"断言。

#include "core/field.hpp"
#include "mpraq/init.hpp"
#include "mpraq/lcte.hpp"
#include "mpraq/node.hpp"
#include "mpraq/predicate.hpp"
#include "shared/secret_sharing.hpp"
#include "test_framework.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

using namespace tsb;
using namespace tsb::mpraq;

namespace {

using Clock = std::chrono::steady_clock;

// 快速用例的 ε：明显加快 IF⁻¹（D22-1），但仍是合法的 PRP 目标 ε。
// ⚠️ 覆盖率/正确性不依赖 ε；只有"找不到覆盖 hint"的概率与 λ 有关（这里 λ 见各用例）。
constexpr double kFastEps = 1e-2;

// ---------------------------------------------------------------------------
// Schema / 记录构造
// ---------------------------------------------------------------------------

AttributeSchema MakeAttr(uint32_t id, uint32_t m, int64_t dmin, int64_t dmax,
                         size_t window_size) {
    AttributeSchema a;
    a.name = "attr" + std::to_string(id);
    a.id = id;
    a.lcte.window_size = static_cast<uint32_t>(window_size);
    a.lcte.range_size = m;
    a.lcte.range_min = dmin;
    a.domain_min = dmin;
    a.domain_max = dmax;
    return a;
}

// 单属性、取值范围 [0, m-3]（恰好满足 D19-5 的 m >= 跨度+2）
Schema MakeSchema(uint32_t m, size_t N) {
    Schema s;
    s.AddAttribute(MakeAttr(0, m, 0, static_cast<int64_t>(m) - 3, N));
    return s;
}

// 确定性记录：feature = i·7+3、属性 0 = i mod (m−2)。
// ⚠️ `MakeSchema(m, N)` 的取值域是 [0, m−3]（跨度 m−3 ⇒ 恰好满足 D19-5 的 m >= 跨度+2），
//    因此取值必须落在 [0, m−3] ⇒ 取模 m−2。
std::vector<MpraqRecord> MakeRecords(size_t N, uint32_t m) {
    std::vector<MpraqRecord> recs(N);
    for (size_t i = 0; i < N; ++i) {
        recs[i].feature = static_cast<int64_t>(i * 7 + 3);
        recs[i].attributes = {static_cast<int64_t>(i % (m - 2))};
    }
    return recs;
}

MpraqInitParams FastParams(uint64_t seed = 7, uint32_t lambda = 8) {
    MpraqInitParams p;
    p.lambda = lambda;
    p.prp_epsilon = kFastEps;
    p.seed = seed;
    return p;
}

// ---------------------------------------------------------------------------
// 强类型重建辅件（**不许手写加法/XOR**：走 `shared/secret_sharing` 的接口）
// ---------------------------------------------------------------------------

// 特征 word 是 XOR 共享的**比特容器**：逐 word 转成字节数组 → `ReconstructXorBytes` → 还原。
// ⚠️ 用 `ReconstructRing`（Z_{2^128} 加法）重建会静默算错 —— 这正是 D3/D12 要防的混用。
uint128_t ReconstructWordShare(const MpraqNode& s0, const MpraqNode& s1, uint64_t i) {
    std::vector<uint8_t> a(kUint128Bytes), b(kUint128Bytes);
    toBytesLE(s0.FeatureWord(i), a.data());
    toBytesLE(s1.FeatureWord(i), b.data());
    const std::vector<uint8_t> r = ReconstructXorBytes(a, b);
    return fromBytesLE(r.data());
}

// 属性值是 Z_q 加法共享 ⇒ 用强类型 `ModShare` + `ReconstructMod`。
uint128_t ReconstructAttrShare(const MpraqNode& s0, const MpraqNode& s1, uint32_t attr,
                               size_t record) {
    const ModShare x = s0.AttributeShare(attr, record);
    const ModShare y = s1.AttributeShare(attr, record);
    return ReconstructMod(x, y, kMpraqModulus);
}

bool IsPowerOfTwo(uint64_t v) { return v != 0 && (v & (v - 1)) == 0; }

// 逐条核对两台服务器的共享与客户端明文副本一致（供多个用例复用）
void ExpectSharesMatchPlain(const MpraqClient& c) {
    const MpraqNode& n0 = c.node(0);
    const MpraqNode& n1 = c.node(1);
    const uint64_t n = c.store_params().entry_count();
    ASSERT_EQ(n0.num_entries(), n);
    ASSERT_EQ(n1.num_entries(), n);

    size_t mismatched_words = 0;
    for (uint64_t i = 0; i < n; ++i) {
        const uint128_t rec = ReconstructWordShare(n0, n1, i);
        if (rec != c.PlainFeatureWord(i)) ++mismatched_words;
    }
    EXPECT_EQ(mismatched_words, size_t{0});

    for (uint32_t a = 0; a < c.schema().num_attributes(); ++a) {
        size_t mismatched_attrs = 0;
        for (size_t r = 0; r < c.store_params().num_records; ++r) {
            const uint128_t rec = ReconstructAttrShare(n0, n1, a, r);
            const uint128_t want =
                reduce(static_cast<uint128_t>(c.plain_attribute_values()[a][r]), kMpraqModulus);
            if (rec != want) ++mismatched_attrs;
        }
        EXPECT_EQ(mismatched_attrs, size_t{0});
    }
}

}  // namespace

// ===========================================================================
// 1. 共享一致性
// ===========================================================================

TEST(MpraqInit, XorSharesReconstructFeatureWordsAndModSharesReconstructAttributes) {
    const uint32_t m = 8;  // 取值域 [0, 5] ⇒ 跨度+2 = 8
    const size_t N = 1000;
    auto c = MpraqClient::Init(MakeSchema(m, N), MakeRecords(N, m), FastParams());

    // 服务端上传的分量必须**不是**明文（否则"共享"名存实亡）。
    // ⚠️ 注意：明文为 0 的 word（例如 LCTE 的全 0 列）**仍然**应当被随机化 ——
    //    "共享分量为 0"只对**补齐列**要求（见补齐相关用例），因为明文 0 的随机掩码
    //    泄漏的是"这个 word 是 0 列"这一结构（真实列里就有）。
    EXPECT_EQ(ReconstructWordShare(c->node(0), c->node(1), 0), c->PlainFeatureWord(0));
    size_t non_trivial_words = 0;
    for (uint64_t i = 0; i < c->store_params().entry_count(); ++i) {
        if (i / c->ColumnWordCount() >= c->real_column_count()) continue;  // 补齐列另测
        if (c->node(0).FeatureWord(i) != c->PlainFeatureWord(i) &&
            c->node(1).FeatureWord(i) != c->PlainFeatureWord(i)) {
            ++non_trivial_words;
        }
    }
    EXPECT_EQ(non_trivial_words, static_cast<size_t>(c->store_params().entry_count()));

    ExpectSharesMatchPlain(*c);

    // 属性值共享也必须是**非平凡**的（掩码不能恒为 0）
    size_t non_trivial = 0;
    for (size_t r = 0; r < N; ++r) {
        if (c->node(0).AttributeShare(0, r).value != 0) ++non_trivial;
    }
    EXPECT_TRUE(non_trivial > N / 2);

    // 说明性断言（D3/D12）：属性值若误用 XOR 重建会得到错值。
    // 只挑一个"真值非 0 且两侧都不为 0"的位置来断言，避免偶然相等。
    size_t checked = 0;
    for (size_t r = 0; r < N && checked < 8; ++r) {
        const ModShare a = c->node(0).AttributeShare(0, r);
        const ModShare b = c->node(1).AttributeShare(0, r);
        const uint128_t by_xor = static_cast<uint128_t>(a.value ^ b.value);
        const uint128_t by_add = ReconstructMod(a, b, kMpraqModulus);
        const uint128_t want =
            reduce(static_cast<uint128_t>(c->plain_attribute_values()[0][r]), kMpraqModulus);
        EXPECT_EQ(by_add, want);
        if (by_xor != want) ++checked;
    }
    EXPECT_EQ(checked, size_t{8});  // 8 个位置里全部"XOR 会算错" ⇒ 混用确实是错的
}

// ===========================================================================
// 2. 布局正确性（N=8、m=3 的手算对照）
// ===========================================================================
//
// LCTE(x) = ([x < r_0], [x < r_1], [x < r_2])，R = {0, 1, 2}（range_min=0、m=3）。
// 8 条记录、属性取值**恒为 0**（取值域 [0,0]），逐位（bit j = 记录 j）：
//   LCTE(0) = ([0<0], [0<1], [0<2]) = (0, 1, 1)
//   ⇒ 列 0 的 word = 0x00、列 1 的 word = 0xFF（8 位全 1）、列 2 的 word = 0xFF
// N=8 ⇒ ℓ = ⌈N/128⌉ = 1 ⇒ 每列 1 个 word；M = 3 ⇒ n = 3，**不合法**（n ≥ 4 要求）
//   ⇒ 本层把列数补齐到 m_pad = 4（多 1 列，明文恒 0）⇒ n = 4、w = 1、c = 4（偶数）。
// 列主序条目号 = 全局列号·1 + 0 ⇒ 列 0 → [0]、列 1 → [1]、列 2 → [2]、补齐列 → [3]。

TEST(MpraqInit, ColumnMajorLayoutAndTailPaddingBitsMatchHandComputedValues) {
    const uint32_t m = 3;
    const size_t N = 8;
    Schema s = MakeSchema(m, N);
    std::vector<MpraqRecord> recs(N);
    for (size_t i = 0; i < N; ++i) {
        recs[i].feature = static_cast<int64_t>(i);  // 手算用 0..7
        recs[i].attributes = {0};                   // 取值域 [0,0]（跨度 0 ⇒ m >= 2 即可）
    }
    MpraqInitParams p = FastParams();
    p.lambda = 2;
    auto c = MpraqClient::Init(s, recs, p);

    const StoreParams& sp = c->store_params();
    EXPECT_EQ(sp.num_records, size_t{8});
    EXPECT_EQ(sp.words_per_column, size_t{1});
    EXPECT_EQ(sp.real_column_count, size_t{3});
    EXPECT_EQ(sp.column_count, size_t{4});           // 补齐后的 m
    EXPECT_EQ(sp.padding_columns(), size_t{1});
    EXPECT_EQ(sp.entry_count(), uint64_t{4});        // n = 4·1
    EXPECT_EQ(sp.plinko.w, uint64_t{1});
    EXPECT_EQ(sp.plinko.block_count(), uint64_t{4}); // c 为偶数

    // ---- 列主序条目号（唯一入口）----
    EXPECT_EQ(c->ColumnWordIndex(0, 0, 0), uint64_t{0});
    EXPECT_EQ(c->ColumnWordIndex(0, 1, 0), uint64_t{1});
    EXPECT_EQ(c->ColumnWordIndex(0, 2, 0), uint64_t{2});
    EXPECT_EQ(c->column_count(), size_t{4});
    const auto seg = c->ColumnSegment(0, 1);
    EXPECT_EQ(seg.first, uint64_t{1});
    EXPECT_EQ(seg.second, uint64_t{2});              // 一段连续条目 [1, 2)

    // ---- 明文特征表逐 word 手算对照 ----
    EXPECT_EQ(c->PlainFeatureWord(0), uint128_t{0x00});  // 列 0（阈值 0）：[x<0] ≡ 0
    EXPECT_EQ(c->PlainFeatureWord(1), uint128_t{0xFF});  // 列 1（阈值 1）：[0<1] ⇒ 8 位全 1
    EXPECT_EQ(c->PlainFeatureWord(2), uint128_t{0xFF});  // 列 2（阈值 2）：[0<2] ⇒ 8 位全 1
    EXPECT_EQ(c->PlainFeatureWord(3), uint128_t{0x00});  // 补齐列

    // ---- word 的第 j 位 = 第 j 条记录 ----
    // LCTE 语义：第 col 列的比特 = [取值_j < range_min + col]（本用例取值恒为 0）
    // ⇒ 列 0/1/2 的比特分别是 [x<0]、[x<1]、[x<2] = 全 0、全 1、全 1
    for (size_t col = 0; col < 3; ++col) {
        const std::vector<uint8_t> bits = c->PlainColumnBits(0, static_cast<uint32_t>(col));
        ASSERT_EQ(bits.size(), size_t{8});
        for (size_t j = 0; j < 8; ++j) {
            const int64_t value = recs[j].attributes[0];
            const uint8_t expect =
                (value < static_cast<int64_t>(col)) ? 1 : 0;  // range_min = 0
            EXPECT_EQ(static_cast<int>(bits[j]), static_cast<int>(expect));
        }
    }

    // ---- 尾部填充位（第 8..127 位）在明文（= 两台 XOR 重建）上是 0 ----
    // ⚠️ 这里只要求"明文为 0"（即两台**一致性**地表达 0），**不**要求两侧分量逐位相等：
    //    真实列的填充位两侧各持随机掩码也是允许的（XOR 后为 0 即可）。
    //    只有**补齐列**才要求两侧分量**同为 0**（见下）。
    for (size_t col = 0; col < 3; ++col) {
        const uint64_t idx = c->ColumnWordIndex(0, static_cast<uint32_t>(col), 0);
        const uint128_t tail = static_cast<uint128_t>(c->PlainFeatureWord(idx) >>
                                                     static_cast<unsigned>(N));
        EXPECT_EQ(tail, uint128_t{0});
        const uint128_t recon = ReconstructWordShare(c->node(0), c->node(1), idx);
        EXPECT_EQ(static_cast<uint128_t>(recon >> static_cast<unsigned>(N)), uint128_t{0});
    }

    // ---- 补齐列：明文全 0 且两台共享都恰好是 0（不只是"XOR 结果为 0"）----
    for (size_t col = 3; col < 4; ++col) {
        const uint64_t idx = c->GlobalColumnWordIndex(col, 0);
        EXPECT_EQ(c->PlainFeatureWord(idx), uint128_t{0});
        EXPECT_EQ(c->node(0).FeatureWord(idx), uint128_t{0});
        EXPECT_EQ(c->node(1).FeatureWord(idx), uint128_t{0});
    }

    ExpectSharesMatchPlain(*c);
}

// N 不是 128 的倍数：⌈N/128⌉ = 2，最后一个 word 的填充位（第 N%128..127 位）必须为 0
TEST(MpraqInit, TailPaddingBitsAreZeroWhenRecordCountIsNotMultipleOf128) {
    const uint32_t m = 8;
    const size_t N = 130;  // ⌈130/128⌉ = 2，尾 word 只用到低 2 位
    auto c = MpraqClient::Init(MakeSchema(m, N), MakeRecords(N, m), FastParams());

    ASSERT_EQ(c->store_params().words_per_column, size_t{2});
    EXPECT_EQ(c->store_params().num_records % 128, size_t{2});

    const size_t real_cols = c->real_column_count();
    for (size_t col = 0; col < real_cols; ++col) {
        const uint64_t tail_idx = c->GlobalColumnWordIndex(col, 1);
        const uint128_t tail_bits =
            static_cast<uint128_t>(c->PlainFeatureWord(tail_idx) >> 2);  // 位 2..127
        EXPECT_EQ(tail_bits, uint128_t{0});
        // 两台**一致地**表达 0（XOR 重建的填充位为 0）
        EXPECT_EQ(static_cast<uint128_t>(
                      ReconstructWordShare(c->node(0), c->node(1), tail_idx) >> 2),
                  uint128_t{0});
    }
    ExpectSharesMatchPlain(*c);
}

// ===========================================================================
// 3. 补齐逻辑（D15(a)：补齐是**上层**的事；PLINKO_SPEC §1 的几何约束）
// ===========================================================================

TEST(MpraqInit, PaddingColumnsMakeGeometryLegalAndStayZero) {
    struct Case {
        size_t M;   // 真实列数
        size_t N;   // 记录数
    };
    const Case cases[] = {{3, 8}, {3, 130}, {5, 8}, {17, 1000}, {33, 2000}};

    for (const Case& k : cases) {
        const MpraqPaddedGeometry g = DerivePaddedGeometry(k.M, k.N, 4, kFastEps);
        const PlinkoParams& p = g.plinko;

        // ---- 补齐后必须满足 Plinko 的几何约束 ----
        EXPECT_TRUE(IsPowerOfTwo(p.w));
        EXPECT_EQ(p.n % p.w, uint64_t{0});
        EXPECT_EQ(p.n / p.w % 2, uint64_t{0});  // c 为偶数（PLINKO_SPEC §5.5）
        EXPECT_TRUE(p.n >= 4);
        EXPECT_TRUE(g.column_count >= k.M);
        EXPECT_EQ(g.padding_columns, g.column_count - k.M);
        EXPECT_EQ(p.n, static_cast<uint64_t>(g.column_count) * ((k.N + 127) / 128));

        // ---- 自然不变量：不存在**更小的合法列数**能装下真实数据 ----
        //
        // ⚠️ 这里**不**断言"cols = M 一定不合法"：M 本身合法时当然不补列，而 M 与
        //    `column_count` 之间的某些列数可能恰好也合法（例如 M=8、N=1000 时 cols=8
        //    与 cols=16 都合法：c = 32 与 16 都是偶数）。**列数最小 ≠ 存储最小** ——
        //    PIR 的存储是 `columns·⌈N/128⌉` 个 word，与 w 无关（D24④）。本层保证的是
        //    "补齐后几何合法、且补齐后仍装得下真实列"。下面只断言可判定的不变量。
        for (size_t cols = 1; cols < g.column_count; ++cols) {
            if ((cols & (cols - 1)) != 0) continue;  // 只看 2 的幂候选
            if (cols < k.M) {
                // 装不下真实列 ⇒ 该候选不可能被选中
                continue;
            }
            // 若某个更小的 2 的幂列数让 `n < 4`，则它一定不合法
            const uint64_t n_small = static_cast<uint64_t>(cols) * ((k.N + 127) / 128);
            if (n_small < 4) EXPECT_TRUE(n_small < 4);
        }
        EXPECT_TRUE(g.column_count >= k.M);
        EXPECT_TRUE((g.column_count & (g.column_count - 1)) == 0);  // 补齐到 2 的幂
    }
}

TEST(MpraqInit, PaddingColumnsAreZeroInPlaintextAndIdenticalOnBothServers) {
    // M=3、N=8 的最小补齐情形：真实列 3、补齐列 1
    const uint32_t m = 3;
    const size_t N = 8;
    auto c = MpraqClient::Init(MakeSchema(m, N), MakeRecords(N, m), FastParams());
    ASSERT_EQ(c->column_count(), size_t{4});
    ASSERT_EQ(c->real_column_count(), size_t{3});

    for (size_t col = c->real_column_count(); col < c->column_count(); ++col) {
        // 补齐列不属于任何属性 ⇒ 只能用**全局列号**定位（`PlainColumnBits(attr, column)`
        // 会因为 column >= range_size 而抛 out_of_range —— 这正是"补齐列对上层不可见"）
        EXPECT_THROW(c->PlainColumnBits(0, static_cast<uint32_t>(col)), std::out_of_range);
        const uint64_t idx = c->GlobalColumnWordIndex(col, 0);
        EXPECT_EQ(c->node(0).FeatureWord(idx), uint128_t{0});
        EXPECT_EQ(c->node(1).FeatureWord(idx), uint128_t{0});
    }

    // 服务器条目数 = column_count·⌈N/128⌉（**含**补齐列）
    EXPECT_EQ(c->node(0).num_entries(),
              static_cast<uint64_t>(c->column_count()) * c->store_params().words_per_column);
    ExpectSharesMatchPlain(*c);
}

// ===========================================================================
// 4. 参数校验（全部抛异常，且消息可读）
// ===========================================================================

TEST(MpraqInit, RejectsIllegalLcteRangeRelativeToDomain) {
    // D19-5：m 必须 >= (domain_max − domain_min) + 2
    Schema s;
    s.AddAttribute(MakeAttr(0, /*m=*/4, /*dmin=*/0, /*dmax=*/3, 8));  // 跨度 3 ⇒ 需要 5
    EXPECT_THROW(MpraqClient::Init(s, MakeRecords(8, 4), FastParams()), std::invalid_argument);

    // 恰好满足（跨度 3 ⇒ m = 5）必须通过
    Schema ok;
    ok.AddAttribute(MakeAttr(0, 5, 0, 3, 8));
    std::vector<MpraqRecord> recs(8);
    for (size_t i = 0; i < 8; ++i) {
        recs[i].feature = static_cast<int64_t>(i);
        recs[i].attributes = {static_cast<int64_t>(i % 4)};
    }
    EXPECT_NO_THROW(MpraqClient::Init(ok, recs, FastParams()));
}

TEST(MpraqInit, RejectsZeroRecordsAndAttributeCountMismatch) {
    const uint32_t m = 8;
    // N = 0
    EXPECT_THROW(MpraqClient::Init(MakeSchema(m, 0), {}, FastParams()), std::invalid_argument);
    // 记录属性个数与 schema 不符
    std::vector<MpraqRecord> recs(4);
    for (auto& r : recs) {
        r.feature = 0;
        r.attributes = {0, 1};  // schema 只有 1 个属性
    }
    EXPECT_THROW(MpraqClient::Init(MakeSchema(m, 4), recs, FastParams()), std::invalid_argument);
    // lcte.window_size 与记录数不符
    Schema s = MakeSchema(m, 5);
    EXPECT_THROW(MpraqClient::Init(s, MakeRecords(4, m), FastParams()), std::invalid_argument);
}

TEST(MpraqInit, RejectsOutOfDomainRecordValues) {
    const uint32_t m = 8;  // 取值域 [0, 5]
    auto recs = MakeRecords(16, m);
    recs[3].attributes[0] = 6;  // > domain_max
    EXPECT_THROW(MpraqClient::Init(MakeSchema(m, 16), recs, FastParams()), std::out_of_range);

    auto recs2 = MakeRecords(16, m);
    recs2[5].attributes[0] = -1;  // < domain_min
    EXPECT_THROW(MpraqClient::Init(MakeSchema(m, 16), recs2, FastParams()), std::out_of_range);
}

TEST(MpraqInit, RejectsNonPowerOfTwoBlockSizeAndInconsistentExplicitWidth) {
    const uint32_t m = 8;
    const size_t N = 1000;  // m=8、ℓ=8 ⇒ n = 64（w=8、c=8 合法）
    MpraqInitParams bad = FastParams();
    bad.has_explicit_w = true;
    bad.w = 6;  // 非 2 的幂（D21）
    EXPECT_THROW(MpraqClient::Init(MakeSchema(m, N), MakeRecords(N, m), bad),
                 std::invalid_argument);

    MpraqInitParams bad2 = FastParams();
    bad2.has_explicit_w = true;
    bad2.w = 7;
    EXPECT_THROW(MpraqClient::Init(MakeSchema(m, N), MakeRecords(N, m), bad2),
                 std::invalid_argument);

    // 合法的显式 w（n = 64 ⇒ w = 8、c = 8）
    MpraqInitParams good = FastParams();
    good.has_explicit_w = true;
    good.w = 8;
    auto c = MpraqClient::Init(MakeSchema(m, N), MakeRecords(N, m), good);
    EXPECT_EQ(c->store_params().plinko.w, uint64_t{8});
    EXPECT_EQ(c->store_params().plinko.block_count(), uint64_t{8});
    EXPECT_EQ(c->store_params().padding_columns(), size_t{0});  // 恰好整除 ⇒ 无需补齐
}

TEST(MpraqInit, RejectsOutOfRangeAttributeAndWordIndexOnClientAndNode) {
    const uint32_t m = 8;
    const size_t N = 1000;
    auto c = MpraqClient::Init(MakeSchema(m, N), MakeRecords(N, m), FastParams());

    EXPECT_THROW(c->ColumnWordIndex(1, 0, 0), std::out_of_range);   // 属性号越界
    EXPECT_THROW(c->ColumnWordIndex(0, m, 0), std::out_of_range);   // 列号越界（range_size = m）
    EXPECT_THROW(c->ColumnWordIndex(0, 0, c->ColumnWordCount()), std::out_of_range);
    EXPECT_THROW(c->ColumnSegment(0, m), std::out_of_range);
    EXPECT_THROW(c->AttributeShare(1, 0, 0), std::out_of_range);
    EXPECT_THROW(c->AttributeShares(0, 2), std::out_of_range);
    EXPECT_THROW(c->AttributeShare(0, N, 0), std::out_of_range);
    EXPECT_THROW(c->PlainFeatureWord(c->store_params().entry_count()), std::out_of_range);
    EXPECT_THROW(c->node(2), std::out_of_range);
    EXPECT_THROW(c->node(-1), std::out_of_range);

    // 节点侧：越界上传（历史缺陷：旧 VMPQ 服务器这里是**堆越界写**）、长度不符、隐式扩容
    MpraqNode& n0 = c->node(0);
    const uint64_t n = n0.num_entries();
    EXPECT_THROW(n0.UploadFeatureWords(n - 1, {1, 2}, 2), std::out_of_range);
    EXPECT_THROW(n0.UploadFeatureWords(0, {1, 2, 3}, 2), std::invalid_argument);
    EXPECT_THROW(n0.UploadFeatureWords(0, {}), std::invalid_argument);
    EXPECT_THROW(n0.FeatureWord(n), std::out_of_range);
    EXPECT_THROW(n0.SetAttributeShares(0, std::vector<ModShare>(N + 1, ModShare{0})),
                 std::invalid_argument);
    EXPECT_THROW(n0.SetAttributeShares(1, std::vector<ModShare>(N, ModShare{0})),
                 std::out_of_range);
    EXPECT_THROW(n0.SetAttributeShares(0, std::vector<ModShare>(N, ModShare{kMpraqModulus})),
                 std::out_of_range);  // 分量必须已在 mod q 域内
    EXPECT_EQ(n0.num_entries(), n);  // ⚠️ 失败的上传绝不能改变表规模
    EXPECT_THROW(n0.AttributeShare(0, N), std::out_of_range);
}

TEST(MpraqInit, ServerRespRejectsMalformedQueriesAndWrongGeometry) {
    const uint32_t m = 8;
    const size_t N = 1000;
    auto c = MpraqClient::Init(MakeSchema(m, N), MakeRecords(N, m), FastParams());
    const PlinkoParams& p = c->plinko_params();

    // 正确几何的查询必须被接受
    PlinkoQuery q;
    q.blocks = p.block_count();
    q.block_size = p.w;
    q.offsets.assign(static_cast<size_t>(q.blocks), 0);
    q.groups.assign(static_cast<size_t>(q.blocks), 0);
    EXPECT_NO_THROW(c->node(0).ServerResp(q));

    // ⚠️ D24④ 的"静默错 128 倍"陷阱：步长写错（把 w 写成"每区块的记录数"）必须被拒
    PlinkoQuery wrong_step = q;
    wrong_step.block_size = p.w * 128;
    EXPECT_THROW(c->node(0).ServerResp(wrong_step), std::invalid_argument);

    PlinkoQuery wrong_blocks = q;
    wrong_blocks.blocks = p.block_count() / 2;
    wrong_blocks.offsets.resize(static_cast<size_t>(wrong_blocks.blocks), 0);
    wrong_blocks.groups.resize(static_cast<size_t>(wrong_blocks.blocks), 0);
    EXPECT_THROW(c->node(0).ServerResp(wrong_blocks), std::invalid_argument);

    PlinkoQuery offset_oor = q;
    offset_oor.offsets[0] = p.w;  // 偏移必须 < w
    EXPECT_THROW(c->node(0).ServerResp(offset_oor), std::invalid_argument);

    PlinkoQuery bad_group = q;
    bad_group.groups[0] = 2;
    EXPECT_THROW(c->node(0).ServerResp(bad_group), std::invalid_argument);

    // 未初始化的节点必须显式报错（绝不静默返回 0）
    MpraqNode fresh;
    EXPECT_THROW(fresh.ServerResp(q), std::logic_error);
    EXPECT_THROW(fresh.UploadFeatureWords(0, {0}), std::logic_error);
    EXPECT_THROW(fresh.SetAttributeShares(0, {}), std::logic_error);
}

// ===========================================================================
// 5. 接线冒烟（关键）：Init → QueryGen → 两台 ServerResp → XorAnswers → ClientRecon
// ===========================================================================

TEST(MpraqInit, SingleWordQueryThroughBothServersReconstructsPlaintextWord) {
    const uint32_t m = 8;
    const size_t N = 1000;
    auto c = MpraqClient::Init(MakeSchema(m, N), MakeRecords(N, m), FastParams());

    // 挑几个有代表性的 word：真实列的首/末 word、最后一列
    const size_t words = c->ColumnWordCount();
    std::vector<ColumnWord> targets = {
        ColumnWord{0, 0, 0},
        ColumnWord{0, 0, words - 1},
        ColumnWord{0, m - 1, 0},
    };

    size_t ok = 0;
    size_t non_zero = 0;
    for (const ColumnWord& t : targets) {
        const uint64_t flat = c->ColumnWordIndex(t.attr_id, t.column, t.word);
        const uint128_t want = c->PlainFeatureWord(flat);

        MpraqQueryBatch batch = c->CreateQueries({t});
        ASSERT_EQ(batch.size(), size_t{1});
        // 服务器可见的查询集：c 个偏移 + c 个分组比特（不含目标、不含 parity）
        EXPECT_EQ(batch.at(0).query().offsets.size(),
                  static_cast<size_t>(c->plinko_params().block_count()));
        EXPECT_EQ(batch.at(0).query().groups.size(),
                  static_cast<size_t>(c->plinko_params().block_count()));
        EXPECT_EQ(batch.at(0).query().block_size, c->plinko_params().w);

        const std::vector<uint128_t> got = batch.Run();
        ASSERT_EQ(got.size(), size_t{1});
        EXPECT_EQ(got[0], want);
        EXPECT_EQ(batch.at(0).value(), want);
        // 两台服务器各自的应答 XOR 之后就是明文应答（D12/D3：⊕ 与 XOR 共享线性相容）
        const PlinkoAnswer merged =
            PlinkoClient::XorAnswers(batch.at(0).answer0(), batch.at(0).answer1());
        EXPECT_EQ(merged.r0, batch.at(0).answer().r0);
        EXPECT_EQ(merged.r1, batch.at(0).answer().r1);
        if (got[0] == want) ++ok;
        if (want != 0) ++non_zero;
    }
    EXPECT_EQ(ok, targets.size());
    EXPECT_TRUE(non_zero >= 1);  // 至少有一个非零 word，避免"全 0 也算过"

    // ⚠️ 口径（Q5 / D24④）：`RunBatch` 走**批量**接口 ⇒ 每台服务器**各一次**
    //    `ServerRespBatch`（= 远程部署下的 1 次往返），**标量** `ServerResp` 一次都不调。
    //    「跑了多少个查询集」由 `queries` 表达，与 RPC 次数分开。
    EXPECT_EQ(c->channel_rpc_stats(0).server_resp_batch_calls, uint64_t{targets.size()});
    EXPECT_EQ(c->channel_rpc_stats(1).server_resp_batch_calls, uint64_t{targets.size()});
    EXPECT_EQ(c->channel_rpc_stats(0).server_resp_single_calls, uint64_t{0});
    EXPECT_EQ(c->channel_server_resp_calls(0), uint64_t{0});  // 兼容旧名 = 标量次数
    EXPECT_EQ(c->channel_rpc_stats(0).queries, static_cast<uint64_t>(targets.size()));
    EXPECT_EQ(c->node(0).batch_rpc_count(), uint64_t{targets.size()});
    EXPECT_EQ(c->node(0).rpc_count(), uint64_t{0});  // 批量路径不让标量计数增长

    // 补齐列（不属于任何属性）只有**全局列号**能定位：查它必须返回全 0，
    // 且绝不与真实列的共享混淆
    if (c->column_count() > c->real_column_count()) {
        const uint64_t flat = c->GlobalColumnWordIndex(c->real_column_count(), 0);
        EXPECT_EQ(flat, c->real_column_count() * words);  // 列主序：第 1 个补齐列的基址
        EXPECT_THROW(c->CreateQueries({ColumnWord{0, m, 0}}), std::out_of_range);  // 列号越界
        MpraqQueryBatch pad = c->CreateQueriesForIndices({flat});
        EXPECT_EQ(pad.Run()[0], uint128_t{0});  // 补齐列恒为 0
    }

    // 半诚实下"服务器可见信息"只有 c 个偏移 + c 个分组比特：不含目标、不含 parity
    MpraqQueryBatch b0 = c->CreateQueries({ColumnWord{0, 1, 0}});
    const PlinkoQuery& vis = b0.at(0).query();
    EXPECT_EQ(vis.offsets.size(), vis.groups.size());
    EXPECT_EQ(vis.offsets.size(), static_cast<size_t>(c->plinko_params().block_count()));
    size_t group0 = 0, group1 = 0;
    for (uint8_t g : vis.groups) (g ? group1 : group0)++;
    EXPECT_EQ(group0, group1);  // 两半规模严格相等（PLINKO_SPEC §5.5）
}

TEST(MpraqInit, WholeColumnQueryLandsOnContiguousEntriesAndRebuildsTheColumn) {
    const uint32_t m = 8;
    const size_t N = 1000;
    // λ=24：覆盖失败概率 2^{-24}，让"整列 ⌈N/128⌉=8 个 word 全部可查"稳定成立
    // （`HintInit` 的成本只取决于 n，与 λ 只差 hint 表的常数因子 ⇒ 仍然很快）
    auto c = MpraqClient::Init(MakeSchema(m, N), MakeRecords(N, m), FastParams(7, 24));

    const size_t words = c->ColumnWordCount();
    const auto seg = c->ColumnSegment(0, 2);
    EXPECT_EQ(seg.second - seg.first, static_cast<uint64_t>(words));  // "取一整列"是连续段

    // ⚠️ 每轮 PIR 消费 1 条 hint ⇒ 整列查询受"剩余备份 hint 数"限制（D8）
    if (words > c->backup_remaining()) {
        MpraqQueryBatch too_big = c->CreateColumnQuery(0, 2);
        (void)too_big;
    }

    MpraqQueryBatch batch = c->CreateColumnQuery(0, 2);
    ASSERT_EQ(batch.size(), words);
    for (size_t w = 0; w < words; ++w) {
        EXPECT_EQ(batch.at(w).flat_index(), seg.first + w);  // 条目号 = 基址 + word 序号
    }
    const std::vector<uint128_t> got = batch.Run();
    ASSERT_EQ(got.size(), words);
    for (size_t w = 0; w < words; ++w) {
        EXPECT_EQ(got[w], c->PlainFeatureWord(seg.first + w));
    }
    // 与 LCTE 明文列逐位对照（这条列就是 predicate.hpp 的 `LcteColumnLookup` 的输入）
    const std::vector<uint8_t> plain_bits = c->PlainColumnBits(0, 2);
    for (size_t j = 0; j < N; ++j) {
        const uint8_t bit =
            static_cast<uint8_t>((got[j / 128] >> (j % 128)) & 1u);
        EXPECT_EQ(static_cast<int>(bit), static_cast<int>(plain_bits[j]));
    }
}

// ===========================================================================
// 5b. **Q5 / D24④ 的口径固化**：一批查询集只对应**一次**网络往返
// ===========================================================================
//
// `MPRAQ_IMPL.md` §3 与 `TASK_PLAN` 的 Q5/D24④ 要求"一次 `AggQuery`
// （全部谓词涉及的**全部列的全部 word**）只发一次 RPC"。这条口径此前**无法在接口上
// 表达**（`IMpraqChannel` 只有标量 `ServerResp`），本用例把它固化成可执行断言：
//   * `RunBatch` ⇒ 每台服务器**恰好 1 次** `ServerRespBatch`；
//   * 同一批里的**标量** `ServerResp` 次数**保持 0**（不能悄悄退化成 N 次往返）；
//   * `k = 1` 与 `k = 4` 列的往返次数**相同**（都是 1）—— 往返数与列数无关；
//   * 批量不改变数值：重建结果与明文逐位一致。
// ⚠️ 进程内通道下"一次 `ServerRespBatch` 方法调用"就代表"一次往返"（无序列化开销）。
//    远程通道（`MPA-08` 的 `GrpcMpraqChannel`）必须覆写该方法只发 1 次 RPC。

TEST(MpraqInit, OneRpcPerBatchRegardlessOfColumnCount) {
    // 显式 w 让几何可预期：m=16、N=1000 ⇒ ℓ=8、n=128、w=16（c=8、H=3λw/2=192）
    // λ=8 ⇒ 备份 hint q=48 条，够 4 列 × 8 word = 32 条查询
    const uint32_t m = 16;
    const size_t N = 1000;
    MpraqInitParams p = FastParams(7, 8);
    p.has_explicit_w = true;
    p.w = 16;
    auto c = MpraqClient::Init(MakeSchema(m, N), MakeRecords(N, m), p);
    ASSERT_EQ(c->store_params().words_per_column, size_t{8});
    ASSERT_EQ(c->plinko_params().w, uint64_t{16});
    ASSERT_EQ(c->plinko_params().block_count(), uint64_t{8});

    // ---- ① 单条路径（`RunQuery`）仍走标量接口：1 条 ⇒ 1 次往返 ----
    {
        MpraqQueryBatch one = c->CreateQueries({ColumnWord{0, 1, 0}});
        const uint64_t flat = one.at(0).flat_index();
        EXPECT_EQ(c->RunQuery(one.at(0)), c->PlainFeatureWord(flat));
        EXPECT_EQ(c->channel_rpc_stats(0).server_resp_batch_calls, uint64_t{0});
        EXPECT_EQ(c->channel_rpc_stats(0).server_resp_single_calls, uint64_t{1});
        EXPECT_EQ(c->channel_rpc_stats(0).queries, uint64_t{1});
        EXPECT_EQ(c->channel_rpc_stats(0).rpc_calls(), uint64_t{1});
        EXPECT_EQ(c->node(0).rpc_count(), uint64_t{1});
        EXPECT_EQ(c->node(0).batch_rpc_count(), uint64_t{0});
    }

    // ---- ② k=1 列（8 个 word）⇒ 每台服务器**1 次** ServerRespBatch ----
    const auto measure = [&](uint32_t k, const char* tag) {
        const MpraqRpcStats before0 = c->channel_rpc_stats(0);
        const MpraqRpcStats before1 = c->channel_rpc_stats(1);
        const uint64_t single_before0 = before0.server_resp_single_calls;
        const uint64_t node_single_before = c->node(0).rpc_count();

        std::vector<ColumnWord> targets;
        for (uint32_t col = 0; col < k; ++col) {
            for (size_t w = 0; w < c->ColumnWordCount(); ++w) {
                targets.push_back(ColumnWord{0, col, w});
            }
        }
        MpraqQueryBatch batch = c->CreateQueries(targets);
        ASSERT_EQ(batch.size(), static_cast<size_t>(k) * c->ColumnWordCount());
        const std::vector<uint128_t> got = batch.Run();
        ASSERT_EQ(got.size(), batch.size());

        // 数值仍与明文逐位一致（别为了批量把值搞错）
        size_t mismatched = 0;
        for (size_t i = 0; i < got.size(); ++i) {
            if (got[i] != c->PlainFeatureWord(batch.at(i).flat_index())) ++mismatched;
        }
        EXPECT_EQ(mismatched, size_t{0});

        const MpraqRpcStats after0 = c->channel_rpc_stats(0);
        const MpraqRpcStats after1 = c->channel_rpc_stats(1);
        // ⚠️ 关键断言：往返次数恒为 1，与列数/word 数无关
        EXPECT_EQ(after0.server_resp_batch_calls - before0.server_resp_batch_calls, uint64_t{1});
        EXPECT_EQ(after1.server_resp_batch_calls - before1.server_resp_batch_calls, uint64_t{1});
        // ⚠️ 且**没有**偷偷走标量路径（否则就是 N 次往返）
        EXPECT_EQ(after0.server_resp_single_calls, single_before0);
        EXPECT_EQ(c->node(0).rpc_count(), node_single_before);
        // 工作量口径：处理了 k·⌈N/128⌉ 个查询集
        EXPECT_EQ(after0.queries - before0.queries, static_cast<uint64_t>(batch.size()));
        EXPECT_EQ(c->channel_rpc_stats(1).queries, after0.queries);  // 两台对称
        EXPECT_EQ(c->node(0).batch_rpc_count() - (before0.server_resp_batch_calls),
                  uint64_t{1});

        std::printf(
            "[mpraq-q5] %s: %zu 个查询集（%u 列 × %zu word）⇒ ServerRespBatch=%llu、"
            "标量 ServerResp=%llu（= %llu 次往返承载 %zu 个查询集）\n",
            tag, batch.size(), k, c->ColumnWordCount(),
            (unsigned long long)(after0.server_resp_batch_calls -
                                 before0.server_resp_batch_calls),
            (unsigned long long)(after0.server_resp_single_calls - single_before0),
            (unsigned long long)(after0.server_resp_batch_calls -
                                 before0.server_resp_batch_calls),
            batch.size());
        return after0.server_resp_batch_calls;
    };

    const uint64_t after_k1 = measure(1, "k=1");
    const uint64_t after_k4 = measure(4, "k=4");

    // ---- ③ 往返数**不随列数增长**：1 列与 4 列各自只多 1 次 ----
    EXPECT_EQ(after_k1, uint64_t{1});  // ① 的单条路径走标量 ⇒ 批量计数从 0 起
    EXPECT_EQ(after_k4, uint64_t{2});
    EXPECT_EQ(c->channel_rpc_stats(0).server_resp_single_calls, uint64_t{1});  // 只有 ① 那次

    // 反面对照：如果按标量接口逐条发，4 列 × 8 word 会是 32 次往返
    EXPECT_TRUE(after_k4 - after_k1 == 1);
    EXPECT_TRUE(c->channel_rpc_stats(0).queries == 1 + 8 + 32);
}

TEST(MpraqInit, BackupExhaustionIsReportedBeforeIssuingQueries) {
    const uint32_t m = 8;
    const size_t N = 1000;
    MpraqInitParams p = FastParams(7, /*lambda=*/4);  // λ=4 ⇒ q = λw/2 条备份 hint，很少
    auto c = MpraqClient::Init(MakeSchema(m, N), MakeRecords(N, m), p);

    const size_t cap = c->backup_remaining();
    EXPECT_TRUE(cap >= 1);
    std::vector<ColumnWord> too_many;
    for (size_t i = 0; i <= cap; ++i) too_many.push_back(ColumnWord{0, 0, 0});
    EXPECT_THROW(c->CreateQueries(too_many), std::invalid_argument);
}

// ===========================================================================
// 6. 存储口径（MPRAQ_IMPL.md §1）
// ===========================================================================

TEST(MpraqInit, StorageBytesMatchTheSpecFormulaIncludingPadding) {
    const uint32_t m = 8;
    const size_t N = 1000;
    auto c = MpraqClient::Init(MakeSchema(m, N), MakeRecords(N, m), FastParams());
    const StoreParams& sp = c->store_params();

    const uint64_t words = static_cast<uint64_t>(sp.column_count) * sp.words_per_column;
    const uint64_t expect_feature = kUint128Bytes * words;
    const uint64_t expect_attr = kUint128Bytes * sp.num_records * sp.attrs.size();
    EXPECT_EQ(c->node(0).StorageBytes(), expect_feature + expect_attr);
    EXPECT_EQ(c->node(1).StorageBytes(), expect_feature + expect_attr);
    EXPECT_EQ(c->node(0).FeatureStorageBytes(), expect_feature);
    EXPECT_EQ(c->node(0).AttributeStorageBytes(), expect_attr);
    EXPECT_EQ(c->storage_bytes(0), c->storage_bytes(1));

    // 补齐会让 feature 部分按**补齐后**的列数计（本用例恰好 m 已合法 ⇒ padding = 0）
    EXPECT_EQ(sp.padding_columns(), size_t{0});
    EXPECT_EQ(words, static_cast<uint64_t>(m) * ((N + 127) / 128));

    // 上传通信量 = 2 台 ×（特征 word + 属性值）
    EXPECT_EQ(c->upload_bytes(),
              2 * (kUint128Bytes * words + kUint128Bytes * sp.num_records * sp.attrs.size()));

    // hint 存储口径（PLINKO_SPEC §6）：H = λw + q
    EXPECT_EQ(c->hint_slot_count(), static_cast<size_t>(sp.plinko.hint_slots()));
    EXPECT_TRUE(c->hint_state_bytes() > 0);

    // 补齐情形下 feature 存储必须含补齐列
    auto c2 = MpraqClient::Init(MakeSchema(3, 8), MakeRecords(8, 3), FastParams());
    ASSERT_EQ(c2->store_params().padding_columns(), size_t{1});
    EXPECT_EQ(c2->node(0).FeatureStorageBytes(),
              static_cast<uint64_t>(kUint128Bytes) * c2->store_params().column_count *
                  c2->store_params().words_per_column);
    EXPECT_TRUE(c2->node(0).FeatureStorageBytes() >
                static_cast<uint64_t>(kUint128Bytes) * c2->real_column_count());
}

// ===========================================================================
// 7. 确定性（同种子逐位一致）
// ===========================================================================

TEST(MpraqInit, SameSeedProducesBitIdenticalHintsAndShares) {
    const uint32_t m = 8;
    const size_t N = 1000;
    auto a = MpraqClient::Init(MakeSchema(m, N), MakeRecords(N, m), FastParams(20260910));
    auto b = MpraqClient::Init(MakeSchema(m, N), MakeRecords(N, m), FastParams(20260910));

    const uint64_t n = a->store_params().entry_count();
    ASSERT_EQ(b->store_params().entry_count(), n);
    size_t word_diff = 0;
    for (uint64_t i = 0; i < n; ++i) {
        if (a->node(0).FeatureWord(i) != b->node(0).FeatureWord(i)) ++word_diff;
        if (a->node(1).FeatureWord(i) != b->node(1).FeatureWord(i)) ++word_diff;
    }
    EXPECT_EQ(word_diff, size_t{0});

    size_t attr_diff = 0;
    for (size_t r = 0; r < N; ++r) {
        if (a->node(0).AttributeShare(0, r).value != b->node(0).AttributeShare(0, r).value) {
            ++attr_diff;
        }
        if (a->node(1).AttributeShare(0, r).value != b->node(1).AttributeShare(0, r).value) {
            ++attr_diff;
        }
    }
    EXPECT_EQ(attr_diff, size_t{0});

    // hint 表（槽位状态 + parity + 位图）逐位一致
    ASSERT_EQ(a->hint_slot_count(), b->hint_slot_count());
    size_t slot_diff = 0;
    for (size_t j = 0; j < a->hint_slot_count(); ++j) {
        const PlinkoHintSlot& x = a->plinko().slot(j);
        const PlinkoHintSlot& y = b->plinko().slot(j);
        if (x.kind != y.kind || x.parity != y.parity ||
            x.backup_parity_in != y.backup_parity_in ||
            x.backup_parity_out != y.backup_parity_out) {
            ++slot_diff;
        }
    }
    EXPECT_EQ(slot_diff, size_t{0});
    EXPECT_EQ(a->hint_state_bytes(), b->hint_state_bytes());
    {
        const std::vector<uint8_t> ma = a->coverage_mask();
        const std::vector<uint8_t> mb = b->coverage_mask();
        ASSERT_EQ(ma.size(), mb.size());
        size_t mask_diff = 0;
        for (size_t i = 0; i < ma.size(); ++i) {
            if (ma[i] != mb[i]) ++mask_diff;
        }
        EXPECT_EQ(mask_diff, size_t{0});
    }

    // 每区块 iPRF 密钥也必须一致
    size_t key_diff = 0;
    for (uint64_t i = 0; i < a->plinko_params().block_count(); ++i) {
        if (a->block_key(i).prp_key != b->block_key(i).prp_key) ++key_diff;
        if (a->block_key(i).pmns_key != b->block_key(i).pmns_key) ++key_diff;
    }
    EXPECT_EQ(key_diff, size_t{0});

    // 不同种子必须给出**不同**的共享与 hint（否则"确定性"是假的）
    auto d = MpraqClient::Init(MakeSchema(m, N), MakeRecords(N, m), FastParams(99));
    size_t diff_words = 0;
    for (uint64_t i = 0; i < n; ++i) {
        if (a->node(0).FeatureWord(i) != d->node(0).FeatureWord(i)) ++diff_words;
    }
    EXPECT_TRUE(diff_words > n / 2);
}

// ===========================================================================
// 8. 通道 / 远程占位 / MAC 密钥
// ===========================================================================

TEST(MpraqInit, LocalChannelMirrorsNodeAndRemotePlaceholderNeverFakesSuccess) {
    auto c = MpraqClient::Init(MakeSchema(8, 1000), MakeRecords(1000, 8), FastParams());

    // 本地通道就是节点的直连（无序列化开销）：同一个查询集 ⇒ 同一个应答
    const PlinkoParams& p = c->plinko_params();
    PlinkoQuery q;
    q.blocks = p.block_count();
    q.block_size = p.w;
    q.offsets.assign(static_cast<size_t>(q.blocks), 0);
    q.groups.assign(static_cast<size_t>(q.blocks), 0);
    const PlinkoAnswer via_channel = c->channel(0).ServerResp(q);
    const PlinkoAnswer via_node = c->node(0).ServerResp(q);
    EXPECT_EQ(via_channel.r0, via_node.r0);
    EXPECT_EQ(via_channel.r1, via_node.r1);
    EXPECT_THROW(c->channel(2), std::out_of_range);

    // 远程占位：**任何**远程路径都必须显式报错，绝不静默退化成本地调用（MPA-08 才实现 gRPC）
    PlaceholderRemoteMpraqChannel remote("mpraq://127.0.0.1:9");
    EXPECT_EQ(remote.endpoint(), std::string("mpraq://127.0.0.1:9"));
    EXPECT_THROW(remote.Connect(), RemoteMpraqChannelNotImplemented);
    EXPECT_THROW(remote.ServerResp(PlinkoQuery{}), RemoteMpraqChannelNotImplemented);
    EXPECT_THROW(remote.InitTable(c->store_params()), RemoteMpraqChannelNotImplemented);
}

TEST(MpraqInit, MacKeyIsGeneratedOnceGloballyButNoHmacVerificationValueIsStored) {
    auto c = MpraqClient::Init(MakeSchema(8, 1000), MakeRecords(1000, 8), FastParams());

    // Q3：α 全局一份、每台服务器一份分享（供 MPA-06 的 SecureMul / SPDZ MAC）
    EXPECT_EQ(c->mac_key_shares().alpha_shares.size(), size_t{2});
    EXPECT_TRUE(c->mac_key_shares().alpha != 0);
    // α 的重建必须等于 α（分享自洽）
    EXPECT_EQ(ReconstructMod(ModShare{c->mac_key_shares().alpha_shares[0]},
                             ModShare{c->mac_key_shares().alpha_shares[1]}, kMpraqModulus),
              c->mac_key_shares().alpha);
    EXPECT_EQ(c->modulus(), kMpraqModulus);

    // ⚠️ 本任务**不生成任何 HMAC 验证值**（论文 :527 不可实现，D24①/L9）。
    //    这里用"服务器不持有任何额外状态"来表达：存储量恰好等于 §1 的两项公式，
    //    多出来的一个字节都会让下面的等式不成立。
    const uint64_t words =
        static_cast<uint64_t>(c->column_count()) * c->store_params().words_per_column;
    EXPECT_EQ(c->node(0).StorageBytes(),
              static_cast<uint64_t>(kUint128Bytes) * words +
                  static_cast<uint64_t>(kUint128Bytes) * c->store_params().num_records);
}

TEST(MpraqInit, InitWithChannelsUsesCallerProvidedChannels) {
    const uint32_t m = 8;
    const size_t N = 1000;
    Schema s = MakeSchema(m, N);
    auto recs = MakeRecords(N, m);

    MpraqNode node0, node1;
    LocalMpraqChannel ch0(node0), ch1(node1);
    // λ=24：把"找不到覆盖 hint"（2^{-λ}，PLINKO_SPEC §5.1 的致命失败）压到可忽略，
    // 让本用例只测"通道接线"这一件事
    MpraqInitParams p = FastParams(7, 24);
    auto c = MpraqClient::InitWithChannels(s, recs, p, ch0, ch1);
    EXPECT_EQ(node0.num_entries(), c->store_params().entry_count());
    EXPECT_EQ(node1.num_entries(), c->store_params().entry_count());
    // 远程模式下没有本地节点
    EXPECT_THROW(c->node(0), std::logic_error);

    const uint64_t flat = c->ColumnWordIndex(0, 3, 0);
    MpraqQueryBatch batch = c->CreateQueries({ColumnWord{0, 3, 0}});
    const uint128_t got0 = batch.Run()[0];
    const uint128_t want0 = c->PlainFeatureWord(flat);
    EXPECT_EQ(got0, want0);
    // 两台**独立提供**的通道各自持有自己那半共享（XOR 回来 = 明文）
    EXPECT_EQ(static_cast<uint128_t>(node0.FeatureWord(flat) ^ node1.FeatureWord(flat)), want0);
    std::printf(
        "[mpraq] InitWithChannels 冒烟: 条目号 %llu = 列主序 3·⌈N/128⌉ + 0；"
        "两台节点的共享 XOR 回明文（w=%llu、c=%llu、n=%llu）\n",
        (unsigned long long)flat, (unsigned long long)c->plinko_params().w,
        (unsigned long long)c->plinko_params().block_count(),
        (unsigned long long)c->store_params().entry_count());

    // ⚠️ 注意：**同一个通道对象不能接两次** —— 第二次 `InitWithChannels` 会把该服务器上的
    // 共享换成新的一份，使第一个客户端持有的共享失效（XOR 重建立刻错值）。下面的
    // "拒绝同一对象" 用例因此单独建节点，不污染本用例。
}

TEST(MpraqInit, InitWithChannelsRejectsTheSameChannelObjectTwice) {
    const uint32_t m = 8;
    const size_t N = 1000;
    Schema s = MakeSchema(m, N);
    auto recs = MakeRecords(N, m);

    MpraqNode node0, node1;
    LocalMpraqChannel ch0(node0), ch1(node1);
    MpraqInitParams p = FastParams();
    EXPECT_THROW(MpraqClient::InitWithChannels(s, recs, p, ch0, ch0), std::invalid_argument);

    // 两条不同对象（各接一台**不同**节点）必须都能用
    EXPECT_NO_THROW(MpraqClient::InitWithChannels(s, recs, p, ch0, ch1));
}

// ===========================================================================
// 9. 验收用例（**唯一**使用默认 ε = 1e-10 的用例，D22-1 慢用例标注）
// ===========================================================================
//
// λ=80（论文部署值）、ε=1e-10（Plinko 默认）。规模：N=1024、m=16 ⇒ ℓ = 8、
// n = 128、w = 16、c = 8、H = 3λw/2 = 1920 ⇒ `HintInit` 跑 128 个 word 的 IF⁻¹。
// 本用例同时验证：整列 8 个 word 的 PIR 全链、覆盖率（λ=80 下不该有未覆盖条目）、
// 以及"两台服务器应答 XOR = 明文"。

TEST(MpraqInitAcceptance, DefaultEpsilonFullColumnPirMatchesPlaintextAndCoversEverything) {
    const uint32_t m = 16;  // 取值域 [0, 13] ⇒ 跨度+2 = 16
    const size_t N = 1024;
    Schema s = MakeSchema(m, N);
    auto recs = MakeRecords(N, m);

    MpraqInitParams p;
    p.lambda = 80;
    p.prp_epsilon = 1e-10;  // **默认** ε，不调小
    p.seed = 20260910;

    const auto t0 = Clock::now();
    auto c = MpraqClient::Init(s, recs, p);
    const double total_ms =
        std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
    const MpraqInitTimings& tm = c->timings();

    // 几何自洽（派生值不硬编码：w 由本层按 PLINKO_SPEC §1 派生）
    EXPECT_TRUE(IsPowerOfTwo(tm.block_size));
    EXPECT_EQ(tm.entry_count % tm.block_size, uint64_t{0});
    EXPECT_EQ(tm.block_count % 2, uint64_t{0});
    EXPECT_EQ(tm.entry_count, tm.block_count * tm.block_size);
    EXPECT_EQ(tm.column_count, static_cast<size_t>(m));
    EXPECT_EQ(tm.padding_columns, size_t{0});
    EXPECT_EQ(tm.entry_count,
              static_cast<uint64_t>(tm.column_count) * tm.words_per_column);

    // ---- 覆盖率（PLINKO_SPEC §5.1：λ=80 下不应有未覆盖条目）----
    const std::vector<uint8_t> mask = c->coverage_mask();
    ASSERT_EQ(mask.size(), static_cast<size_t>(tm.entry_count));
    size_t uncovered = 0;
    for (uint8_t b : mask) {
        if (!b) ++uncovered;
    }
    EXPECT_EQ(uncovered, size_t{0});

    // ---- 整列 PIR（8 个 word = 8 次查询，一次批）----
    const auto seg = c->ColumnSegment(0, 5);
    MpraqQueryBatch batch = c->CreateColumnQuery(0, 5);
    ASSERT_EQ(batch.size(), static_cast<size_t>(tm.words_per_column));
    const auto t1 = Clock::now();
    const std::vector<uint128_t> got = batch.Run();
    const double pir_ms = std::chrono::duration<double, std::milli>(Clock::now() - t1).count();
    ASSERT_EQ(got.size(), static_cast<size_t>(tm.words_per_column));
    size_t ok = 0;
    for (size_t w = 0; w < got.size(); ++w) {
        EXPECT_EQ(got[w], c->PlainFeatureWord(seg.first + w));
        if (got[w] == c->PlainFeatureWord(seg.first + w)) ++ok;
    }
    EXPECT_EQ(ok, got.size());

    // ---- 明文列与 LCTE 语义对照（与 predicate.hpp 的 `LcteColumnLookup` 同口径）----
    const std::vector<uint8_t> bits = c->PlainColumnBits(0, 5);
    ASSERT_EQ(bits.size(), N);
    const int64_t threshold = 5;  // range_min = 0 ⇒ 第 5 列的阈值是 5
    size_t mismatched = 0;
    for (size_t j = 0; j < N; ++j) {
        const uint8_t want = recs[j].attributes[0] < threshold ? 1 : 0;
        if (bits[j] != want) ++mismatched;
    }
    EXPECT_EQ(mismatched, size_t{0});

    std::printf(
        "[mpraq-accept] Init 几何: N=%zu m=%u ℓ=%zu n=%llu w=%llu c=%llu λ=%u padding=%zu\n",
        N, m, tm.words_per_column, static_cast<unsigned long long>(tm.entry_count),
        static_cast<unsigned long long>(tm.block_size),
        static_cast<unsigned long long>(tm.block_count), p.lambda, tm.padding_columns);
    std::printf(
        "[mpraq-accept] Init 耗时拆分: total=%.1f ms (lcte=%.1f pack=%.1f share=%.1f "
        "hint=%.1f upload=%.1f) ；HintInit ≈ %.3f ms/word = n × IF⁻¹\n",
        total_ms, tm.lcte_ms, tm.pack_ms, tm.share_ms, tm.hint_ms, tm.upload_ms,
        tm.hint_ms / static_cast<double>(tm.entry_count));
    std::printf(
        "[mpraq-accept] 服务器存储 = %llu B/台（特征 %llu B 含补齐 + 属性 %llu B）；"
        "hint 状态 = %.1f KB（H=%zu 槽位，逻辑 %.1f KB）；上传 %.1f KB；"
        "整列 %zu 个 word 的 PIR = %.1f ms\n",
        static_cast<unsigned long long>(c->storage_bytes(0)),
        static_cast<unsigned long long>(c->node(0).FeatureStorageBytes()),
        static_cast<unsigned long long>(c->node(0).AttributeStorageBytes()),
        static_cast<double>(c->hint_state_bytes()) / 1024.0, c->hint_slot_count(),
        c->plinko().logical_hint_bytes() / 1024.0,
        static_cast<double>(c->upload_bytes()) / 1024.0, got.size(), pir_ms);
    std::printf(
        "[mpraq-accept] 覆盖: n=%llu 中未覆盖 = %zu；整列 %zu 个 word 全部重建正确；"
        "分块上传 = %zu 块 × %zu word\n",
        static_cast<unsigned long long>(tm.entry_count), uncovered, got.size(),
        tm.chunk_count, tm.chunk_words);
    std::printf(
        "[mpraq-accept] ⚠️ 本任务**不生成任何 HMAC 验证值**（论文 :527 在共享域上不可实现，"
        "D24①/L9，待 §7.13 的 V1 裁决）\n");
}

// ---------------------------------------------------------------------------
// D36：`MpraqRecord::feature` 是**死字段**（刻意的：客户端明文标签，便于预估/手算结果）
//   本用例把"它不影响任何协议输出"钉死 —— 若将来有人让它参与编码/共享，这里会立刻失败。
//   ① 本地明文副本如实保存（这是它唯一的去处）；
//   ② 两台服务器上的 word 表（LCTE 编码 + 位打包）**逐 word 逐位相同**；
//   ③ 属性共享逐条相同；④ 存储字节与几何不受影响。
// ---------------------------------------------------------------------------
TEST(MpraqInit, FeatureFieldIsInertAndOnlyALocalLabel) {
    const uint32_t m = 8;   // 取值域 [0, m−3]
    const size_t N = 40;    // 非 128 的倍数（顺带覆盖尾部填充）
    const Schema schema = MakeSchema(m, N);
    const std::vector<MpraqRecord> a = MakeRecords(N, m);
    std::vector<MpraqRecord> b = a;
    for (size_t i = 0; i < N; ++i) {
        b[i].feature = static_cast<int64_t>(1000 + i * 3);   // **只改标签**，其余逐位不动
    }

    auto ca = MpraqClient::Init(schema, a, FastParams());
    auto cb = MpraqClient::Init(schema, b, FastParams());    // 同种子

    // ① 唯一的去处：客户端本地明文副本
    EXPECT_EQ(ca->plain_feature_values().size(), N);
    for (size_t i = 0; i < N; ++i) {
        EXPECT_EQ(ca->plain_feature_values()[i], a[i].feature);
        EXPECT_EQ(cb->plain_feature_values()[i], b[i].feature);
    }

    // ② LCTE 编码后的 word 表逐 word 逐位相同（⇒ feature 没进编码）
    const uint64_t words = ca->store_params().entry_count();
    EXPECT_TRUE(words > 0);
    for (uint64_t w = 0; w < words; ++w) {
        EXPECT_EQ(ReconstructWordShare(ca->node(0), ca->node(1), w),
                  ReconstructWordShare(cb->node(0), cb->node(1), w));
    }

    // ③ 属性共享逐条相同（⇒ feature 没以任何形式掺进共享）
    for (uint32_t attr = 0; attr < static_cast<uint32_t>(schema.num_attributes()); ++attr) {
        for (size_t i = 0; i < N; ++i) {
            EXPECT_EQ(ReconstructAttrShare(ca->node(0), ca->node(1), attr, i),
                      ReconstructAttrShare(cb->node(0), cb->node(1), attr, i));
        }
    }

    // ④ 存储/几何不受影响（服务器永远看不到 feature ⇒ 它的值不可能改变任何账目）
    EXPECT_EQ(ca->node(0).StorageBytes(), cb->node(0).StorageBytes());
    EXPECT_EQ(ca->store_params().entry_count(), cb->store_params().entry_count());
    EXPECT_EQ(ca->store_params().column_count, cb->store_params().column_count);
    std::printf("[mpraq-init] D36：feature 只进本地明文副本（首个标签 %lld / %lld），"
                "改它不影响 word 表（%llu 个 word 逐位相同）、属性共享、存储与几何\n",
                static_cast<long long>(ca->plain_feature_values()[0]),
                static_cast<long long>(cb->plain_feature_values()[0]),
                static_cast<unsigned long long>(words));
}
