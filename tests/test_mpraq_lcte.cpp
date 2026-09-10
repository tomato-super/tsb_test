// MPRAQ 第 5 层 MPA-01（LCTE 编码）/ MPA-02（谓词解析）的期望值测试。
//
// 测试口径（TASK_PLAN 决策 D6 / §10 项目铁律）：
//   * **每个算法都要有确定性随机源下的期望值测试**，只验"跑通"不算；
//   * 期望值**手写死**，不用被测代码算期望（暴力对照实现写在测试内部）；
//   * 随机源一律用 `random::DeterministicPrng`（可复现），不用真随机。
//
// 用例组织：
//   1) LCTE 精确期望值表 / 边界 / 单调性 / 暴力对照 / 位打包 / XOR 分片
//   2) 阈值对齐（Q6）：宽松模式夹到最近值 + 告警；严格模式抛异常
//   3) 谓词解析（Q7/Q8）：操作符 → 列索引 + 取反标记；AND 合取；De Morgan 形式
//   4) 本地求值（Q5）：与暴力语义逐记录对照
//   5) 错误路径：属性越界、取值超域、范围倒置、不支持的操作符
//   6) MPA-01 + MPA-02 联调：XOR 分片 → 客户端重建 → 谓词 filter

#include "mpraq/lcte.hpp"
#include "mpraq_baseline.hpp"
#include "mpraq/predicate.hpp"

#include "core/random.hpp"
#include "test_framework.hpp"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

using namespace tsb;
using namespace tsb::mpraq;

namespace {

// ---------------------------------------------------------------------------
// 公共测试夹具
// ---------------------------------------------------------------------------

// R = {10, 11, 12, 13, 14}（r_min = 10, m = 5）
LcteParams Params10x5(uint32_t window = 0) {
    LcteParams p;
    p.window_size = window;
    p.range_size = 5;
    p.range_min = 10;
    return p;
}

// 手写的期望行比较（期望值必须在调用处写死）
void ExpectRow(const std::vector<uint128_t>& row, const std::vector<int>& expect) {
    ASSERT_EQ(row.size(), expect.size());
    for (size_t i = 0; i < expect.size(); ++i) {
        EXPECT_EQ(row[i], static_cast<uint128_t>(expect[i]));
    }
}

// 独立暴力实现 #1：显式枚举阈值集合（用"起点 + 逐个自增"而不是索引算式，
// 避免与实现共用一个公式，从而能真正抓到"偏移 1"这类口径错误）
std::vector<int64_t> BruteForceThresholdSet(int64_t r_min, uint32_t m) {
    std::vector<int64_t> thresholds;
    int64_t cur = r_min;
    for (uint32_t i = 0; i < m; ++i) {
        thresholds.push_back(cur);
        ++cur;
    }
    return thresholds;
}

// 独立暴力实现 #2：按论文定义逐阈值比较（朴素双重循环）
std::vector<uint128_t> BruteForceLcte(int64_t x,
                                      const std::vector<int64_t>& thresholds) {
    std::vector<uint128_t> row;
    row.reserve(thresholds.size());
    for (int64_t r : thresholds) {
        row.push_back(static_cast<uint128_t>(x < r ? 1 : 0));
    }
    return row;
}

// 属性数据：schema + 明文取值 + 逐列明文比特（由 BuildLcteTable 得到）
struct AttrData {
    AttributeSchema schema;
    std::vector<int64_t> values;
    std::vector<std::vector<uint8_t>> column_bits;
};

AttrData MakeAttrData(const AttributeSchema& attr, const std::vector<int64_t>& values) {
    AttrData d;
    d.schema = attr;
    d.values = values;
    d.column_bits = LcteColumnBits(BuildLcteTable(values, attr.lcte));
    return d;
}

// 客户端本地取列的 lookup（模拟 Q5：一次性把所有列取回后本地组合）
// ⚠️ 按**值**捕获 attrs：调用处常写成 MakeLookup({&a}) 这种临时 vector，
// 按引用捕获会立刻悬垂。
LcteColumnLookup MakeLookup(std::vector<const AttrData*> attrs) {
    return [attrs](const LcteColumnRef& ref) -> std::vector<uint8_t> {
        for (const AttrData* a : attrs) {
            if (a->schema.id != ref.attribute_id) continue;
            if (ref.column >= a->column_bits.size()) {
                throw std::out_of_range("测试 lookup: 列索引越界");
            }
            return a->column_bits[ref.column];
        }
        throw std::out_of_range("测试 lookup: 属性不存在");
    };
}

// 暴力语义基准（直接按定义判断，不经过 LCTE）
bool BruteOp(PredicateOp op, int64_t x, int64_t v, int64_t lo, int64_t hi) {
    switch (op) {
        case PredicateOp::kEq: return x == v;
        case PredicateOp::kNeq: return x != v;
        case PredicateOp::kLt: return x < v;
        case PredicateOp::kLe: return x <= v;
        case PredicateOp::kGt: return x > v;
        case PredicateOp::kGe: return x >= v;
        case PredicateOp::kRange: return x >= lo && x < hi;
    }
    throw std::invalid_argument("BruteOp: 未知操作符");
}

// 单值谓词的便捷构造（按属性名）
Predicate Pred(const std::string& attr, PredicateOp op, int64_t v) {
    Predicate p;
    p.attribute = attr;
    p.op = op;
    p.value = v;
    return p;
}

Predicate PredRange(const std::string& attr, int64_t lo, int64_t hi) {
    Predicate p;
    p.attribute = attr;
    p.op = PredicateOp::kRange;
    p.lower = lo;
    p.upper = hi;
    return p;
}

// 确定性 PRNG：key 由 seed 直接派生（不取 CSPRNG），
// 保证同一 seed 在任意运行/任意机器上产生同一序列 ⇒ 期望值测试可复现。
random::DeterministicPrng MakePrng(uint64_t seed) {
    std::array<uint8_t, kAesKeyBytes> key{};
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>((seed * 31u + i * 7u + 11u) & 0xffu);
    }
    return random::DeterministicPrng(key, seed);
}

// 取 [lo, hi] 内的确定性整数
int64_t RandIn(random::DeterministicPrng& prng, int64_t lo, int64_t hi) {
    const uint64_t span = static_cast<uint64_t>(hi - lo + 1);
    return lo + static_cast<int64_t>(prng.Below(span));
}

}  // namespace

// ===========================================================================
// 1. LCTE 精确期望值表（手写死；r_min=10, m=5 ⇒ R={10,11,12,13,14}）
// ===========================================================================

TEST(MpraqLcte, ExpectationTableHandWritten) {
    const LcteParams p = Params10x5();
    // 逐列阈值：第 0 列 10、第 1 列 11、第 2 列 12、第 3 列 13、第 4 列 14
    EXPECT_EQ(LcteThresholdAt(p, 0), static_cast<int64_t>(10));
    EXPECT_EQ(LcteThresholdAt(p, 1), static_cast<int64_t>(11));
    EXPECT_EQ(LcteThresholdAt(p, 2), static_cast<int64_t>(12));
    EXPECT_EQ(LcteThresholdAt(p, 3), static_cast<int64_t>(13));
    EXPECT_EQ(LcteThresholdAt(p, 4), static_cast<int64_t>(14));

    // 手写期望矩阵：行 = x，列 = [x < 10], [x < 11], [x < 12], [x < 13], [x < 14]
    ExpectRow(LcteEncodeRow(9, p), {1, 1, 1, 1, 1});
    ExpectRow(LcteEncodeRow(10, p), {0, 1, 1, 1, 1});
    ExpectRow(LcteEncodeRow(11, p), {0, 0, 1, 1, 1});
    ExpectRow(LcteEncodeRow(12, p), {0, 0, 0, 1, 1});
    ExpectRow(LcteEncodeRow(13, p), {0, 0, 0, 0, 1});
    ExpectRow(LcteEncodeRow(14, p), {0, 0, 0, 0, 0});
    ExpectRow(LcteEncodeRow(100, p), {0, 0, 0, 0, 0});

    // 同一批期望值必须与 shared/database 的 LcteEncode 完全一致
    // （mpraq 层只是校验 + 复用，不得出现第二套阈值口径）
    for (int64_t x = 8; x <= 15; ++x) {
        const auto top = LcteEncodeRow(x, p);
        const auto shared = LcteEncode(x, p);
        ASSERT_EQ(top.size(), shared.size());
        for (size_t i = 0; i < top.size(); ++i) {
            EXPECT_EQ(top[i], shared[i]);
        }
    }
}

TEST(MpraqLcte, BitsMatchRingRow) {
    const LcteParams p = Params10x5();
    for (int64_t x = 8; x <= 15; ++x) {
        const auto row = LcteEncodeRow(x, p);
        const auto bits = LcteBits(x, p);
        ASSERT_EQ(bits.size(), row.size());
        for (size_t i = 0; i < bits.size(); ++i) {
            EXPECT_EQ(static_cast<uint128_t>(bits[i]), row[i]);
        }
    }
}

// ===========================================================================
// 2. 边界语义
// ===========================================================================

TEST(MpraqLcte, BoundaryBelowRminIsAllOnes) {
    const LcteParams p = Params10x5();
    // x < r_min ⇒ 全 1（论文："When x < r_1, the entire vector consists of all 1s"）
    ExpectRow(LcteEncodeRow(9, p), {1, 1, 1, 1, 1});
    ExpectRow(LcteEncodeRow(0, p), {1, 1, 1, 1, 1});
    ExpectRow(LcteEncodeRow(-1000000, p), {1, 1, 1, 1, 1});
}

TEST(MpraqLcte, BoundaryAtRmaxAndAboveIsAllZeros) {
    const LcteParams p = Params10x5();
    // x >= r_m = r_min + m - 1 ⇒ 全 0
    ExpectRow(LcteEncodeRow(14, p), {0, 0, 0, 0, 0});
    ExpectRow(LcteEncodeRow(15, p), {0, 0, 0, 0, 0});
    ExpectRow(LcteEncodeRow(1000000, p), {0, 0, 0, 0, 0});
}

TEST(MpraqLcte, BoundaryAtRminZeroesOnlyFirstColumn) {
    const LcteParams p = Params10x5();
    // x == r_min ⇒ 只有第 0 列为 0（旧实现因偏移 1 会给全 1，本用例专门固化修正）
    ExpectRow(LcteEncodeRow(10, p), {0, 1, 1, 1, 1});
}

TEST(MpraqLcte, NegativeThresholds) {
    LcteParams p;
    p.range_size = 10;
    p.range_min = -5;  // R = {-5, -4, -3, -2, -1, 0, 1, 2, 3, 4}
    EXPECT_EQ(LcteMinThreshold(p), static_cast<int64_t>(-5));
    EXPECT_EQ(LcteMaxThreshold(p), static_cast<int64_t>(4));

    // x = -6 < r_min ⇒ 全 1
    ExpectRow(LcteEncodeRow(-6, p), {1, 1, 1, 1, 1, 1, 1, 1, 1, 1});
    // x = -5 = r_min ⇒ 第 0 列为 0
    ExpectRow(LcteEncodeRow(-5, p), {0, 1, 1, 1, 1, 1, 1, 1, 1, 1});
    // x = -2（= r_min + 3，即第 3 列的阈值）⇒ 第 0..3 列为 0，第 4 列起为 1
    ExpectRow(LcteEncodeRow(-2, p), {0, 0, 0, 0, 1, 1, 1, 1, 1, 1});
    // x = 4 = r_m ⇒ 全 0；x = 5 > r_max ⇒ 全 0
    ExpectRow(LcteEncodeRow(4, p), {0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    ExpectRow(LcteEncodeRow(5, p), {0, 0, 0, 0, 0, 0, 0, 0, 0, 0});

    EXPECT_TRUE(LcteCoversValue(p, -5));
    EXPECT_TRUE(LcteCoversValue(p, 4));
    EXPECT_FALSE(LcteCoversValue(p, -6));
    EXPECT_FALSE(LcteCoversValue(p, 5));
}

// ===========================================================================
// 3. 单调性：x1 < x2 ⇒ 每个分量 LCTE(x1) >= LCTE(x2)
// ===========================================================================

TEST(MpraqLcte, MonotoneComponentwiseUnderValueOrder) {
    const LcteParams p = Params10x5();
    for (int64_t x1 = 5; x1 <= 20; ++x1) {
        for (int64_t x2 = x1 + 1; x2 <= 21; ++x2) {
            const auto a = LcteEncodeRow(x1, p);
            const auto b = LcteEncodeRow(x2, p);
            for (size_t i = 0; i < a.size(); ++i) {
                EXPECT_TRUE(a[i] >= b[i]);
            }
        }
    }
}

TEST(MpraqLcte, MonotoneUnderRandomizedValues) {
    auto prng = MakePrng(20260910);
    LcteParams p;
    p.range_size = 24;
    p.range_min = -12;
    for (int iter = 0; iter < 200; ++iter) {
        const int64_t x1 = RandIn(prng, -30, 30);
        const int64_t x2 = RandIn(prng, -30, 30);
        if (x1 == x2) continue;
        const int64_t lo = std::min(x1, x2);
        const int64_t hi = std::max(x1, x2);
        const auto a = LcteEncodeRow(lo, p);
        const auto b = LcteEncodeRow(hi, p);
        for (size_t i = 0; i < a.size(); ++i) {
            EXPECT_TRUE(a[i] >= b[i]);
        }
    }
}

// ===========================================================================
// 4. 与独立暴力实现逐位一致（确定性随机取值 × 随机阈值集合）
// ===========================================================================

TEST(MpraqLcte, MatchesBruteForceUnderRandomParameters) {
    auto prng = MakePrng(4242);
    for (int iter = 0; iter < 400; ++iter) {
        LcteParams p;
        p.range_size = static_cast<uint32_t>(RandIn(prng, 1, 20));
        p.range_min = RandIn(prng, -50, 50);
        const int64_t x = RandIn(prng, -100, 100);

        const auto thresholds = BruteForceThresholdSet(p.range_min, p.range_size);
        const auto expected = BruteForceLcte(x, thresholds);
        const auto actual = LcteEncodeRow(x, p);

        ASSERT_EQ(actual.size(), expected.size());
        for (size_t i = 0; i < actual.size(); ++i) {
            EXPECT_EQ(actual[i], expected[i]);
        }
    }
}

TEST(MpraqLcte, BruteForceThresholdSetIsUnitInterval) {
    // 固化 R 的形状：单位间隔、严格递增、首元素 = r_min、末元素 = r_min+m-1
    const auto thresholds = BruteForceThresholdSet(-7, 6);
    ASSERT_EQ(thresholds.size(), static_cast<size_t>(6));
    EXPECT_EQ(thresholds.front(), static_cast<int64_t>(-7));
    EXPECT_EQ(thresholds.back(), static_cast<int64_t>(-2));
    for (size_t i = 1; i < thresholds.size(); ++i) {
        EXPECT_EQ(thresholds[i] - thresholds[i - 1], static_cast<int64_t>(1));
    }
}

TEST(MpraqLcte, TableAndColumnsMatchPerRowEncoding) {
    // 一批记录 → LCTE 表 → 逐列比特，必须与逐条 LcteEncodeRow 完全一致
    auto prng = MakePrng(7);
    const uint32_t n = 37;  // 刻意不是 128 的倍数，覆盖打包的尾部
    LcteParams p;
    p.window_size = n;
    p.range_size = 6;
    p.range_min = -3;
    std::vector<int64_t> values(n);
    for (uint32_t i = 0; i < n; ++i) {
        values[i] = RandIn(prng, -6, 4);
    }

    const PlainTable table = BuildLcteTable(values, p);
    EXPECT_EQ(table.num_rows(), static_cast<size_t>(n));
    EXPECT_EQ(table.num_columns(), static_cast<size_t>(6));

    const auto cols = LcteColumnBits(table);
    ASSERT_EQ(cols.size(), static_cast<size_t>(6));
    for (uint32_t c = 0; c < 6; ++c) {
        EXPECT_EQ(cols[c].size(), static_cast<size_t>(n));
        for (uint32_t r = 0; r < n; ++r) {
            const auto row = LcteEncodeRow(values[r], p);
            EXPECT_EQ(static_cast<uint128_t>(cols[c][r]), row[c]);
        }
    }

    // 逐列 128 位打包：第 c 列第 r 位落在 words[c][r/128] 的第 (r%128) 位
    const auto packed = PackLcteColumns(table);
    ASSERT_EQ(packed.size(), static_cast<size_t>(6));
    const size_t words = (n + 127) / 128;
    EXPECT_EQ(packed[0].size(), words);
    for (uint32_t c = 0; c < 6; ++c) {
        for (uint32_t r = 0; r < n; ++r) {
            const uint128_t bit =
                static_cast<uint128_t>((packed[c][r / 128] >> (r % 128)) & 1u);
            EXPECT_EQ(bit, static_cast<uint128_t>(cols[c][r]));
        }
    }
}

TEST(MpraqLcte, PackedTableLayoutIsPirFriendly) {
    // BuildLctePackedTable: rows = ⌈N/128⌉（word 序号），columns = m（LCTE 列）
    auto prng = MakePrng(11);
    const uint32_t n = 130;
    LcteParams p;
    p.window_size = n;
    p.range_size = 4;
    p.range_min = 0;
    std::vector<int64_t> values(n);
    for (uint32_t i = 0; i < n; ++i) {
        values[i] = RandIn(prng, -2, 4);
    }

    const PlainTable packed_table = BuildLctePackedTable(values, p);
    EXPECT_EQ(packed_table.num_rows(), static_cast<size_t>(2));   // ⌈130/128⌉
    EXPECT_EQ(packed_table.num_columns(), static_cast<size_t>(4));

    const auto packed = PackLcteColumns(BuildLcteTable(values, p));
    for (uint32_t c = 0; c < 4; ++c) {
        for (size_t w = 0; w < packed[c].size(); ++w) {
            EXPECT_EQ(packed_table.At(w, c), packed[c][w]);
        }
    }

    // 第 c 列的 parity = 该列所有 word 的 XOR（V-OO-PIR / Plinko 的应答语义）
    for (uint32_t c = 0; c < 4; ++c) {
        uint128_t expected = 0;
        for (const auto& word : packed[c]) {
            expected = static_cast<uint128_t>(expected ^ word);
        }
        EXPECT_EQ(packed_table.ColumnXor(c), expected);
    }
}

// ===========================================================================
// 5. XOR 分片（决策 D3/D12）：分片重建 = 明文；列 parity 可由两服务器 XOR 重建
// ===========================================================================

TEST(MpraqLcte, XorShardsReconstructPlaintext) {
    auto prng = MakePrng(31337);
    const uint32_t n = 200;
    LcteParams p;
    p.window_size = n;
    p.range_size = 5;
    p.range_min = 10;
    std::vector<int64_t> values(n);
    for (uint32_t i = 0; i < n; ++i) {
        values[i] = RandIn(prng, 8, 15);
    }

    const XorShardedLcte sharded = XorShareLcte(values, p);
    EXPECT_EQ(sharded.num_records, static_cast<size_t>(n));
    EXPECT_EQ(sharded.words_per_column, (n + 127) / 128);
    EXPECT_EQ(sharded.words0.size(), sharded.words1.size());

    const PlainTable plain = BuildLcteTable(values, p);
    const PlainTable back = ReconstructLctePlain(sharded);

    EXPECT_EQ(back.num_rows(), plain.num_rows());
    EXPECT_EQ(back.num_columns(), plain.num_columns());
    for (size_t r = 0; r < plain.num_rows(); ++r) {
        for (size_t c = 0; c < plain.num_columns(); ++c) {
            EXPECT_EQ(back.At(r, c), plain.At(r, c));
        }
    }

    // 单个分片不得泄露明文（至少与明文不同）
    const ShareTable s0 = LcteShareTable(sharded, 0);
    bool any_different = false;
    for (size_t r = 0; r < plain.num_rows(); ++r) {
        for (size_t c = 0; c < plain.num_columns(); ++c) {
            if (s0.At(r / 128, c).value != plain.At(r, c)) any_different = true;
        }
    }
    EXPECT_TRUE(any_different);
}

TEST(MpraqLcte, ColumnParityReconstructsFromTwoServers) {
    // ⚠️ 决策 D12 的正确路径：XOR 共享 + 服务器各自 XOR + 客户端 XOR 重建 parity
    auto prng = MakePrng(99);
    const uint32_t n = 300;
    LcteParams p;
    p.window_size = n;
    p.range_size = 3;
    p.range_min = -1;
    std::vector<int64_t> values(n);
    for (uint32_t i = 0; i < n; ++i) {
        values[i] = RandIn(prng, -2, 2);
    }

    const XorShardedLcte sharded = XorShareLcte(values, p);
    const ShareTable s0 = LcteShareTable(sharded, 0);
    const ShareTable s1 = LcteShareTable(sharded, 1);

    const PlainTable plain = BuildLcteTable(values, p);
    const auto packed = PackLcteColumns(plain);
    for (size_t c = 0; c < plain.num_columns(); ++c) {
        // ⚠️ 位打包后 parity 的**粒度是 word**：整列被打成 ⌈N/128⌉ 个 word，
        // 服务器上的一次 XOR 累加得到的是"各 word 逐位 XOR"的 128 位结果，
        // 它**不等于** PlainTable::ColumnXor(c)（整列 N 个比特的奇偶性）。
        // 两者只在 N <= 128（即整列恰好一个 word）时才可能相同，且此时
        // 列 XOR == 该 word 本身（而非它的奇偶性）。
        // 因此这里对照的是"该列所有 word 的 XOR"。
        uint128_t expected = 0;
        for (const auto& word : packed[c]) {
            expected = static_cast<uint128_t>(expected ^ word);
        }
        const uint128_t combined = static_cast<uint128_t>(
            s0.ColumnXor(c).value ^ s1.ColumnXor(c).value);
        EXPECT_EQ(combined, expected);
        EXPECT_EQ(s0.ColumnXor(c).value ^ s1.ColumnXor(c).value, expected);
    }

    // 对照：单 word 情形（N <= 128）下，"整列 word 的 XOR"就是那个 word 自身，
    // 而 PlainTable::ColumnXor 是它的比特奇偶性 —— 两者是不同量，别混用。
    {
        LcteParams q;
        q.window_size = 5;
        q.range_size = 1;
        q.range_min = 1;  // 唯一的阈值 = 1 ⇒ 比特 = [x < 1]
        const std::vector<int64_t> tiny = {0, 1, 0, 1, 0};  // ⇒ 比特 1,0,1,0,1
        const PlainTable tp = BuildLcteTable(tiny, q);
        EXPECT_EQ(tp.ColumnXor(0), static_cast<uint128_t>(1));  // 3 个 1 ⇒ 奇
        const auto words = PackLcteColumns(tp);
        EXPECT_EQ(words[0][0], static_cast<uint128_t>(0b10101));  // 打包后的原始比特
    }

    // 逐 word 的 XOR 也必须重建明文打包表（不只看 parity）
    const PlainTable back = ReconstructLcteFromShares(s0, s1, n);
    for (size_t r = 0; r < plain.num_rows(); ++r) {
        for (size_t c = 0; c < plain.num_columns(); ++c) {
            EXPECT_EQ(back.At(r, c), plain.At(r, c));
        }
    }
}

TEST(MpraqLcte, ZeroRecordsProducesEmptyTables) {
    // N = 0 的退化情形：不得崩溃、不得越界，形状要自洽
    LcteParams p = Params10x5(0);
    const std::vector<int64_t> empty;
    const PlainTable table = BuildLcteTable(empty, p);
    EXPECT_EQ(table.num_rows(), static_cast<size_t>(0));
    EXPECT_EQ(table.num_columns(), static_cast<size_t>(5));
    const auto cols = LcteColumnBits(table);
    ASSERT_EQ(cols.size(), static_cast<size_t>(5));
    for (const auto& c : cols) EXPECT_EQ(c.size(), static_cast<size_t>(0));
    for (const auto& w : PackLcteColumns(table)) {
        EXPECT_EQ(w.size(), static_cast<size_t>(0));
    }

    const XorShardedLcte sharded = XorShareLcte(empty, p);
    EXPECT_EQ(sharded.num_records, static_cast<size_t>(0));
    EXPECT_EQ(sharded.words_per_column, static_cast<size_t>(0));
    const PlainTable back = ReconstructLctePlain(sharded);
    EXPECT_EQ(back.num_rows(), static_cast<size_t>(0));
    EXPECT_EQ(back.num_columns(), static_cast<size_t>(5));
}

TEST(MpraqLcte, ShareTableServerIndexValidation) {
    LcteParams p;
    p.window_size = 4;
    p.range_size = 2;
    p.range_min = 0;
    const std::vector<int64_t> values = {0, 1, -1, 2};
    const XorShardedLcte sharded = XorShareLcte(values, p);
    EXPECT_NO_THROW(LcteShareTable(sharded, 0));
    EXPECT_NO_THROW(LcteShareTable(sharded, 1));
    EXPECT_THROW(LcteShareTable(sharded, 2), std::invalid_argument);
    EXPECT_THROW(LcteShareTable(sharded, -1), std::invalid_argument);
}

// ===========================================================================
// 6. 阈值对齐（Q6）
// ===========================================================================

TEST(MpraqThresholdAlign, InRangeNeedsNoAdjustment) {
    const LcteParams p = Params10x5();
    ClearLcteWarnings();
    const size_t before = LcteWarningCount();
    for (uint32_t c = 0; c < 5; ++c) {
        const int64_t theta = 10 + static_cast<int64_t>(c);
        const ThresholdAlignment a = AlignLcteThreshold(p, theta);
        EXPECT_EQ(a.column, c);
        EXPECT_EQ(a.aligned, theta);
        EXPECT_EQ(a.requested, theta);
        EXPECT_FALSE(a.adjusted);
    }
    EXPECT_EQ(LcteWarningCount(), before);  // R 内不产生告警
}

TEST(MpraqThresholdAlign, BelowRminClampsToFirstColumnWithWarning) {
    const LcteParams p = Params10x5();
    ClearLcteWarnings();
    const size_t before = LcteWarningCount();

    const ThresholdAlignment a = AlignLcteThreshold(p, 3);
    EXPECT_EQ(a.column, static_cast<uint32_t>(0));
    EXPECT_EQ(a.aligned, static_cast<int64_t>(10));
    EXPECT_EQ(a.requested, static_cast<int64_t>(3));
    EXPECT_TRUE(a.adjusted);
    EXPECT_EQ(LcteWarningCount(), before + 1);

    const auto warnings = TakeLcteWarnings();
    ASSERT_EQ(warnings.size(), static_cast<size_t>(1));
    EXPECT_TRUE(warnings[0].find("调整到最近有效值") != std::string::npos);
    EXPECT_TRUE(warnings[0].find("10") != std::string::npos);
}

TEST(MpraqThresholdAlign, AboveRmaxClampsToLastColumnWithWarning) {
    const LcteParams p = Params10x5();
    ClearLcteWarnings();
    const size_t before = LcteWarningCount();

    const ThresholdAlignment a = AlignLcteThreshold(p, 999);
    EXPECT_EQ(a.column, static_cast<uint32_t>(4));
    EXPECT_EQ(a.aligned, static_cast<int64_t>(14));
    EXPECT_TRUE(a.adjusted);
    EXPECT_EQ(LcteWarningCount(), before + 1);

    const auto warnings = TakeLcteWarnings();
    ASSERT_EQ(warnings.size(), static_cast<size_t>(1));
    EXPECT_TRUE(warnings[0].find("999") != std::string::npos);
}

TEST(MpraqThresholdAlign, StrictModeThrowsInsteadOfAdjusting) {
    const LcteParams p = Params10x5();
    // R 内：两种模式都不抛
    EXPECT_NO_THROW(AlignLcteThreshold(p, 12, ThresholdMode::kStrict));
    EXPECT_EQ(AlignLcteThreshold(p, 12, ThresholdMode::kStrict).column,
              static_cast<uint32_t>(2));
    // R 外：严格模式抛 std::out_of_range（论文 "aborts via boundary checking"）
    EXPECT_THROW(AlignLcteThreshold(p, 9, ThresholdMode::kStrict), std::out_of_range);
    EXPECT_THROW(AlignLcteThreshold(p, 15, ThresholdMode::kStrict), std::out_of_range);

    ClearLcteWarnings();
    const size_t before = LcteWarningCount();
    EXPECT_THROW(AlignLcteThreshold(p, 9, ThresholdMode::kStrict), std::out_of_range);
    EXPECT_EQ(LcteWarningCount(), before);  // 严格模式抛错，不应额外产生告警
}

TEST(MpraqThresholdAlign, WarningHandlerReceivesMessages) {
    std::vector<std::string> captured;
    SetLcteWarningHandler([&captured](const std::string& m) {
        captured.push_back(m);
    });
    const LcteParams p = Params10x5();
    ClearLcteWarnings();
    (void)AlignLcteThreshold(p, 0);
    (void)AlignLcteThreshold(p, 100);
    SetLcteWarningHandler(std::function<void(const std::string&)>());  // 恢复默认

    ASSERT_EQ(captured.size(), static_cast<size_t>(2));
    EXPECT_TRUE(captured[0].find("阈值对齐") != std::string::npos);
    EXPECT_TRUE(captured[1].find("阈值对齐") != std::string::npos);
}

TEST(MpraqThresholdAlign, LosslessWhenDataWithinR) {
    // 工程结论：只要数据落在 [r_min, r_max-1]，夹到端点的对齐**不改变**语义。
    // 这里对 R 外的阈值穷举验证：对齐后的列比特 == 真实语义 [x < θ]。
    const LcteParams p = Params10x5();  // R = {10..14}，可精确表示的数据 = [10, 14)
    auto prng = MakePrng(1234);
    std::vector<int64_t> data(64);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = RandIn(prng, 10, 13);  // 全部落在 [r_min, r_max-1]
    }
    const AttrData attr = MakeAttrData(
        AttributeSchema{"hr", 0, p, 10, 13}, data);

    for (int64_t theta = -5; theta <= 25; ++theta) {
        const ThresholdAlignment a = AlignLcteThreshold(p, theta);
        const auto& bits = attr.column_bits[a.column];
        for (size_t r = 0; r < data.size(); ++r) {
            const uint8_t expected = static_cast<uint8_t>(data[r] < theta ? 1 : 0);
            EXPECT_EQ(static_cast<int>(bits[r]), static_cast<int>(expected));
        }
    }
}

TEST(MpraqThresholdAlign, CoversDomainExactlyNeedsOneExtraPoint) {
    // 覆盖条件（本实现新增的工程结论）：R ⊇ [domain_min, domain_max + 1]
    const LcteParams p = Params10x5();  // R = {10..14}
    EXPECT_TRUE(CoversDomainExactly(p, 10, 13));   // 需要覆盖到 14 ⇒ 恰好满足
    EXPECT_FALSE(CoversDomainExactly(p, 10, 14));  // 需要覆盖到 15 ⇒ 不满足
    EXPECT_FALSE(CoversDomainExactly(p, 9, 13));   // r_min=10 > 9 ⇒ 不满足
    EXPECT_TRUE(CoversDomainExactly(p, 11, 11));   // 单点域：需要覆盖到 12 ⇒ 满足
    EXPECT_TRUE(CoversDomainExactly(p, 10, 10));

    // 所需 range_size = (d_max - d_min) + 2
    LcteParams q;
    q.range_min = 0;
    q.range_size = 12;  // 覆盖 [0, 11]
    EXPECT_TRUE(CoversDomainExactly(q, 0, 10));
    EXPECT_FALSE(CoversDomainExactly(q, 0, 11));
}

TEST(MpraqThresholdAlign, CoverageWarningIsEmitted) {
    ClearLcteWarnings();
    const size_t before = LcteWarningCount();
    const LcteParams p = Params10x5();
    EXPECT_EQ(WarnIfLcteDoesNotCoverDomain(p, 10, 13, "hr"),
              static_cast<size_t>(0));
    EXPECT_EQ(LcteWarningCount(), before);

    EXPECT_EQ(WarnIfLcteDoesNotCoverDomain(p, 8, 20, "hr"),
              static_cast<size_t>(1));
    EXPECT_EQ(LcteWarningCount(), before + 1);
    const auto warnings = TakeLcteWarnings();
    ASSERT_EQ(warnings.size(), static_cast<size_t>(1));
    EXPECT_TRUE(warnings[0].find("覆盖检查") != std::string::npos);
    EXPECT_TRUE(warnings[0].find("range_size") != std::string::npos);
}

// ===========================================================================
// 7. 参数校验
// ===========================================================================

TEST(MpraqLcteValidation, RejectsDegenerateParams) {
    LcteParams zero;
    zero.range_size = 0;
    zero.range_min = 0;
    EXPECT_THROW(ValidateLcteParams(zero), std::invalid_argument);
    EXPECT_THROW(LcteEncodeRow(0, zero), std::invalid_argument);
    EXPECT_THROW(AlignLcteThreshold(zero, 0), std::invalid_argument);

    // 阈值集合溢出 int64
    LcteParams big;
    big.range_size = 3;
    big.range_min = std::numeric_limits<int64_t>::max() - 1;
    EXPECT_THROW(ValidateLcteParams(big), std::invalid_argument);

    // 列索引越界
    const LcteParams p = Params10x5();
    EXPECT_THROW(LcteThresholdAt(p, 5), std::out_of_range);
    EXPECT_THROW(LcteThresholdAt(p, 1000), std::out_of_range);
}

TEST(MpraqLcteValidation, RecordCountMustMatchWindowSize) {
    LcteParams p = Params10x5(4);
    EXPECT_NO_THROW(BuildLcteTable({10, 11, 12, 13}, p));
    EXPECT_THROW(BuildLcteTable({10, 11, 12}, p), std::invalid_argument);
    EXPECT_THROW(BuildLcteTable({10, 11, 12, 13, 14}, p), std::invalid_argument);
}

// ===========================================================================
// 8. 谓词解析（Q7）：操作符 → LCTE 列索引 + 取反标记
// ===========================================================================

namespace {

// 测试用 schema：两个属性，R = {10..14} 精确覆盖取值域 [10, 13]
Schema MakeSchema(uint32_t window = 16) {
    Schema s;
    LcteParams hr = Params10x5(window);
    s.AddAttribute(AttributeSchema{"heart_rate", 0, hr, 10, 13});
    s.AddAttribute(AttributeSchema{"spo2", 1, hr, 10, 13});
    return s;
}

}  // namespace

TEST(MpraqPredicate, LtMapsToThresholdColumn) {
    const Schema schema = MakeSchema();
    const PredicatePlan plan = ParsePredicate(Pred("heart_rate", PredicateOp::kLt, 11), schema);
    ASSERT_EQ(plan.literals.size(), static_cast<size_t>(1));
    EXPECT_EQ(plan.literals[0].ref.attribute_id, static_cast<uint32_t>(0));
    EXPECT_EQ(plan.literals[0].ref.column, static_cast<uint32_t>(1));  // r=11
    EXPECT_FALSE(plan.literals[0].negated);
    EXPECT_EQ(plan.literals[0].threshold, static_cast<int64_t>(11));
    EXPECT_EQ(plan.literals[0].requested, static_cast<int64_t>(11));
    EXPECT_FALSE(plan.literals[0].adjusted);
    ASSERT_EQ(plan.columns.size(), static_cast<size_t>(1));
    EXPECT_EQ(plan.columns[0].column, static_cast<uint32_t>(1));
    EXPECT_TRUE(plan.IsConjunction());
    EXPECT_EQ(plan.num_records, static_cast<size_t>(16));
}

TEST(MpraqPredicate, LeMapsToShiftedColumn) {
    const Schema schema = MakeSchema();
    // le(11) = [x <= 11] = [x < 12] ⇒ 阈值 12 的列 = 第 2 列
    const PredicatePlan plan = ParsePredicate(Pred("heart_rate", PredicateOp::kLe, 11), schema);
    ASSERT_EQ(plan.literals.size(), static_cast<size_t>(1));
    EXPECT_EQ(plan.literals[0].ref.column, static_cast<uint32_t>(2));
    EXPECT_FALSE(plan.literals[0].negated);
    EXPECT_EQ(plan.literals[0].threshold, static_cast<int64_t>(12));
}

TEST(MpraqPredicate, GtMapsToNegatedShiftedColumn) {
    const Schema schema = MakeSchema();
    // gt(11) = [x > 11] = [x >= 12] = ¬[x < 12] ⇒ 第 2 列 + 取反
    // （严格大于 ⇒ 取"阈值 θ+1"那一列的取反；与 ge 只差一格，务必核对）
    const PredicatePlan plan = ParsePredicate(Pred("heart_rate", PredicateOp::kGt, 11), schema);
    ASSERT_EQ(plan.literals.size(), static_cast<size_t>(1));
    EXPECT_EQ(plan.literals[0].ref.column, static_cast<uint32_t>(2));
    EXPECT_TRUE(plan.literals[0].negated);
    EXPECT_EQ(plan.literals[0].threshold, static_cast<int64_t>(12));
}

TEST(MpraqPredicate, GeMapsToNegatedColumn) {
    const Schema schema = MakeSchema();
    // ge(11) = [x >= 11] = ¬[x < 11] ⇒ 第 1 列 + 取反
    const PredicatePlan plan = ParsePredicate(Pred("heart_rate", PredicateOp::kGe, 11), schema);
    ASSERT_EQ(plan.literals.size(), static_cast<size_t>(1));
    EXPECT_EQ(plan.literals[0].ref.column, static_cast<uint32_t>(1));
    EXPECT_TRUE(plan.literals[0].negated);
    EXPECT_EQ(plan.literals[0].threshold, static_cast<int64_t>(11));
}

TEST(MpraqPredicate, EqMapsToPointRangeTwoLiterals) {
    const Schema schema = MakeSchema();
    // eq(11) = [11, 12) = ¬[x < 11] ∧ [x < 12]
    const PredicatePlan plan = ParsePredicate(Pred("heart_rate", PredicateOp::kEq, 11), schema);
    ASSERT_EQ(plan.literals.size(), static_cast<size_t>(2));
    EXPECT_EQ(plan.literals[0].ref.column, static_cast<uint32_t>(1));
    EXPECT_TRUE(plan.literals[0].negated);
    EXPECT_EQ(plan.literals[1].ref.column, static_cast<uint32_t>(2));
    EXPECT_FALSE(plan.literals[1].negated);
    ASSERT_EQ(plan.columns.size(), static_cast<size_t>(2));
    EXPECT_EQ(plan.columns[0].column, static_cast<uint32_t>(1));
    EXPECT_EQ(plan.columns[1].column, static_cast<uint32_t>(2));
    EXPECT_TRUE(plan.IsConjunction());

    const auto flat = plan.ConjunctiveLiterals();
    ASSERT_EQ(flat.size(), static_cast<size_t>(2));
    EXPECT_EQ(flat[0].ref.column, static_cast<uint32_t>(1));
    EXPECT_TRUE(flat[0].negated);
    EXPECT_EQ(flat[1].ref.column, static_cast<uint32_t>(2));
    EXPECT_FALSE(flat[1].negated);
}

TEST(MpraqPredicate, RangeMapsToLowerNegatedAndUpperPositive) {
    const Schema schema = MakeSchema();
    // range[11, 13) = ¬[x < 11] ∧ [x < 13] ⇒ 列 1 取反 + 列 3 不取反
    const PredicatePlan plan = ParsePredicate(PredRange("heart_rate", 11, 13), schema);
    ASSERT_EQ(plan.literals.size(), static_cast<size_t>(2));
    EXPECT_EQ(plan.literals[0].ref.column, static_cast<uint32_t>(1));
    EXPECT_TRUE(plan.literals[0].negated);
    EXPECT_EQ(plan.literals[1].ref.column, static_cast<uint32_t>(3));
    EXPECT_FALSE(plan.literals[1].negated);
    ASSERT_EQ(plan.columns.size(), static_cast<size_t>(2));
    EXPECT_EQ(plan.columns[0].column, static_cast<uint32_t>(1));
    EXPECT_EQ(plan.columns[1].column, static_cast<uint32_t>(3));
    EXPECT_TRUE(plan.IsConjunction());
}

TEST(MpraqPredicate, RangeAtDomainTopBoundaryAllowed) {
    const Schema schema = MakeSchema();
    // range[10, 14)：b = domain_max + 1 = 14 是合法的排他上界，且 14 ∈ R
    const PredicatePlan plan = ParsePredicate(PredRange("heart_rate", 10, 14), schema);
    ASSERT_EQ(plan.literals.size(), static_cast<size_t>(2));
    EXPECT_EQ(plan.literals[0].ref.column, static_cast<uint32_t>(0));
    EXPECT_TRUE(plan.literals[0].negated);
    EXPECT_EQ(plan.literals[1].ref.column, static_cast<uint32_t>(4));
    EXPECT_FALSE(plan.literals[1].negated);
}

TEST(MpraqPredicate, NeqIsNegatedConjunctionNotFlatConjunction) {
    const Schema schema = MakeSchema();
    // neq(11) = ¬( ¬[x < 11] ∧ [x < 12] ) ≡ [x < 11] ∨ [x >= 12]
    const PredicatePlan plan = ParsePredicate(Pred("heart_rate", PredicateOp::kNeq, 11), schema);
    ASSERT_EQ(plan.literals.size(), static_cast<size_t>(2));
    EXPECT_EQ(plan.literals[0].ref.column, static_cast<uint32_t>(1));
    EXPECT_TRUE(plan.literals[0].negated);
    EXPECT_EQ(plan.literals[1].ref.column, static_cast<uint32_t>(2));
    EXPECT_FALSE(plan.literals[1].negated);
    ASSERT_EQ(plan.columns.size(), static_cast<size_t>(2));

    // 用的是与 eq 完全相同的两列，只是根节点多一次取反
    EXPECT_TRUE(plan.root.kind == BoolExpr::Kind::kNot);
    ASSERT_EQ(plan.root.children.size(), static_cast<size_t>(1));
    EXPECT_TRUE(plan.root.children[0].kind == BoolExpr::Kind::kAnd);
    EXPECT_FALSE(plan.IsConjunction());
    EXPECT_THROW(plan.ConjunctiveLiterals(), std::logic_error);
}

TEST(MpraqPredicate, AndCombinationMergesColumnsAndLiterals) {
    const Schema schema = MakeSchema();
    const std::vector<Predicate> preds = {
        PredRange("heart_rate", 10, 12),          // ¬[x<10] ∧ [x<12] ⇒ 列 0(neg), 2
        Pred("heart_rate", PredicateOp::kLe, 12), // [x<13]          ⇒ 列 3
    };
    const PredicatePlan plan = ParseConjunction(preds, schema);

    ASSERT_EQ(plan.literals.size(), static_cast<size_t>(3));
    EXPECT_EQ(plan.literals[0].ref.column, static_cast<uint32_t>(0));
    EXPECT_TRUE(plan.literals[0].negated);
    EXPECT_EQ(plan.literals[1].ref.column, static_cast<uint32_t>(2));
    EXPECT_FALSE(plan.literals[1].negated);
    EXPECT_EQ(plan.literals[2].ref.column, static_cast<uint32_t>(3));
    EXPECT_FALSE(plan.literals[2].negated);

    // 去重后的列集合（Q5：一次性取回这些列）
    ASSERT_EQ(plan.columns.size(), static_cast<size_t>(3));
    EXPECT_EQ(plan.columns[0].column, static_cast<uint32_t>(0));
    EXPECT_EQ(plan.columns[1].column, static_cast<uint32_t>(2));
    EXPECT_EQ(plan.columns[2].column, static_cast<uint32_t>(3));

    EXPECT_TRUE(plan.root.kind == BoolExpr::Kind::kAnd);
    EXPECT_EQ(plan.root.children.size(), static_cast<size_t>(2));
    EXPECT_TRUE(plan.IsConjunction());
    EXPECT_EQ(plan.ConjunctiveLiterals().size(), static_cast<size_t>(3));
}

TEST(MpraqPredicate, EmptyConjunctionIsAlwaysTrue) {
    const Schema schema = MakeSchema();
    const PredicatePlan plan = ParseConjunction({}, schema);
    EXPECT_EQ(plan.literals.size(), static_cast<size_t>(0));
    EXPECT_EQ(plan.columns.size(), static_cast<size_t>(0));
    const auto filter = EvaluateFilter(plan, [](const LcteColumnRef&) {
        return std::vector<uint8_t>{};
    });
    EXPECT_EQ(filter.size(), static_cast<size_t>(0));  // N 未知 ⇒ 空向量
}

TEST(MpraqPredicate, ConjunctionDeduplicatesSharedColumns) {
    const Schema schema = MakeSchema();
    // ge(11) ⇒ ¬[x<11] ⇒ 列 1(neg)；gt(11) ⇒ ¬[x<12] ⇒ 列 2(neg)
    // 两个谓词落在同一列（后者重复两次）⇒ 去重后只剩 2 列
    const std::vector<Predicate> preds = {
        Pred("heart_rate", PredicateOp::kGe, 11),  // 列 1(neg)
        Pred("heart_rate", PredicateOp::kGt, 11),  // 列 2(neg)
        Pred("heart_rate", PredicateOp::kGt, 11),  // 列 2(neg) 重复
    };
    const PredicatePlan plan = ParseConjunction(preds, schema);
    EXPECT_EQ(plan.literals.size(), static_cast<size_t>(3));
    ASSERT_EQ(plan.columns.size(), static_cast<size_t>(2));  // 列 1、列 2 去重
    EXPECT_EQ(plan.columns[0].column, static_cast<uint32_t>(1));
    EXPECT_EQ(plan.columns[1].column, static_cast<uint32_t>(2));
}

TEST(MpraqPredicate, MultiAttributeConjunctionKeepsAttributeInColumnRef) {
    const Schema schema = MakeSchema();
    const std::vector<Predicate> preds = {
        PredRange("heart_rate", 11, 14),
        Pred("spo2", PredicateOp::kGe, 12),
    };
    const PredicatePlan plan = ParseConjunction(preds, schema);
    ASSERT_EQ(plan.columns.size(), static_cast<size_t>(3));
    // 列集合按 (attribute_id, column) 升序：(0,1), (0,4), (1,2)
    EXPECT_EQ(plan.columns[0].attribute_id, static_cast<uint32_t>(0));
    EXPECT_EQ(plan.columns[0].column, static_cast<uint32_t>(1));
    EXPECT_EQ(plan.columns[1].attribute_id, static_cast<uint32_t>(0));
    EXPECT_EQ(plan.columns[1].column, static_cast<uint32_t>(4));
    EXPECT_EQ(plan.columns[2].attribute_id, static_cast<uint32_t>(1));
    EXPECT_EQ(plan.columns[2].column, static_cast<uint32_t>(2));
}

TEST(MpraqPredicate, BoundaryOfLtLeGtGeIsHandWritten) {
    // 四个比较操作符在 x == θ 处的差异是**手写死**的期望值：
    //   lt(11) ⇒ x <  11 ；le(11) ⇒ x <= 11 ；gt(11) ⇒ x >  11 ；ge(11) ⇒ x >= 11
    // 若 gt/ge 的被取反列写反（用错 θ 与 θ+1 的列），边界值 x == 11 会整体翻错。
    const std::vector<int64_t> data = {10, 11, 11, 12, 13, 10, 13, 11};
    const Schema schema = MakeSchema(8);
    const AttrData hr = MakeAttrData(schema.ById(0), data);
    const auto lookup = MakeLookup({&hr});

    const std::vector<int> expect_lt = {1, 0, 0, 0, 0, 1, 0, 0};
    const std::vector<int> expect_le = {1, 1, 1, 0, 0, 1, 0, 1};
    const std::vector<int> expect_gt = {0, 0, 0, 1, 1, 0, 1, 0};
    const std::vector<int> expect_ge = {0, 1, 1, 1, 1, 0, 1, 1};

    const auto check = [&](PredicateOp op, const std::vector<int>& expect) {
        const PredicatePlan plan =
            ParsePredicate(Pred("heart_rate", op, 11), schema);
        const auto filter = EvaluateFilter(plan, lookup);
        ASSERT_EQ(filter.size(), expect.size());
        for (size_t r = 0; r < expect.size(); ++r) {
            EXPECT_EQ(static_cast<int>(filter[r]), expect[r]);
        }
    };
    check(PredicateOp::kLt, expect_lt);
    check(PredicateOp::kLe, expect_le);
    check(PredicateOp::kGt, expect_gt);
    check(PredicateOp::kGe, expect_ge);
}

// ===========================================================================
// 9. De Morgan 优化形式 Φ = ¬(∨ P_i0(l_i)) ∧ (∧ P_i1(r_i))
// ===========================================================================

TEST(MpraqPredicate, DeMorganShapeMatchesPaperForm) {
    const Schema schema = MakeSchema(64);  // window_size 必须与下面的数据规模一致
    const std::vector<Predicate> ranges = {
        PredRange("heart_rate", 11, 13),  // l_1 = 11, r_1 = 13
        PredRange("heart_rate", 12, 14),  // l_2 = 12, r_2 = 14
    };
    const PredicatePlan plan = ParseRangeConjunctionDeMorgan(ranges, schema);

    // 字面量：按 (l_i, r_i) 交错排列，且**全部为正**
    // （取反不在字面量上，而由树里的那一次 Not(Or(...)) 承担 —— 这正是论文
    //  "把多个左边界检测合并成一次统一检查"的含义；与 ParseConjunction 产出
    //  的"左边界字面量带 negated=true"的扁平形式不同但语义等价）。
    ASSERT_EQ(plan.literals.size(), static_cast<size_t>(4));
    EXPECT_EQ(plan.literals[0].ref.column, static_cast<uint32_t>(1));  // l_1 = 11
    EXPECT_FALSE(plan.literals[0].negated);
    EXPECT_EQ(plan.literals[1].ref.column, static_cast<uint32_t>(3));  // r_1 = 13
    EXPECT_FALSE(plan.literals[1].negated);
    EXPECT_EQ(plan.literals[2].ref.column, static_cast<uint32_t>(2));  // l_2 = 12
    EXPECT_FALSE(plan.literals[2].negated);
    EXPECT_EQ(plan.literals[3].ref.column, static_cast<uint32_t>(4));  // r_2 = 14
    EXPECT_FALSE(plan.literals[3].negated);
    EXPECT_FALSE(plan.IsConjunction());

    // 结构：And( Not(Or(左边界字面量)), And(右边界字面量) )
    ASSERT_TRUE(plan.root.kind == BoolExpr::Kind::kAnd);
    ASSERT_EQ(plan.root.children.size(), static_cast<size_t>(2));
    EXPECT_TRUE(plan.root.children[0].kind == BoolExpr::Kind::kNot);
    ASSERT_EQ(plan.root.children[0].children.size(), static_cast<size_t>(1));
    EXPECT_TRUE(plan.root.children[0].children[0].kind == BoolExpr::Kind::kOr);
    EXPECT_EQ(plan.root.children[0].children[0].children.size(),
              static_cast<size_t>(2));
    EXPECT_TRUE(plan.root.children[1].kind == BoolExpr::Kind::kAnd);
    EXPECT_EQ(plan.root.children[1].children.size(), static_cast<size_t>(2));

    // ── 与逐条合取（论文未优化形式 Φ = ∧(¬P_i0 ∧ P_i1)）语义等价 ──
    // 扁平形式的左边界字面量带 negated=true（已被吸收进取反标记），
    // 列集合两者相同。
    const PredicatePlan flat = ParseConjunction(ranges, schema);
    ASSERT_EQ(flat.literals.size(), plan.literals.size());
    EXPECT_TRUE(flat.literals[0].negated);
    EXPECT_FALSE(flat.literals[1].negated);
    EXPECT_TRUE(flat.IsConjunction());
    ASSERT_EQ(flat.columns.size(), plan.columns.size());
    for (size_t i = 0; i < flat.columns.size(); ++i) {
        EXPECT_TRUE(flat.columns[i] == plan.columns[i]);
    }
    auto prng = MakePrng(8888);
    std::vector<int64_t> data(64);
    for (size_t i = 0; i < data.size(); ++i) data[i] = RandIn(prng, 10, 13);
    const AttrData hr = MakeAttrData(schema.ById(0), data);
    const auto lookup = MakeLookup({&hr});

    const auto filter_demorgan = EvaluateFilter(plan, lookup);
    const auto filter_flat = EvaluateFilter(flat, lookup);
    ASSERT_EQ(filter_demorgan.size(), filter_flat.size());
    for (size_t r = 0; r < data.size(); ++r) {
        EXPECT_EQ(static_cast<int>(filter_demorgan[r]), static_cast<int>(filter_flat[r]));
        const bool expected = (data[r] >= 11 && data[r] < 13) &&
                              (data[r] >= 12 && data[r] < 14);
        EXPECT_EQ(static_cast<int>(filter_demorgan[r]), expected ? 1 : 0);
    }
}

TEST(MpraqPredicate, DeMorganRejectsNonRangePredicates) {
    const Schema schema = MakeSchema();
    EXPECT_THROW(ParseRangeConjunctionDeMorgan(
                     {Pred("heart_rate", PredicateOp::kLt, 12)}, schema),
                 std::invalid_argument);
    EXPECT_THROW(ParseRangeConjunctionDeMorgan(
                     {PredRange("heart_rate", 11, 13),
                      Pred("heart_rate", PredicateOp::kEq, 12)},
                     schema),
                 std::invalid_argument);
}

// ===========================================================================
// 10. 本地求值（Q5）：与暴力语义逐记录对照
// ===========================================================================

TEST(MpraqPredicate, FilterEvaluationMatchesBruteForceAllOperators) {
    auto prng = MakePrng(20260101);
    const uint32_t n = 128;
    std::vector<int64_t> data(n);
    for (uint32_t i = 0; i < n; ++i) data[i] = RandIn(prng, 10, 13);

    const Schema schema = MakeSchema(n);
    const AttrData hr = MakeAttrData(schema.ById(0), data);
    const auto lookup = MakeLookup({&hr});

    // (操作符, 取值) 组合穷举整个取值域 + 上界
    const std::vector<std::pair<PredicateOp, int64_t>> single = {
        {PredicateOp::kLt, 10}, {PredicateOp::kLt, 12}, {PredicateOp::kLt, 13},
        {PredicateOp::kLe, 10}, {PredicateOp::kLe, 12}, {PredicateOp::kLe, 13},
        {PredicateOp::kGt, 10}, {PredicateOp::kGt, 12}, {PredicateOp::kGt, 13},
        {PredicateOp::kGe, 10}, {PredicateOp::kGe, 12}, {PredicateOp::kGe, 13},
        {PredicateOp::kEq, 10}, {PredicateOp::kEq, 11}, {PredicateOp::kEq, 12},
        {PredicateOp::kEq, 13},
        {PredicateOp::kNeq, 10}, {PredicateOp::kNeq, 11}, {PredicateOp::kNeq, 12},
        {PredicateOp::kNeq, 13},
    };

    for (const auto& [op, value] : single) {
        const PredicatePlan plan = ParsePredicate(Pred("heart_rate", op, value), schema);
        const auto filter = EvaluateFilter(plan, lookup);
        ASSERT_EQ(filter.size(), static_cast<size_t>(n));
        for (uint32_t r = 0; r < n; ++r) {
            const uint8_t expected =
                static_cast<uint8_t>(BruteOp(op, data[r], value, 0, 0) ? 1 : 0);
            EXPECT_EQ(static_cast<int>(filter[r]), static_cast<int>(expected));
        }
    }

    // range 的穷举
    for (int64_t lo = 10; lo <= 14; ++lo) {
        for (int64_t hi = lo + 1; hi <= 14; ++hi) {
            const PredicatePlan plan =
                ParsePredicate(PredRange("heart_rate", lo, hi), schema);
            const auto filter = EvaluateFilter(plan, lookup);
            for (uint32_t r = 0; r < n; ++r) {
                const uint8_t expected = static_cast<uint8_t>(
                    BruteOp(PredicateOp::kRange, data[r], 0, lo, hi) ? 1 : 0);
                EXPECT_EQ(static_cast<int>(filter[r]), static_cast<int>(expected));
            }
        }
    }
}

TEST(MpraqPredicate, ConjunctiveFilterMatchesBruteForce) {
    auto prng = MakePrng(555);
    const uint32_t n = 96;
    std::vector<int64_t> hr_data(n), spo2_data(n);
    for (uint32_t i = 0; i < n; ++i) {
        hr_data[i] = RandIn(prng, 10, 13);
        spo2_data[i] = RandIn(prng, 10, 13);
    }
    const Schema schema = MakeSchema(n);
    const AttrData hr = MakeAttrData(schema.ById(0), hr_data);
    const AttrData spo2 = MakeAttrData(schema.ById(1), spo2_data);
    const auto lookup = MakeLookup({&hr, &spo2});

    const std::vector<Predicate> preds = {
        PredRange("heart_rate", 11, 14),           // 11 <= hr < 14
        Pred("spo2", PredicateOp::kGe, 12),        // spo2 >= 12
        Pred("heart_rate", PredicateOp::kNeq, 13), // hr != 13
    };
    const PredicatePlan plan = ParseConjunction(preds, schema);
    const auto filter = EvaluateFilter(plan, lookup);
    ASSERT_EQ(filter.size(), static_cast<size_t>(n));

    for (uint32_t r = 0; r < n; ++r) {
        const bool expected = (hr_data[r] >= 11 && hr_data[r] < 14) &&
                              (spo2_data[r] >= 12) && (hr_data[r] != 13);
        EXPECT_EQ(static_cast<int>(filter[r]), expected ? 1 : 0);
    }
}

TEST(MpraqPredicate, LookupIsCalledOncePerDistinctColumn) {
    auto prng = MakePrng(31);
    const uint32_t n = 32;
    std::vector<int64_t> data(n);
    for (uint32_t i = 0; i < n; ++i) data[i] = RandIn(prng, 10, 13);
    const Schema schema = MakeSchema(n);
    const AttrData hr = MakeAttrData(schema.ById(0), data);

    const std::vector<Predicate> preds = {
        PredRange("heart_rate", 11, 13),
        Pred("heart_rate", PredicateOp::kGt, 11),  // 复用列 1
    };
    const PredicatePlan plan = ParseConjunction(preds, schema);
    ASSERT_EQ(plan.columns.size(), static_cast<size_t>(3));  // 列 1、2、3

    size_t calls = 0;
    const auto lookup = [&hr, &calls](const LcteColumnRef& ref) {
        ++calls;
        if (ref.column >= hr.column_bits.size()) throw std::out_of_range("bad col");
        return hr.column_bits[ref.column];
    };
    const auto filter = EvaluateFilter(plan, lookup);
    EXPECT_EQ(calls, plan.columns.size());  // 每列恰好取一次
    EXPECT_EQ(filter.size(), static_cast<size_t>(n));
}

TEST(MpraqPredicate, EvaluateWithColumnsMatchesLookupVersion) {
    auto prng = MakePrng(64);
    const uint32_t n = 24;
    std::vector<int64_t> data(n);
    for (uint32_t i = 0; i < n; ++i) data[i] = RandIn(prng, 10, 13);
    const Schema schema = MakeSchema(n);
    const AttrData hr = MakeAttrData(schema.ById(0), data);
    const auto lookup = MakeLookup({&hr});

    const PredicatePlan plan = ParsePredicate(PredRange("heart_rate", 11, 14), schema);
    const auto a = EvaluateFilter(plan, lookup);

    std::vector<std::vector<uint8_t>> cols;
    for (const auto& ref : plan.columns) cols.push_back(lookup(ref));
    const auto b = EvaluateFilterWithColumns(plan, cols);
    EXPECT_EQ(a, b);

    cols.pop_back();
    EXPECT_THROW(EvaluateFilterWithColumns(plan, cols), std::invalid_argument);
}

// ===========================================================================
// 11. 错误路径
// ===========================================================================

TEST(MpraqPredicateErrors, UnknownAttributeThrows) {
    const Schema schema = MakeSchema();
    // 名字不存在
    EXPECT_THROW(ParsePredicate(Pred("nope", PredicateOp::kEq, 11), schema),
                 std::out_of_range);
    // id 不存在
    Predicate by_id;
    by_id.by_id = true;
    by_id.attribute_id = 99;
    by_id.op = PredicateOp::kEq;
    by_id.value = 11;
    EXPECT_THROW(ParsePredicate(by_id, schema), std::out_of_range);
    // 既不给 id 也不给名字
    Predicate empty;
    empty.op = PredicateOp::kEq;
    empty.value = 11;
    EXPECT_THROW(ParsePredicate(empty, schema), std::invalid_argument);
    // Schema 查找本身
    EXPECT_THROW(schema.ById(7), std::out_of_range);
    EXPECT_THROW(schema.ByName("nope"), std::out_of_range);
    EXPECT_TRUE(schema.HasAttribute("heart_rate"));
    EXPECT_FALSE(schema.HasAttribute("nope"));
}

TEST(MpraqPredicateErrors, ValueOutOfDomainThrows) {
    const Schema schema = MakeSchema();
    // eq/neq 必须落在闭取值域 [10, 13]
    EXPECT_THROW(ParsePredicate(Pred("heart_rate", PredicateOp::kEq, 9), schema),
                 std::out_of_range);
    EXPECT_THROW(ParsePredicate(Pred("heart_rate", PredicateOp::kEq, 14), schema),
                 std::out_of_range);
    EXPECT_THROW(ParsePredicate(Pred("heart_rate", PredicateOp::kNeq, 14), schema),
                 std::out_of_range);
    // 比较边界允许 [10, 14]（14 = domain_max + 1）
    EXPECT_NO_THROW(ParsePredicate(Pred("heart_rate", PredicateOp::kLt, 14), schema));
    EXPECT_NO_THROW(ParsePredicate(Pred("heart_rate", PredicateOp::kGe, 10), schema));
    EXPECT_THROW(ParsePredicate(Pred("heart_rate", PredicateOp::kLt, 9), schema),
                 std::out_of_range);
    EXPECT_THROW(ParsePredicate(Pred("heart_rate", PredicateOp::kLe, 15), schema),
                 std::out_of_range);
    // range 边界同样受取值域约束
    EXPECT_THROW(ParsePredicate(PredRange("heart_rate", 9, 12), schema),
                 std::out_of_range);
    EXPECT_THROW(ParsePredicate(PredRange("heart_rate", 11, 15), schema),
                 std::out_of_range);
}

TEST(MpraqPredicateErrors, ReversedOrEmptyRangeThrows) {
    const Schema schema = MakeSchema();
    // b <= a ⇒ 范围倒置（含 b == a 的空区间）
    EXPECT_THROW(ParsePredicate(PredRange("heart_rate", 12, 12), schema),
                 std::invalid_argument);
    EXPECT_THROW(ParsePredicate(PredRange("heart_rate", 13, 12), schema),
                 std::invalid_argument);
    EXPECT_THROW(ParseRangeConjunctionDeMorgan(
                     {PredRange("heart_rate", 13, 12)}, schema),
                 std::invalid_argument);
}

TEST(MpraqPredicateErrors, UnsupportedOperatorThrows) {
    EXPECT_THROW(ParsePredicateOp("between"), std::invalid_argument);
    EXPECT_THROW(ParsePredicateOp(""), std::invalid_argument);
    EXPECT_THROW(ParsePredicateOp("AND"), std::invalid_argument);
    EXPECT_FALSE(IsSupportedPredicateOp("between"));
    EXPECT_TRUE(IsSupportedPredicateOp("range"));
    // 支持集合的往返
    for (const char* name : {"eq", "neq", "lt", "le", "gt", "ge", "range"}) {
        EXPECT_TRUE(IsSupportedPredicateOp(name));
        const PredicateOp op = ParsePredicateOp(name);
        EXPECT_EQ(std::string(PredicateOpName(op)), std::string(name));
    }
}

TEST(MpraqPredicateErrors, StrictModeRejectsThresholdsOutsideR) {
    // R = {10..14}，取值域 [10, 13]；严格模式下域外阈值一律报错
    Schema schema;
    schema.AddAttribute(AttributeSchema{"hr", 0, Params10x5(8), 6, 13});
    // 宽松模式：夹到 r_min=10（列 0）
    const PredicatePlan lenient =
        ParsePredicate(Pred("hr", PredicateOp::kLt, 7), schema);
    ASSERT_EQ(lenient.literals.size(), static_cast<size_t>(1));
    EXPECT_EQ(lenient.literals[0].ref.column, static_cast<uint32_t>(0));
    EXPECT_TRUE(lenient.literals[0].adjusted);
    EXPECT_EQ(lenient.literals[0].threshold, static_cast<int64_t>(10));
    // 严格模式：抛 std::out_of_range
    EXPECT_THROW(ParsePredicate(Pred("hr", PredicateOp::kLt, 7), schema,
                                ThresholdMode::kStrict),
                 std::out_of_range);
}

TEST(MpraqPredicateErrors, BoundOverflowThrows) {
    Schema schema;
    LcteParams p;
    p.range_size = 4;
    p.range_min = std::numeric_limits<int64_t>::max() - 3;
    p.window_size = 2;
    schema.AddAttribute(
        AttributeSchema{"big", 0, p, std::numeric_limits<int64_t>::max() - 4,
                        std::numeric_limits<int64_t>::max()});
    // le/gt/eq/neq 需要 θ+1（le(θ)=[x<θ+1]、gt(θ)=¬[x<θ+1]）
    // ⇒ 溢出 int64 时应显式报错而不是 UB
    const int64_t vmax = std::numeric_limits<int64_t>::max();
    EXPECT_THROW(ParsePredicate(Pred("big", PredicateOp::kLe, vmax), schema),
                 std::invalid_argument);
    EXPECT_THROW(ParsePredicate(Pred("big", PredicateOp::kGt, vmax), schema),
                 std::invalid_argument);
    EXPECT_THROW(ParsePredicate(Pred("big", PredicateOp::kEq, vmax), schema),
                 std::invalid_argument);
    EXPECT_THROW(ParsePredicate(Pred("big", PredicateOp::kNeq, vmax), schema),
                 std::invalid_argument);
    // lt/ge 不需要 +1，仍可工作
    EXPECT_NO_THROW(ParsePredicate(Pred("big", PredicateOp::kLt, vmax), schema));
    EXPECT_NO_THROW(ParsePredicate(Pred("big", PredicateOp::kGe, vmax), schema));
}

TEST(MpraqPredicateErrors, SchemaRejectsInvalidAttributes) {
    Schema schema = MakeSchema();
    // 名字为空
    EXPECT_THROW(schema.AddAttribute(AttributeSchema{"", 9, Params10x5(), 0, 1}),
                 std::invalid_argument);
    // id 重复
    EXPECT_THROW(
        schema.AddAttribute(AttributeSchema{"other", 0, Params10x5(), 0, 1}),
        std::invalid_argument);
    // 名字重复
    EXPECT_THROW(
        schema.AddAttribute(AttributeSchema{"heart_rate", 2, Params10x5(), 0, 1}),
        std::invalid_argument);
    // 取值域倒置
    EXPECT_THROW(
        schema.AddAttribute(AttributeSchema{"x", 3, Params10x5(), 5, 1}),
        std::invalid_argument);
    // LCTE 参数非法（range_size = 0）
    LcteParams bad;
    bad.range_size = 0;
    EXPECT_THROW(schema.AddAttribute(AttributeSchema{"y", 4, bad, 0, 1}),
                 std::invalid_argument);
}

TEST(MpraqPredicateErrors, EvaluationRejectsBadColumnLengths) {
    const Schema schema = MakeSchema(16);
    const PredicatePlan plan = ParsePredicate(Pred("heart_rate", PredicateOp::kLt, 12), schema);
    // 列长度与 num_records 不符
    EXPECT_THROW(
        EvaluateFilter(plan, [](const LcteColumnRef&) {
            return std::vector<uint8_t>(3, 1);  // 期望 16
        }),
        std::invalid_argument);
    // lookup 为空
    EXPECT_THROW(EvaluateFilter(plan, LcteColumnLookup()), std::invalid_argument);
}

TEST(MpraqPredicateErrors, MultiAttributeWindowMismatchThrows) {
    Schema schema;
    schema.AddAttribute(AttributeSchema{"a", 0, Params10x5(8), 10, 13});
    schema.AddAttribute(AttributeSchema{"b", 1, Params10x5(16), 10, 13});
    EXPECT_THROW(ParseConjunction({Pred("a", PredicateOp::kLt, 12),
                                   Pred("b", PredicateOp::kLt, 12)},
                                  schema),
                 std::invalid_argument);
}

// ===========================================================================
// 12. MPA-01 + MPA-02 联调：XOR 分片 → 客户端重建 → 谓词 filter
// ===========================================================================

TEST(MpraqIntegration, ShardedLcteThenPredicateFilterMatchesPlaintext) {
    auto prng = MakePrng(777001);
    const uint32_t n = 150;
    std::vector<int64_t> hr_data(n), spo2_data(n);
    for (uint32_t i = 0; i < n; ++i) {
        hr_data[i] = RandIn(prng, 10, 13);
        spo2_data[i] = RandIn(prng, 10, 13);
    }
    const Schema schema = MakeSchema(n);

    // ── MPA-01：编码 + 打包 + XOR 分片（决策 D3/D12 的正确共享方案）──
    const XorShardedLcte hr_shard = XorShareLcte(hr_data, schema.ById(0).lcte);
    const XorShardedLcte spo2_shard = XorShareLcte(spo2_data, schema.ById(1).lcte);
    const ShareTable hr0 = LcteShareTable(hr_shard, 0);
    const ShareTable hr1 = LcteShareTable(hr_shard, 1);
    const ShareTable spo2_0 = LcteShareTable(spo2_shard, 0);
    const ShareTable spo2_1 = LcteShareTable(spo2_shard, 1);

    // ── 客户端重建（必须 XOR，不能用加法共享的 ReconstructTable）──
    const PlainTable hr_plain = ReconstructLcteFromShares(hr0, hr1, n);
    const PlainTable spo2_plain = ReconstructLcteFromShares(spo2_0, spo2_1, n);
    const auto hr_bits = LcteColumnBits(hr_plain);
    const auto spo2_bits = LcteColumnBits(spo2_plain);

    // 重建结果 = 明文 LCTE（对照独立编码）
    const PlainTable hr_expect = BuildLcteTable(hr_data, schema.ById(0).lcte);
    for (size_t r = 0; r < n; ++r) {
        for (size_t c = 0; c < hr_expect.num_columns(); ++c) {
            EXPECT_EQ(hr_plain.At(r, c), hr_expect.At(r, c));
        }
    }

    // ── MPA-02：解析合取 + 本地组合（Q5：全部在客户端）──
    const std::vector<Predicate> preds = {
        PredRange("heart_rate", 11, 14),   // 11 <= hr < 14
        Pred("spo2", PredicateOp::kGe, 12),  // spo2 >= 12
    };
    const PredicatePlan plan = ParseConjunction(preds, schema);
    const auto lookup = [&hr_bits, &spo2_bits](const LcteColumnRef& ref) {
        const auto& bits = (ref.attribute_id == 0) ? hr_bits : spo2_bits;
        if (ref.column >= bits.size()) throw std::out_of_range("列越界");
        return bits[ref.column];
    };
    const auto filter = EvaluateFilter(plan, lookup);
    ASSERT_EQ(filter.size(), static_cast<size_t>(n));

    size_t counted = 0;
    for (uint32_t r = 0; r < n; ++r) {
        const bool expected =
            (hr_data[r] >= 11 && hr_data[r] < 14) && (spo2_data[r] >= 12);
        EXPECT_EQ(static_cast<int>(filter[r]), expected ? 1 : 0);
        if (expected) ++counted;
    }
    // 明文 COUNT 基准（MPA-04 的 Count 稍后会复用同一条 filter）
    size_t plain_count = 0;
    for (uint32_t r = 0; r < n; ++r) {
        if (hr_data[r] >= 11 && hr_data[r] < 14 && spo2_data[r] >= 12) ++plain_count;
    }
    EXPECT_EQ(counted, plain_count);
}

TEST(MpraqIntegration, SchemaCoverageWarningOnLoad) {
    Schema schema;
    // 取值域 [10, 13] 但 R = {10..12} 只覆盖到 12 ⇒ 应告警（Q6 装载期校验）
    LcteParams p;
    p.range_size = 3;
    p.range_min = 10;
    p.window_size = 4;
    schema.AddAttribute(AttributeSchema{"tight", 0, p, 10, 13});
    ClearLcteWarnings();
    const size_t bad = schema.WarnOnIncompleteLcteCoverage();
    EXPECT_EQ(bad, static_cast<size_t>(1));
    const auto warnings = TakeLcteWarnings();
    ASSERT_EQ(warnings.size(), static_cast<size_t>(1));
    EXPECT_TRUE(warnings[0].find("tight") != std::string::npos);
}

// ===========================================================================
// MPRAQ 明文基准（tests/support/mpraq_baseline.hpp）的自检
//
// 这份基准是 MPA-04/06/07 的"已知答案"来源，它自己必须先是可信的：
// 这里用**手算好的 10 条记录**逐项核对每个操作符与整数矩。基准内部是朴素暴力实现，
// 且**不引用** tsb::mpraq 的谓词层（否则就是自己证明自己）。
// ===========================================================================

namespace {

// 10 条记录：attr0 = i，attr1 = 9 - i
mpraq_baseline::Dataset HandDataset() {
    mpraq_baseline::Dataset d;
    d.num_attributes = 2;
    d.domain_min = {0, 0};
    d.domain_max = {9, 9};
    for (int64_t i = 0; i < 10; ++i) d.records.push_back({i, 9 - i});
    return d;
}

}  // namespace

TEST(MpraqBaseline, FilterShapesMatchHandComputed) {
    const auto d = HandDataset();
    // attr0 < 5 ⇒ i=0..4 ⇒ 形状 1111100000
    const std::vector<mpraq_baseline::Pred> lt5 = {{0, mpraq_baseline::Op::kLt, 5}};
    EXPECT_EQ(mpraq_baseline::FilterShape(mpraq_baseline::Filter(d, lt5)),
              std::string("1111100000"));
    // 合取 i>=2 ∧ 9-i>=2 ⇒ i∈[2,7]（共 6 条：i=2,3,4,5,6,7）⇒ 0011111100
    // ⚠️ 这里刻意保留手算过程：我第一版把形状写成了 0011111110（多算一个 i=8），
    // 被基准实现当场纠正 —— 这正是"独立基准"的价值（错的是我，不是被测代码）。
    const std::vector<mpraq_baseline::Pred> conj = {
        {0, mpraq_baseline::Op::kGe, 2}, {1, mpraq_baseline::Op::kGe, 2}};
    EXPECT_EQ(mpraq_baseline::FilterShape(mpraq_baseline::Filter(d, conj)),
              std::string("0011111100"));
    // 空集：i<5 ∧ 9-i<5 ⇒ 空
    const std::vector<mpraq_baseline::Pred> empty = {
        {0, mpraq_baseline::Op::kLt, 5}, {1, mpraq_baseline::Op::kLt, 5}};
    EXPECT_EQ(mpraq_baseline::FilterShape(mpraq_baseline::Filter(d, empty)),
              std::string("0000000000"));
}

TEST(MpraqBaseline, EachOperatorMatchesHandComputedCount) {
    const auto d = HandDataset();
    const auto count = [&d](mpraq_baseline::Op op, int64_t v) {
        return mpraq_baseline::Count(d, {{0, op, v}});
    };
    EXPECT_EQ(count(mpraq_baseline::Op::kEq, 3), 1u);
    EXPECT_EQ(count(mpraq_baseline::Op::kNe, 3), 9u);
    EXPECT_EQ(count(mpraq_baseline::Op::kLt, 3), 3u);
    EXPECT_EQ(count(mpraq_baseline::Op::kLe, 3), 4u);
    EXPECT_EQ(count(mpraq_baseline::Op::kGt, 3), 6u);
    EXPECT_EQ(count(mpraq_baseline::Op::kGe, 3), 7u);
    // 半开区间 [2,7) ⇒ i=2..6 ⇒ 5 条
    EXPECT_EQ(mpraq_baseline::Count(d, {{0, mpraq_baseline::Op::kRange, 0, 2, 7}}), 5u);
    EXPECT_EQ(mpraq_baseline::Count(d, {{0, mpraq_baseline::Op::kRange, 0, 0, 10}}), 10u);
    EXPECT_EQ(mpraq_baseline::Count(d, {{0, mpraq_baseline::Op::kRange, 0, 10, 20}}), 0u);
}

TEST(MpraqBaseline, MomentsAndAvgMatchHandComputed) {
    const auto d = HandDataset();
    // attr0 < 5 ⇒ attr1 = 9,8,7,6,5 ⇒ count=5 sum=35 sum_sq=255 avg=7
    const std::vector<mpraq_baseline::Pred> p = {{0, mpraq_baseline::Op::kLt, 5}};
    const auto m = mpraq_baseline::Aggregate(d, p, 1);
    EXPECT_EQ(m.count, 5u);
    EXPECT_EQ(m.sum, 35u);
    EXPECT_EQ(m.sum_sq, 255u);
    EXPECT_EQ(mpraq_baseline::Avg(d, p, 1), 7u);
    // attr0 >= 5 ⇒ attr1 = 4,3,2,1,0 ⇒ sum=10, sum_sq=30
    const std::vector<mpraq_baseline::Pred> q = {{0, mpraq_baseline::Op::kGe, 5}};
    const auto m2 = mpraq_baseline::Aggregate(d, q, 1);
    EXPECT_EQ(m2.count, 5u);
    EXPECT_EQ(m2.sum, 10u);
    EXPECT_EQ(m2.sum_sq, 30u);
    // 合取 i>=2 ∧ 9-i>=2 ⇒ i∈[2,7] ⇒ sum(attr1)=7+6+5+4+3+2=27
    const std::vector<mpraq_baseline::Pred> conj = {
        {0, mpraq_baseline::Op::kGe, 2}, {1, mpraq_baseline::Op::kGe, 2}};
    EXPECT_EQ(mpraq_baseline::Sum(d, conj, 1), 27u);
    // 无命中 ⇒ count/sum 为 0，Avg 约定返回 0（不是除零）
    const std::vector<mpraq_baseline::Pred> none = {{0, mpraq_baseline::Op::kRange, 0, 10, 20}};
    EXPECT_EQ(mpraq_baseline::Aggregate(d, none, 1).count, 0u);
    EXPECT_EQ(mpraq_baseline::Avg(d, none, 1), 0u);
}

TEST(MpraqBaseline, DatasetIsReproducibleInDomainAndSeedDependent) {
    const auto a = mpraq_baseline::MakeDataset(64, {0, 0}, {63, 31}, 7);
    const auto b = mpraq_baseline::MakeDataset(64, {0, 0}, {63, 31}, 7);
    const auto c = mpraq_baseline::MakeDataset(64, {0, 0}, {63, 31}, 8);
    EXPECT_EQ(a.size(), size_t{64});
    int diff_ab = 0, diff_ac = 0, out_of_domain = 0;
    for (size_t r = 0; r < a.size(); ++r) {
        for (size_t k = 0; k < 2; ++k) {
            diff_ab += (a.records[r][k] != b.records[r][k]);
            diff_ac += (a.records[r][k] != c.records[r][k]);
            if (a.records[r][k] < 0 || a.records[r][k] > (k == 0 ? 63 : 31)) ++out_of_domain;
        }
    }
    EXPECT_EQ(diff_ab, 0);      // 同种子逐位一致
    EXPECT_TRUE(diff_ac > 60);  // 异种子必须明显不同（D23 修好 nonce 后应成立）
    EXPECT_EQ(out_of_domain, 0);
    // 负值域也要支持（属性可以是负整数）
    const auto neg = mpraq_baseline::MakeDataset(32, {-5}, {5}, 3);
    for (const auto& r : neg.records) EXPECT_TRUE(r[0] >= -5 && r[0] <= 5);
}

TEST(MpraqBaseline, RejectsBadArguments) {
    const auto d = HandDataset();
    EXPECT_THROW(mpraq_baseline::Count(d, {{2, mpraq_baseline::Op::kEq, 1}}),
                 std::out_of_range);                       // 属性号越界
    EXPECT_THROW(mpraq_baseline::Aggregate(d, {}, 2), std::out_of_range);  // 求和属性越界
    EXPECT_THROW(mpraq_baseline::MakeDataset(4, {0, 0}, {1}, 1), std::invalid_argument);
    EXPECT_THROW(mpraq_baseline::MakeDataset(4, {5}, {1}, 1), std::invalid_argument);
    EXPECT_THROW(mpraq_baseline::MakeDataset(4, {}, {}, 1), std::invalid_argument);
}
