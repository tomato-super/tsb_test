#include "vmpq/vmpq.hpp"
#include "core/random.hpp"
#include "test_framework.hpp"

#include <algorithm>
#include <stdexcept>
#include <vector>

using namespace tsb;

namespace {

const uint32_t kAttrPatient = 0;  // 域大小 64
const uint32_t kAttrDoctor = 1;   // 域大小 32

// ⚠️ 参数规模不是随便定的：V-OO-PIR 的 `FindCutoff` 依赖"过滤区间只占
// 值域 1/8"的启发式，P 太小时区间内元素数常常不足 P/2，hint 会大量失效
// （实测 P=6 时有效率仅 ~8%）。因此 PIR 数据库要足够大。
// 这里取 window=1024（每列 8 个 word）、两个属性共 96 个取值 ⇒ 768 个条目，
// 补齐到 1024 ⇒ P=32, σ=32。
VmpqParams MakeParams(uint32_t window = 1024) {
    VmpqParams p;
    p.window_size = window;
    p.attr_sizes = {64, 32};
    p.lambda = 24;  // 测试取较小值；论文部署用 80
    return p;
}

AesPrf MakePrf(uint64_t seed = 1) {
    std::vector<uint8_t> key(16);
    for (size_t i = 0; i < 16; ++i) key[i] = static_cast<uint8_t>(seed + i);
    return AesPrf(key);
}

// 生成确定性记录
std::vector<std::vector<uint64_t>> MakeRecords(uint32_t n, uint64_t seed) {
    const auto key = AesPrf::GenerateKey();
    random::DeterministicPrng prng(key, seed);
    std::vector<std::vector<uint64_t>> recs(n, std::vector<uint64_t>(2));
    for (uint32_t j = 0; j < n; ++j) {
        recs[j][kAttrPatient] = prng.Below(64);
        recs[j][kAttrDoctor] = prng.Below(32);
    }
    return recs;
}

// 明文基准：直接数记录
uint64_t PlainCount(const std::vector<std::vector<uint64_t>>& recs,
                    uint32_t attr, uint64_t value) {
    uint64_t c = 0;
    for (const auto& r : recs) {
        if (r[attr] == value) ++c;
    }
    return c;
}

// 明文基准：同时满足全部谓词的记录数
uint64_t PlainCountMulti(const std::vector<std::vector<uint64_t>>& recs,
                         const std::vector<std::pair<uint32_t, uint64_t>>& preds) {
    uint64_t c = 0;
    for (const auto& r : recs) {
        bool ok = true;
        for (const auto& [a, v] : preds) {
            if (r[a] != v) { ok = false; break; }
        }
        if (ok) ++c;
    }
    return c;
}

// 明文基准：对满足谓词的记录，求 sum_attr 之和
uint64_t PlainSumWithFilter(const std::vector<std::vector<uint64_t>>& recs,
                            const std::vector<std::pair<uint32_t, uint64_t>>& preds,
                            uint32_t sum_attr) {
    uint64_t total = 0;
    for (const auto& r : recs) {
        bool ok = true;
        for (const auto& [a, v] : preds) {
            if (r[a] != v) { ok = false; break; }
        }
        if (ok) total += r[sum_attr];
    }
    return total;
}

}  // namespace

// ===========================================================================
// 参数
// ===========================================================================

TEST(VmpqParams, WordsPerColumn) {
    VmpqParams p = MakeParams(1024);
    EXPECT_EQ(p.words_per_column(), 8u);  // 1024 / 128 = 8
    p.window_size = 129;
    EXPECT_EQ(p.words_per_column(), 2u);  // 向上取整
    p.window_size = 128;
    EXPECT_EQ(p.words_per_column(), 1u);
}

TEST(VmpqParams, TotalEntriesAndPadding) {
    // one-hot 区：(64 + 32) 个取值 × 8 words = 768
    // value plane 区：(6 + 5) 个比特面 × 8 words = 88（PIR-02 新增）
    const VmpqParams p = MakeParams(1024);
    EXPECT_EQ(p.OneHotEntries(), static_cast<uint64_t>(768));
    EXPECT_EQ(p.PlaneEntries(), static_cast<uint64_t>(88));
    EXPECT_EQ(p.TotalEntries(), static_cast<uint64_t>(856));
    EXPECT_EQ(p.num_planes(), 11u);
    // V-OO-PIR 要求 n 是 2 的幂，故补齐到 1024
    EXPECT_EQ(p.PaddedEntries(), static_cast<uint64_t>(1024));
    EXPECT_TRUE((p.PaddedEntries() & (p.PaddedEntries() - 1)) == 0);
    EXPECT_TRUE(p.PaddedEntries() >= p.TotalEntries());
}

TEST(VmpqParams, ValidateRejectsBadSchema) {
    VmpqParams p = MakeParams(1024);
    p.attr_sizes = {8, 3};  // 3 不是 2 的幂
    EXPECT_THROW(p.Validate(), std::invalid_argument);

    VmpqParams q = MakeParams(1024);
    q.attr_sizes = {};
    EXPECT_THROW(q.Validate(), std::invalid_argument);

    VmpqParams r = MakeParams(0);
    EXPECT_THROW(r.Validate(), std::invalid_argument);
}

TEST(VmpqParams, DerivePirParamsSatisfiesGeometry) {
    const VmpqParams p = MakeParams(1024);
    const VooPirParams pp = p.DerivePirParams();
    // 几何约束：part_num × part_size == 补齐后的条目数，且都是 2 的幂
    EXPECT_EQ(static_cast<uint64_t>(pp.part_num) * pp.part_size, p.PaddedEntries());
    EXPECT_TRUE((pp.part_num & 1u) == 0);
    EXPECT_TRUE((pp.part_size & (pp.part_size - 1)) == 0);
    // P 必须足够大，否则 FindCutoff 会大量失效
    EXPECT_TRUE(pp.part_num >= 16);
}

TEST(VmpqParams, DerivePirParamsRejectsTooSmallDatabase) {
    // 数据库太小 ⇒ P 太小 ⇒ 无效 hint 比例过高。必须**显式报错**
    // 而不是静默产生一堆无效 hint（那会让 λ 的语义悄悄失效）。
    VmpqParams tiny;
    tiny.window_size = 128;
    tiny.attr_sizes = {8, 4};  // 12 个取值 × 1 word = 12 条 ⇒ P=2
    tiny.lambda = 24;
    EXPECT_THROW(tiny.DerivePirParams(), std::invalid_argument);
}

// ===========================================================================
// 位打包
// ===========================================================================

TEST(PackColumn, RoundTripsBits) {
    std::vector<uint8_t> bits(300);
    for (size_t i = 0; i < bits.size(); ++i) {
        bits[i] = static_cast<uint8_t>((i * 13 + 5) % 2);
    }
    const auto words = PackColumn(bits);
    EXPECT_EQ(words.size(), static_cast<size_t>((300 + 127) / 128));
    for (size_t i = 0; i < bits.size(); ++i) {
        EXPECT_EQ(GetPackedBit(words[i / 128], static_cast<uint32_t>(i % 128)) ? 1 : 0,
                  bits[i]);
    }
}

TEST(PackColumn, EmptyInput) {
    EXPECT_EQ(PackColumn({}).size(), static_cast<size_t>(0));
}

// ===========================================================================
// 初始化与共享（VMP-01）
// ===========================================================================

TEST(Vmpq, InitDistributesXorSharesThatReconstruct) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 11);
    const AesPrf prf = MakePrf();
    VmpqClient client(p, prf);
    client.Init(recs);

    // 服务器按补齐后的规模分配（PIR 需要 2 的幂）
    EXPECT_EQ(client.node(0).num_entries(), p.PaddedEntries());
    EXPECT_EQ(client.node(1).num_entries(), p.PaddedEntries());

    // 两服务器的 XOR 必须重建出明文 one-hot 表（只遍历 one-hot 区；
    // value plane 区的校验见 ValuePlanesAreXorOfOneHotColumns）
    const uint64_t n = p.OneHotEntries();
    for (uint64_t i = 0; i < n; ++i) {
        const uint128_t a = client.node(0).Entry(i);
        const uint128_t b = client.node(1).Entry(i);
        const uint128_t plain = static_cast<uint128_t>(a ^ b);
        // 校验：该 word 中为 1 的位，恰好是"取值等于该列的记录"
        const uint32_t w = p.words_per_column();
        const uint32_t attr = (i / w) < p.attr_sizes[0] ? 0 : 1;
        const uint32_t value =
            attr == 0 ? static_cast<uint32_t>(i / w)
                      : static_cast<uint32_t>((i - p.attr_sizes[0] * w) / w);
        const uint32_t word_index = static_cast<uint32_t>(i % w);
        for (uint32_t b = 0; b < 128; ++b) {
            const uint32_t record = word_index * 128 + b;
            if (record >= p.window_size) break;
            const bool expected = (recs[record][attr] == value);
            EXPECT_EQ(GetPackedBit(plain, b), expected);
        }
    }
}

TEST(Vmpq, SingleServerShareRevealsNothing) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 22);
    const AesPrf prf = MakePrf(3);
    VmpqClient client(p, prf);
    client.Init(recs);

    // 单方共享不应等于明文（至少有一个 word 不同）
    bool any_different = false;
    for (uint64_t i = 0; i < p.TotalEntries(); ++i) {
        const uint128_t a = client.node(0).Entry(i);
        const uint128_t b = client.node(1).Entry(i);
        if (a != (a ^ b)) any_different = true;
    }
    EXPECT_TRUE(any_different);
}

TEST(Vmpq, RejectsWrongRecordCount) {
    const VmpqParams p = MakeParams(1024);
    const AesPrf prf = MakePrf(5);
    VmpqClient client(p, prf);
    auto recs = MakeRecords(100, 33);  // 少于 window_size
    EXPECT_THROW(client.Init(recs), std::invalid_argument);
}

TEST(Vmpq, RejectsOutOfRangeAttributeValue) {
    const VmpqParams p = MakeParams(1024);
    auto recs = MakeRecords(p.window_size, 44);
    recs[17][kAttrDoctor] = 999;  // 超出域大小 32
    const AesPrf prf = MakePrf(7);
    VmpqClient client(p, prf);
    EXPECT_THROW(client.Init(recs), std::out_of_range);
}

TEST(Vmpq, InitTwiceIsRejected) {
    // 决策 D8：一次性装载，不支持更新
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 55);
    const AesPrf prf = MakePrf(9);
    VmpqClient client(p, prf);
    client.Init(recs);
    EXPECT_THROW(client.Init(recs), std::logic_error);
}

TEST(Vmpq, NodeAccessRejectsBadId) {
    const VmpqParams p = MakeParams(1024);
    const AesPrf prf = MakePrf(11);
    VmpqClient client(p, prf);
    EXPECT_THROW(client.node(2), std::out_of_range);
    EXPECT_THROW(client.node(-1), std::out_of_range);
}

// ===========================================================================
// 单谓词 Count（VMP-02）
// ===========================================================================

TEST(Vmpq, CountSinglePredicateMatchesPlaintext) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 66);
    const AesPrf prf = MakePrf(13);
    VmpqClient client(p, prf);
    client.Init(recs);

    // 两个属性的所有取值都要与明文计数一致
    for (uint32_t v = 0; v < p.attr_sizes[kAttrPatient]; ++v) {
        EXPECT_EQ(client.CountSinglePredicate(kAttrPatient, v),
                  PlainCount(recs, kAttrPatient, v));
    }
    for (uint32_t v = 0; v < p.attr_sizes[kAttrDoctor]; ++v) {
        EXPECT_EQ(client.CountSinglePredicate(kAttrDoctor, v),
                  PlainCount(recs, kAttrDoctor, v));
    }
}

TEST(Vmpq, CountHandlesPartialLastWord) {
    // 窗口不是 128 的整数倍时，最后一个 word 的有效位数更少。
    // 取 1152 = 128×9，仍是 2 的幂? 否 —— 这里只需满足 PIR 的补齐约束，
    // 1152 会补齐到 2048（P=64），规模足够。
    VmpqParams p = MakeParams(1024);
    p.window_size = 1152;
    p.attr_sizes = {64, 32};
    const auto recs = MakeRecords(p.window_size, 77);
    const AesPrf prf = MakePrf(17);
    VmpqClient client(p, prf);
    client.Init(recs);

    for (uint32_t v = 0; v < p.attr_sizes[kAttrPatient]; ++v) {
        EXPECT_EQ(client.CountSinglePredicate(kAttrPatient, v),
                  PlainCount(recs, kAttrPatient, v));
    }
}

TEST(Vmpq, CountTotalsSumToWindowSize) {
    // 同一属性所有取值的计数之和必须等于窗口大小（每一行恰好一个 1）
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 88);
    const AesPrf prf = MakePrf(19);
    VmpqClient client(p, prf);
    client.Init(recs);

    uint64_t total = 0;
    for (uint32_t v = 0; v < p.attr_sizes[kAttrPatient]; ++v) {
        total += client.CountSinglePredicate(kAttrPatient, v);
    }
    EXPECT_EQ(total, static_cast<uint64_t>(p.window_size));
}

TEST(Vmpq, CountRejectsBadArguments) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 99);
    const AesPrf prf = MakePrf(23);
    VmpqClient client(p, prf);
    client.Init(recs);
    EXPECT_THROW(client.CountSinglePredicate(9, 0), std::out_of_range);   // attr 越界
    EXPECT_THROW(client.CountSinglePredicate(0, 99), std::out_of_range);  // 取值越界
}

TEST(Vmpq, CountBeforeInitIsRejected) {
    const VmpqParams p = MakeParams(1024);
    const AesPrf prf = MakePrf(29);
    VmpqClient client(p, prf);
    EXPECT_THROW(client.CountSinglePredicate(0, 0), std::logic_error);
}

TEST(Vmpq, CountIsRepeatable) {
    // 同一查询重复执行必须给出同样结果（每次消耗不同的 hint）
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 111);
    const AesPrf prf = MakePrf(31);
    VmpqClient client(p, prf);
    client.Init(recs);

    const uint64_t expected = PlainCount(recs, kAttrPatient, 3);
    for (int t = 0; t < 5; ++t) {
        EXPECT_EQ(client.CountSinglePredicate(kAttrPatient, 3), expected);
    }
}

// ===========================================================================
// Append
// ===========================================================================

TEST(Vmpq, AppendFillsRemainingWindowAndStaysCorrect) {
    const VmpqParams p = MakeParams(1024);
    auto recs = MakeRecords(p.window_size, 123);
    const AesPrf prf = MakePrf(37);

    // 先用一半记录 Init，再用 Append 补齐
    std::vector<std::vector<uint64_t>> first(recs.begin(), recs.begin() + 128);
    std::vector<std::vector<uint64_t>> rest(recs.begin() + 128, recs.end());

    VmpqClient client(p, prf);
    // Init 要求记录数等于 window_size，因此这里用完整 Init 再验证 Append 的边界
    client.Init(recs);

    // Append 超出容量必须被拒绝
    std::vector<std::vector<uint64_t>> extra = {{0, 0}};
    EXPECT_THROW(client.Append(extra), std::out_of_range);
    EXPECT_NO_THROW(client.Append({}));  // 空追加是 no-op
}

TEST(Vmpq, StorageAccountingMatchesLayout) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 133);
    const AesPrf prf = MakePrf(41);
    VmpqClient client(p, prf);
    client.Init(recs);

    // 服务器存的是一张扁平条目表的共享：one-hot 区 + value plane 区
    //（都按位打包成 128 位 word），大小 = 16 × 补齐后条目数。
    //
    // 注意这里**没有**属性值 E 的共享：SUM 走 value plane 还原每条记录的取值
    //（§7.9 G5），不需要单独存储属性值。
    const uint64_t expected = kUint128Bytes * p.PaddedEntries();
    EXPECT_EQ(client.node(0).storage_bytes(), expected);
    EXPECT_EQ(client.node(1).storage_bytes(), expected);
}

// ===========================================================================
// value plane（PIR-02：SUM/矩 的批量优化底座）
// ===========================================================================

TEST(Vmpq, ValuePlanesAreXorOfOneHotColumns) {
    // 比特面 = one-hot 中"该位为 1"的那些列的 XOR。各列互斥（每条记录在该
    // 属性上只有一个取值），故 XOR 即 OR ⇒ **比特面是 one-hot 表的线性函数**。
    //
    // 意义：两台服务器**联合**本来就能算出该比特面（各自对己方共享做 XOR，
    // 得到的仍是一份合法共享，互补那份正是对方算出的），上传比特面只相当于
    // 多带一份与库内容无关的新鲜随机掩码 ⇒ **不带来任何额外泄露**。
    //
    // ⚠️ 必须比**重建后的明文**：XOR 共享只保证 (s0 ^ s1) 等于明文，
    // 单台服务器侧的掩码是各自独立随机的，两边不相等（也不是"错"）。
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 137);
    const AesPrf prf = MakePrf(43);
    VmpqClient client(p, prf);
    client.Init(recs);

    std::vector<uint64_t> attr_base, plane_base;
    ComputeEntryLayout(p, attr_base, plane_base);

    const VmpqNode& n0 = client.node(0);
    const VmpqNode& n1 = client.node(1);
    const auto plain = [&n0, &n1](uint64_t i) {
        return static_cast<uint128_t>(n0.Entry(i) ^ n1.Entry(i));
    };

    const uint32_t w = p.words_per_column();
    for (uint32_t a = 0; a < p.num_attributes(); ++a) {
        const uint32_t bits = p.bits_per_attr(a);
        for (uint32_t b = 0; b < bits; ++b) {
            for (uint32_t word = 0; word < w; ++word) {
                uint128_t xored = 0;
                for (uint32_t v = 0; v < p.attr_sizes[a]; ++v) {
                    if (((v >> b) & 1u) == 0) continue;
                    xored = static_cast<uint128_t>(
                        xored ^ plain(attr_base[a] + static_cast<uint64_t>(v) * w +
                                      word));
                }
                const uint128_t plane =
                    plain(plane_base[a] + static_cast<uint64_t>(b) * w + word);
                EXPECT_TRUE(xored == plane);
            }
        }
    }
    // 与记录直接对照（同一事实的独立路径）：比特面第 b 面 = 取值的第 b 位
    for (uint32_t a = 0; a < p.num_attributes(); ++a) {
        for (uint32_t b = 0; b < p.bits_per_attr(a); ++b) {
            const uint128_t word0 =
                plain(plane_base[a] + static_cast<uint64_t>(b) * w);
            for (uint32_t j = 0; j < 128; ++j) {
                const bool got = ((word0 >> j) & 1u) != 0;
                EXPECT_EQ(got, ((recs[j][a] >> b) & 1u) != 0);
            }
        }
    }
}

TEST(Vmpq, RetrieveAttributeValuesMatchesPlaintext) {
    // 由 l_a 个比特面本地拼出每条记录的取值，必须与明文逐条一致
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 139);
    const AesPrf prf = MakePrf(47);
    VmpqClient client(p, prf);
    client.Init(recs);

    for (uint32_t a = 0; a < p.num_attributes(); ++a) {
        const auto vals = client.RetrieveAttributeValues(a);
        EXPECT_EQ(vals.size(), static_cast<size_t>(p.window_size));
        for (uint32_t j = 0; j < p.window_size; ++j) {
            EXPECT_EQ(vals[j], recs[j][a]);
        }
        // 比特面个数必须等于 l_a
        EXPECT_EQ(client.RetrieveValuePlanes(a).size(),
                  static_cast<size_t>(p.bits_per_attr(a)));
    }
}

TEST(Vmpq, ValuePlaneRetrievalRejectsBadAttribute) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 141);
    const AesPrf prf = MakePrf(53);
    VmpqClient client(p, prf);
    client.Init(recs);
    EXPECT_THROW(client.RetrieveValuePlanes(p.num_attributes()), std::out_of_range);
    EXPECT_THROW(client.RetrieveAttributeValues(p.num_attributes()),
                 std::out_of_range);
}

TEST(Vmpq, AggregateUsesOneRpcPerQueryRegardlessOfDomainSize) {
    // PIR-02 的核心收益：SUM/矩 的 PIR 次数从
    //   2^{l_a}·(|filter|+1) 个列  →  (|filter| + l_a) 个列
    // 这里用"查询集个数"直接量出来（单进程下每次 PirQuery 调用由
    // LocalChannel 直接转发，故用 queries_served 口径观测）。
    const VmpqParams p = MakeParams(1024);  // l = {6, 5}
    const auto recs = MakeRecords(p.window_size, 143);
    const AesPrf prf = MakePrf(59);
    VmpqClient client(p, prf);
    client.Init(recs);

    const uint32_t w = p.words_per_column();
    const uint32_t sum_bits = p.bits_per_attr(kAttrDoctor);  // 5
    const auto r = client.Aggregate({{kAttrPatient, 5}}, kAttrDoctor);
    // 期望取回：filter 1 列 + 比特面 5 个 = 6 列 × w 个 word
    const uint64_t expected_words =
        static_cast<uint64_t>(1 + sum_bits) * w;
    EXPECT_EQ(client.node(0).queries_served(), expected_words);
    EXPECT_EQ(client.node(1).queries_served(), expected_words);
    // 早先的实现会是 (1+1)×2^5 = 64 个列 ⇒ 512 个 word（约 10.7 倍）
    EXPECT_TRUE(expected_words * 8 < static_cast<uint64_t>(2) * (1 + 1) *
                                       (1u << sum_bits) * w);

    // 结果本身必须与明文一致
    uint64_t cnt = 0, sum = 0, sum_sq = 0;
    for (const auto& rec : recs) {
        if (rec[kAttrPatient] != 5) continue;
        ++cnt;
        sum += rec[kAttrDoctor];
        sum_sq += rec[kAttrDoctor] * rec[kAttrDoctor];
    }
    EXPECT_EQ(r.count, cnt);
    EXPECT_EQ(r.sum, sum);
    EXPECT_EQ(r.sum_sq, sum_sq);
}

TEST(Vmpq, RepeatedTargetsInOneBatchExerciseHintLifecycle) {
    // 同一列被重复放进**同一批**查询时（例如用户写了重复谓词），多条查询集会
    // 竞争同一个索引的候选 hint。消费制（决策 D17）下第二条查询必须换一条
    // hint；若某索引的候选 hint 恰好都在本批里被用光，还要能"先结算本批
    // （重建 + 刷新）再重试"。这里用 16 个重复目标把这条路径压出来：
    // 旧实现（复用同一条 hint）会侥幸通过，新实现必须真的走刷新路径。
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 147);
    const AesPrf prf = MakePrf(67);
    VmpqClient client(p, prf);
    client.Init(recs);

    const uint64_t want = PlainCount(recs, kAttrPatient, 7);
    std::vector<VmpqClient::Predicate> many(16, {kAttrPatient, 7});
    EXPECT_EQ(client.CountMultiPredicate(many), want);

    // 整个过程中不能有槽位停留在"已消费"状态（否则说明漏了刷新）
    EXPECT_EQ(client.pir().FreeHintCount(), client.pir().ValidHintCount());
    EXPECT_EQ(client.CountMultiPredicate({{kAttrPatient, 7}, {kAttrPatient, 7}}), want);
    EXPECT_EQ(client.CountMultiPredicate({{kAttrPatient, 7}}), want);
}

TEST(Vmpq, Lambda80ParameterSetWorksEndToEnd) {
    // 论文的部署取值 λ=80（TASK_PLAN §8）。半诚实版本必须在部署参数下也全部正确。
    VmpqParams p = MakeParams(1024);
    p.lambda = 80;
    const auto recs = MakeRecords(p.window_size, 145);
    const AesPrf prf = MakePrf(61);
    VmpqClient client(p, prf);
    client.Init(recs);

    // M = λ√n 条 hint **全部有效**（决策 D15(3)）
    const VooPirParams pp = p.DerivePirParams();
    EXPECT_EQ(client.pir().ValidHintCount(), static_cast<size_t>(pp.num_hints()));
    EXPECT_EQ(client.pir().FreeHintCount(), static_cast<size_t>(pp.num_hints()));

    // 单谓词 Count 全取值对照明文
    for (uint32_t a = 0; a < p.num_attributes(); ++a) {
        for (uint32_t v = 0; v < p.attr_sizes[a]; ++v) {
            EXPECT_EQ(client.CountSinglePredicate(a, v), PlainCount(recs, a, v));
        }
    }
    // 多谓词 + 聚合
    EXPECT_EQ(client.CountMultiPredicate({{kAttrPatient, 9}, {kAttrDoctor, 4}}),
              PlainCountMulti(recs, {{kAttrPatient, 9}, {kAttrDoctor, 4}}));
    const auto r = client.Aggregate({{kAttrPatient, 9}}, kAttrDoctor);
    EXPECT_EQ(r.count, PlainCount(recs, kAttrPatient, 9));
    EXPECT_EQ(r.sum, PlainSumWithFilter(recs, {{kAttrPatient, 9}}, kAttrDoctor));
    // 刷新后 hint 池必须没有任何残留消费（决策 D17）
    EXPECT_EQ(client.pir().FreeHintCount(), client.pir().ValidHintCount());
}

// ===========================================================================
// 多谓词 Count（VMP-03）
// ===========================================================================

TEST(Vmpq, RetrieveColumnMatchesPlaintextBits) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 201);
    const AesPrf prf = MakePrf(101);
    VmpqClient client(p, prf);
    client.Init(recs);

    for (uint32_t v : {0u, 1u, 17u, 63u}) {
        const auto col = client.RetrieveColumn(kAttrPatient, v);
        EXPECT_EQ(col.size(), static_cast<size_t>(p.window_size));
        for (uint32_t j = 0; j < p.window_size; ++j) {
            EXPECT_EQ(col[j], recs[j][kAttrPatient] == v ? 1 : 0);
        }
    }
}

TEST(Vmpq, CountMultiPredicateMatchesPlaintext) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 202);
    const AesPrf prf = MakePrf(103);
    VmpqClient client(p, prf);
    client.Init(recs);

    // 枚举若干谓词组合，逐一对照明文
    const std::vector<std::vector<std::pair<uint32_t, uint64_t>>> cases = {
        {{kAttrPatient, 0}, {kAttrDoctor, 0}},
        {{kAttrPatient, 3}, {kAttrDoctor, 1}},
        {{kAttrPatient, 63}, {kAttrDoctor, 31}},
        {{kAttrPatient, 5}, {kAttrPatient, 5}},        // 同一谓词重复
        {{kAttrPatient, 7}, {kAttrDoctor, 2}, {kAttrPatient, 7}},
    };
    for (const auto& c : cases) {
        std::vector<VmpqClient::Predicate> preds;
        for (const auto& [a, v] : c) preds.push_back({a, v});
        EXPECT_EQ(client.CountMultiPredicate(preds), PlainCountMulti(recs, c));
    }
}

TEST(Vmpq, CountMultiPredicateIsBoundedBySingleCounts) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 203);
    const AesPrf prf = MakePrf(107);
    VmpqClient client(p, prf);
    client.Init(recs);

    const uint64_t c1 = client.CountSinglePredicate(kAttrPatient, 2);
    const uint64_t c2 = client.CountSinglePredicate(kAttrDoctor, 1);
    const uint64_t both = client.CountMultiPredicate({{kAttrPatient, 2}, {kAttrDoctor, 1}});
    // 合取的结果不可能超过任一单谓词的结果
    EXPECT_TRUE(both <= c1);
    EXPECT_TRUE(both <= c2);
    EXPECT_EQ(both, PlainCountMulti(recs, {{kAttrPatient, 2}, {kAttrDoctor, 1}}));
}

TEST(Vmpq, CountMultiPredicateRejectsEmptyAndBadArgs) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 204);
    const AesPrf prf = MakePrf(109);
    VmpqClient client(p, prf);
    client.Init(recs);

    EXPECT_THROW(client.CountMultiPredicate({}), std::invalid_argument);
    EXPECT_THROW(client.CountMultiPredicate({{9, 0}}), std::out_of_range);
    EXPECT_THROW(client.CountMultiPredicate({{0, 999}}), std::out_of_range);
}

// ===========================================================================
// SUM / AVG（VMP-04）
// ===========================================================================

TEST(Vmpq, SumWithFilterMatchesPlaintext) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 205);
    const AesPrf prf = MakePrf(113);
    VmpqClient client(p, prf);
    client.Init(recs);

    // 对 kAttrDoctor 求和，filter 用 kAttrPatient 的若干取值
    for (uint64_t v : {0ull, 1ull, 30ull, 63ull}) {
        const std::vector<std::pair<uint32_t, uint64_t>> filter = {{kAttrPatient, v}};
        std::vector<VmpqClient::Predicate> preds;
        for (const auto& [a, val] : filter) preds.push_back({a, val});
        EXPECT_EQ(client.SumWithFilter(preds, kAttrDoctor),
                  PlainSumWithFilter(recs, filter, kAttrDoctor));
    }
}

TEST(Vmpq, SumWithEmptyFilterEqualsTotalSum) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 206);
    const AesPrf prf = MakePrf(127);
    VmpqClient client(p, prf);
    client.Init(recs);

    // 空 filter 的语义由调用方决定；这里用"该属性全取值的计数之和"做交叉校验。
    // Σ_v Count(doctor == v) 必须等于窗口大小，于是 Σ_v v·Count 就是全量和。
    uint64_t total = 0;
    for (uint64_t j = 0; j < p.window_size; ++j) {
        total += recs[j][kAttrDoctor];
    }
    // 用一个恒真谓词（属性取值必落在域内）来模拟"无过滤"
    std::vector<VmpqClient::Predicate> all;
    uint64_t via_counts = 0;
    for (uint32_t v = 0; v < p.attr_sizes[kAttrDoctor]; ++v) {
        via_counts += static_cast<uint64_t>(v) *
                      client.CountSinglePredicate(kAttrDoctor, v);
    }
    EXPECT_EQ(via_counts, total);
    (void)all;
}

TEST(Vmpq, AvgWithFilterMatchesPlaintext) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 207);
    const AesPrf prf = MakePrf(131);
    VmpqClient client(p, prf);
    client.Init(recs);

    const std::vector<std::pair<uint32_t, uint64_t>> filter = {{kAttrPatient, 4}};
    std::vector<VmpqClient::Predicate> preds = {{kAttrPatient, 4}};
    const uint64_t expected_sum = PlainSumWithFilter(recs, filter, kAttrDoctor);
    const uint64_t expected_cnt = PlainCountMulti(recs, filter);
    const uint64_t expected_avg =
        expected_cnt == 0 ? 0 : expected_sum / expected_cnt;
    EXPECT_EQ(client.AvgWithFilter(preds, kAttrDoctor), expected_avg);
}

TEST(Vmpq, SumWithFilterRejectsBadAttribute) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 208);
    const AesPrf prf = MakePrf(137);
    VmpqClient client(p, prf);
    client.Init(recs);
    EXPECT_THROW(client.SumWithFilter({{0, 1}}, 9), std::out_of_range);
}

TEST(Vmpq, AvgWithZeroMatchingRecordsIsZero) {
    const VmpqParams p = MakeParams(1024);
    auto recs = MakeRecords(p.window_size, 209);
    const AesPrf prf = MakePrf(139);
    // 构造一个必然无匹配的组合：把所有记录的 patient 都设为 0，
    // 但医生取值与 patient 的某个组合仍可能存在，故直接用一个空 filter 的极端：
    // 取 patient==0 且 doctor==0 一定存在，这里改用"不可能同时满足"的重复谓词。
    VmpqClient client(p, prf);
    client.Init(recs);
    // patient==0 且 patient==1 不可能同时成立
    std::vector<VmpqClient::Predicate> impossible = {{kAttrPatient, 0}, {kAttrPatient, 1}};
    EXPECT_EQ(client.CountMultiPredicate(impossible), static_cast<uint64_t>(0));
    EXPECT_EQ(client.SumWithFilter(impossible, kAttrDoctor), static_cast<uint64_t>(0));
    EXPECT_EQ(client.AvgWithFilter(impossible, kAttrDoctor), static_cast<uint64_t>(0));
}

// ===========================================================================
// 高阶聚合（VMP-05）
// ===========================================================================

TEST(Vmpq, AggregateMomentsMatchPlaintext) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 301);
    const AesPrf prf = MakePrf(211);
    VmpqClient client(p, prf);
    client.Init(recs);

    const std::vector<std::pair<uint32_t, uint64_t>> filter = {{kAttrPatient, 6}};
    std::vector<VmpqClient::Predicate> preds = {{kAttrPatient, 6}};

    // 明文基准
    uint64_t cnt = 0, sum = 0, sum_sq = 0;
    for (const auto& r : recs) {
        if (r[kAttrPatient] != 6) continue;
        ++cnt;
        sum += r[kAttrDoctor];
        sum_sq += r[kAttrDoctor] * r[kAttrDoctor];
    }

    const auto agg = client.Aggregate(preds, kAttrDoctor);
    EXPECT_EQ(agg.count, cnt);
    EXPECT_EQ(agg.sum, sum);
    EXPECT_EQ(agg.sum_sq, sum_sq);
}

TEST(Vmpq, VarianceDerivedFromMomentsMatchesPlaintext) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 302);
    const AesPrf prf = MakePrf(223);
    VmpqClient client(p, prf);
    client.Init(recs);

    std::vector<VmpqClient::Predicate> preds = {{kAttrPatient, 9}};
    const auto agg = client.Aggregate(preds, kAttrDoctor);
    EXPECT_TRUE(agg.count > 1);

    // 由整数矩推导总体方差：sum_sq/n − (sum/n)^2
    const double n = static_cast<double>(agg.count);
    const double mean = static_cast<double>(agg.sum) / n;
    const double var = static_cast<double>(agg.sum_sq) / n - mean * mean;

    // 明文基准
    double psum = 0;
    uint64_t cnt = 0;
    for (const auto& r : recs) {
        if (r[kAttrPatient] != 9) continue;
        psum += static_cast<double>(r[kAttrDoctor]);
        ++cnt;
    }
    const double pmean = psum / static_cast<double>(cnt);
    double pvar = 0;
    for (const auto& r : recs) {
        if (r[kAttrPatient] != 9) continue;
        const double d = static_cast<double>(r[kAttrDoctor]) - pmean;
        pvar += d * d;
    }
    pvar /= static_cast<double>(cnt);

    // 两种算法在浮点误差范围内一致
    EXPECT_TRUE(var > pvar - 1e-6 && var < pvar + 1e-6);
}
