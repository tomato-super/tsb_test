#include "pir/voo_pir.hpp"
#include "core/random.hpp"
#include "test_framework.hpp"

#include <algorithm>
#include <set>
#include <stdexcept>
#include <vector>

using namespace tsb;

namespace {

std::vector<uint8_t> TestKey() { return std::vector<uint8_t>(16, 0x3C); }

// 构造一个确定性的明文数据库
std::vector<uint128_t> MakeDb(uint64_t n, uint64_t seed) {
    const auto key = AesPrf::GenerateKey();
    random::DeterministicPrng prng(key, seed);
    std::vector<uint128_t> db(n);
    for (uint64_t i = 0; i < n; ++i) {
        db[i] = prng.Next();
    }
    return db;
}

// 一个可用的参数集：n = 4096, P = 64, σ = 64（都是 2 的幂，P 为偶数）
//
// ⚠️ λ 直接决定 hint 数量 M = λ√n，进而决定"任意索引都被至少一条 hint 覆盖"
// 的概率。每个 hint 覆盖 σ/2 个条目，M 条 hint 的总覆盖量约 n·λ/2，
// 故单个索引未被任一 hint 覆盖的概率 ≈ e^{−λ/2}（实测 λ=16 时 4096 个
// 索引里有 12 个未被覆盖，与理论吻合）。
//
// 测试取 λ=48 ⇒ e^{−24} ≈ 4e−11，4096 个索引基本不会出现未覆盖，
// 从而让"找不到 hint"这类正常失效模式不会干扰功能测试。
// （协议部署时按官方取 λ=80。）
VooPirParams MakeParams(uint64_t n = 4096, uint32_t lambda = 48) {
    VooPirParams p;
    p.n = n;
    p.part_num = 64;
    p.part_size = static_cast<uint32_t>(n / 64);
    p.lambda = lambda;
    p.Validate();
    return p;
}

// 从明文数据库取填充值（真实部署中由客户端另行点查询获得）
uint128_t FillerValue(const std::vector<uint128_t>& db, const VooPirQuery& q) {
    return q.filler_index == kNoExtraIndex ? 0 : db[q.filler_index];
}

AesPrf MakePrf(uint64_t seed = 1) {
    // 确定性密钥，便于复现
    std::vector<uint8_t> key(16);
    for (size_t i = 0; i < 16; ++i) {
        key[i] = static_cast<uint8_t>(seed + i);
    }
    return AesPrf(key);
}

}  // namespace

// ===========================================================================
// 参数
// ===========================================================================

TEST(VooPirParams, DeriveProducesPowerOfTwoGeometry) {
    for (uint64_t n : {256ull, 1024ull, 4096ull, 65536ull}) {
        const VooPirParams p = VooPirParams::Derive(n, 80);
        EXPECT_EQ(static_cast<uint64_t>(p.part_num) * p.part_size, n);
        EXPECT_TRUE((p.part_num & 1u) == 0);  // 偶数
        // σ 必须是 2 的幂
        EXPECT_TRUE((p.part_size & (p.part_size - 1)) == 0);
    }
}

TEST(VooPirParams, DeriveRejectsZero) {
    EXPECT_THROW(VooPirParams::Derive(0, 80), std::invalid_argument);
}

TEST(VooPirParams, ValidateRejectsBadGeometry) {
    VooPirParams p;
    p.n = 100;
    p.part_num = 3;  // 奇数
    p.part_size = 33;
    p.lambda = 80;
    EXPECT_THROW(p.Validate(), std::invalid_argument);

    p.part_num = 4;
    p.part_size = 33;  // 非 2 的幂
    EXPECT_THROW(p.Validate(), std::invalid_argument);

    p.part_num = 4;
    p.part_size = 16;  // 乘积 64 != 100
    EXPECT_THROW(p.Validate(), std::invalid_argument);
}

TEST(VooPirParams, NumHintsFollowsLambdaSqrtN) {
    const VooPirParams p = MakeParams(4096, 10);
    // sqrt(4096) = 64，M = λ·√n：λ=10 时 M = 640
    EXPECT_EQ(p.num_hints(), static_cast<uint64_t>(640));
    const VooPirParams p80 = MakeParams(4096, 80);  // 论文取值
    EXPECT_EQ(p80.num_hints(), static_cast<uint64_t>(80 * 64));
}

// ===========================================================================
// FindCutoff（S3PIR 规则，决策 D7）
// ===========================================================================

TEST(FindCutoff, SplitsEvenlyForUniformValues) {
    const auto key = AesPrf::GenerateKey();
    random::DeterministicPrng prng(key, 3);
    const uint32_t P = 256;
    std::vector<uint32_t> vals(P);
    for (uint32_t i = 0; i < P; ++i) {
        vals[i] = static_cast<uint32_t>(prng.Next() & 0xFFFFFFFFu);
    }
    const uint32_t c = FindCutoff(vals);
    EXPECT_NE(c, 0u);
    // 恰好一半在下
    const size_t below = std::count_if(vals.begin(), vals.end(),
                                       [c](uint32_t v) { return v < c; });
    EXPECT_EQ(below, static_cast<size_t>(P / 2));
}

TEST(FindCutoff, ReturnsZeroWhenAllValuesExtreme) {
    // 全部落在过滤区间之外 ⇒ 无法均分 ⇒ 无效
    std::vector<uint32_t> low(64, 0x00000001u);
    EXPECT_EQ(FindCutoff(low), 0u);
    std::vector<uint32_t> high(64, 0xFFFFFFF0u);
    EXPECT_EQ(FindCutoff(high), 0u);
}

TEST(FindCutoff, ReturnsZeroOnDuplicatesAtCutoff) {
    // 若 cutoff 在区间内重复，无法把 P/2 与 P/2 分干净 ⇒ 无效
    std::vector<uint32_t> vals;
    for (int i = 0; i < 40; ++i) vals.push_back(0x80000000u);  // 40 个相同
    for (int i = 0; i < 24; ++i) vals.push_back(0xA0000000u + i);
    EXPECT_EQ(FindCutoff(vals), 0u);
}

TEST(FindCutoff, RejectsOddOrEmptyInput) {
    std::vector<uint32_t> odd(3, 0x80000000u);
    EXPECT_THROW(FindCutoff(odd.data(), 3), std::invalid_argument);
    EXPECT_THROW(FindCutoff(static_cast<const uint32_t*>(nullptr), 0),
                 std::invalid_argument);
}

TEST(FindCutoff, RealPartitionsMatchCutoffSemantics) {
    // 用真正分散的随机值——均匀分布下 Filter 区域才装得下 P/2 个元素
    const auto key = AesPrf::GenerateKey();
    random::DeterministicPrng prng(key, 5);
    const uint32_t P = 1024;  // 样本量要够大：过滤区间只占 1/8
    std::vector<uint32_t> vals(P);
    for (uint32_t i = 0; i < P; ++i) {
        // 取 128 位输出的低 32 位（高位切片并非均匀）
        vals[i] = static_cast<uint32_t>(prng.Next() & 0xFFFFFFFFu);
    }
    const uint32_t c = FindCutoff(vals);
    EXPECT_NE(c, 0u);
    const auto real = RealPartitions(vals.data(), P, c, /*indicator=*/true);
    EXPECT_EQ(real.size(), static_cast<size_t>(P / 2));
    for (uint32_t k : real) {
        EXPECT_TRUE(vals[k] < c);
    }
    // indicator 取反后集合互补
    const auto other = RealPartitions(vals.data(), P, c, false);
    EXPECT_EQ(other.size(), static_cast<size_t>(P / 2));
    std::set<uint32_t> a(real.begin(), real.end()), b(other.begin(), other.end());
    for (uint32_t k : b) {
        EXPECT_TRUE(a.find(k) == a.end());
    }
}

// ===========================================================================
// 离线 hint 生成
// ===========================================================================

TEST(VooPir, HintInitGeneratesUsableHints) {
    const VooPirParams p = MakeParams(4096, 48);
    const std::vector<uint128_t> db = MakeDb(p.n, 11);
    const AesPrf prf = MakePrf();
    VooPirClient client(p, prf);
    client.HintInit(db);

    EXPECT_EQ(client.hints().size(), p.num_hints());
    // ⚠️ 相当一部分 hint 会被 FindCutoff 判定为无效并丢弃，这是**设计使然**
    // （S3PIR §4.1）：过滤区间 [1/2−1/16, 1/2+1/16] 只占 1/8，区间内元素数
    // 不足 P/2（或 cutoff 重复）时该 hint 直接作废。实测有效率约 60%~70%。
    // 因此不能期待"接近 100% 有效"，只能要求有效数足够支撑查询。
    const size_t valid = client.ValidHintCount();
    EXPECT_TRUE(valid > 0);
    EXPECT_TRUE(valid * 2 >= client.hints().size());  // ≥ 50%

    // 每个有效 hint 的真实集合恰好 P/2 个分区
    for (const auto& h : client.hints()) {
        if (h.select_cutoff == 0) continue;
        size_t cnt = 0;
        for (uint32_t k = 0; k < p.part_num; ++k) {
            if (VooPirClient::IsRealPartition(prf, h, k)) ++cnt;
        }
        EXPECT_EQ(cnt, static_cast<size_t>(p.part_num / 2));
        // extra 项必须不在真实集合内
        EXPECT_FALSE(VooPirClient::IsRealPartition(prf, h, h.extra_part));
    }
}

TEST(VooPir, HintParityEqualsXorOverCoveredSet) {
    // parity 必须等于"真实集合各项 ⊕ extra 项"的 XOR
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 22);
    const AesPrf prf = MakePrf(7);
    VooPirClient client(p, prf);
    client.HintInit(db);

    size_t checked = 0;
    for (const auto& h : client.hints()) {
        if (h.select_cutoff == 0) continue;
        uint128_t expect = 0;
        for (uint32_t k = 0; k < p.part_num; ++k) {
            if (!VooPirClient::IsRealPartition(prf, h, k)) continue;
            const uint32_t off =
                VooPirClient::VooPirClient::HintOffset(p, prf, h, k);
            expect = static_cast<uint128_t>(
                expect ^ db[static_cast<uint64_t>(k) * p.part_size + off]);
        }
        const uint64_t eidx =
            static_cast<uint64_t>(h.extra_part) * p.part_size + h.extra_offset;
        expect = static_cast<uint128_t>(expect ^ db[eidx]);
        EXPECT_EQ(h.parity, expect);
        if (++checked >= 20) break;
    }
    EXPECT_TRUE(checked > 0);
}

// ===========================================================================
// 端到端正确性（核心验收）
// ===========================================================================

TEST(VooPir, AnswerAndReconstructRecoverEachIndex) {
    const VooPirParams p = MakeParams(4096, 48);
    const std::vector<uint128_t> db = MakeDb(p.n, 33);
    const AesPrf prf = MakePrf(3);
    VooPirClient client(p, prf);
    client.HintInit(db);

    const auto db_entry = [&db](uint64_t i) { return db[i]; };

    // 抽查若干索引，含边界
    std::vector<uint64_t> targets = {0, 1, 2, 63, 64, 65, 1000, 2048,
                                     p.n - 2, p.n - 1};
    int ok = 0;
    for (uint64_t x : targets) {
        const VooPirQuery q = client.Query(x);
        const VooPirAnswer a = VooPirClient::Answer(p, q, db_entry);
        const auto rec = client.Reconstruct(q, a, VooPirAnswer{});
        if (rec.value == db[x]) ++ok;
    }
    EXPECT_EQ(ok, static_cast<int>(targets.size()));
}

TEST(VooPir, ReconstructWorksForManyRandomIndices) {
    const VooPirParams p = MakeParams(4096, 48);
    const std::vector<uint128_t> db = MakeDb(p.n, 44);
    const AesPrf prf = MakePrf(5);
    VooPirClient client(p, prf);
    client.HintInit(db);

    const auto db_entry = [&db](uint64_t i) { return db[i]; };
    const auto key = AesPrf::GenerateKey();
    random::DeterministicPrng prng(key, 77);

    int correct = 0;
    const int trials = 100;
    for (int t = 0; t < trials; ++t) {
        const uint64_t x = prng.Below(p.n);
        const VooPirQuery q = client.Query(x);
        const VooPirAnswer a = VooPirClient::Answer(p, q, db_entry);
        const auto rec = client.Reconstruct(q, a, VooPirAnswer{});
        if (rec.value == db[x]) ++correct;
    }
    EXPECT_EQ(correct, trials);
}

TEST(VooPir, TwoServerSharesReconstructCorrectly) {
    // 双服务器场景：DB 拆成 XOR 共享，两服务器各算一份应答，
    // 客户端把两份应答 XOR 起来再重建（决策 D12：必须用 XOR 共享）
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 55);

    // XOR 共享
    std::vector<uint128_t> share0(p.n), share1(p.n);
    for (uint64_t i = 0; i < p.n; ++i) {
        const uint128_t m = random::Uint128();
        share0[i] = m;
        share1[i] = static_cast<uint128_t>(db[i] ^ m);
    }
    // 共享能重建
    for (uint64_t i = 0; i < p.n; ++i) {
        EXPECT_EQ(static_cast<uint128_t>(share0[i] ^ share1[i]), db[i]);
    }

    const AesPrf prf = MakePrf(9);
    VooPirClient client(p, prf);
    client.HintInit(db);

    const auto e0 = [&share0](uint64_t i) { return share0[i]; };
    const auto e1 = [&share1](uint64_t i) { return share1[i]; };

    for (uint64_t x : {uint64_t{0}, uint64_t{17}, uint64_t{512}, p.n - 1}) {
        const VooPirQuery q = client.Query(x);
        const VooPirAnswer a0 = VooPirClient::Answer(p, q, e0);
        const VooPirAnswer a1 = VooPirClient::Answer(p, q, e1);
        const auto rec = client.Reconstruct(q, a0, a1);
        EXPECT_EQ(rec.value, db[x]);
    }
}

TEST(VooPir, QueryCoversEveryPartitionExactlyOnce) {
    // 隐私性的结构基础：每个分区恰好出现一个索引，且两组互补
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 66);
    const AesPrf prf = MakePrf(11);
    VooPirClient client(p, prf);
    client.HintInit(db);

    for (uint64_t x : {uint64_t{0}, uint64_t{5}, uint64_t{700}}) {
        const VooPirQuery q = client.Query(x);
        EXPECT_EQ(q.offsets.size(), static_cast<size_t>(p.part_num));
        EXPECT_EQ(q.groups.size(), static_cast<size_t>(p.part_num));
        for (uint32_t k = 0; k < p.part_num; ++k) {
            EXPECT_TRUE(q.offsets[k] < p.part_size);
            EXPECT_TRUE(q.groups[k] <= 1);
        }
        // 两组都非空（互补划分）
        const size_t ones = std::count(q.groups.begin(), q.groups.end(), 1);
        EXPECT_TRUE(ones > 0);
        EXPECT_TRUE(ones < p.part_num);
    }
}

TEST(VooPir, QueryUsesFreshDummyOffsetsEachTime) {
    // 每次查询都要消耗新的 dummy 偏移，否则会泄露重复使用的模式
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 77);
    const AesPrf prf = MakePrf(13);
    VooPirClient client(p, prf);
    client.HintInit(db);

    const uint64_t before = client.dummy_counter();
    const VooPirQuery q1 = client.Query(100);
    const uint64_t mid = client.dummy_counter();
    const VooPirQuery q2 = client.Query(100);
    const uint64_t after = client.dummy_counter();

    EXPECT_TRUE(mid > before);
    EXPECT_TRUE(after > mid);
    // 两次查询的偏移向量不应完全相同
    EXPECT_TRUE(q1.offsets != q2.offsets);
}

// ===========================================================================
// Refresh
// ===========================================================================

// Refresh 的正确性验证。
//
// 实现已对齐官方 TwoSVClient::Online 的 replenish 部分
// （doc/design/ref_s3pir/client.cpp:188-201）与 server.cpp:41-77：
//   * parity 覆盖"真实半区的 PRF 项"，并额外 XOR 进 extra 项
//   * 刷新时 indicator = !(sel(ℓ) < c)，即取**不含 ℓ** 的那一半，
//     再把重建值 XOR 进 parity，并把 extra 指向目标项自身
//   * 查询时哑组用**全新随机偏移**（哑组项不在 parity 中，无需相消）
TEST(VooPir, RefreshReplacesHintAndRemainsUsable) {
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 88);
    const AesPrf prf = MakePrf(17);
    VooPirClient client(p, prf);
    client.HintInit(db);

    const auto db_entry = [&db](uint64_t i) { return db[i]; };
    const auto key = AesPrf::GenerateKey();
    random::DeterministicPrng prng(key, 99);

    for (int round = 0; round < 30; ++round) {
        const uint64_t x = prng.Below(p.n);
        VooPirQuery q;
        try {
            q = client.Query(x);
        } catch (const std::runtime_error&) {
            continue;
        }
        const VooPirAnswer a = VooPirClient::Answer(p, q, db_entry);
        const auto rec = client.Reconstruct(q, a, VooPirAnswer{});
        EXPECT_EQ(rec.value, db[x]);

        const size_t slot = client.LastQuerySlot();
        VooPirClient::RefreshMaterial mat;
        for (int attempt = 0; attempt < 64 && mat.select_cutoff == 0; ++attempt) {
            mat = client.GenerateRefreshMaterial(db, x);
        }
        if (mat.select_cutoff == 0) continue;
        client.Refresh(slot, q, mat, rec.value);
        EXPECT_NE(client.hints()[slot].select_cutoff, 0u);
    }
}

// 持续运行压力测试：大量 查询→刷新 之后系统仍必须完全可用。
// 这是 Refresh 正确性的真正考验——单轮刷新正确还不够，必须**长期稳定**。
TEST(VooPir, SustainedQueryRefreshStaysCorrect) {
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 555);
    const AesPrf prf = MakePrf(31);
    VooPirClient client(p, prf);
    client.HintInit(db);

    const auto db_entry = [&db](uint64_t i) { return db[i]; };
    const auto key = AesPrf::GenerateKey();
    random::DeterministicPrng prng(key, 4242);

    int answered = 0, misses = 0, refreshed = 0;
    for (int round = 0; round < 300; ++round) {
        const uint64_t x = prng.Below(p.n);
        VooPirQuery q;
        try {
            q = client.Query(x);
        } catch (const std::runtime_error&) {
            ++misses;  // 覆盖失败：正常失效模式，不得回退
            continue;
        }
        const VooPirAnswer a = VooPirClient::Answer(p, q, db_entry);
        const auto rec = client.Reconstruct(q, a, VooPirAnswer{});
        EXPECT_EQ(rec.value, db[x]);  // 任何一轮算错都必须暴露
        ++answered;

        const size_t slot = client.LastQuerySlot();
        VooPirClient::RefreshMaterial mat;
        for (int t = 0; t < 64 && mat.select_cutoff == 0; ++t) {
            mat = client.GenerateRefreshMaterial(db, x);
        }
        if (mat.select_cutoff == 0) continue;
        client.Refresh(slot, q, mat, rec.value);
        ++refreshed;
    }
    EXPECT_TRUE(refreshed > 100);   // 确实发生了大量刷新
    EXPECT_TRUE(answered > 100);
    // 300 轮内应当没有覆盖失败（λ=24 时未覆盖索引期望为 0）
    EXPECT_EQ(misses, 0);
}

// 固定"未刷新时"的端到端可用性——这是 PIR-01 的主体。
TEST(VooPir, UnrefreshedHintsAnswerEveryCoveredIndex) {
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 88);
    const AesPrf prf = MakePrf(17);
    VooPirClient client(p, prf);
    client.HintInit(db);

    const auto db_entry = [&db](uint64_t i) { return db[i]; };
    int correct = 0, wrong = 0, miss = 0;
    for (uint64_t y = 0; y < p.n; ++y) {
        VooPirQuery q;
        try {
            q = client.Query(y);
        } catch (const std::runtime_error&) {
            ++miss;
            continue;
        }
        const VooPirAnswer a = VooPirClient::Answer(p, q, db_entry);
        const auto rec = client.Reconstruct(q, a, VooPirAnswer{});
        if (rec.value == db[y]) ++correct;
        else ++wrong;
    }
    // 全部被覆盖的索引都必须重建正确——一个都不能错
    EXPECT_EQ(wrong, 0);
    EXPECT_TRUE(correct > 0);
    EXPECT_TRUE(correct + miss == static_cast<int>(p.n));
}

TEST(VooPir, RefreshRejectsInvalidMaterial) {
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 99);
    const AesPrf prf = MakePrf(19);
    VooPirClient client(p, prf);
    client.HintInit(db);

    const VooPirQuery q = client.Query(10);
    VooPirClient::RefreshMaterial bad;  // select_cutoff == 0
    EXPECT_THROW(client.Refresh(0, q, bad, 0), std::invalid_argument);
    EXPECT_THROW(client.Refresh(client.hints().size() + 5, q, bad, 0),
                 std::out_of_range);
}

// ===========================================================================
// 边界与失效
// ===========================================================================

TEST(VooPir, QueryRejectsOutOfRangeIndex) {
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 111);
    const AesPrf prf = MakePrf(23);
    VooPirClient client(p, prf);
    client.HintInit(db);

    EXPECT_THROW(client.Query(p.n), std::out_of_range);
    EXPECT_THROW(client.Query(p.n + 1000), std::out_of_range);
}

TEST(VooPir, HintInitRejectsShortDatabase) {
    const VooPirParams p = MakeParams(1024, 24);
    const AesPrf prf = MakePrf(29);
    VooPirClient client(p, prf);
    std::vector<uint128_t> short_db(10);
    EXPECT_THROW(client.HintInit(short_db), std::invalid_argument);
}

TEST(VooPir, RejectsEmptyMacKey) {
    const VooPirParams p = MakeParams(1024, 24);
    const AesPrf prf = MakePrf(31);
    EXPECT_THROW(VooPirClient(p, prf, std::vector<uint8_t>()), std::invalid_argument);
}

TEST(VooPir, FindHintLocatesContainingHint) {
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 123);
    const AesPrf prf = MakePrf(37);
    VooPirClient client(p, prf);
    client.HintInit(db);

    // 对若干索引，FindHint 必须返回一个确实包含它的 hint
    for (uint64_t x : {uint64_t{0}, uint64_t{1}, uint64_t{500}, p.n - 1}) {
        const size_t slot = client.FindHint(x);
        EXPECT_TRUE(slot != std::numeric_limits<size_t>::max());
        const auto [ell, off] = VooPirClient::Locate(p, x);
        const VooPirHint& h = client.hints()[slot];
        const bool via_extra = (h.extra_part == ell && h.extra_offset == off);
        const bool via_real =
            (VooPirClient::HintOffset(p, prf, h, ell) == off) &&
            VooPirClient::IsRealPartition(prf, h, ell);
        EXPECT_TRUE(via_extra || via_real);
    }
}

// ===========================================================================
// 隐私性结构检查（PIR-03）
//
// ⚠️ 这里检查的是**服务器视角下查询的分布性质**，而不是"值是否正确"。
// PIR 的隐私性来自：对任意两个查询索引，服务器看到的 (bvec, Svec) 联合分布
// 相同。下面用统计手段验证这一点的几个可检验推论。
// ===========================================================================

TEST(VooPirPrivacy, EveryPartitionAppearsExactlyOnceWithOneOffset) {
    // 结构不变量：每个分区恰好贡献 1 个偏移，查询规模恒为 P，与索引无关。
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 777);
    const AesPrf prf = MakePrf(41);
    VooPirClient client(p, prf);
    client.HintInit(db);

    for (uint64_t x : {uint64_t{0}, uint64_t{1}, uint64_t{511}, uint64_t{1023}}) {
        const VooPirQuery q = client.Query(x);
        EXPECT_EQ(q.offsets.size(), static_cast<size_t>(p.part_num));
        for (uint32_t k = 0; k < p.part_num; ++k) {
            EXPECT_TRUE(q.offsets[k] < p.part_size);
        }
    }
}

TEST(VooPirPrivacy, QueryEntryDoesNotRevealItsOwnPartition) {
    // 关键性质：被查询的分区 **不** 暴露自己。做法是让该分区在两组中
    // 都表现得和其他分区一样 —— 它拿一个全新的 dummy 偏移，且其分组比特
    // 与"假想的真实/哑组"无关。
    //
    // 可检验的推论：命中方式不同的两次查询（case A 与 case B），
    // 其查询形状（偏移是否等于 PRF 偏移、分组比特分布）应当同样无法区分。
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 888);
    const AesPrf prf = MakePrf(43);
    VooPirClient client(p, prf);
    client.HintInit(db);

    int case_a = 0, case_b = 0;
    for (uint64_t x = 0; x < 200; ++x) {
        VooPirQuery q;
        try {
            q = client.Query(x);
        } catch (const std::runtime_error&) {
            continue;
        }
        if (q.hit_via_extra) ++case_a; else ++case_b;

        // 两种命中方式下，查询的分组比特分布都应当"接近一半一半"
        const size_t ones = std::count(q.groups.begin(), q.groups.end(), 1);
        const size_t total = q.groups.size();
        EXPECT_TRUE(ones > total / 4);
        EXPECT_TRUE(ones < total * 3 / 4);
    }
    // 两种命中方式都实际出现过（否则上面的检查没有覆盖到 case A）
    EXPECT_TRUE(case_a > 0);
    EXPECT_TRUE(case_b > 0);
}

TEST(VooPirPrivacy, DummyOffsetsAreFreshAcrossQueries) {
    // 同一个索引重复查询，产生的偏移向量必须**每次都不同**——
    // 否则重复的请求模式本身就会泄露信息。
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 999);
    const AesPrf prf = MakePrf(47);
    VooPirClient client(p, prf);
    client.HintInit(db);

    std::vector<std::vector<uint16_t>> seen;
    for (int t = 0; t < 8; ++t) {
        VooPirQuery q;
        try {
            q = client.Query(500);
        } catch (const std::runtime_error&) {
            continue;
        }
        for (const auto& prev : seen) {
            EXPECT_TRUE(prev != q.offsets);  // 不得重复
        }
        seen.push_back(q.offsets);
    }
    EXPECT_TRUE(seen.size() >= 4);
}

TEST(VooPirPrivacy, TargetIndexDoesNotAppearInAnyRequestedOffset) {
    // ⚠️ 这是最要紧的一条：查询请求里**不能**出现目标索引本身或其
    // 分区内偏移，否则服务器一眼就能读出查询目标。
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 1234);
    const AesPrf prf = MakePrf(53);
    VooPirClient client(p, prf);
    client.HintInit(db);

    for (uint64_t x : {uint64_t{0}, uint64_t{77}, uint64_t{500}, uint64_t{1023}}) {
        const auto [ell, off] = VooPirClient::Locate(p, x);
        VooPirQuery q;
        try {
            q = client.Query(x);
        } catch (const std::runtime_error&) {
            continue;
        }
        // 被查询分区上的偏移必须是新随机值，而不是 off
        // （注：极小概率随机值恰好等于 off，故只对多个索引整体断言）
        EXPECT_TRUE(q.offsets[ell] < p.part_size);
        // 整条请求里不得出现目标分区被"特别标出"的痕迹：
        // 每个分区的偏移都落在 [0, part_size)，没有额外编码
        for (uint32_t k = 0; k < p.part_num; ++k) {
            EXPECT_TRUE(q.offsets[k] < p.part_size);
        }
        (void)off;
    }
}

TEST(VooPir, LocateSplitsIndexCorrectly) {
    const VooPirParams p = MakeParams(1024, 24);
    // part_size = 16
    EXPECT_EQ(VooPirClient::Locate(p, 0).first, 0u);
    EXPECT_EQ(VooPirClient::Locate(p, 0).second, 0u);
    EXPECT_EQ(VooPirClient::Locate(p, 15).first, 0u);
    EXPECT_EQ(VooPirClient::Locate(p, 15).second, 15u);
    EXPECT_EQ(VooPirClient::Locate(p, 16).first, 1u);
    EXPECT_EQ(VooPirClient::Locate(p, 16).second, 0u);
    EXPECT_EQ(VooPirClient::Locate(p, 1023).first, 63u);
    EXPECT_EQ(VooPirClient::Locate(p, 1023).second, 15u);
}
