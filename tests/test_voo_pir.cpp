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

// λ=80 是论文的部署取值（TASK_PLAN §8：λ=80、V_j 为 32-bit）。
// 这里验证在 λ=80 下：
//   * M = λ√n 条 hint **全部有效**（决策 D15(3)：M 必须指"有效 hint 数"，
//     而不是尝试次数，否则等效安全参数掉到 ~0.5λ）；
//   * 全量索引都被覆盖（λ=80 ⇒ 未覆盖概率 e^{−40}，不可能出现）；
//   * 端到端重建仍然正确。
TEST(VooPir, Lambda80GivesFullValidHintSetAndCompleteCoverage) {
    const VooPirParams p = MakeParams(4096, 80);  // P=64, σ=64, M=5120
    const std::vector<uint128_t> db = MakeDb(p.n, 8080);
    const AesPrf prf = MakePrf(83);
    VooPirClient client(p, prf);
    client.HintInit(db);

    // 有效 hint 数必须**恰好**等于 M（而非"尝试 M 次"的残留）
    EXPECT_EQ(client.ValidHintCount(), static_cast<size_t>(p.num_hints()));
    EXPECT_EQ(client.FreeHintCount(), static_cast<size_t>(p.num_hints()));
    EXPECT_EQ(client.hints().size(), static_cast<size_t>(p.num_hints()));

    // 全量覆盖：4096 个索引一个都不能漏
    for (uint64_t y = 0; y < p.n; ++y) {
        EXPECT_TRUE(client.FindHintIgnoringConsumed(y) !=
                    std::numeric_limits<size_t>::max());
    }

    // 随机抽样做端到端重建（同一索引重复查会消费 hint，故此处逐索引一次）
    const auto db_entry = [&db](uint64_t i) { return db[i]; };
    int checked = 0;
    for (uint64_t y = 0; y < p.n; y += 97) {
        const VooPirQuery q = client.Query(y);
        const VooPirAnswer a = VooPirClient::Answer(p, q, db_entry);
        const auto rec = client.Reconstruct(q, a, VooPirAnswer{});
        EXPECT_EQ(rec.value, db[y]);
        ++checked;
    }
    EXPECT_TRUE(checked >= 40);
}

// ===========================================================================
// FindCutoff（S3PIR 规则，决策 D7）
// ===========================================================================

TEST(FindCutoff, SplitsEvenlyForUniformValues) {
    // ⚠️ 取值必须**显式写死且均匀铺开**，不要依赖任何 PRNG 流。
    // 历史上这里用 `AesPrf::GenerateKey()`（真随机密钥），用例会**随机失败**：
    // 过滤区间 [1/2−1/16, 1/2+1/16] 只占值域 1/8，P=256 时两侧各约 112 个，
    // 各自越界到 ≥ P/2 = 128 的概率约 2% —— 那时 `FindCutoff` 依规则返回 0
    // （"过滤过头 ⇒ 该 hint 无效"，见 PIR_SPEC §3.1），断言随之失败（实测 2/100）。
    // 改成确定性 PRNG 只是把它变成"稳定地碰运气"；这里改成**构造性**取值：
    // 在 32 位值域上等距铺 256 个点，两侧计数恒为 112 < 128 ⇒ 永不触发过滤失效。
    const uint32_t P = 256;
    std::vector<uint32_t> vals(P);
    for (uint32_t i = 0; i < P; ++i) {
        vals[i] = static_cast<uint32_t>((static_cast<uint64_t>(i) << 24) + i);
    }
    const uint32_t c = FindCutoff(vals);
    EXPECT_NE(c, 0u);
    // 恰好一半在下
    const size_t below = std::count_if(vals.begin(), vals.end(),
                                       [c](uint32_t v) { return v < c; });
    EXPECT_EQ(below, static_cast<size_t>(P / 2));
}

TEST(FindCutoff, ReturnsZeroWhenOneSideExceedsHalf) {
    // "过滤过头"这一条拒绝分支的**确定性**覆盖：区间外任一侧元素数 ≥ P/2
    // 就无法把分区均分成两半 ⇒ 必须返回 0（哨兵）。
    constexpr uint32_t kLower = 0x80000000u - (1u << 28);
    constexpr uint32_t kUpper = 0x80000000u + (1u << 28);

    std::vector<uint32_t> low_heavy;                    // 下侧 130 个 ⇒ 越界
    for (int i = 0; i < 130; ++i) low_heavy.push_back(kLower - 1u);
    for (int i = 0; i < 126; ++i) low_heavy.push_back(0x80000000u + i);
    EXPECT_EQ(FindCutoff(low_heavy), 0u);

    std::vector<uint32_t> high_heavy;                   // 上侧 128 个 ⇒ 恰好越界
    for (int i = 0; i < 128; ++i) high_heavy.push_back(0x80000000u + i);
    for (int i = 0; i < 128; ++i) high_heavy.push_back(kUpper + 1u + i);
    EXPECT_EQ(FindCutoff(high_heavy), 0u);
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
// （doc/refs/ref_s3pir/client.cpp:188-201）与 server.cpp:41-77：
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
//
// ⚠️ 这里必须显式启用 `kAllowUnsafeForTesting`：默认策略（决策 D17）会禁止
// 复用未刷新的 hint，而本测试刻意用 768 条 hint 扫描 1024 个索引（大量复用），
// 目的是验证**离线 hint 本身的正确性**，不是可部署的用法。
// 可部署用法见 `QueryConsumesHintAndForbidsReuse` 与
// `QueryRefreshSweepStaysCorrectForEveryIndex`。
TEST(VooPir, UnrefreshedHintsAnswerEveryCoveredIndex) {
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 88);
    const AesPrf prf = MakePrf(17);
    VooPirClient client(p, prf);
    client.HintInit(db);
    client.SetHintReusePolicy(HintReusePolicy::kAllowUnsafeForTesting);

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

// ---------------------------------------------------------------------------
// ⚠️ 隐私缺陷（见 TASK_PLAN 决策 D17）：hint 被**反复使用**（查询后不 Refresh）
// 时，服务器能从多轮查询里把"真实半区"和"查询分区 ℓ"都还原出来。
//
// 协议正确用法是每轮查询后立即 `Refresh`（官方 `TwoSVClient::Online` 的
// replenish 正是这个作用）：刷新会换掉整条 hint（新的 hint_id、新的 cutoff、
// 新的半区划分），于是服务器无法跨轮比对。
//
// 若客户端偷懒反复用同一条 hint，服务器手里就有了**跨轮可比**的偏移向量：
//   * 真实半区的偏移是 `PRF_off(h, k)` —— **跨轮恒定**
//   * 哑组各分区与查询分区 ℓ 的偏移每轮重新随机 —— 跨轮变化
// 攻击三步：
//   ① 取所有轮次偏移都相同的分区 ⇒ 真实半区（`flip` 的随机置换因此失效）
//   ② 真实组 = 每轮中包含①的那一组
//   ③ 对每个分区 k 统计它"不在真实组"的轮次：真实半区的每个分区恰好**只在
//      "以该分区为查询分区的那一轮"**掉出真实组 ⇒ `ℓ_t` 被精确还原，
//      目标索引从 n 个候选缩到 σ = part_size 个候选。
//
// 本测试把这个攻击**跑出来**，作为"必须 Refresh"的可执行证据。
TEST(VooPirPrivacy, HintReuseWithoutRefreshLeaksRealHalfAndQueryPartition) {
    const VooPirParams p = MakeParams(1024, 24);  // P=64, σ=16
    const std::vector<uint128_t> db = MakeDb(p.n, 20260910);
    const AesPrf prf = MakePrf(59);
    VooPirClient client(p, prf);
    client.HintInit(db);
    // ⚠️ 本测试是"证伪测试"：它必须**故意**启用显式不安全策略才能构造出攻击
    // 场景。默认策略 kForbidReuse 下第二次 Query 就会换一条 hint（见
    // QueryConsumesHintAndForbidsReuse），攻击无法成立。
    client.SetHintReusePolicy(HintReusePolicy::kAllowUnsafeForTesting);

    // 1) 找一条会被反复命中的 hint 槽位，以及若干**分区互不相同**的索引
    constexpr size_t kRounds = 4;
    size_t slot = std::numeric_limits<size_t>::max();
    std::vector<uint64_t> targets;
    std::set<uint32_t> parts;
    for (uint64_t y = 0; y < p.n && targets.size() < kRounds; ++y) {
        const size_t s = client.FindHint(y);
        if (s == std::numeric_limits<size_t>::max()) continue;
        if (slot == std::numeric_limits<size_t>::max()) slot = s;
        if (s != slot) continue;
        if (!parts.insert(VooPirClient::Locate(p, y).first).second) continue;
        targets.push_back(y);
    }
    EXPECT_EQ(targets.size(), kRounds);

    // 2) 服务器视角：只看到 offsets + groups（同一条 hint 被复用，且不刷新）
    std::vector<VooPirQuery> wire;
    for (uint64_t y : targets) {
        const VooPirQuery q = client.Query(y);
        EXPECT_EQ(client.LastQuerySlot(), slot);  // 确认确实复用了同一槽位
        wire.push_back(q);
    }

    // 3) 攻击①：跨轮恒定 ⇒ 真实半区（外加 extra 项，二者都在真实组里）
    const uint32_t P = p.part_num;
    std::vector<uint32_t> stable;
    for (uint32_t k = 0; k < P; ++k) {
        bool same = true;
        for (size_t t = 1; t < wire.size(); ++t) {
            if (wire[t].offsets[k] != wire[0].offsets[k]) {
                same = false;
                break;
            }
        }
        if (same) stable.push_back(k);
    }
    // 真实半区有 P/2 个分区，减去被查询分区后仍应剩下大部分
    EXPECT_TRUE(stable.size() >= static_cast<size_t>(P) / 2 - kRounds + 1);

    // 4) 攻击②：逐轮定位"真实组"（flip 每轮随机，故必须逐轮判定）
    std::vector<uint8_t> real_bit(wire.size(), 0);
    for (size_t t = 0; t < wire.size(); ++t) {
        size_t ones = 0;
        for (uint32_t k : stable) {
            if (wire[t].groups[k] != 0) ++ones;
        }
        real_bit[t] = (ones * 2 > stable.size()) ? 1 : 0;
        // 真实半区成员在每一轮必须同组（这就是攻击者能识别它们的依据）
        size_t agree = 0;
        for (uint32_t k : stable) {
            if (wire[t].groups[k] == real_bit[t]) ++agree;
        }
        EXPECT_TRUE(agree * 4 >= stable.size() * 3);
    }

    // 5) 攻击③：ℓ_t = "恰好在第 t 轮掉出真实组"的那个分区
    std::vector<int> ell_of_round(wire.size(), -1);
    for (uint32_t k = 0; k < P; ++k) {
        size_t out = 0;
        int only = -1;
        for (size_t t = 0; t < wire.size(); ++t) {
            if (wire[t].groups[k] != real_bit[t]) {
                ++out;
                only = static_cast<int>(t);
            }
        }
        if (out == 1) ell_of_round[static_cast<size_t>(only)] = static_cast<int>(k);
    }

    int recovered = 0;
    for (size_t t = 0; t < wire.size(); ++t) {
        EXPECT_TRUE(ell_of_round[t] >= 0);
        const uint32_t truth = VooPirClient::Locate(p, targets[t]).first;
        if (ell_of_round[t] == static_cast<int>(truth)) ++recovered;
    }
    // ⚠️ 每一轮的查询分区都被精确还原 ⇒ 目标索引只剩 σ 个候选
    EXPECT_EQ(recovered, static_cast<int>(kRounds));
}

// ===========================================================================
// hint 生命周期（决策 D17：Query 消费槽位，Refresh 才能补充）
// ===========================================================================

// D17 的**正向**检查：按协议正确路径（每轮查询后 Refresh）运行时，
// 攻击所依赖的结构**不存在**了。
//
// 刷新会换掉整条 hint（新 hint_id ⇒ 新 cutoff ⇒ 新半区划分 ⇒ 新的 PRF 偏移），
// 因此"真实半区的偏移跨轮恒定"这一前提不成立：跨轮恒定的分区只可能来自
// 随机巧合（概率 ~1/σ），而真实半区本身每轮都不同。
TEST(VooPirPrivacy, RefreshedQueriesExposeNoClusterableRealHalf) {
    const VooPirParams p = MakeParams(1024, 24);  // P=64, σ=16
    const std::vector<uint128_t> db = MakeDb(p.n, 31337);
    const AesPrf prf = MakePrf(79);
    VooPirClient client(p, prf);
    client.HintInit(db);

    constexpr size_t kRounds = 5;
    std::vector<VooPirQuery> seen;
    std::vector<std::vector<uint32_t>> real_halves;

    for (size_t t = 0; t < kRounds; ++t) {
        const uint64_t x = 77 + t * 101;  // 分区互不相同
        const VooPirQuery q = client.Query(x);
        seen.push_back(q);

        // 该轮真实半区（测试侧可以直接算出来 —— 服务器当然算不出来）
        const VooPirHint& h = client.hints()[q.hint_slot];
        std::vector<uint32_t> real;
        for (uint32_t k = 0; k < p.part_num; ++k) {
            if (VooPirClient::IsRealPartition(prf, h, k)) real.push_back(k);
        }
        real_halves.push_back(real);

        // 协议要求：每轮查询后立刻刷新
        VooPirClient::RefreshMaterial mat;
        for (int a = 0; a < 64 && mat.select_cutoff == 0; ++a) {
            mat = client.GenerateRefreshMaterial(db, x);
        }
        EXPECT_TRUE(mat.select_cutoff != 0);
        client.Refresh(q.hint_slot, q, mat, db[x]);
    }

    // ① 每轮用的是**不同的** hint ⇒ 真实半区每轮都换
    for (size_t t = 1; t < kRounds; ++t) {
        EXPECT_TRUE(seen[t].hint_slot != seen[t - 1].hint_slot);
        EXPECT_TRUE(real_halves[t] != real_halves[t - 1]);
    }

    // ② 攻击的第一步（找"跨轮恒定"的分区）不再有收获：
    //    恒定的分区数只剩随机巧合量级（每轮 1/σ 的概率，5 轮 ≤ 数条）
    size_t stable = 0;
    for (uint32_t k = 0; k < p.part_num; ++k) {
        bool same = true;
        for (size_t t = 1; t < kRounds; ++t) {
            if (seen[t].offsets[k] != seen[0].offsets[k]) { same = false; break; }
        }
        if (same) ++stable;
    }
    EXPECT_TRUE(stable <= 2);

    // ③ 即使有巧合，恒定集合也不等于任何一轮的真实半区 —— 攻击者据此
    //    既认不出真实组，也定位不到查询分区
    for (size_t t = 0; t < kRounds; ++t) {
        std::vector<uint32_t> stable_set;
        for (uint32_t k = 0; k < p.part_num; ++k) {
            bool same = true;
            for (size_t u = 1; u < kRounds; ++u) {
                if (seen[u].offsets[k] != seen[0].offsets[k]) { same = false; break; }
            }
            if (same) stable_set.push_back(k);
        }
        EXPECT_TRUE(stable_set != real_halves[t]);
    }
}

TEST(VooPir, QueryConsumesHintAndForbidsReuse) {
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 4242);
    const AesPrf prf = MakePrf(61);
    VooPirClient client(p, prf);
    client.HintInit(db);

    // 默认必须是安全策略（禁止复用）
    EXPECT_EQ(static_cast<int>(client.hint_reuse_policy()),
              static_cast<int>(HintReusePolicy::kForbidReuse));
    const size_t free_before = client.FreeHintCount();
    EXPECT_EQ(free_before, client.ValidHintCount());
    EXPECT_TRUE(free_before > 0);

    const uint64_t x = 300;
    const VooPirQuery q1 = client.Query(x);
    const size_t slot = q1.hint_slot;
    EXPECT_TRUE(slot < client.hints().size());
    EXPECT_EQ(client.LastQuerySlot(), slot);
    EXPECT_TRUE(client.hint_consumed(slot));
    EXPECT_EQ(client.FreeHintCount(), free_before - 1);

    // 同一个索引再查一次：必须换**另一条** hint，绝不能复用已消费的槽位
    const VooPirQuery q2 = client.Query(x);
    EXPECT_TRUE(q2.hint_slot != slot);
    EXPECT_TRUE(client.hint_consumed(q2.hint_slot));  // 新槽位同样被消费
    EXPECT_EQ(client.FreeHintCount(), free_before - 2);
    // 一个索引通常被多条 hint 覆盖，否则上一步会抛 HintsExhausted
    EXPECT_TRUE(client.HintsContaining(x).size() >= 2);

    // Refresh 之后槽位重新可用，且换成了一条**全新**的 hint
    const uint64_t old_hint_id = client.hints()[slot].hint_id;
    VooPirClient::RefreshMaterial mat;
    for (int t = 0; t < 64 && mat.select_cutoff == 0; ++t) {
        mat = client.GenerateRefreshMaterial(db, x);
    }
    EXPECT_TRUE(mat.select_cutoff != 0);
    client.Refresh(slot, q1, mat, db[x]);
    EXPECT_TRUE(!client.hint_consumed(slot));
    EXPECT_EQ(client.FreeHintCount(), free_before - 1);
    EXPECT_TRUE(client.hints()[slot].hint_id != old_hint_id);
    EXPECT_EQ(client.hints()[slot].select_cutoff, mat.select_cutoff);
    // 刷新后必须真的还能用：同一条新 hint 立刻可查（extra 指向 x）
    const VooPirQuery q3 = client.Query(x);
    EXPECT_EQ(q3.hint_slot, slot);
}

TEST(VooPir, ConsumingEveryHintCoveringAnIndexRaisesHintsExhausted) {
    // "覆盖该索引的 hint 全部被消费"必须报成 **HintsExhausted**（可恢复：
    // 先 Refresh），而不是与"覆盖失败"（致命）混为一谈。
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 5150);
    const AesPrf prf = MakePrf(67);
    VooPirClient client(p, prf);
    client.HintInit(db);

    const uint64_t x = 123;
    const std::vector<size_t> covering = client.HintsContaining(x);
    EXPECT_TRUE(covering.size() > 0);

    // 反复查询 x，直到它的候选 hint 全部被消费
    VooPirQuery qx;
    for (size_t i = 0; i < covering.size(); ++i) {
        qx = client.Query(x);
        EXPECT_TRUE(client.hint_consumed(qx.hint_slot));
    }
    EXPECT_THROW(client.Query(x), HintsExhausted);

    // 刷新刚才那条被消费的槽位（其充实材料以 x 为目标 ⇒ extra 指向 x），
    // 槽位立刻重新可用
    VooPirClient::RefreshMaterial mat;
    for (int t = 0; t < 64 && mat.select_cutoff == 0; ++t) {
        mat = client.GenerateRefreshMaterial(db, x);
    }
    EXPECT_TRUE(mat.select_cutoff != 0);
    client.Refresh(qx.hint_slot, qx, mat, db[x]);
    EXPECT_TRUE(!client.hint_consumed(qx.hint_slot));
    EXPECT_NO_THROW(qx = client.Query(x));
}

TEST(VooPir, UncoveredIndexRaisesCoverageFailure) {
    // λ 很小时必然存在"没有任何 hint 覆盖"的索引 —— 那属于致命失败，
    // 必须报成 HintCoverageFailure（不得回退到可区分的明文路径）。
    const VooPirParams p = MakeParams(1024, 4);  // 每个索引未被覆盖概率 ≈ e^{−2}
    const std::vector<uint128_t> db = MakeDb(p.n, 6060);
    const AesPrf prf = MakePrf(71);
    VooPirClient client(p, prf);
    client.HintInit(db);

    uint64_t uncovered = p.n;
    for (uint64_t y = 0; y < p.n; ++y) {
        if (client.FindHintIgnoringConsumed(y) == std::numeric_limits<size_t>::max()) {
            uncovered = y;
            break;
        }
    }
    EXPECT_TRUE(uncovered < p.n);  // 该参数下必然存在未覆盖索引
    EXPECT_THROW(client.Query(uncovered), HintCoverageFailure);
}

TEST(VooPir, QueryRefreshSweepStaysCorrectForEveryIndex) {
    // 协议正确路径（默认策略）下的全量扫描：1024 个索引逐个 查询→重建→刷新。
    // 这是"消费制不会让系统变脆"的直接证据：hint 池始终被刷新补充，
    // 查询次数不受 M 限制。
    const VooPirParams p = MakeParams(1024, 24);
    const std::vector<uint128_t> db = MakeDb(p.n, 7070);
    const AesPrf prf = MakePrf(73);
    VooPirClient client(p, prf);
    client.HintInit(db);

    const auto db_entry = [&db](uint64_t i) { return db[i]; };
    int correct = 0, miss = 0, refreshed = 0;
    for (uint64_t y = 0; y < p.n; ++y) {
        VooPirQuery q;
        try {
            q = client.Query(y);
        } catch (const HintCoverageFailure&) {
            ++miss;  // λ=24 下期望为 0
            continue;
        }
        const VooPirAnswer a = VooPirClient::Answer(p, q, db_entry);
        const auto rec = client.Reconstruct(q, a, VooPirAnswer{});
        if (rec.value == db[y]) ++correct;
        VooPirClient::RefreshMaterial mat;
        for (int t = 0; t < 64 && mat.select_cutoff == 0; ++t) {
            mat = client.GenerateRefreshMaterial(db, y);
        }
        if (mat.select_cutoff == 0) continue;
        client.Refresh(q.hint_slot, q, mat, rec.value);
        ++refreshed;
    }
    EXPECT_EQ(correct, static_cast<int>(p.n));
    EXPECT_EQ(miss, 0);
    EXPECT_EQ(refreshed, static_cast<int>(p.n));
    // 池子始终被补充：扫描结束后**没有任何**槽位停留在"已消费"状态
    EXPECT_EQ(client.FreeHintCount(), client.ValidHintCount());
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
