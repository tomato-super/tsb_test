// Plinko（PIR-04）测试 —— 按 doc/design/PLINKO_SPEC.md §7 的 1–8 条落地。
//
// 参数与预算（决策 D22-1）：
//   * `HintInit ≈ n × IF⁻¹ ≈ 1.0 ms × n`，**与 w 无关** ⇒ 常规用例取 n ≤ 2¹²，
//     并给它们传更小的 `prp_epsilon`（正确性不依赖 ε，只有 PRP 的可区分优势依赖它）；
//   * 用例名带 `Acceptance` 的两个用例跑 **默认 ε = 1e-10**（n = 2¹² 与 n = 2¹¹），
//     接受它们各跑几秒；其余用例用 ε = 1e-4。
//   * 所有随机性都来自**显式种子**的确定性源（铁律 D6 / D23）。

#include "pir/plinko.hpp"

#include "core/random.hpp"
#include "test_framework.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <numeric>
#include <stdexcept>
#include <vector>

using namespace tsb;

namespace {

// 固定密钥 ⇒ 数据库跨进程/跨次运行逐位可复现（D6；不能依赖 CSPRNG 的 AesPrf::GenerateKey）
constexpr std::array<uint8_t, kAesKeyBytes> kDbKey = {
    't', 's', 'b', ':', 'p', 'l', 'i', 'n', 'k', 'o', '/', 'd', 'b', '/', '0', '1'};

std::vector<uint128_t> MakeDb(uint64_t n, uint64_t seed) {
    random::DeterministicPrng prng(kDbKey, seed);
    std::vector<uint128_t> db(static_cast<size_t>(n));
    for (uint128_t& v : db) v = prng.Next();
    return db;
}

PlinkoParams MakeParams(uint64_t n, uint64_t w, uint32_t lambda = 80, double eps = 1e-4) {
    PlinkoParams p;
    p.n = n;
    p.w = w;
    p.lambda = lambda;
    p.prp_epsilon = eps;
    p.Validate();
    return p;
}

// 测试用的"快"几何：n = 1024, w = 32 ⇒ c = 32, λw = 2560, q = 1280, H = 3840
PlinkoParams FastParams(uint32_t lambda = 80) { return MakeParams(1024, 32, lambda, 1e-4); }

// ---- 独立地按定义重算 parity（不复用实现内部的任何中间量）----
uint128_t XorOverSubset(const PlinkoClient& cl, const std::vector<uint128_t>& db, size_t slot,
                        bool in_subset) {
    const PlinkoParams& p = cl.params();
    uint128_t acc = 0;
    for (uint64_t b = 0; b < p.block_count(); ++b) {
        if (cl.slot_contains_block(slot, b) != in_subset) continue;
        acc = static_cast<uint128_t>(acc ^ db[static_cast<size_t>(b * p.w + cl.iprf_offset(b, slot))]);
    }
    return acc;
}

uint128_t XorCovered(const PlinkoClient& cl, const std::vector<uint128_t>& db, size_t slot) {
    uint128_t acc = 0;
    for (uint64_t idx : cl.covered_indices(slot)) acc = static_cast<uint128_t>(acc ^ db[static_cast<size_t>(idx)]);
    return acc;
}

size_t PopCountSlot(const PlinkoClient& cl, size_t slot) {
    size_t n = 0;
    for (uint64_t b = 0; b < cl.params().block_count(); ++b) {
        if (cl.slot_contains_block(slot, b)) ++n;
    }
    return n;
}

using Clock = std::chrono::steady_clock;
double SecsSince(const Clock::time_point& t0) {
    return std::chrono::duration<double>(Clock::now() - t0).count();
}

uint64_t CountOnes(const std::vector<uint8_t>& v) {
    return static_cast<uint64_t>(std::count(v.begin(), v.end(), static_cast<uint8_t>(1)));
}

}  // namespace

// ===========================================================================
// 参数几何（PLINKO_SPEC §1 / §5.3 / §5.5；勘误 ④）
// ===========================================================================

TEST(PlinkoParams, DerivePicksPowerOfTwoBlockSizeAndEvenBlockCount) {
    for (uint64_t n : {uint64_t{256}, uint64_t{1024}, uint64_t{4096}, uint64_t{16384}}) {
        const PlinkoParams p = PlinkoParams::Derive(n, 80);
        EXPECT_EQ(p.n, n);
        // w = 2^⌈log₂√n⌉ 且必须是 2 的幂（D21）
        uint64_t expected_w = 1;
        while (expected_w * expected_w < n) expected_w *= 2;
        EXPECT_EQ(p.w, expected_w);
        EXPECT_EQ(p.block_count() * p.w, n);              // n = c·w
        EXPECT_EQ(p.block_count() % 2, uint64_t{0});       // c 必须偶数（§5.5）
        EXPECT_EQ(p.main_hints(), uint64_t{80} * p.w);     // M = λw
        EXPECT_EQ(p.backup_hints(), p.main_hints() / 2);   // q = λw/2（本项目口径）
        EXPECT_EQ(p.hint_slots(), p.main_hints() + p.backup_hints());  // H = λw+q
        EXPECT_EQ(p.main_hint_blocks(), p.block_count() / 2 + 1);      // c/2+1（区块数！勘误 ④）
        EXPECT_EQ(p.backup_hint_blocks(), p.block_count() / 2);        // c/2
        // 交给 core/iprf 的口径：domain = H、range = w、ε 透传
        EXPECT_EQ(p.iprf().domain, p.hint_slots());
        EXPECT_EQ(p.iprf().range, p.w);
    }
}

TEST(PlinkoParams, ValidateRejectsIllegalGeometry) {
    // w 非 2 的幂（D21：iPRF 的值域必须是 2 的幂）
    EXPECT_THROW(MakeParams(1024, 48, 80, 1e-4), std::invalid_argument);
    // c 为奇数（§5.5：c/2+1 个区块去掉 α 后必须与补集同为 c/2 个）
    EXPECT_THROW(MakeParams(6, 2, 8, 1e-4), std::invalid_argument);
    // 退化几何 n = w（c = 1）
    EXPECT_THROW(MakeParams(8, 8, 4, 1e-4), std::invalid_argument);
    // n 不是 w 的整数倍
    EXPECT_THROW(MakeParams(100, 32, 4, 1e-4), std::invalid_argument);
    // λ = 0
    EXPECT_THROW(MakeParams(1024, 32, 0, 1e-4), std::invalid_argument);
    // ε 越界
    EXPECT_THROW(MakeParams(1024, 32, 80, 0.0), std::invalid_argument);
    EXPECT_THROW(MakeParams(1024, 32, 80, 1.0), std::invalid_argument);
    // H = λw+q 超过 iPRF 的定义域上界 2³²
    EXPECT_THROW(MakeParams(static_cast<uint64_t>(1) << 27, static_cast<uint64_t>(1) << 26, 80, 1e-4),
                 std::invalid_argument);

    // Derive 对不合规的 n 抛出**可读**的补齐建议
    bool threw = false;
    try {
        (void)PlinkoParams::Derive(1000, 80);
    } catch (const std::invalid_argument& e) {
        threw = true;
        const std::string msg = e.what();
        EXPECT_TRUE(msg.find("补齐") != std::string::npos);
    }
    EXPECT_TRUE(threw);
}

// ===========================================================================
// 离线阶段：HintInit（PLINKO_SPEC §3.1，只用到 IF⁻¹）
// ===========================================================================

TEST(Plinko, HintInitBuildsLambdaWRegularHintsAndQBackups) {
    const PlinkoParams p = FastParams();
    const std::vector<uint128_t> db = MakeDb(p.n, 11);
    PlinkoClient cl(p, /*seed=*/1);
    cl.HintInit(db);

    EXPECT_EQ(cl.hint_slot_count(), static_cast<size_t>(p.hint_slots()));
    EXPECT_EQ(cl.hints_in_table(), static_cast<size_t>(p.main_hints()));  // H 中恰有 λw 条
    EXPECT_EQ(cl.regular_hint_count(), static_cast<size_t>(p.main_hints()));
    EXPECT_EQ(cl.promoted_hint_count(), size_t{0});
    EXPECT_EQ(cl.backup_remaining(), static_cast<size_t>(p.backup_hints()));
    EXPECT_FALSE(cl.backups_low(0));

    // 槽位类型：0..λw-1 = 常规；λw..H-1 = 备份（在 T 里，**不在 H 中**，不可被查询选中）
    for (uint64_t j = 0; j < p.hint_slots(); j += 7) {
        const PlinkoSlotKind k = cl.slot_kind(static_cast<size_t>(j));
        if (j < p.main_hints()) {
            EXPECT_TRUE(k == PlinkoSlotKind::kRegular);
        } else {
            EXPECT_TRUE(k == PlinkoSlotKind::kBackup);
        }
    }

    // 子集规模：常规 hint 恒为 c/2+1、备份 hint 恒为 c/2（组合结构上的"平衡"）
    for (uint64_t j = 0; j < p.main_hints(); j += 13) {
        EXPECT_EQ(PopCountSlot(cl, static_cast<size_t>(j)), static_cast<size_t>(p.main_hint_blocks()));
    }
    for (uint64_t j = p.main_hints(); j < p.hint_slots(); j += 11) {
        EXPECT_EQ(PopCountSlot(cl, static_cast<size_t>(j)), static_cast<size_t>(p.backup_hint_blocks()));
    }

    // parity 必须等于"按定义重算"的值（这是 HintInit 正确性的实质）
    for (uint64_t j = 0; j < 120; ++j) {
        const size_t s = static_cast<size_t>(j);
        EXPECT_EQ(cl.slot(s).parity, XorOverSubset(cl, db, s, true));
    }
    for (uint64_t j = p.main_hints(); j < p.main_hints() + 60; ++j) {
        const size_t s = static_cast<size_t>(j);
        // 备份：ℓ_j 是 B_j 上的 parity、r_j 是**补集**上的 parity（论文 §5.2）
        EXPECT_EQ(cl.slot(s).backup_parity_in, XorOverSubset(cl, db, s, true));
        EXPECT_EQ(cl.slot(s).backup_parity_out, XorOverSubset(cl, db, s, false));
    }

    EXPECT_EQ(cl.query_count(), uint64_t{0});
    EXPECT_EQ(cl.answered_count(), uint64_t{0});
}

TEST(Plinko, DeployedClientUsesCsprngAndWorksEndToEnd) {
    // 部署路径的冒烟测试（区块密钥与随机流都取自 CSPRNG）。小几何以省时间。
    const PlinkoParams p = MakeParams(256, 16, 24, 1e-3);
    const std::vector<uint128_t> db = MakeDb(p.n, 181);
    PlinkoClient cl = PlinkoClient::Deployed(p);
    cl.HintInit(db);
    for (uint64_t x : {uint64_t{0}, uint64_t{17}, uint64_t{200}, uint64_t{255}}) {
        auto [q, h] = cl.QueryGen(x);
        EXPECT_EQ(cl.ClientRecon(h, PlinkoClient::ServerResp(q, db)), db[static_cast<size_t>(x)]);
    }
    // 两次 Deployed 构造必须给出不同的密钥/随机流（否则"随机"名不副实）
    PlinkoClient c2 = PlinkoClient::Deployed(p);
    c2.HintInit(db);
    EXPECT_NE(cl.slot(0).parity, c2.slot(0).parity);
}

TEST(Plinko, HintInitRejectsShortDatabaseAndWrongKeyCount) {
    const PlinkoParams p = FastParams();
    PlinkoClient cl(p, 2);
    EXPECT_THROW(cl.HintInit(MakeDb(p.n - 1, 3)), std::invalid_argument);
    // 区块密钥必须是 c 把（勘误 ①/⑤：每区块一把）
    EXPECT_THROW(cl.HintInitWithKeys(MakeDb(p.n, 3), Iprf::GenBlockKeys(2, false, 0)),
                 std::invalid_argument);
    // 未 HintInit 时查询类接口必须报错，而不是给出错误值
    EXPECT_THROW(cl.GetHint(0, 0), std::logic_error);
    EXPECT_THROW(cl.QueryGen(0), std::logic_error);
}

// ===========================================================================
// 算法 2：GetHint 的"候选检查"（PLINKO_SPEC §7.3 —— 防"漏检 α ∈ P_j"的回归用例）
// ===========================================================================

TEST(Plinko, GetHintCandidatesAreOnlyHalfContainedRegression) {
    const PlinkoParams p = FastParams();
    const std::vector<uint128_t> db = MakeDb(p.n, 21);
    PlinkoClient cl(p, 3);
    cl.HintInit(db);

    uint64_t examined = 0;
    uint64_t containing = 0;
    uint64_t indices = 0;
    for (uint64_t x = 0; x < p.n; x += 17) {  // 60 个索引，覆盖不同区块/偏移
        const std::vector<uint64_t> cand = cl.candidates(x);
        // 候选的**定义性要求**：IF(K[α], j) == β（一次求逆拿到的就是这些 hint）
        for (uint64_t j : cand) {
            EXPECT_EQ(cl.iprf_offset(p.block_of(x), j), p.offset_of(x));
        }
        for (uint64_t j : cand) {
            ++examined;
            if (cl.slot_contains_block(static_cast<size_t>(j), p.block_of(x))) ++containing;
        }
        ++indices;

        const PlinkoHintSelection sel = cl.GetHint(x);
        EXPECT_TRUE(sel.found);
        // 命中的 hint 必须**语义上覆盖**目标（这是漏检检查的真正目的）
        EXPECT_TRUE(cl.hint_covers(sel.slot, x));
        EXPECT_TRUE(sel.candidates_examined > 0);
        EXPECT_TRUE(sel.candidates_containing > 0);
    }
    EXPECT_TRUE(indices > 50);
    EXPECT_TRUE(examined > 0);

    const double ratio = static_cast<double>(containing) / static_cast<double>(examined);
    // 期望 ≈ (2/3)·(c/2+1)/c + (1/3)·(c/2)/c ≈ 0.51（实测 50.1%，见 Q9 报告 D5）；
    // ⚠️ 若漏掉"α ∈ P_j"检查，这个比例会变成 **1.0**（约一半查询静默错值）。
    std::printf("[plinko] GetHint 候选检查: examined=%llu containing=%llu ratio=%.4f\n",
                static_cast<unsigned long long>(examined),
                static_cast<unsigned long long>(containing), ratio);
    EXPECT_TRUE(ratio > 0.45);
    EXPECT_TRUE(ratio < 0.58);

    // 候选规模 ≈ H/w = 1.5λ = 120（PLINKO_SPEC §1 的覆盖概率口径）
    const double mean_candidates = static_cast<double>(examined) / static_cast<double>(indices);
    std::printf("[plinko] 平均候选数 H/w = %.2f（理论 1.5λ = %.1f）\n", mean_candidates,
                1.5 * static_cast<double>(p.lambda));
    EXPECT_TRUE(mean_candidates > 100.0);
    EXPECT_TRUE(mean_candidates < 145.0);
}

// ===========================================================================
// 全量覆盖扫描（PLINKO_SPEC §7.2）
// ===========================================================================

TEST(Plinko, FullCoverageScanHasNoUncoveredIndexAtLambda80) {
    const PlinkoParams p = FastParams();
    const std::vector<uint128_t> db = MakeDb(p.n, 31);
    PlinkoClient cl(p, 4);
    cl.HintInit(db);

    const std::vector<uint8_t> mask = cl.coverage_mask();
    EXPECT_EQ(mask.size(), static_cast<size_t>(p.n));
    const size_t uncovered = static_cast<size_t>(std::count(mask.begin(), mask.end(), uint8_t{0}));
    std::printf("[plinko] λ=80 全量覆盖扫描: n=%llu 未覆盖=%zu\n",
                static_cast<unsigned long long>(p.n), uncovered);
    EXPECT_EQ(uncovered, size_t{0});

    // 抽样重建：100 个索引走完整链路，与明文逐一对照
    random::DeterministicPrng prng(kDbKey, 99);
    for (int t = 0; t < 100; ++t) {
        const uint64_t x = static_cast<uint64_t>(prng.Below(p.n));
        auto [q, h] = cl.QueryGen(x);
        EXPECT_EQ(cl.ClientRecon(h, PlinkoClient::ServerResp(q, db)), db[static_cast<size_t>(x)]);
    }
    EXPECT_EQ(cl.hints_in_table(), static_cast<size_t>(p.main_hints()));  // 不变量
}

// ===========================================================================
// 算法 3/4/5：查询链路的正确性（含 XOR 共享、双服务器实例化）
// ===========================================================================

TEST(Plinko, QueryReconstructsEveryIndexThroughServerResp) {
    const PlinkoParams p = MakeParams(1024, 16, 24, 1e-4);  // c = 64
    const std::vector<uint128_t> db = MakeDb(p.n, 41);
    PlinkoClient cl(p, 5);
    cl.HintInit(db);

    uint64_t ok = 0;
    for (uint64_t x = 0; x < 128; ++x) {
        auto [q, h] = cl.QueryGen(x);
        // 服务器可见信息：长度 c，分组恰好 c/2 + c/2（§5.5 的对称性）
        EXPECT_EQ(q.offsets.size(), static_cast<size_t>(p.block_count()));
        EXPECT_EQ(q.groups.size(), static_cast<size_t>(p.block_count()));
        EXPECT_EQ(CountOnes(q.groups), p.block_count() / 2);
        EXPECT_TRUE(q.well_formed());
        const uint128_t got = cl.ClientRecon(h, PlinkoClient::ServerResp(q, db));
        EXPECT_EQ(got, db[static_cast<size_t>(x)]);
        if (got == db[static_cast<size_t>(x)]) ++ok;
        // 每次查询消费 1 条 + 提升 1 条 ⇒ H 中可用 hint 数恒为 λw
        EXPECT_EQ(cl.hints_in_table(), static_cast<size_t>(p.main_hints()));
    }
    EXPECT_EQ(ok, uint64_t{128});
}

TEST(Plinko, ServerRespActsOnXorSharesForTwoServerInstantiation) {
    const PlinkoParams p = MakeParams(512, 16, 16, 1e-4);
    const std::vector<uint128_t> db = MakeDb(p.n, 51);
    PlinkoClient cl(p, 6);
    cl.HintInit(db);

    // 把明文表拆成两份 XOR 共享（MPRAQ 的两服务器）
    random::DeterministicPrng prng(kDbKey, 1234);
    std::vector<uint128_t> s0(static_cast<size_t>(p.n));
    std::vector<uint128_t> s1(static_cast<size_t>(p.n));
    for (uint64_t i = 0; i < p.n; ++i) {
        s0[static_cast<size_t>(i)] = prng.Next();
        s1[static_cast<size_t>(i)] = static_cast<uint128_t>(s0[static_cast<size_t>(i)] ^ db[static_cast<size_t>(i)]);
    }

    for (uint64_t x : {uint64_t{0}, uint64_t{7}, uint64_t{255}, uint64_t{511}}) {
        auto [q, h] = cl.QueryGen(x);
        const PlinkoAnswer a0 = PlinkoClient::ServerRespShared(
            q, [&](uint64_t i) { return s0[static_cast<size_t>(i)]; });
        const PlinkoAnswer a1 = PlinkoClient::ServerRespShared(
            q, [&](uint64_t i) { return s1[static_cast<size_t>(i)]; });
        // XOR 与共享线性相容（D12/D3）：合并后等价于在明文上直接累加
        const PlinkoAnswer combined = PlinkoClient::XorAnswers(a0, a1);
        const PlinkoAnswer plain = PlinkoClient::ServerResp(q, db);
        EXPECT_EQ(combined.r0, plain.r0);
        EXPECT_EQ(combined.r1, plain.r1);
        EXPECT_EQ(cl.ClientRecon(h, combined), db[static_cast<size_t>(x)]);
    }
}

TEST(Plinko, QueryRejectsOutOfRangeIndexAndShortDatabase) {
    const PlinkoParams p = FastParams();
    const std::vector<uint128_t> db = MakeDb(p.n, 61);
    PlinkoClient cl(p, 7);
    cl.HintInit(db);
    EXPECT_THROW(cl.QueryGen(p.n), std::out_of_range);
    EXPECT_THROW(cl.GetHint(p.block_count(), 0), std::out_of_range);
    EXPECT_THROW(cl.GetHint(0, p.w), std::out_of_range);
    // 未预留/外来句柄必须被拒（否则会复用被消费的 hint）
    PlinkoQueryHandle bogus;
    EXPECT_THROW(cl.ClientRecon(bogus, PlinkoAnswer{}), std::invalid_argument);
    // 数据库长度不足的服务器侧应答
    EXPECT_THROW(PlinkoClient::ServerResp(cl.QueryGen(3).first, std::vector<uint128_t>(4)),
                 std::invalid_argument);
}

// ===========================================================================
// 提升（promotion）：η 两条分支 + 提升后立刻用同槽位查询（PLINKO_SPEC §7.6 / §7.9）
// ===========================================================================

TEST(Plinko, PromotionCoversBothEtaBranchesAndReusableImmediately) {
    const PlinkoParams p = FastParams();
    const std::vector<uint128_t> db = MakeDb(p.n, 71);
    PlinkoClient cl(p, 8);
    cl.HintInit(db);

    int eta0_first = -1;
    int eta1_first = -1;
    for (int t = 0; t < 40 && (eta0_first < 0 || eta1_first < 0); ++t) {
        const uint64_t x = static_cast<uint64_t>(t) * 13 + 5;
        auto [q, h] = cl.QueryGen(x);
        const uint128_t got = cl.ClientRecon(h, PlinkoClient::ServerResp(q, db));
        EXPECT_EQ(got, db[static_cast<size_t>(x)]);

        // 提升的备份 hint **保留下标**：j' = λw + k（论文 §5.2：keeps the same table index）。
        // 本轮之前已发生的提升次数 = q − 剩余备份数 − 1（减掉本次刚用掉的那条）
        const size_t expected_slot = static_cast<size_t>(p.main_hints()) +
                                     (static_cast<size_t>(p.backup_hints()) - cl.backup_remaining() - 1);
        EXPECT_EQ(h.promoted_slot, expected_slot);
        const PlinkoHintSlot& slot = cl.slot(h.promoted_slot);
        EXPECT_TRUE(slot.kind == PlinkoSlotKind::kPromoted);
        EXPECT_EQ(slot.promoted_index, x);
        EXPECT_EQ(slot.eta, h.promotion_eta);
        // η ∈ {0,1} 且 α' 恒被并入有效集；η 分支的**语义正确性**由下面
        // "parity == 有效集上的 XOR" 这一条彻底验证（η 取错时 parity 必然对不上）。
        EXPECT_TRUE(slot.eta == 0 || slot.eta == 1);
        EXPECT_TRUE(cl.slot_contains_block(h.promoted_slot, p.block_of(x)));
        // 提升后有效集恰为 c/2+1 个区块、parity 必须等于有效集上的 XOR（按定义重算）
        EXPECT_EQ(PopCountSlot(cl, h.promoted_slot), static_cast<size_t>(p.main_hint_blocks()));
        EXPECT_EQ(slot.parity, XorCovered(cl, db, h.promoted_slot));
        // ⚠️ 必须**按值**取走 η：下面的 QueryViaSlot 会把本槽位消费掉（kind ← ⊥、η ← 0）
        const uint8_t eta = slot.eta;
        const size_t promoted_slot = h.promoted_slot;
        // H 中可用 hint 总数仍为 λw（消耗 1 条 + 提升 1 条）
        EXPECT_EQ(cl.hints_in_table(), static_cast<size_t>(p.main_hints()));

        // ⭐ 提升后**立刻**用同一个槽位查询被提升进来的那个索引：必须正确
        auto [q2, h2] = cl.QueryViaSlot(promoted_slot, x);
        EXPECT_EQ(h2.hint_slot, promoted_slot);
        EXPECT_EQ(cl.ClientRecon(h2, PlinkoClient::ServerResp(q2, db)), db[static_cast<size_t>(x)]);
        // 被消费掉的槽位必须回到 ⊥（消费制：同一条 hint 不会被两条查询复用）
        EXPECT_TRUE(cl.slot_kind(promoted_slot) == PlinkoSlotKind::kEmpty);

        if (eta == 0 && eta0_first < 0) eta0_first = t;
        if (eta == 1 && eta1_first < 0) eta1_first = t;
    }
    std::printf("[plinko] 提升分支覆盖: η=0 首次于第 %d 轮、η=1 首次于第 %d 轮；"
                "累计 η0=%llu η1=%llu\n",
                eta0_first, eta1_first, static_cast<unsigned long long>(cl.promotion_count_eta0()),
                static_cast<unsigned long long>(cl.promotion_count_eta1()));
    EXPECT_TRUE(eta0_first >= 0);  // 两条分支都必须被真实走到
    EXPECT_TRUE(eta1_first >= 0);
    EXPECT_TRUE(cl.promotion_count_eta0() > 0);
    EXPECT_TRUE(cl.promotion_count_eta1() > 0);
}

TEST(Plinko, PromotedHintAnswersItsOtherCoveredRecords) {
    const PlinkoParams p = FastParams();
    const std::vector<uint128_t> db = MakeDb(p.n, 81);
    PlinkoClient cl(p, 9);
    cl.HintInit(db);

    // 先做几次查询造出若干提升 hint，再抽查它们覆盖的其余记录（α' 块之外）
    std::vector<size_t> promoted;
    for (int t = 0; t < 6; ++t) {
        auto [q, h] = cl.QueryGen(static_cast<uint64_t>(t) * 29 + 3);
        (void)cl.ClientRecon(h, PlinkoClient::ServerResp(q, db));
        promoted.push_back(h.promoted_slot);
    }

    uint64_t checked = 0;
    for (size_t slot : promoted) {
        const PlinkoHintSlot& s = cl.slot(slot);
        const uint64_t alpha_prime = p.block_of(s.promoted_index);
        // α' 块里除了被提升的那一条，其余记录**都不得**被这条 hint 覆盖（勘误 ⑦）
        for (uint64_t idx = alpha_prime * p.w; idx < (alpha_prime + 1) * p.w; ++idx) {
            if (idx == s.promoted_index) continue;
            EXPECT_FALSE(cl.hint_covers(slot, idx));
        }
        for (uint64_t idx : cl.covered_indices(slot)) {
            if (p.block_of(idx) == alpha_prime) continue;  // α' 块只覆盖被提升的那一条（见下）
            EXPECT_TRUE(cl.hint_covers(slot, idx));
            auto [q, h] = cl.QueryViaSlot(slot, idx);
            EXPECT_EQ(cl.ClientRecon(h, PlinkoClient::ServerResp(q, db)), db[static_cast<size_t>(idx)]);
            ++checked;
            break;  // 每个提升 hint 抽查一条（槽位消费制：一条 hint 只能出一次查询）
        }
    }
    EXPECT_EQ(checked, promoted.size());
}

// ===========================================================================
// 覆盖语义的精确性（勘误 ② / ⑦：α ∈ E 与"提升块只覆盖 β' 那一条"）
// ===========================================================================

TEST(Plinko, CoverageSemanticsIsExactForRegularAndPromotedHints) {
    const PlinkoParams p = FastParams();
    const std::vector<uint128_t> db = MakeDb(p.n, 191);
    PlinkoClient cl(p, 19);
    cl.HintInit(db);

    // 常规 hint：hint_covers 的覆盖集必须**恰好**等于按定义算出的集合（不多不少）
    for (size_t slot : {size_t{0}, size_t{7}, size_t{100}}) {
        const std::vector<uint64_t> def = cl.covered_indices(slot);
        EXPECT_EQ(def.size(), static_cast<size_t>(p.main_hint_blocks()));
        std::vector<uint8_t> def_mask(static_cast<size_t>(p.n), 0);
        for (uint64_t idx : def) def_mask[static_cast<size_t>(idx)] = 1;
        uint64_t covered = 0;
        for (uint64_t x = 0; x < p.n; ++x) {
            const bool c = cl.hint_covers(slot, x);
            EXPECT_EQ(c, def_mask[static_cast<size_t>(x)] != 0);
            if (c) ++covered;
        }
        EXPECT_EQ(covered, static_cast<uint64_t>(def.size()));
    }

    // 提升 hint：α' 块**只**覆盖被提升进来的那一条（补丁偏移 β'），其余块照常覆盖
    auto [q, h] = cl.QueryGen(321);
    EXPECT_EQ(cl.ClientRecon(h, PlinkoClient::ServerResp(q, db)), db[321]);
    const size_t jp = h.promoted_slot;
    const uint64_t x = cl.slot(jp).promoted_index;
    const uint64_t alpha_p = p.block_of(x);
    const uint64_t beta_p = p.offset_of(x);
    EXPECT_EQ(x, uint64_t{321});
    EXPECT_TRUE(cl.hint_covers(jp, x));
    uint64_t in_block = 0;
    for (uint64_t idx = alpha_p * p.w; idx < (alpha_p + 1) * p.w; ++idx) {
        if (cl.hint_covers(jp, idx)) ++in_block;
    }
    // 若这里 > 1，说明把整个 α' 块当成了覆盖集（论文 Fig 7 的 B∪{α'} 口径会犯这个错）
    EXPECT_EQ(in_block, uint64_t{1});
    uint64_t total = 0;
    for (uint64_t idx : cl.covered_indices(jp)) {
        EXPECT_TRUE(cl.hint_covers(jp, idx));
        ++total;
    }
    EXPECT_EQ(total, static_cast<uint64_t>(p.main_hint_blocks()));
    // 提升索引**不是** iF 在 α' 块选中的那一条 —— 这正是"补丁偏移 β'"存在的原因
    //（也是论文那句"提升后的 hint 不会作为 x 的候选出现"的含义）。这里统计巧合率：
    // 若实现改用 iF 偏移（而不是补丁值），这个比例会恒为 1。
    uint64_t coincidences = 0;
    uint64_t samples = 0;
    for (int t = 0; t < 20; ++t) {
        auto [q2, h2] = cl.QueryGen(7 + static_cast<uint64_t>(t) * 13);
        (void)cl.ClientRecon(h2, PlinkoClient::ServerResp(q2, db));
        const PlinkoHintSlot& s2 = cl.slot(h2.promoted_slot);
        const uint64_t ap = p.block_of(s2.promoted_index);
        const uint64_t bp = p.offset_of(s2.promoted_index);
        if (cl.iprf_offset(ap, h2.promoted_slot) == bp) ++coincidences;
        ++samples;
    }
    EXPECT_EQ(samples, uint64_t{20});
    EXPECT_TRUE(coincidences * 8 <= samples);  // 巧合率 ≈ 1/w，远小于 1
}

TEST(Plinko, GetHintFallsBackToPromotedHintsWhenRegularCandidatesAreConsumed) {
    // GetHint 的**提升 hint 分支**（η 折算 + "α' 块只覆盖 β'"规则 + 补丁偏移）在常规运行里
    // 很少被走到：候选按下标升序返回，而提升 hint 的下标 ≥ λw 恒大于所有常规槽位。
    // 这里构造出"某个索引的低下标候选都被消费掉"的局面，逼 GetHint 回落到提升 hint。
    const PlinkoParams p = MakeParams(1024, 32, 24, 1e-4);  // c=32, λw=768, q=384
    const std::vector<uint128_t> db = MakeDb(p.n, 201);
    PlinkoClient cl(p, 20);
    cl.HintInit(db);

    size_t via_promoted = kPlinkoNoSlot;
    uint64_t target = kPlinkoNoIndex;
    uint64_t queries_used = 0;
    for (uint64_t y = 0; y < 8 && via_promoted == kPlinkoNoSlot; ++y) {
        if (cl.cached(y)) continue;
        // 消费掉 y 的**全部常规**覆盖槽位：用该槽位覆盖的另一个索引去消费它，
        // 这样既消耗了槽位，又不会把 y 写进缓存（y 必须保持"未被答复"）。
        for (size_t s : cl.covering_slots(y)) {
            if (s >= p.main_hints()) continue;  // 提升后的槽位留着 —— 正是我们要用的那些
            const std::vector<uint64_t> recs = cl.covered_indices(s);
            uint64_t z = kPlinkoNoIndex;
            for (uint64_t r : recs) {
                if (r != y) {
                    z = r;
                    break;
                }
            }
            ASSERT_TRUE(z != kPlinkoNoIndex);
            auto [qz, hz] = cl.QueryViaSlot(s, z);
            EXPECT_EQ(cl.ClientRecon(hz, PlinkoClient::ServerResp(qz, db)), db[static_cast<size_t>(z)]);
            ++queries_used;
        }
        const PlinkoHintSelection sel = cl.GetHint(y);
        if (sel.found && sel.slot >= p.main_hints()) {
            via_promoted = sel.slot;
            target = y;
            EXPECT_TRUE(cl.slot_kind(sel.slot) == PlinkoSlotKind::kPromoted);
            EXPECT_TRUE(cl.hint_covers(sel.slot, y));
            for (uint64_t idx : cl.covered_indices(sel.slot)) {
                EXPECT_TRUE(cl.hint_covers(sel.slot, idx));
            }
            auto [q, h] = cl.QueryViaSlot(sel.slot, y);
            EXPECT_EQ(cl.ClientRecon(h, PlinkoClient::ServerResp(q, db)), db[static_cast<size_t>(y)]);
            ++queries_used;
        }
    }
    std::printf("[plinko] GetHint 回落到提升 hint: 槽位 %zu（目标 %llu，耗了 %llu 次查询）\n",
                via_promoted, static_cast<unsigned long long>(target),
                static_cast<unsigned long long>(queries_used));
    EXPECT_TRUE(via_promoted != kPlinkoNoSlot);
    EXPECT_TRUE(via_promoted >= p.main_hints());
    EXPECT_EQ(cl.hints_in_table(), static_cast<size_t>(p.main_hints()));
    EXPECT_TRUE(cl.backups_low(380));  // 备份额度仍然够用
}

// ===========================================================================
// 重复查询缓存（PLINKO_SPEC §7.7）
// ===========================================================================

TEST(Plinko, RepeatQueryUsesCacheAndStillConsumesAHint) {
    const PlinkoParams p = FastParams();
    const std::vector<uint128_t> db = MakeDb(p.n, 91);
    PlinkoClient cl(p, 10);
    cl.HintInit(db);

    const size_t backups0 = cl.backup_remaining();
    auto [q1, h1] = cl.QueryGen(400);
    EXPECT_FALSE(h1.cache_hit);
    EXPECT_EQ(h1.target, uint64_t{400});
    EXPECT_EQ(cl.ClientRecon(h1, PlinkoClient::ServerResp(q1, db)), db[400]);
    EXPECT_TRUE(cl.cached(400));
    EXPECT_EQ(cl.cached_value(400), db[400]);
    EXPECT_EQ(cl.cached_slot(400), h1.promoted_slot);

    // 第二次查同一索引：i' = 400 早已答复 ⇒ 论文做法是**换一个没查过的索引**
    // 真正做 PIR，结果取自缓存；hint 的消费/提升照样发生（服务器视角与查询模式无关）
    auto [q2, h2] = cl.QueryGen(400);
    EXPECT_TRUE(h2.cache_hit);
    EXPECT_EQ(h2.requested, uint64_t{400});
    EXPECT_NE(h2.target, uint64_t{400});
    EXPECT_FALSE(cl.cached(h2.target));
    const uint128_t v2 = cl.ClientRecon(h2, PlinkoClient::ServerResp(q2, db));
    EXPECT_EQ(v2, db[400]);
    EXPECT_EQ(cl.backup_remaining(), backups0 - 2);          // 两次查询各消费一条备份
    EXPECT_EQ(cl.query_count(), uint64_t{2});
    EXPECT_EQ(cl.hints_in_table(), static_cast<size_t>(p.main_hints()));
    EXPECT_EQ(cl.answered_count(), uint64_t{2});             // 两个不同的索引被真正答复
}

// ===========================================================================
// 哑偏移新鲜性 + 服务器视角的结构不可区分（PLINKO_SPEC §7.4 / §7.5）
// ===========================================================================

TEST(PlinkoPrivacy, DummyOffsetsAreFreshEveryRound) {
    const PlinkoParams p = FastParams();
    const std::vector<uint128_t> db = MakeDb(p.n, 101);
    PlinkoClient cl(p, 11);
    cl.HintInit(db);

    std::vector<std::vector<uint64_t>> seen;
    int cache_hits = 0;
    for (int t = 0; t < 6; ++t) {
        auto [q, h] = cl.QueryGen(777);  // 同一个索引连续查 6 次
        if (h.cache_hit) ++cache_hits;
        for (const std::vector<uint64_t>& prev : seen) {
            EXPECT_TRUE(prev != q.offsets);  // 偏移向量每轮都不同（哑偏移全新随机）
        }
        seen.push_back(q.offsets);
        EXPECT_EQ(cl.ClientRecon(h, PlinkoClient::ServerResp(q, db)), db[777]);
    }
    EXPECT_EQ(seen.size(), size_t{6});
    EXPECT_EQ(cache_hits, 5);  // 第 1 次是真查，后 5 次都走缓存换索引
}

TEST(PlinkoPrivacy, ServerViewOfQueryHasNoDistinguishingStructure) {
    const PlinkoParams p = FastParams();
    const std::vector<uint128_t> db = MakeDb(p.n, 111);
    PlinkoClient cl(p, 12);
    cl.HintInit(db);

    // 偏移直方图（两个分组分别统计）：两组都应接近均匀 —— 服务器看不出哪一组是
    // "hint 的真实覆盖集"（真实组的偏移是 iF 输出，也是伪随机的）。
    std::vector<uint64_t> hist[2];
    hist[0].assign(static_cast<size_t>(p.w), 0);
    hist[1].assign(static_cast<size_t>(p.w), 0);

    const int kRounds = 64;
    uint64_t target_offset_leaks = 0;
    uint64_t total = 0;
    for (int t = 0; t < kRounds; ++t) {
        const uint64_t x = static_cast<uint64_t>(t) * 7 + 1;
        const uint64_t alpha = p.block_of(x);
        auto [q, h] = cl.QueryGen(x);
        // ① 结构：c 个区块恰好切成两半，每块一个偏移（PLINKO_SPEC §3.3）
        EXPECT_EQ(CountOnes(q.groups), p.block_count() / 2);
        for (uint64_t a = 0; a < p.block_count(); ++a) {
            EXPECT_TRUE(q.offsets[static_cast<size_t>(a)] < p.w);
            EXPECT_TRUE(q.groups[static_cast<size_t>(a)] <= 1);
            ++hist[q.groups[static_cast<size_t>(a)]][static_cast<size_t>(q.offsets[static_cast<size_t>(a)])];
        }
        // ② 被查询区块的偏移必须是**全新哑偏移**：恰好等于 β 的概率 ≈ 1/w，
        //    若客户端把目标偏移直接发出去（或漏掉哑偏移），这里就会次次命中。
        if (q.offsets[static_cast<size_t>(alpha)] == p.offset_of(x)) ++target_offset_leaks;
        ++total;
        EXPECT_EQ(cl.ClientRecon(h, PlinkoClient::ServerResp(q, db)), db[static_cast<size_t>(x)]);
    }
    std::printf("[plinko] 查询形状: 每轮恰好 %llu 个区块进 r0、%llu 个进 r1；"
                "查询区块偏移 == β 的次数 = %llu/%d（期望 ≈ %d，若目标偏移被直接发出则为 %d）\n",
                static_cast<unsigned long long>(p.block_count() / 2),
                static_cast<unsigned long long>(p.block_count() / 2),
                static_cast<unsigned long long>(target_offset_leaks), kRounds,
                kRounds / static_cast<int>(p.w), kRounds);
    EXPECT_TRUE(target_offset_leaks * 4 <= static_cast<uint64_t>(kRounds));  // 远小于 1/w 之上的噪声

    // ③ 每个偏移值都要出现，且不得有严重偏斜（两组同分布 ⇒ 无法把两组分开）
    const uint64_t expected = static_cast<uint64_t>(kRounds) * (p.block_count() / 2) / p.w;
    for (int g = 0; g < 2; ++g) {
        for (uint64_t v = 0; v < p.w; ++v) {
            EXPECT_TRUE(hist[g][static_cast<size_t>(v)] > 0);
            EXPECT_TRUE(hist[g][static_cast<size_t>(v)] < expected * 3);
        }
    }
}

// ===========================================================================
// 确定性随机源与期望值（铁律 D6 / D23）
// ===========================================================================

TEST(Plinko, DeterministicSeedsReproduceStateAndQueries) {
    const PlinkoParams p = FastParams();
    const std::vector<uint128_t> db = MakeDb(p.n, 121);

    PlinkoClient a(p, /*seed=*/20260910);
    PlinkoClient b(p, /*seed=*/20260910);
    PlinkoClient c(p, /*seed=*/20260911);  // 仅低 32 位不同（D23 的回归点）
    a.HintInit(db);
    b.HintInit(db);
    c.HintInit(db);

    // hint 状态逐位相同（parity + 子集位图）
    for (size_t s = 0; s < a.hint_slot_count(); s += 37) {
        EXPECT_TRUE(a.slot_kind(s) == b.slot_kind(s));
        EXPECT_EQ(a.slot(s).parity, b.slot(s).parity);
        for (uint64_t blk = 0; blk < p.block_count(); ++blk) {
            EXPECT_EQ(a.slot_contains_block(s, blk), b.slot_contains_block(s, blk));
        }
        EXPECT_EQ(PopCountSlot(a, s), PopCountSlot(b, s));
    }

    // 同一索引序列 ⇒ 完全相同的查询（偏移向量与分组比特逐位相同）
    for (uint64_t x : {uint64_t{0}, uint64_t{123}, uint64_t{1000}}) {
        auto [q1, h1] = a.QueryGen(x);
        auto [q2, h2] = b.QueryGen(x);
        EXPECT_TRUE(q1.offsets == q2.offsets);
        EXPECT_TRUE(q1.groups == q2.groups);
        EXPECT_EQ(h1.b, h2.b);
        EXPECT_EQ(h1.hint_slot, h2.hint_slot);
        (void)a.ClientRecon(h1, PlinkoClient::ServerResp(q1, db));
        (void)b.ClientRecon(h2, PlinkoClient::ServerResp(q2, db));
    }

    // 不同 seed ⇒ 不同的 hint 与不同的查询（"不同 seed 其实是同一份数据"是 D23 的教训）
    EXPECT_NE(a.slot(0).parity, c.slot(0).parity);
    auto [qa, ha] = a.QueryGen(5);
    auto [qc, hc] = c.QueryGen(5);
    EXPECT_TRUE(qa.offsets != qc.offsets);
    (void)ha;
    (void)hc;
}

// ===========================================================================
// 边界：备份用尽（PLINKO_SPEC §7.8/§7.10、决策 D8）
// ===========================================================================

TEST(Plinko, BackupsExhaustAfterQQueriesThenThrows) {
    // q = λw/2 = 640，且 n = 2048 ≥ q（论文口径 q = w = Õ(r)）
    const PlinkoParams p = MakeParams(2048, 16, 80, 1e-4);
    const std::vector<uint128_t> db = MakeDb(p.n, 131);
    PlinkoClient cl(p, 13);
    cl.HintInit(db);
    EXPECT_EQ(p.backup_hints(), uint64_t{640});
    EXPECT_EQ(cl.backup_remaining(), static_cast<size_t>(p.backup_hints()));
    EXPECT_FALSE(cl.backups_low(638));
    EXPECT_TRUE(cl.backups_low(640));

    random::DeterministicPrng prng(kDbKey, 555);
    uint64_t ok = 0;
    const uint64_t q = p.backup_hints();
    for (uint64_t t = 0; t < q; ++t) {
        const uint64_t x = static_cast<uint64_t>(prng.Below(p.n));
        auto [qr, h] = cl.QueryGen(x);
        const uint128_t v = cl.ClientRecon(h, PlinkoClient::ServerResp(qr, db));
        EXPECT_EQ(v, db[static_cast<size_t>(x)]);
        if (v == db[static_cast<size_t>(x)]) ++ok;
    }
    EXPECT_EQ(ok, q);
    EXPECT_EQ(cl.backup_remaining(), size_t{0});
    EXPECT_EQ(cl.promoted_hint_count(), static_cast<size_t>(q));
    EXPECT_EQ(cl.hints_in_table(), static_cast<size_t>(p.main_hints()));  // 不变量仍然成立
    EXPECT_TRUE(cl.backups_low(0));

    // 第 q+1 次查询：**显式报错**（D8：不实现摊销式离线，绝不静默降级）
    EXPECT_THROW(cl.QueryGen(0), PlinkoBackupsExhausted);
    const uint64_t queries_before = cl.query_count();
    EXPECT_THROW(cl.QueryGen(0), PlinkoBackupsExhausted);
    EXPECT_EQ(cl.query_count(), queries_before);  // 失败的查询不产生任何状态变化
}

// ===========================================================================
// 边界：找不到覆盖 hint 时的致命失败（PLINKO_SPEC §5.1，绝不明文回退）
// ===========================================================================

TEST(Plinko, UncoveredIndexRaisesFatalFailureWithoutPlaintextFallback) {
    // λ = 1 ⇒ 覆盖概率极低（每个索引的期望覆盖 hint 数 ≈ 0.75），必然存在未被覆盖的索引。
    // ⚠️ 用 coverage_mask 先**找出**未覆盖的索引（不消耗任何 hint），再验证 QueryGen 抛致命错误。
    const PlinkoParams p = MakeParams(1024, 32, 1, 1e-4);
    const std::vector<uint128_t> db = MakeDb(p.n, 141);
    PlinkoClient cl(p, 14);
    cl.HintInit(db);

    const std::vector<uint8_t> mask = cl.coverage_mask();
    uint64_t uncovered = 0;
    uint64_t first_uncovered = kPlinkoNoIndex;
    uint64_t first_covered = kPlinkoNoIndex;
    for (uint64_t x = 0; x < p.n; ++x) {
        if (mask[static_cast<size_t>(x)] == 0) {
            ++uncovered;
            if (first_uncovered == kPlinkoNoIndex) first_uncovered = x;
        } else if (first_covered == kPlinkoNoIndex) {
            first_covered = x;
        }
    }
    std::printf("[plinko] λ=1: n=%llu 中未覆盖 %llu 个索引（首个 = %llu）\n",
                static_cast<unsigned long long>(p.n), static_cast<unsigned long long>(uncovered),
                static_cast<unsigned long long>(first_uncovered));
    EXPECT_TRUE(uncovered > 0);
    EXPECT_TRUE(first_covered != kPlinkoNoIndex);
    EXPECT_TRUE(cl.covering_slots(first_uncovered).empty());

    // 覆盖正常时链路正确（不会走任何"明文回退"）
    {
        auto [q, h] = cl.QueryGen(first_covered);
        EXPECT_EQ(cl.ClientRecon(h, PlinkoClient::ServerResp(q, db)), db[static_cast<size_t>(first_covered)]);
    }

    // 未被覆盖 ⇒ **致命失败**：抛 PlinkoHintCoverageFailure，提示重跑离线，且明确禁止回退明文
    bool threw = false;
    const uint64_t queries_before = cl.query_count();
    try {
        auto [q, h] = cl.QueryGen(first_uncovered);
        (void)q;
        (void)h;
    } catch (const PlinkoHintCoverageFailure& e) {
        threw = true;
        const std::string msg = e.what();
        EXPECT_TRUE(msg.find("重跑离线") != std::string::npos);
        EXPECT_TRUE(msg.find("明文") != std::string::npos);
    }
    EXPECT_TRUE(threw);
    EXPECT_EQ(cl.query_count(), queries_before);  // 失败不产生任何状态变化
}

// ===========================================================================
// 算法 6：Verify 的占位语义（Plinko 原文没有 Verify）
// ===========================================================================

TEST(Plinko, VerifyIsExplicitlyUnimplementedAndNeverPassesFalsely) {
    const PlinkoParams p = FastParams();
    const std::vector<uint128_t> db = MakeDb(p.n, 151);
    PlinkoClient cl(p, 15);
    cl.HintInit(db);
    auto [q, h] = cl.QueryGen(17);
    const PlinkoAnswer ans = PlinkoClient::ServerResp(q, db);
    (void)cl.ClientRecon(h, ans);

    bool threw = false;
    try {
        Verify(h, q, ans);  // 自由函数形式
    } catch (const PlinkoVerificationUnsupported& e) {
        threw = true;
        const std::string msg = e.what();
        EXPECT_TRUE(msg.find("未实现") != std::string::npos);
        EXPECT_TRUE(msg.find("MPA-07") != std::string::npos);
        EXPECT_TRUE(msg.find("shared/verify") != std::string::npos);
    }
    EXPECT_TRUE(threw);
    EXPECT_THROW(PlinkoClient::Verify(h, q, ans), PlinkoVerificationUnsupported);
}

// ===========================================================================
// 句柄安全：同一句柄不得重建两次、外来句柄必须被拒（hint 消费制的守卫）
// ===========================================================================

TEST(Plinko, HandleGuardsRejectDoubleReconAndForeignHandles) {
    const PlinkoParams p = FastParams();
    const std::vector<uint128_t> db = MakeDb(p.n, 161);
    PlinkoClient a(p, 16);
    PlinkoClient b(p, 16);  // 同 seed、不同实例 ⇒ owner 标识必须不同（各取一次流）
    a.HintInit(db);
    b.HintInit(db);

    auto [q, h] = a.QueryGen(9);
    const PlinkoAnswer ans = PlinkoClient::ServerResp(q, db);
    EXPECT_EQ(a.ClientRecon(h, ans), db[9]);
    EXPECT_THROW(a.ClientRecon(h, ans), std::invalid_argument);  // 重复重建
    // 外来句柄：owner 不匹配 ⇒ 拒绝（否则会复用别的客户端的 hint 槽位）
    auto [q2, h2] = a.QueryGen(10);
    EXPECT_THROW(b.ClientRecon(h2, PlinkoClient::ServerResp(q2, db)), std::invalid_argument);
    // 未预留的槽位不能用 QueryViaSlot 直接查（备份槽位在提升前不在 H 中）
    EXPECT_THROW(a.QueryViaSlot(static_cast<size_t>(p.main_hints()), 0), std::invalid_argument);
    // 已消费的槽位不能再被选中
    auto [q3, h3] = a.QueryGen(11);
    EXPECT_THROW(a.QueryViaSlot(h3.hint_slot, 11), std::invalid_argument);
    // 不覆盖目标的槽位被拒（"α ∈ E"检查）
    size_t not_covering = kPlinkoNoSlot;
    for (size_t s = 0; s < a.hint_slot_count() && not_covering == kPlinkoNoSlot; ++s) {
        if (!a.slot(s).in_hint_table() || a.slot(s).reserved) continue;
        if (!a.hint_covers(s, 12)) not_covering = s;
    }
    EXPECT_TRUE(not_covering != kPlinkoNoSlot);
    EXPECT_THROW(a.QueryViaSlot(not_covering, 12), std::invalid_argument);
    (void)h3;
}

// ===========================================================================
// 验收用例（默认 ε = 1e-10，PLINKO_SPEC §7.1；D22-1：慢用例单独标注）
// ===========================================================================

TEST(PlinkoAcceptance, PointQueriesAtDefaultEpsilonMatchPlaintext) {
    const PlinkoParams p = MakeParams(4096, 64, 80, 1e-10);  // n = 2¹²、w = 64 ⇒ c = 64
    const std::vector<uint128_t> db = MakeDb(p.n, 20260910);
    PlinkoClient cl(p, 17);

    const Clock::time_point t0 = Clock::now();
    cl.HintInit(db);
    const double init_secs = SecsSince(t0);

    // 500 个**互不相同**的随机点查询（Fisher–Yates 打乱后取前 500）
    std::vector<uint64_t> order(static_cast<size_t>(p.n));
    std::iota(order.begin(), order.end(), uint64_t{0});
    random::DeterministicPrng prng(kDbKey, 4242);
    for (size_t i = 0; i + 1 < order.size(); ++i) {
        const size_t j = i + static_cast<size_t>(prng.Below(order.size() - i));
        std::swap(order[i], order[j]);
    }

    const Clock::time_point t1 = Clock::now();
    uint64_t correct = 0;
    uint64_t promoted_used = 0;
    for (int t = 0; t < 500; ++t) {
        const uint64_t x = order[static_cast<size_t>(t)];
        auto [q, h] = cl.QueryGen(x);
        if (h.hint_slot >= p.main_hints()) ++promoted_used;  // 常规路径里用到"提升后的备份 hint"
        EXPECT_EQ(cl.ClientRecon(h, PlinkoClient::ServerResp(q, db)), db[static_cast<size_t>(x)]);
        ++correct;
        // 每轮都检查不变量（H 中可用 hint 数恒为 λw）
        EXPECT_EQ(cl.hints_in_table(), static_cast<size_t>(p.main_hints()));
    }
    const double query_secs = SecsSince(t1);
    EXPECT_EQ(correct, uint64_t{500});

    // 服务器通信量（PLINKO_SPEC §6 口径）：请求 = c 个偏移（⌈log₂w⌉ bit）+ c 个分组比特；
    // 应答 = 2 个 parity
    const double req_bits =
        static_cast<double>(p.block_count()) * (std::log2(static_cast<double>(p.w)) + 1.0);
    std::printf(
        "[plinko-accept] 几何 n=%llu w=%llu c=%llu λ=%u: M=λw=%llu q=%llu H=%llu",
        static_cast<unsigned long long>(p.n), static_cast<unsigned long long>(p.w),
        static_cast<unsigned long long>(p.block_count()), p.lambda,
        static_cast<unsigned long long>(p.main_hints()),
        static_cast<unsigned long long>(p.backup_hints()),
        static_cast<unsigned long long>(p.hint_slots()));
    std::printf("\n[plinko-accept] HintInit = %.2f s（%.3f ms/记录 = n × IF⁻¹）\n", init_secs,
                1000.0 * init_secs / static_cast<double>(p.n));
    std::printf("[plinko-accept] 500 次点查询 = %.3f s（%.3f ms/查询：客户端 1×IF⁻¹ + c×IF + "
                "服务器 c 次读；一次 RPC）\n",
                query_secs, 1000.0 * query_secs / 500.0);
    std::printf("[plinko-accept] 500 次查询中命中**提升后**备份 hint 的次数 = %llu；"
                "提升分支 η0=%llu η1=%llu\n",
                static_cast<unsigned long long>(promoted_used),
                static_cast<unsigned long long>(cl.promotion_count_eta0()),
                static_cast<unsigned long long>(cl.promotion_count_eta1()));
    std::printf("[plinko-accept] hint 存储: 逻辑 %.1f KB（每条 = parity + ⌈c/64⌉×8 B 位图）、"
                "实际状态 %.1f KB；在线通信 ≈ 请求 %.1f B + 应答 32 B\n",
                cl.logical_hint_bytes() / 1024.0, static_cast<double>(cl.hint_state_bytes()) / 1024.0,
                req_bits / 8.0);

    // 覆盖与存储口径的自检
    EXPECT_TRUE(cl.hints_in_table() == static_cast<size_t>(p.main_hints()));
    EXPECT_EQ(cl.promoted_hint_count(), size_t{500});
    EXPECT_EQ(cl.backup_remaining(), static_cast<size_t>(p.backup_hints() - 500));
    EXPECT_TRUE(cl.logical_hint_bytes() > 0.0);
    EXPECT_TRUE(cl.hint_state_bytes() > 0);
}

TEST(PlinkoAcceptance, CandidateCheckRatioAtDefaultEpsilon) {
    // 默认 ε 下再确认一次"候选检查"的比例（§7.3 的验收口径）
    const PlinkoParams p = MakeParams(1024, 16, 80, 1e-10);  // c = 64 ⇒ 期望比例 ≈ 0.508
    const std::vector<uint128_t> db = MakeDb(p.n, 171);
    PlinkoClient cl(p, 18);
    cl.HintInit(db);

    uint64_t examined = 0;
    uint64_t containing = 0;
    for (uint64_t x = 0; x < p.n; x += 8) {
        for (uint64_t j : cl.candidates(x)) {
            ++examined;
            if (cl.slot_contains_block(static_cast<size_t>(j), p.block_of(x))) ++containing;
        }
    }
    const double ratio = static_cast<double>(containing) / static_cast<double>(examined);
    std::printf("[plinko-accept] c=64 候选检查比例 = %.4f（理论 (c/2+1)/c ≈ 0.5078；"
                "漏检时 = 1.0）examined=%llu\n",
                ratio, static_cast<unsigned long long>(examined));
    EXPECT_TRUE(ratio > 0.48);
    EXPECT_TRUE(ratio < 0.54);
}

TEST(PlinkoAcceptance, HintInitAndQueriesAtM3ScaleN2e14) {
    // M3 口径的规模验收（D22-1③：n ≈ 2¹⁴ 只留给里程碑验收；默认 ε = 1e-10）。
    // 这一条会跑十几秒（HintInit ≈ n × IF⁻¹ ≈ 17 s，与 D22-1 的预算一致）。
    const PlinkoParams p = MakeParams(16384, 128, 80, 1e-10);  // n = 2¹⁴、w = 128 ⇒ c = 128
    const std::vector<uint128_t> db = MakeDb(p.n, 271);
    PlinkoClient cl(p, 21);
    const Clock::time_point t0 = Clock::now();
    cl.HintInit(db);
    const double init_secs = SecsSince(t0);

    // 8 次点查询全部正确（含缓存路径：故意重复一次）
    uint64_t correct = 0;
    for (int t = 0; t < 8; ++t) {
        const uint64_t x = 123 + static_cast<uint64_t>(t) * 1700;
        auto [q, h] = cl.QueryGen(x);
        const uint128_t v = cl.ClientRecon(h, PlinkoClient::ServerResp(q, db));
        EXPECT_EQ(v, db[static_cast<size_t>(x)]);
        ++correct;
    }
    {
        auto [q, h] = cl.QueryGen(5223);  // 重复查询（上面第 4 次已答复过）⇒ 走缓存
        EXPECT_TRUE(h.cache_hit);
        EXPECT_EQ(cl.ClientRecon(h, PlinkoClient::ServerResp(q, db)), db[5223]);
    }
    EXPECT_EQ(correct, uint64_t{8});
    EXPECT_EQ(cl.hints_in_table(), static_cast<size_t>(p.main_hints()));

    // 抽样确认可查询性（每 1024 个索引取一个；GetHint 不消耗 hint）
    uint64_t found = 0;
    uint64_t samples = 0;
    for (uint64_t x = 0; x < p.n; x += 1024) {
        ++samples;
        if (cl.GetHint(x).found) ++found;
    }
    EXPECT_EQ(found, samples);

    std::printf("[plinko-m3] n=%llu w=%llu c=%llu H=%llu: HintInit = %.2f s（%.3f ms/记录）；"
                "每次查询 ≈ %.2f ms；hint 存储 逻辑 %.1f KB / 状态 %.1f KB\n",
                static_cast<unsigned long long>(p.n), static_cast<unsigned long long>(p.w),
                static_cast<unsigned long long>(p.block_count()),
                static_cast<unsigned long long>(p.hint_slots()), init_secs,
                1000.0 * init_secs / static_cast<double>(p.n),
                1000.0 * init_secs / static_cast<double>(p.n) * 2.0 + 0.13,
                cl.logical_hint_bytes() / 1024.0, static_cast<double>(cl.hint_state_bytes()) / 1024.0);
}
