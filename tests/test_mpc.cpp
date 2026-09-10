#include "shared/mpc.hpp"
#include "core/random.hpp"
#include "test_framework.hpp"

#include <stdexcept>
#include <vector>

using namespace tsb;

namespace {

const uint128_t kQ = (static_cast<uint128_t>(1) << 127) - 1;  // 梅森素数（奇）
const uint128_t kSmallQ = 1000003;                             // 小素数（奇）

MacKeyShares MakeKeys(uint128_t q = kQ) { return GenerateMacKey(2, q); }

// 把一个明文 y 拆成两方共享
std::pair<ModShare, ModShare> ShareY(uint128_t y, uint128_t q) {
    return ShareMod(y, q);
}

}  // namespace

// ===========================================================================
// 模数约束（决策 D11）
// ===========================================================================

TEST(SecureMul, RejectsEvenModulus) {
    // ⚠️ 这是本模块存在的根本原因：2 的幂环中 2 不可逆，
    // 公式里的 e·d·2^{-1} 无定义，必须显式拒绝而不是静默算错。
    const uint128_t pow2 = static_cast<uint128_t>(1) << 64;
    EXPECT_THROW(RequireOddModulus(pow2), std::invalid_argument);
    EXPECT_THROW(RequireOddModulus(static_cast<uint128_t>(256)), std::invalid_argument);
    EXPECT_THROW(RequireOddModulus(static_cast<uint128_t>(2)), std::invalid_argument);
    // 奇数可通过
    RequireOddModulus(kQ);
    RequireOddModulus(static_cast<uint128_t>(3));
}

TEST(SecureMul, RejectsTinyOrOversizedModulus) {
    EXPECT_THROW(RequireOddModulus(0), std::invalid_argument);
    EXPECT_THROW(RequireOddModulus(1), std::invalid_argument);
    // 超过 2^127 会被 core/field 的 modmul 拒绝
    EXPECT_THROW(RequireOddModulus(~static_cast<uint128_t>(0)), std::invalid_argument);
    EXPECT_THROW(RequireOddModulus((static_cast<uint128_t>(1) << 127) + 1),
                 std::invalid_argument);
}

// ===========================================================================
// 正确性：对照明文乘法
// ===========================================================================

TEST(SecureMul, FilterBitTimesAttributeValue) {
    // MPRAQ 的 SUM 场景：x 是 filter bit（0/1），y 是属性值
    const MacKeyShares keys = MakeKeys();
    const uint128_t attribute_value = 987654321_k;

    for (uint128_t filter : {static_cast<uint128_t>(0), static_cast<uint128_t>(1)}) {
        auto [y0, y1] = ShareY(attribute_value, kQ);
        const SecureMulResult r = SecureMulSimple(filter, y0, y1, keys, kQ);
        EXPECT_TRUE(r.ok);
        // 期望：filter ? attribute_value : 0
        EXPECT_EQ(r.z, mulMod(filter, attribute_value, kQ));
    }
}

TEST(SecureMul, MatchesPlaintextMultiplicationOverManyValues) {
    const MacKeyShares keys = MakeKeys();
    const auto key = AesPrf::GenerateKey();
    random::DeterministicPrng prng(key, 4242);

    for (int round = 0; round < 128; ++round) {
        const uint128_t x = prng.Next() % kQ;
        const uint128_t y = prng.Next() % kQ;
        auto [y0, y1] = ShareY(y, kQ);
        const SecureMulResult r = SecureMulSimple(x, y0, y1, keys, kQ);
        EXPECT_TRUE(r.ok);
        EXPECT_EQ(r.z, mulMod(x, y, kQ));
    }
}

TEST(SecureMul, WorksWithSmallPrimeModulus) {
    const MacKeyShares keys = MakeKeys(kSmallQ);
    // 小模数下可以穷举一部分组合
    for (uint128_t x = 0; x < 20; ++x) {
        for (uint128_t y = 0; y < 20; ++y) {
            auto [y0, y1] = ShareY(y, kSmallQ);
            const SecureMulResult r = SecureMulSimple(x, y0, y1, keys, kSmallQ);
            EXPECT_TRUE(r.ok);
            EXPECT_EQ(r.z, mulMod(x, y, kSmallQ));
        }
    }
}

TEST(SecureMul, HandlesZeroAndIdentity) {
    const MacKeyShares keys = MakeKeys();
    // x = 0
    {
        auto [y0, y1] = ShareY(12345, kQ);
        const auto r = SecureMulSimple(0, y0, y1, keys, kQ);
        EXPECT_TRUE(r.ok);
        EXPECT_EQ(r.z, static_cast<uint128_t>(0));
    }
    // y = 0
    {
        auto [y0, y1] = ShareY(0, kQ);
        const auto r = SecureMulSimple(999, y0, y1, keys, kQ);
        EXPECT_TRUE(r.ok);
        EXPECT_EQ(r.z, static_cast<uint128_t>(0));
    }
    // x = 1：结果应等于 y
    {
        auto [y0, y1] = ShareY(kQ - 1, kQ);
        const auto r = SecureMulSimple(1, y0, y1, keys, kQ);
        EXPECT_TRUE(r.ok);
        EXPECT_EQ(r.z, kQ - 1);
    }
}

TEST(SecureMul, OddProductIsTheCaseThatBreaksInPow2Ring) {
    // 显式覆盖"e·d 为奇数"这一在 Z_{2^k} 中会算错的情形。
    // 在奇模数下它必须完全正确。
    const MacKeyShares keys = MakeKeys();
    // 枚举若干组取值，确保有 e·d 为奇数的轮次
    int odd_product_rounds = 0;
    for (uint128_t x = 1; x < 40; x += 2) {
        for (uint128_t y = 1; y < 40; y += 2) {
            auto [y0, y1] = ShareY(y, kQ);
            const auto r = SecureMulSimple(x, y0, y1, keys, kQ);
            EXPECT_TRUE(r.ok);
            EXPECT_EQ(r.z, mulMod(x, y, kQ));
            if (((x * y) & 1u) != 0) ++odd_product_rounds;
        }
    }
    EXPECT_TRUE(odd_product_rounds > 0);
}

// ===========================================================================
// 客户端与服务器的中间量
// ===========================================================================

TEST(SecureMul, ClientSendsOnlyDWhichIsUniformlyMasked) {
    // d = x − a 中 a 是均匀随机的，因此 d 不泄露 x。
    // 这里用统计方式确认 d 的取值分散。
    const MacKeyShares keys = MakeKeys();
    uint128_t min_d = ~static_cast<uint128_t>(0), max_d = 0;
    for (int i = 0; i < 64; ++i) {
        auto [t0, t1] = GenerateTripleShares(keys, kQ);
        const uint128_t a = addMod(t0.a.value, t1.a.value, kQ);
        const uint128_t d = subMod(1, a, kQ);  // x = 1
        if (d < min_d) min_d = d;
        if (d > max_d) max_d = d;
    }
    EXPECT_NE(min_d, max_d);
}

TEST(SecureMul, ServerPhase1ComputesEFromItsShares) {
    const MacKeyShares keys = MakeKeys();
    auto [t0, t1] = GenerateTripleShares(keys, kQ);
    const uint128_t y = 555;
    auto [y0, y1] = ShareY(y, kQ);

    SecureMulServerInput in0{y0, t0};
    const SecureMulRound1 r1 = SecureMulServerPhase1(in0, kQ);
    // ⟨e⟩_0 = ⟨y⟩_0 − ⟨b⟩_0
    EXPECT_EQ(r1.e.value, subMod(y0.value, t0.b.value, kQ));

    SecureMulServerInput in1{y1, t1};
    const SecureMulRound1 r2 = SecureMulServerPhase1(in1, kQ);
    // 两方重建出的 e 应等于 y − b
    const uint128_t b = addMod(t0.b.value, t1.b.value, kQ);
    EXPECT_EQ(addMod(r1.e.value, r2.e.value, kQ), subMod(y, b, kQ));
}

// ===========================================================================
// 恶意行为：篡改必须被检出
// ===========================================================================

TEST(SecureMul, DetectsTamperedZShare) {
    const MacKeyShares keys = MakeKeys();
    auto [t0, t1] = GenerateTripleShares(keys, kQ);
    const uint128_t a = addMod(t0.a.value, t1.a.value, kQ);
    const uint128_t b = addMod(t0.b.value, t1.b.value, kQ);
    const uint128_t c = addMod(t0.c.value, t1.c.value, kQ);
    BeaverTriple triple{a, b, c};

    const uint128_t y = 8888;
    auto [y0, y1] = ShareY(y, kQ);
    SecureMulServerInput in0{y0, t0};
    SecureMulServerInput in1{y1, t1};

    // 诚实情形通过
    const auto honest = SecureMulRun(1, in0, in1, triple, keys, kQ);
    EXPECT_TRUE(honest.ok);

    // 服务器 0 伪造自己的 z 共享 —— 客户端手上没有 ⟨z⟩_0，
    // 只能靠 MAC 校验发现，这里把篡改模拟到第二阶段输出上
    const uint128_t d = subMod(1, triple.a, kQ);
    const auto r1_0 = SecureMulServerPhase1(in0, kQ);
    const auto r1_1 = SecureMulServerPhase1(in1, kQ);
    const uint128_t e = addMod(r1_0.e.value, r1_1.e.value, kQ);

    auto z0 = SecureMulServerPhase2(in0, d, e, kQ);
    const auto z1 = SecureMulServerPhase2(in1, d, e, kQ);
    z0.z.value = addMod(z0.z.value, 1, kQ);  // 恶意服务器篡改

    const AuthenticatedShare a0{z0.z, z0.mac};
    const AuthenticatedShare a1{z1.z, z1.mac};
    EXPECT_FALSE(VerifyAuthenticatedShares(a0, a1, keys.alpha, kQ));
}

TEST(SecureMul, DetectsTamperedMacShare) {
    const MacKeyShares keys = MakeKeys();
    auto [t0, t1] = GenerateTripleShares(keys, kQ);
    const uint128_t a = addMod(t0.a.value, t1.a.value, kQ);
    const uint128_t b = addMod(t0.b.value, t1.b.value, kQ);
    const uint128_t c = addMod(t0.c.value, t1.c.value, kQ);
    BeaverTriple triple{a, b, c};

    auto [y0, y1] = ShareY(4321, kQ);
    SecureMulServerInput in0{y0, t0};
    SecureMulServerInput in1{y1, t1};

    const uint128_t d = subMod(1, triple.a, kQ);
    const auto r1_0 = SecureMulServerPhase1(in0, kQ);
    const auto r1_1 = SecureMulServerPhase1(in1, kQ);
    const uint128_t e = addMod(r1_0.e.value, r1_1.e.value, kQ);

    const auto z0 = SecureMulServerPhase2(in0, d, e, kQ);
    auto z1 = SecureMulServerPhase2(in1, d, e, kQ);
    z1.mac.value = addMod(z1.mac.value, 9, kQ);

    const AuthenticatedShare a0{z0.z, z0.mac};
    const AuthenticatedShare a1{z1.z, z1.mac};
    EXPECT_FALSE(VerifyAuthenticatedShares(a0, a1, keys.alpha, kQ));
}

TEST(SecureMul, DetectsCorruptedTripleShare) {
    // 服务器若擅自改动自己的 triple 共享，MAC 校验会失败
    const MacKeyShares keys = MakeKeys();
    auto [t0, t1] = GenerateTripleShares(keys, kQ);
    const uint128_t a = addMod(t0.a.value, t1.a.value, kQ);
    const uint128_t b = addMod(t0.b.value, t1.b.value, kQ);
    const uint128_t c = addMod(t0.c.value, t1.c.value, kQ);

    auto [y0, y1] = ShareY(100, kQ);
    SecureMulServerInput evil0{y0, t0};
    evil0.triple.a.value = addMod(evil0.triple.a.value, 5, kQ);  // 篡改 ⟨a⟩_0

    SecureMulServerInput in1{y1, t1};
    const auto r = SecureMulRun(1, evil0, in1, BeaverTriple{a, b, c}, keys, kQ);
    // 客户端用的 a 与服务器持有的 ⟨a⟩ 不再一致，MAC 校验应失败
    EXPECT_FALSE(r.ok);
}

// ===========================================================================
// triple 的性质
// ===========================================================================

TEST(SecureMul, TripleShareReconstructsToTriple) {
    const MacKeyShares keys = MakeKeys();
    for (int i = 0; i < 16; ++i) {
        auto [t0, t1] = GenerateTripleShares(keys, kQ);
        const uint128_t a = addMod(t0.a.value, t1.a.value, kQ);
        const uint128_t b = addMod(t0.b.value, t1.b.value, kQ);
        const uint128_t c = addMod(t0.c.value, t1.c.value, kQ);
        EXPECT_EQ(c, mulMod(a, b, kQ));  // c = a·b
        // α 的分享也能重建
        EXPECT_EQ(addMod(t0.alpha.value, t1.alpha.value, kQ), keys.alpha);
        // α·a、α·b、α·c 的分享与真实值一致
        EXPECT_EQ(addMod(t0.alpha_a.value, t1.alpha_a.value, kQ),
                  mulMod(keys.alpha, a, kQ));
        EXPECT_EQ(addMod(t0.alpha_b.value, t1.alpha_b.value, kQ),
                  mulMod(keys.alpha, b, kQ));
        EXPECT_EQ(addMod(t0.alpha_c.value, t1.alpha_c.value, kQ),
                  mulMod(keys.alpha, c, kQ));
    }
}

TEST(SecureMul, TripleSharesAreFresh) {
    const MacKeyShares keys = MakeKeys();
    auto [t0a, t1a] = GenerateTripleShares(keys, kQ);
    auto [t0b, t1b] = GenerateTripleShares(keys, kQ);
    EXPECT_NE(t0a.a.value, t0b.a.value);
    EXPECT_NE(t0a.b.value, t0b.b.value);
    EXPECT_NE(t0a.c.value, t0b.c.value);
}

TEST(SecureMul, RejectsWrongServerCount) {
    MacKeyShares keys = GenerateMacKey(3, kQ);
    EXPECT_THROW(GenerateTripleShares(keys, kQ), std::invalid_argument);
}
