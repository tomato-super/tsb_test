#include "core/field.hpp"
#include "core/random.hpp"
#include "shared/secret_sharing.hpp"
#include "test_framework.hpp"

#include <stdexcept>
#include <vector>

using namespace tsb;

namespace {
const uint128_t kMax = ~static_cast<uint128_t>(0);
// 梅森素数，SecureMul 候选模数（决策 D11）
const uint128_t kQ = (static_cast<uint128_t>(1) << 127) - 1;
}  // namespace

// ---------------------------------------------------------------------------
// 随机数基础设施
// ---------------------------------------------------------------------------

TEST(Random, Uint128ProducesVariedValues) {
    uint128_t first = random::Uint128();
    bool all_same = true;
    for (int i = 0; i < 64; ++i) {
        if (random::Uint128() != first) {
            all_same = false;
            break;
        }
    }
    EXPECT_FALSE(all_same);
}

TEST(Random, BelowRespectsBound) {
    const std::vector<uint128_t> bounds = {2, 7, 1000, kQ, kMax};
    for (uint128_t bound : bounds) {
        for (int i = 0; i < 32; ++i) {
            const uint128_t v = random::Below(bound);
            EXPECT_TRUE(v < bound);
        }
    }
    EXPECT_EQ(random::Below(1), static_cast<uint128_t>(0));
}

TEST(Random, BelowRejectsZeroBound) {
    EXPECT_THROW(random::Below(0), std::invalid_argument);
}

TEST(Random, DeterministicPrngIsReproducible) {
    const auto key = AesPrf::GenerateKey();
    random::DeterministicPrng a(key, 12345);
    random::DeterministicPrng b(key, 12345);
    for (int i = 0; i < 20; ++i) {
        EXPECT_EQ(a.Next(), b.Next());
    }
    // Reset 后重放同一序列
    a.Reset();
    random::DeterministicPrng c(key, 12345);
    EXPECT_EQ(a.Next(), c.Next());
    // 不同 nonce 应给出不同流
    random::DeterministicPrng d(key, 54321);
    EXPECT_NE(c.Next(), d.Next());
}

TEST(Random, DeterministicPrngBelowInRange) {
    const auto key = AesPrf::GenerateKey();
    random::DeterministicPrng prng(key, 7);
    const std::vector<uint128_t> bounds = {2, 100, kQ, kMax};
    for (uint128_t bound : bounds) {
        for (int i = 0; i < 16; ++i) {
            EXPECT_TRUE(prng.Below(bound) < bound);
        }
    }
}

// ---------------------------------------------------------------------------
// Z_{2^128} 加法共享
// ---------------------------------------------------------------------------

TEST(RingShare, ReconstructsSecret) {
    const uint128_t secrets[] = {0, 1, 42, kMax, 1_k << 64, 0xdeadbeefcafebabe_k};
    for (uint128_t s : secrets) {
        auto [a, b] = ShareRing(s);
        EXPECT_EQ(ReconstructRing(a, b), s);
    }
}

TEST(RingShare, SharesDifferFromSecretAndFromEachOther) {
    const uint128_t secret = 123456789_k;
    auto [a, b] = ShareRing(secret);
    // 单个共享不应等于秘密本身（对非零秘密，这是概率性但极高的期望）
    EXPECT_NE(a.value, secret);
    EXPECT_NE(b.value, secret);
    EXPECT_NE(a.value, b.value);
}

TEST(RingShare, MaskIsUniformAcrossRuns) {
    // 同一个秘密多次共享，掩码必须每次都不同（否则掩码复用会泄露）
    const uint128_t secret = 777_k;
    auto [a1, b1] = ShareRing(secret);
    auto [a2, b2] = ShareRing(secret);
    EXPECT_NE(a1.value, a2.value);
    EXPECT_NE(b1.value, b2.value);
    EXPECT_EQ(ReconstructRing(a1, b1), secret);
    EXPECT_EQ(ReconstructRing(a2, b2), secret);
}

TEST(RingShare, SingleShareRevealsNothingAboutKnownSecret) {
    // 给定秘密 s，a 的分布应覆盖整个环（这里采样检查分散度）
    const uint128_t s = 999_k;
    uint128_t min_v = kMax, max_v = 0;
    for (int i = 0; i < 100; ++i) {
        auto [a, b] = ShareRing(s);
        if (a.value < min_v) min_v = a.value;
        if (a.value > max_v) max_v = a.value;
    }
    // 100 个均匀样本极不可能全部落在很小的区间里
    EXPECT_NE(min_v, max_v);
    EXPECT_TRUE(max_v > min_v);
}

TEST(RingShare, BatchRoundTrip) {
    std::vector<uint128_t> secrets;
    for (uint64_t i = 0; i < 257; ++i) {  // 非对齐长度
        secrets.push_back(static_cast<uint128_t>(i) * 1000003_k);
    }
    auto [a, b] = ShareRingBatch(secrets);
    EXPECT_EQ(a.size(), secrets.size());
    EXPECT_EQ(b.size(), secrets.size());
    EXPECT_TRUE(VerifyRingShares(secrets, a, b));
    const auto back = ReconstructRingBatch(a, b);
    for (size_t i = 0; i < secrets.size(); ++i) {
        EXPECT_EQ(back[i], secrets[i]);
    }
}

TEST(RingShare, BatchRejectsMismatchedLengths) {
    std::vector<RingShare> a(3), b(4);
    EXPECT_THROW(ReconstructRingBatch(a, b), std::invalid_argument);
}

TEST(RingShare, VerifyDetectsCorruption) {
    std::vector<uint128_t> secrets = {1, 2, 3};
    auto [a, b] = ShareRingBatch(secrets);
    EXPECT_TRUE(VerifyRingShares(secrets, a, b));
    a[1].value ^= 1;  // 篡改一个共享
    EXPECT_FALSE(VerifyRingShares(secrets, a, b));
}

// ---------------------------------------------------------------------------
// Z_q 加法共享
// ---------------------------------------------------------------------------

TEST(ModShare, ReconstructsSecretModQ) {
    const uint128_t secrets[] = {0, 1, 42, kQ - 1, kQ / 2};
    for (uint128_t s : secrets) {
        auto [a, b] = ShareMod(s, kQ);
        EXPECT_EQ(ReconstructMod(a, b, kQ), s);
        EXPECT_TRUE(a.value < kQ);
        EXPECT_TRUE(b.value < kQ);
    }
}

TEST(ModShare, ReducesSecretAboveQ) {
    const uint128_t big = kQ + 12345;
    auto [a, b] = ShareMod(big, kQ);
    EXPECT_EQ(ReconstructMod(a, b, kQ), reduce(big, kQ));
}

TEST(ModShare, RejectsTinyModulus) {
    EXPECT_THROW(ShareMod(1, 0), std::invalid_argument);
    EXPECT_THROW(ShareMod(1, 1), std::invalid_argument);
}

TEST(ModShare, MasksAreFresh) {
    auto [a1, b1] = ShareMod(5, kQ);
    auto [a2, b2] = ShareMod(5, kQ);
    EXPECT_NE(a1.value, a2.value);
    EXPECT_EQ(ReconstructMod(a1, b1, kQ), static_cast<uint128_t>(5));
    EXPECT_EQ(ReconstructMod(a2, b2, kQ), static_cast<uint128_t>(5));
}

TEST(ModShare, RandomUnitIsInvertible) {
    for (int i = 0; i < 16; ++i) {
        const uint128_t u = RandomUnitMod(kQ);
        EXPECT_TRUE(u > 0);
        EXPECT_TRUE(u < kQ);
        // 必须可逆
        const uint128_t inv = modInverse(u, kQ);
        EXPECT_EQ(mulMod(u, inv, kQ), static_cast<uint128_t>(1));
    }
}

TEST(ModShare, RandomUnitWorksForCompositeModulus) {
    // 合数模数下也应只返回可逆元（会拒绝掉不互素的）
    const uint128_t composite = 1000000007ull * 1000000009ull;  // 乘积 < 2^127
    for (int i = 0; i < 16; ++i) {
        const uint128_t u = RandomUnitMod(composite);
        const uint128_t inv = modInverse(u, composite);
        EXPECT_EQ(mulMod(u, inv, composite), static_cast<uint128_t>(1));
    }
}

// ---------------------------------------------------------------------------
// XOR 共享
// ---------------------------------------------------------------------------

TEST(XorShare, BitRoundTrip) {
    for (int i = 0; i < 32; ++i) {
        for (uint8_t bit : {static_cast<uint8_t>(0), static_cast<uint8_t>(1)}) {
            auto [a, b] = ShareXorBit(bit);
            EXPECT_EQ(ReconstructXorBit(a, b), bit);
            EXPECT_TRUE(a.value <= 1);
            EXPECT_TRUE(b.value <= 1);
        }
    }
}

TEST(XorShare, BitRejectsNonBit) {
    EXPECT_THROW(ShareXorBit(2), std::invalid_argument);
    EXPECT_THROW(ShareXorBit(255), std::invalid_argument);
}

TEST(XorShare, BitSharesAreFresh) {
    auto [a1, b1] = ShareXorBit(1);
    bool saw_difference = false;
    for (int i = 0; i < 64; ++i) {
        auto [a, b] = ShareXorBit(1);
        if (a.value != a1.value) saw_difference = true;
    }
    EXPECT_TRUE(saw_difference);
    EXPECT_EQ(ReconstructXorBit(a1, b1), static_cast<uint8_t>(1));
}

TEST(XorShare, ByteRoundTrip) {
    const std::vector<uint8_t> secret = {0x00, 0xff, 0x5a, 0xa5, 0x01};
    auto [a, b] = ShareXorBytes(secret);
    EXPECT_EQ(a.size(), secret.size());
    EXPECT_EQ(ReconstructXorBytes(a, b), secret);
    // 单个共享不应等于明文
    EXPECT_NE(a, secret);
    EXPECT_NE(b, secret);
}

TEST(XorShare, BytesHandlesEmptyInput) {
    const std::vector<uint8_t> empty;
    auto [a, b] = ShareXorBytes(empty);
    EXPECT_EQ(a.size(), static_cast<size_t>(0));
    EXPECT_EQ(ReconstructXorBytes(a, b), empty);
}

TEST(XorShare, BytesAreFreshEachTime) {
    const std::vector<uint8_t> secret = {1, 2, 3, 4};
    auto [a1, b1] = ShareXorBytes(secret);
    auto [a2, b2] = ShareXorBytes(secret);
    EXPECT_NE(a1, a2);
    EXPECT_EQ(ReconstructXorBytes(a1, b1), secret);
    EXPECT_EQ(ReconstructXorBytes(a2, b2), secret);
}

TEST(XorShare, BytesRejectsMismatchedLengths) {
    std::vector<uint8_t> a(3), b(4);
    EXPECT_THROW(ReconstructXorBytes(a, b), std::invalid_argument);
}

TEST(XorShare, MultipleSharesXorToReconstruct) {
    // 直接验证 XOR 的群结构：s0 ^ s1 ^ ... ^ s_{n-1} = secret
    const std::vector<uint8_t> secret = {0xde, 0xad, 0xbe, 0xef};
    auto [a, b] = ShareXorBytes(secret);
    for (size_t i = 0; i < secret.size(); ++i) {
        EXPECT_EQ(static_cast<uint8_t>(a[i] ^ b[i]), secret[i]);
    }
}
