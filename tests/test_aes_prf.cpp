#include "core/aes_prf.hpp"
#include "core/field.hpp"
#include "core/random.hpp"
#include "test_framework.hpp"

#include <array>
#include <cstring>
#include <stdexcept>
#include <vector>

using namespace tsb;

namespace {

// 构造 PRF 输入块 [w0, w1, 0, 0]（w1 为原始 32 位值，不含域）
std::array<uint8_t, 16> Block(uint32_t w0, uint32_t w1) {
    std::array<uint8_t, 16> b{};
    std::memcpy(b.data(), &w0, 4);
    std::memcpy(b.data() + 4, &w1, 4);
    return b;
}

std::array<uint8_t, 16> KeyFromHex(const char* hex32) {
    std::array<uint8_t, 16> k{};
    for (size_t i = 0; i < 16; ++i) {
        auto nib = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0;
        };
        k[i] = static_cast<uint8_t>((nib(hex32[2 * i]) << 4) | nib(hex32[2 * i + 1]));
    }
    return k;
}

AesPrf MakePrf() {
    std::vector<uint8_t> key(16);
    for (size_t i = 0; i < 16; ++i) key[i] = static_cast<uint8_t>(i);
    return AesPrf(key);
}

}  // namespace

// ---------------------------------------------------------------------------
// 基础正确性：AES-128 是否接对了
// ---------------------------------------------------------------------------

TEST(AesPrf, MatchesFips197Aes128Vector) {
    // FIPS-197 附录 C.1：
    //   key       = 000102030405060708090a0b0c0d0e0f
    //   plaintext = 00112233445566778899aabbccddeeff
    //   ciphertext= 69c4e0d86a7b0430d8cdb78070b4c55a
    //
    // AES 把输入块按字节序处理，而我们的 uint128_t 字面量是数值——
    // 因此字节串 00 11 22 ... ff 对应的 u128 值是字节倒序。
    // 同理密文 69 c4 e0 ... 5a 对应的 u128 是 5a c5 b4 ... 69。
    const uint128_t plain = 0xffeeddccbbaa99887766554433221100_k;
    const uint128_t expected_ct = 0x5ac5b47080b7cdd830047b6ad8e0c469_k;
    const AesPrf prf = MakePrf();  // key = 00 01 02 ... 0f
    EXPECT_EQ(prf.Eval(plain), expected_ct);
}

TEST(AesPrf, DeterministicForSameKeyAndInput) {
    const AesPrf prf = MakePrf();
    EXPECT_EQ(prf.Eval(42), prf.Eval(42));
    EXPECT_EQ(prf.Eval(0), prf.Eval(0));
    EXPECT_EQ(prf.EvalDomainU32(PrfDomain::kSelect, 1, 2),
              prf.EvalDomainU32(PrfDomain::kSelect, 1, 2));
}

TEST(AesPrf, DifferentKeysGiveDifferentOutputs) {
    const AesPrf a = MakePrf();
    std::vector<uint8_t> key2(16, 0xAB);
    const AesPrf b(key2);
    EXPECT_NE(a.Eval(0), b.Eval(0));
    EXPECT_NE(a.Eval(12345), b.Eval(12345));
}

TEST(AesPrf, PermutationForFixedKey) {
    // 固定密钥下 AES 是双射：不同输入必得不同输出
    const AesPrf prf = MakePrf();
    const uint128_t inputs[] = {0, 1, 2, 0xffffffffffffffff_k, 0x8000000000000000_k,
                               0x0123456789abcdef_k, ~static_cast<uint128_t>(0)};
    for (size_t i = 0; i < 7; ++i) {
        for (size_t j = i + 1; j < 7; ++j) {
            EXPECT_NE(prf.Eval(inputs[i]), prf.Eval(inputs[j]));
        }
    }
    // 单比特翻转必然改变输出（雪崩的最弱要求）
    EXPECT_NE(prf.Eval(0), prf.Eval(1));
}

TEST(AesPrf, EvalBatchMatchesEvalOneByOne) {
    const AesPrf prf = MakePrf();
    const size_t n = 37;  // 非 4/8 对齐，检验边界
    std::vector<uint128_t> in(n), out(n);
    for (size_t i = 0; i < n; ++i) {
        in[i] = static_cast<uint128_t>(i) * 0x9E3779B97F4A7C15_k;
    }
    prf.EvalBatch(in.data(), out.data(), n);
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(out[i], prf.Eval(in[i]));
    }
}

TEST(AesPrf, EvalBatchHandlesZeroCount) {
    const AesPrf prf = MakePrf();
    uint128_t dummy = 0;
    prf.EvalBatch(&dummy, &dummy, 0);  // 不应崩溃或访问内存
    EXPECT_EQ(dummy, static_cast<uint128_t>(0));
}

// ---------------------------------------------------------------------------
// 密钥处理
// ---------------------------------------------------------------------------

TEST(AesPrf, RejectsWrongKeyLength) {
    EXPECT_THROW(AesPrf(std::vector<uint8_t>(15, 0)), std::invalid_argument);
    EXPECT_THROW(AesPrf(std::vector<uint8_t>(17, 0)), std::invalid_argument);
    EXPECT_THROW(AesPrf(std::vector<uint8_t>()), std::invalid_argument);
    EXPECT_THROW(AesPrf(std::vector<uint8_t>(32, 0)), std::invalid_argument);  // AES-256 不接受
    // 正确长度可以构造
    const AesPrf ok(std::vector<uint8_t>(16, 0x5A));
    EXPECT_EQ(ok.key()[0], static_cast<uint8_t>(0x5A));
}

TEST(AesPrf, GenerateKeyProducesRandomKeys) {
    const auto k1 = AesPrf::GenerateKey();
    const auto k2 = AesPrf::GenerateKey();
    EXPECT_NE(k1, k2);  // 概率 2^-128 才相等
    // 不应是全零
    bool all_zero = true;
    for (uint8_t b : k1) {
        if (b != 0) all_zero = false;
    }
    EXPECT_FALSE(all_zero);
}

TEST(AesPrf, DefaultConstructorUsesRandomKey) {
    const AesPrf a;
    const AesPrf b;
    EXPECT_NE(a.key(), b.key());
    EXPECT_NE(a.Eval(0), b.Eval(0));
}

// ---------------------------------------------------------------------------
// 域分隔
// ---------------------------------------------------------------------------

TEST(AesPrf, EvalDomainU32MatchesManualBlockLayout) {
    // in[1] = (domain << 16) | w1
    const AesPrf prf = MakePrf();
    const uint32_t w0 = 7;
    const uint32_t w1 = 0x1234;
    const uint32_t expected_block_word1 =
        (static_cast<uint32_t>(PrfDomain::kOffset) << 16) | w1;

    // 手工构造同样的输入块，走通用 Eval 路径
    const auto block = Block(w0, expected_block_word1);
    uint128_t manual = 0;
    for (size_t i = 0; i < 16; ++i) {
        manual |= static_cast<uint128_t>(block[i]) << (8 * i);
    }
    EXPECT_EQ(prf.EvalDomainU32(PrfDomain::kOffset, w0, w1), prf.Eval(manual));
}

TEST(AesPrf, DomainsAreSeparated) {
    // 同一 w0/w1、不同域必须给出不同输出（否则域分隔失效）
    const AesPrf prf = MakePrf();
    const uint128_t dummy = prf.EvalDomainU32(PrfDomain::kDummyOffset, 1, 2);
    const uint128_t sel = prf.EvalDomainU32(PrfDomain::kSelect, 1, 2);
    const uint128_t off = prf.EvalDomainU32(PrfDomain::kOffset, 1, 2);
    EXPECT_NE(dummy, sel);
    EXPECT_NE(dummy, off);
    EXPECT_NE(sel, off);
}

TEST(AesPrf, EvalDomainU32RejectsOversizedW1) {
    const AesPrf prf = MakePrf();
    EXPECT_THROW(prf.EvalDomainU32(PrfDomain::kSelect, 0, 0x10000),
                 std::invalid_argument);
    EXPECT_THROW(prf.EvalDomainU32(PrfDomain::kSelect, 0, 0xFFFFFFFF),
                 std::invalid_argument);
    // 边界 0xFFFF 允许
    EXPECT_EQ(prf.EvalDomainU32(PrfDomain::kSelect, 0, 0xFFFF),
              prf.EvalDomainU32(PrfDomain::kSelect, 0, 0xFFFF));
}

// ---------------------------------------------------------------------------
// 批量拆分与 S3PIR 兼容封装
// ---------------------------------------------------------------------------

TEST(AesPrf, SelectBatchSplitsIntoFourU32LE) {
    const AesPrf prf = MakePrf();
    uint32_t vals[4];
    prf.PrfBatchSelect(3, 5, vals);
    const uint128_t raw = prf.EvalDomainU32(PrfDomain::kSelect, 3, 5);
    for (size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(vals[i], static_cast<uint32_t>(raw >> (32 * i)));
    }
}

TEST(AesPrf, OffsetBatchSplitsIntoEightU16LE) {
    const AesPrf prf = MakePrf();
    uint16_t vals[8];
    prf.PrfBatchIdx(9, 2, vals);
    const uint128_t raw = prf.EvalDomainU32(PrfDomain::kOffset, 9, 2);
    for (size_t i = 0; i < 8; ++i) {
        EXPECT_EQ(vals[i], static_cast<uint16_t>(raw >> (16 * i)));
    }
}

TEST(AesPrf, PrfSelectIndividualMatchesBatch) {
    // PrfSelect(hint, k) 必须等于同批 4 个值中的第 k%4 个
    const AesPrf prf = MakePrf();
    for (uint32_t part = 0; part < 16; ++part) {
        uint32_t batch[4];
        prf.PrfBatchSelect(11, part / 4, batch);
        EXPECT_EQ(prf.PrfSelect(11, part), batch[part % 4]);
    }
}

TEST(AesPrf, PrfIdxIndividualMatchesBatchAndReduces) {
    const AesPrf prf = MakePrf();
    const uint32_t part_size = 1024;  // 2 的幂
    for (uint32_t part = 0; part < 16; ++part) {
        uint16_t batch[8];
        prf.PrfBatchIdx(11, part / 8, batch);
        const uint16_t v = prf.PrfIdx(11, part, part_size);
        EXPECT_EQ(v, static_cast<uint16_t>(batch[part % 8] & (part_size - 1)));
        EXPECT_TRUE(v < part_size);
    }
}

TEST(AesPrf, NextDummyOffsetIsDeterministicAndInRange) {
    const AesPrf prf = MakePrf();
    const uint32_t part_size = 4096;
    for (uint64_t cnt = 0; cnt < 24; ++cnt) {
        const uint16_t v = prf.NextDummyOffset(cnt, part_size);
        EXPECT_EQ(v, prf.NextDummyOffset(cnt, part_size));  // 确定性
        EXPECT_TRUE(v < part_size);
    }
    // 同一批（cnt 0..7）内应互不相同：AES 输出块的双射性质
    // 注意归约到 part_size 后有可能碰撞，因此这里只检查原始分组相同
    uint16_t batch[8];
    prf.EvalOffsetBatch(PrfDomain::kDummyOffset, 0, 0, batch);
    EXPECT_EQ(prf.NextDummyOffset(0, part_size),
              static_cast<uint16_t>(batch[0] & (part_size - 1)));
    EXPECT_EQ(prf.NextDummyOffset(7, part_size),
              static_cast<uint16_t>(batch[7] & (part_size - 1)));
}

TEST(AesPrf, NextDummyOffsetRejectsCounterOverflow) {
    const AesPrf prf = MakePrf();
    // cnt/8 超过 16 位即无法编码进输入块
    EXPECT_THROW(prf.NextDummyOffset(8ull * 0x10000ull, 1024), std::invalid_argument);
    // 边界允许
    EXPECT_EQ(prf.NextDummyOffset(8ull * 0xFFFFull + 7, 1024),
              prf.NextDummyOffset(8ull * 0xFFFFull + 7, 1024));
}

TEST(AesPrf, DummyStreamDoesNotRepeatWithinBatch) {
    // 同一批 8 个 uint16 来自同一 AES 输出块，互不相同（块是双射，但
    // uint16 切分之间理论上可碰撞；这里用具体密钥验证实际不碰撞）
    const AesPrf prf = MakePrf();
    uint16_t batch[8];
    prf.EvalOffsetBatch(PrfDomain::kDummyOffset, 0, 0, batch);
    for (size_t i = 0; i < 8; ++i) {
        for (size_t j = i + 1; j < 8; ++j) {
            EXPECT_NE(batch[i], batch[j]);
        }
    }
}

// ===========================================================================
// DeterministicPrng（测试用确定性随机源；D6 的可复现性依赖它）
// ===========================================================================

namespace {
std::array<uint8_t, kAesKeyBytes> PrngKey(uint8_t fill) {
    std::array<uint8_t, kAesKeyBytes> k{};
    k.fill(fill);
    return k;
}
}  // namespace

TEST(DeterministicPrng, IsReproducibleForSameKeyAndNonce) {
    const auto key = PrngKey(0x11);
    random::DeterministicPrng a(key, 7);
    random::DeterministicPrng b(key, 7);
    for (int i = 0; i < 8; ++i) EXPECT_EQ(a.Next(), b.Next());
    // Reset 之后必须能原样重放
    a.Reset();
    random::DeterministicPrng c(key, 7);
    for (int i = 0; i < 8; ++i) EXPECT_EQ(a.Next(), c.Next());
}

TEST(DeterministicPrng, UsesAllNonceBits) {
    // ⚠️ 回归用例：早期实现用 `nonce >> 32`，于是"只有低 32 位不同"的 nonce
    // 产出**完全相同**的密钥流（seed 99 与 100 一模一样）。
    const auto key = PrngKey(0x22);
    const auto stream = [&key](uint64_t nonce, int n) {
        random::DeterministicPrng p(key, nonce);
        std::vector<uint128_t> out;
        for (int i = 0; i < n; ++i) out.push_back(p.Next());
        return out;
    };
    EXPECT_TRUE(stream(99, 4) != stream(100, 4));          // 低 32 位必须参与
    EXPECT_TRUE(stream(0, 4) != stream(uint64_t{1} << 32, 4));  // 高 32 位也要参与
    EXPECT_TRUE(stream(1, 4) != stream((uint64_t{1} << 32) | 1, 4));
    // 不同密钥、同一 nonce 也要不同
    random::DeterministicPrng other(PrngKey(0x23), 99);
    EXPECT_TRUE(other.Next() != stream(99, 1)[0]);
}

TEST(DeterministicPrng, SupportsLongStreams) {
    // ⚠️ 回归用例：早期 counter 只有 16 位 ⇒ 第 65536 个块就抛异常（1 MiB 上限）
    const auto key = PrngKey(0x33);
    random::DeterministicPrng p(key, 3);
    constexpr uint64_t kN = 70000;  // > 2^16
    uint128_t acc = 0;
    for (uint64_t i = 0; i < kN; ++i) acc = static_cast<uint128_t>(acc ^ p.Next());
    EXPECT_TRUE(acc != 0);
    const uint128_t after = p.Next();
    random::DeterministicPrng q(key, 3);
    uint128_t same = 0;
    for (uint64_t i = 0; i <= kN; ++i) same = q.Next();
    EXPECT_EQ(after, same);
}

TEST(DeterministicPrng, BelowIsInRangeAndDeterministic) {
    const auto key = PrngKey(0x44);
    random::DeterministicPrng a(key, 5);
    random::DeterministicPrng b(key, 5);
    for (uint32_t i = 0; i < 64; ++i) {
        const uint128_t bound = static_cast<uint128_t>(1000 + i);
        const uint128_t x = a.Below(bound);
        EXPECT_TRUE(x < bound);
        EXPECT_EQ(x, b.Below(bound));
    }
    EXPECT_THROW(a.Below(0), std::invalid_argument);
}
