#include "core/field.hpp"
#include "test_framework.hpp"

#include <stdexcept>
#include <string>

using namespace tsb;

namespace {
constexpr uint128_t kMax = ~static_cast<uint128_t>(0);
// 2^127 - 1 是梅森素数，用作 modInverse 的素域测试模数
constexpr uint128_t kMersenne127 = (static_cast<uint128_t>(1) << 127) - 1;
}  // namespace

// ---------------------------------------------------------------------------
// Z_{2^128} 环运算
// ---------------------------------------------------------------------------

TEST(Field, AddWrapsAround) {
    EXPECT_EQ(add(kMax, static_cast<uint128_t>(1)), static_cast<uint128_t>(0));
    EXPECT_EQ(add(kMax, kMax), kMax - static_cast<uint128_t>(1));
    EXPECT_EQ(add(static_cast<uint128_t>(7), static_cast<uint128_t>(0)),
              static_cast<uint128_t>(7));
}

TEST(Field, SubWrapsAround) {
    EXPECT_EQ(sub(static_cast<uint128_t>(0), static_cast<uint128_t>(1)), kMax);
    EXPECT_EQ(sub(static_cast<uint128_t>(5), static_cast<uint128_t>(5)),
              static_cast<uint128_t>(0));
}

TEST(Field, AddSubAreInverse) {
    const uint128_t vals[] = {0, 1, 42, kMax, kMax - 1,
                              static_cast<uint128_t>(1) << 127};
    for (uint128_t a : vals) {
        for (uint128_t b : vals) {
            EXPECT_EQ(sub(add(a, b), b), a);
        }
    }
}

TEST(Field, NegIsAdditiveInverse) {
    EXPECT_EQ(add(neg(static_cast<uint128_t>(12345)), static_cast<uint128_t>(12345)),
              static_cast<uint128_t>(0));
    EXPECT_EQ(neg(static_cast<uint128_t>(0)), static_cast<uint128_t>(0));
}

TEST(Field, MulBasics) {
    EXPECT_EQ(mul(static_cast<uint128_t>(0), kMax), static_cast<uint128_t>(0));
    EXPECT_EQ(mul(static_cast<uint128_t>(1), kMax), kMax);
    EXPECT_EQ(mul(static_cast<uint128_t>(2), kMax), kMax - static_cast<uint128_t>(1));
    // 交换律
    EXPECT_EQ(mul(static_cast<uint128_t>(123456789), static_cast<uint128_t>(987654321)),
              mul(static_cast<uint128_t>(987654321), static_cast<uint128_t>(123456789)));
    // (2^64) * (2^64) = 2^128 ≡ 0
    const uint128_t t64 = static_cast<uint128_t>(1) << 64;
    EXPECT_EQ(mul(t64, t64), static_cast<uint128_t>(0));
}

TEST(Field, MulDistributes) {
    const uint128_t a = 0x0123456789abcdef_k;
    const uint128_t b = 0xfedcba9876543210_k;
    const uint128_t c = 12345678901234567_k;
    EXPECT_EQ(mul(a, add(b, c)), add(mul(a, b), mul(a, c)));
}

TEST(Field, MulBy2Pow127OnlyCoincidesWithHalvingForTinyInputs) {
    // ⚠️ 关键事实：2 在 Z_{2^128} 中不可逆（gcd(2, 2^128) = 2），
    // 不存在 2^{-1}。2^127 本身是偶数、是零因子（2^127 * 2 == 0）。
    // 所以"乘以 2^{-1}"并非除法：只有 x == 2 时 2^127 * x 恰好 == 1。
    //
    // 这直接影响 SecureMul：论文公式 e*d*2^{-1} 要求 2 可逆，
    // 在 Z_{2^k} 上对奇数 e*d 不成立（见 TASK_PLAN §7.6 Q1）。
    EXPECT_EQ(mulBy2Pow127(static_cast<uint128_t>(0)), static_cast<uint128_t>(0));
    // 2^127 * 2 == 2^128 ≡ 0：连 x == 2 都没有除法语义
    EXPECT_EQ(mulBy2Pow127(static_cast<uint128_t>(2)), static_cast<uint128_t>(0));
    // 更大的偶数会回绕，不再等于 x/2
    const uint128_t big_even = 100;
    EXPECT_NE(mulBy2Pow127(big_even), big_even / 2);
    // 正确的除法用移位
    EXPECT_EQ(shr(big_even, 1), static_cast<uint128_t>(50));
    // 2^127 是零因子
    EXPECT_EQ(mul(pow2_127(), static_cast<uint128_t>(2)), static_cast<uint128_t>(0));
    // 2^127 * 2^127 == 0（2^254 mod 2^128）
    EXPECT_EQ(mul(pow2_127(), pow2_127()), static_cast<uint128_t>(0));
    // 兼容别名与主名一致
    EXPECT_EQ(mulHalf(big_even), mulBy2Pow127(big_even));
    EXPECT_EQ(inv2Pow2k(), pow2_127());
}

TEST(Field, OddNumbersCannotBeHalvedInPow2Ring) {
    // 奇数在 Z_{2^128} 中无法"除以 2"：不存在 x 使 2x == odd
    const uint128_t odd = 0x123456789abcdef1_k;
    EXPECT_EQ(mul(mulBy2Pow127(odd), static_cast<uint128_t>(2)), static_cast<uint128_t>(0));
    // shr 只对偶数给出 x/2；对奇数给出向下取整，且 2*shr != odd
    EXPECT_NE(mul(shr(odd, 1), static_cast<uint128_t>(2)), odd);
}

// ---------------------------------------------------------------------------
// 位操作
// ---------------------------------------------------------------------------

TEST(Field, ShiftHandlesBoundary) {
    const uint128_t v = 0xffffffffffffffff_k;
    EXPECT_EQ(shl(v, 0), v);
    EXPECT_EQ(shl(v, 64), static_cast<uint128_t>(0xffffffffffffffff_k) << 64);
    EXPECT_EQ(shl(v, 128), static_cast<uint128_t>(0));
    EXPECT_EQ(shl(v, 200), static_cast<uint128_t>(0));
    EXPECT_EQ(shr(v, 0), v);
    EXPECT_EQ(shr(v, 128), static_cast<uint128_t>(0));
    EXPECT_EQ(shr(v, 200), static_cast<uint128_t>(0));
}

TEST(Field, HighLowSplit) {
    const uint128_t v = 0x0123456789abcdeffedcba9876543210_k;
    EXPECT_EQ(high64(v), 0x0123456789abcdefULL);
    EXPECT_EQ(low64(v), 0xfedcba9876543210ULL);
    EXPECT_EQ(from64(high64(v), low64(v)), v);
}

// ---------------------------------------------------------------------------
// 模幂次逆元
// ---------------------------------------------------------------------------

TEST(Field, ModInversePow2InvertsOddNumbers) {
    // 全部为奇数（注意 0x...be 是偶数，不能放进这个列表）
    const uint128_t odds[] = {1, 3, 5, 7, 123456789, 0xdeadbeefcafebabf_k,
                              kMax, kMax - 2, pow2_127() + 1};
    for (uint128_t a : odds) {
        EXPECT_EQ(a & 1u, static_cast<uint128_t>(1));
        const uint128_t inv = modInversePow2(a, 128);
        // a * a^{-1} ≡ 1 (mod 2^128)
        EXPECT_EQ(mul(a, inv), static_cast<uint128_t>(1));
    }
}

TEST(Field, ModInversePow2RejectsEvenInput) {
    // 偶数在 2 的幂环中不可逆（gcd(2,2^k) != 1），必须显式拒绝而不是静默返回错值。
    // 注意 2^127 也是偶数，同样不可逆。
    EXPECT_THROW(modInversePow2(static_cast<uint128_t>(2), 128), std::invalid_argument);
    EXPECT_THROW(modInversePow2(static_cast<uint128_t>(4), 128), std::invalid_argument);
    EXPECT_THROW(modInversePow2(static_cast<uint128_t>(0), 128), std::invalid_argument);
    EXPECT_THROW(modInversePow2(pow2_127(), 128), std::invalid_argument);
    EXPECT_THROW(modInversePow2(pow2_127() * 2, 128), std::invalid_argument);
}

TEST(Field, ModInversePow2RejectsBadK) {
    EXPECT_THROW(modInversePow2(static_cast<uint128_t>(3), 0), std::invalid_argument);
    EXPECT_THROW(modInversePow2(static_cast<uint128_t>(3), 129), std::invalid_argument);
}

TEST(Field, ModInversePow2SmallK) {
    // mod 2^8 下 3 的逆元是 171（3*171 = 513 = 2*256 + 1）
    EXPECT_EQ(modInversePow2(static_cast<uint128_t>(3), 8), static_cast<uint128_t>(171));
    EXPECT_EQ(modInversePow2(static_cast<uint128_t>(1), 8), static_cast<uint128_t>(1));
}

TEST(Field, Pow2_127IsEvenZeroDivisorNotInverse) {
    // 2^127 是偶数 ⇒ mod 2^128 下不可逆，是零因子
    EXPECT_EQ(pow2_127() & 1u, static_cast<uint128_t>(0));
    EXPECT_EQ(mul(pow2_127(), static_cast<uint128_t>(2)), static_cast<uint128_t>(0));
    EXPECT_THROW(modInversePow2(pow2_127(), 128), std::invalid_argument);
    // 但它模 2^127 时等价于 0，模其他奇数是可逆的
    EXPECT_EQ(reduce(pow2_127(), static_cast<uint128_t>(7)),
              static_cast<uint128_t>(2));  // 2^127 mod 7 = 2
}

// ---------------------------------------------------------------------------
// 一般模幂次逆元（扩展欧几里得）
// ---------------------------------------------------------------------------

TEST(Field, ModInverseGeneral) {
    // 小模数，与 Python pow(a,-1,m) 的结果逐一对照
    EXPECT_EQ(modInverse(static_cast<uint128_t>(3), static_cast<uint128_t>(7)),
              static_cast<uint128_t>(5));  // 3*5 = 15 = 2*7+1
    EXPECT_EQ(modInverse(static_cast<uint128_t>(2), static_cast<uint128_t>(7)),
              static_cast<uint128_t>(4));  // 2*4 = 8 = 7+1
    EXPECT_EQ(modInverse(static_cast<uint128_t>(1), static_cast<uint128_t>(7)),
              static_cast<uint128_t>(1));
    // 大数（运行期输入 > 模数）走 reduce 预归约路径
    EXPECT_EQ(modInverse(12345678901234567890_k, static_cast<uint128_t>(1000000007)),
              static_cast<uint128_t>(782581696));

    // 梅森素数 2^127-1，与 Python pow(a,-1,m) 结果一致
    const uint128_t a = 12345678901234567890_k;
    EXPECT_EQ(modInverse(a, kMersenne127),
              95987530177320089548629399254220539361_k);

    // 多组值验证 a * a^{-1} ≡ 1 (mod m)
    const uint128_t mods[] = {7, 1000003, 65537, kMersenne127};
    const uint128_t vals[] = {2, 3, 12345, 999999999_k};
    for (uint128_t m : mods) {
        for (uint128_t v : vals) {
            if (v >= m) continue;
            const uint128_t iv = modInverse(v, m);
            EXPECT_EQ(mulMod(v, iv, m), static_cast<uint128_t>(1));
        }
    }
}

TEST(Field, MulModAvoidsOverflow) {
    // 直接 mul 会回绕；mulMod 必须给出正确的模结果
    const uint128_t q = kMersenne127;
    // ⚠️ mulMod 要求 2q <= 2^128（即 q <= 2^127），因为中间量是 256 位、
    // 且以 2^128 位宽的循环实现需要 q 足够小。用 q = 2^127-1 满足该约束。
    const uint128_t a = q - 1;  // ≡ -1
    const uint128_t b = q - 1;  // ≡ -1
    EXPECT_EQ(mulMod(a, b, q), static_cast<uint128_t>(1));

    // (q-1) * 2 ≡ -2 ≡ q-2
    EXPECT_EQ(mulMod(a, static_cast<uint128_t>(2), q), q - static_cast<uint128_t>(2));

    // 与直接相乘在无溢出时一致
    const uint128_t small_q = 1000000007;
    EXPECT_EQ(mulMod(123456, 654321, small_q),
              reduce(mul(static_cast<uint128_t>(123456), static_cast<uint128_t>(654321)),
                     small_q));

    // 大数相乘（直接 mul 会丢高位），与 Python 参照值对照：
    //   0xfedcba9876543210fedcba9876543210 % 1000000007 == 957334187
    //   其平方 % 1000000007 == 183529796
    const uint128_t big = 0xfedcba9876543210fedcba9876543210_k;
    EXPECT_EQ(reduce(big, small_q), static_cast<uint128_t>(957334187));
    EXPECT_EQ(mulMod(big, big, small_q), static_cast<uint128_t>(183529796));
}

TEST(Field, MulModRequiresModulusBelow2Pow127) {
    // 模数必须 <= 2^127 才能保证中间量不回绕；越界应显式报错而非静默给错值
    EXPECT_THROW(mulMod(1, 1, kMax), std::invalid_argument);
    EXPECT_THROW(mulMod(1, 1, (static_cast<uint128_t>(1) << 127) + 1),
                 std::invalid_argument);
    // 边界值 2^127 本身允许
    EXPECT_EQ(mulMod(static_cast<uint128_t>(2), static_cast<uint128_t>(3),
                     static_cast<uint128_t>(1) << 127),
              static_cast<uint128_t>(6));
}

TEST(Field, ModInverseRejectsNonCoprime) {
    EXPECT_THROW(modInverse(static_cast<uint128_t>(4), static_cast<uint128_t>(8)),
                 std::invalid_argument);
    EXPECT_THROW(modInverse(static_cast<uint128_t>(0), static_cast<uint128_t>(7)),
                 std::invalid_argument);
    EXPECT_THROW(modInverse(static_cast<uint128_t>(3), static_cast<uint128_t>(0)),
                 std::invalid_argument);
}

// ---------------------------------------------------------------------------
// reduce / addMod / subMod
// ---------------------------------------------------------------------------

TEST(Field, ReduceBasics) {
    EXPECT_EQ(reduce(static_cast<uint128_t>(10), static_cast<uint128_t>(7)),
              static_cast<uint128_t>(3));
    EXPECT_EQ(reduce(static_cast<uint128_t>(7), static_cast<uint128_t>(7)),
              static_cast<uint128_t>(0));
    EXPECT_EQ(reduce(static_cast<uint128_t>(6), static_cast<uint128_t>(7)),
              static_cast<uint128_t>(6));
    EXPECT_EQ(reduce(static_cast<uint128_t>(0), static_cast<uint128_t>(7)),
              static_cast<uint128_t>(0));
    EXPECT_EQ(reduce(kMax, static_cast<uint128_t>(1)), static_cast<uint128_t>(0));
    // 大数归约，与 Python 对照：
    //   2^128-1 ≡ 3 (mod 7); 2^128-1 ≡ 279632276 (mod 1000000007)
    EXPECT_EQ(reduce(kMax, static_cast<uint128_t>(7)), static_cast<uint128_t>(3));
    EXPECT_EQ(reduce(kMax, static_cast<uint128_t>(1000000007)),
              static_cast<uint128_t>(279632276));
    EXPECT_EQ(reduce(kMersenne127, kMersenne127), static_cast<uint128_t>(0));
}

TEST(Field, ReduceRequiresModulusBelow2Pow127) {
    // 逐位约减的中间量需要 2q 可表示，故 q 必须 <= 2^127。
    // 2^128-1 不是本函数的合法模数（Z_{2^128} 的语义是自然回绕）。
    // 注意必须让 v > q，否则函数在 v < q 时直接返回、走不到校验分支。
    EXPECT_THROW(reduce(kMax, kMax), std::invalid_argument);
    EXPECT_THROW(reduce(kMax, pow2_127() + 1), std::invalid_argument);
    // 边界 2^127 允许（要求 v > q 才会进入约减路径）
    EXPECT_EQ(reduce(pow2_127() + 5, pow2_127()), static_cast<uint128_t>(5));
    EXPECT_EQ(reduce(kMax, kMersenne127), reduce(kMax - kMersenne127, kMersenne127));
}

TEST(Field, ReduceRejectsZeroModulus) {
    EXPECT_THROW(reduce(static_cast<uint128_t>(5), static_cast<uint128_t>(0)),
                 std::invalid_argument);
}

TEST(Field, AddModWraps) {
    const uint128_t q = 100;
    EXPECT_EQ(addMod(static_cast<uint128_t>(60), static_cast<uint128_t>(50), q),
              static_cast<uint128_t>(10));
    EXPECT_EQ(addMod(static_cast<uint128_t>(99), static_cast<uint128_t>(0), q),
              static_cast<uint128_t>(99));
    EXPECT_EQ(addMod(static_cast<uint128_t>(0), static_cast<uint128_t>(0), q),
              static_cast<uint128_t>(0));
}

TEST(Field, AddModWithLargeModulusDoesNotOverflow) {
    // q 接近 2^128 时，a+b 会溢出，必须走条件分支
    const uint128_t q = kMax;  // 2^128 - 1
    const uint128_t a = kMax - 1;
    const uint128_t b = kMax - 1;
    // (q-1) + (q-1) = 2q - 2 ≡ q - 2 (mod q)
    EXPECT_EQ(addMod(a, b, q), q - static_cast<uint128_t>(2));
}

TEST(Field, SubModWraps) {
    const uint128_t q = 100;
    EXPECT_EQ(subMod(static_cast<uint128_t>(10), static_cast<uint128_t>(30), q),
              static_cast<uint128_t>(80));
    EXPECT_EQ(subMod(static_cast<uint128_t>(30), static_cast<uint128_t>(30), q),
              static_cast<uint128_t>(0));
}

TEST(Field, AddSubModAreInverse) {
    // 用最大合法模数 2^127-1（2^128-1 超出 reduce 的约束，见
    // ReduceRequiresModulusBelow2Pow127）
    const uint128_t q = kMersenne127;
    const uint128_t vals[] = {0, 1, 12345, q - 1, q / 2};
    for (uint128_t a : vals) {
        for (uint128_t b : vals) {
            EXPECT_EQ(subMod(addMod(a, b, q), b, q), reduce(a, q));
        }
    }
}

// ---------------------------------------------------------------------------
// 序列化
// ---------------------------------------------------------------------------

TEST(Field, ByteRoundTrip) {
    const uint128_t vals[] = {0, 1, kMax, 0x0123456789abcdeffedcba9876543210_k,
                              static_cast<uint128_t>(1) << 127};
    for (uint128_t v : vals) {
        uint8_t buf[kUint128Bytes];
        toBytesLE(v, buf);
        EXPECT_EQ(fromBytesLE(buf), v);
        const std::vector<uint8_t> vec = toBytes(v);
        EXPECT_EQ(vec.size(), kUint128Bytes);
        EXPECT_EQ(fromBytes(vec.data(), vec.size()), v);
    }
}

TEST(Field, ByteLayoutIsLittleEndian) {
    uint8_t buf[kUint128Bytes];
    toBytesLE(static_cast<uint128_t>(1), buf);
    EXPECT_EQ(static_cast<int>(buf[0]), 1);
    EXPECT_EQ(static_cast<int>(buf[1]), 0);
    EXPECT_EQ(static_cast<int>(buf[15]), 0);

    toBytesLE(static_cast<uint128_t>(1) << 127, buf);
    EXPECT_EQ(static_cast<int>(buf[15]), 0x80);
    EXPECT_EQ(static_cast<int>(buf[0]), 0);
}

TEST(Field, FromBytesHandlesShortInput) {
    const uint8_t two_bytes[2] = {0x34, 0x12};
    EXPECT_EQ(fromBytes(two_bytes, 2), static_cast<uint128_t>(0x1234));
}

// ---------------------------------------------------------------------------
// 字符串渲染与解析
// ---------------------------------------------------------------------------

TEST(Field, ToStringMatchesValue) {
    EXPECT_EQ(toString(static_cast<uint128_t>(0)), std::string("0"));
    EXPECT_EQ(toString(static_cast<uint128_t>(1234567890)), std::string("1234567890"));
    // 2^128-1 = 340282366920938463463374607431768211455
    EXPECT_EQ(toString(kMax),
              std::string("340282366920938463463374607431768211455"));
}

TEST(Field, ToHexIsFixedWidth) {
    EXPECT_EQ(toHex(static_cast<uint128_t>(0)),
              std::string("0x00000000000000000000000000000000"));
    EXPECT_EQ(toHex(static_cast<uint128_t>(255)),
              std::string("0x000000000000000000000000000000ff"));
    EXPECT_EQ(toHex(kMax),
              std::string("0xffffffffffffffffffffffffffffffff"));
}

TEST(Field, ParseRoundTrip) {
    const uint128_t vals[] = {0, 1, 255, kMax, 12345678901234567890_k};
    for (uint128_t v : vals) {
        EXPECT_EQ(parse(toString(v)), v);
        EXPECT_EQ(parse(toHex(v)), v);
    }
    EXPECT_EQ(parse("0xdeadBEEF"), static_cast<uint128_t>(0xdeadbeef));
}

TEST(Field, ParseRejectsGarbage) {
    EXPECT_THROW(parse(""), std::invalid_argument);
    EXPECT_THROW(parse("12x3"), std::invalid_argument);
    EXPECT_THROW(parse("0x"), std::invalid_argument);
    // 超出 128-bit
    EXPECT_THROW(parse("340282366920938463463374607431768211456"), std::invalid_argument);
}

TEST(Field, ParseAcceptsMaxValue) {
    EXPECT_EQ(parse("340282366920938463463374607431768211455"), kMax);
}

