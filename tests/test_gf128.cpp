// `test_gf128` —— `GF(2^128)` 的域公理、不可约性与同态性（xmac 的地基）。
//
// ===========================================================================
// 为什么这份测试很重要
// ===========================================================================
// xmac 的**全部**正确性都压在这一层上（`M_b = γ ⊙ R_b`）。而它此前只有一份
// `doc/evidence/gf128/probe_gf128.cpp` 的独立探针 —— 那份探针**不在 `ctest` 里**
// （`doc/` 还不在版本控制内）⇒ 这一层实际上**没有回归网**。
// 本文件把探针转成正式用例，并补上几条**独立可推导**的判据。
//
// ===========================================================================
// 判据分两类（这一点决定了测试的价值）
// ===========================================================================
// ① **独立可推导的恒等式** —— 不依赖实现，从"bit k ↔ x^k、P = x^128+x^7+x^2+x+1"
//    直接推出来。它们是真正能抓错的那一类：
//      * `x^i · x^j = x^(i+j)`（i+j < 128）⇒ 位序约定正确；
//      * `x^i · x^j = x^(i+j-128) · 0x87`（i+j >= 128）⇒ 约简多项式正确；
//      * `Gf128Mul(a, 2) == Gf128Xtime(a)`；
//      * `a · 1 = a`、`a · 0 = 0`。
//    ⚠️ 这几条能**独立**抓住两类最危险的错误：GCM 式 bit-reflection（会让
//       `x^i · x^j` 给出 `x^(127-i-j)` 量级的结果）、以及写错约简常数。
// ② **代数性质的随机抽查** —— 交换/结合/分配/逆元/单射。
// ③ **不可约性的严格证明** —— 见 `Gf128IsIrreducibleByGeneratorOrder`。

#include <array>
#include <cstdint>
#include <random>
#include <vector>

#include "core/gf128.hpp"
#include "core/random.hpp"
#include "test_framework.hpp"

namespace {

using namespace tsb;

// 确定性随机源（铁律 D6：测试不得依赖进程随机）
uint128_t Rand(std::mt19937_64& g) {
    return (static_cast<uint128_t>(g()) << 64) | g();
}

std::string Hex(uint128_t v) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (int i = 31; i >= 0; --i) s.push_back(d[(v >> (4 * i)) & 0xF]);
    return s;
}

}  // namespace

// ---------------------------------------------------------------------------
// G1：**位序与约简多项式**（独立可推导 —— 最能抓错的一组）
// ---------------------------------------------------------------------------

TEST(Gf128, BitOrderAndReductionPolynomial) {
    // bit k ↔ x^k ⇒ x^i · x^j = x^(i+j)（未溢出时）
    for (int i = 0; i < 128; ++i) {
        for (int j = 0; j < 128 - i; ++j) {
            const uint128_t a = static_cast<uint128_t>(1) << i;
            const uint128_t b = static_cast<uint128_t>(1) << j;
            const uint128_t want = static_cast<uint128_t>(1) << (i + j);
            if (Gf128Mul(a, b) != want) {
                TSB_FAIL_("x^" + std::to_string(i) + " · x^" + std::to_string(j) +
                          " != x^" + std::to_string(i + j) + "（位序约定被破坏？得到 " +
                          Hex(Gf128Mul(a, b)) + "）");
                return;
            }
        }
    }

    // 溢出时：x^128 = x^7 + x^2 + x + 1 = 0x87 ⇒ x^i · x^j = x^(i+j-128) · 0x87
    // ⚠️ 这条**独立**验证约简常数与多项式的对应关系（位序对了但约简常数写错会在这里挂）
    for (int i = 128 - 7; i < 128; ++i) {
        for (int j = 128 - i; j < 128; ++j) {
            const uint128_t a = static_cast<uint128_t>(1) << i;
            const uint128_t b = static_cast<uint128_t>(1) << j;
            const uint128_t want = Gf128Mul(static_cast<uint128_t>(1) << (i + j - 128), 0x87u);
            if (Gf128Mul(a, b) != want) {
                TSB_FAIL_("x^" + std::to_string(i) + " · x^" + std::to_string(j) +
                          " 的约简结果不等于 x^" + std::to_string(i + j - 128) +
                          " · 0x87（约简多项式 x^128+x^7+x^2+x+1 被破坏？）");
                return;
            }
        }
    }

    // 均匀抽查若干 (i, j) 覆盖全部溢出区间
    std::mt19937_64 g(20241008);
    for (int t = 0; t < 4000; ++t) {
        const int i = static_cast<int>(g() % 128);
        const int j = static_cast<int>(g() % 128);
        const uint128_t a = static_cast<uint128_t>(1) << i;
        const uint128_t b = static_cast<uint128_t>(1) << j;
        const int s = i + j;
        const uint128_t want = (s < 128) ? (static_cast<uint128_t>(1) << s)
                                         : Gf128Mul(static_cast<uint128_t>(1) << (s - 128), 0x87u);
        if (Gf128Mul(a, b) != want) {
            TSB_FAIL_("随机单项式乘法与多项式约定不符（i=" + std::to_string(i) +
                      ", j=" + std::to_string(j) + "）");
            return;
        }
    }

    // xtime 与"乘 x"必须一致 —— 这条直接锁住 `0x87` 的用法
    for (int t = 0; t < 4000; ++t) {
        const uint128_t a = Rand(g);
        if (Gf128Mul(a, 2) != Gf128Xtime(a)) {
            TSB_FAIL_("a · 2 != Gf128Xtime(a)（x 的乘法与 xtime 不一致）");
            return;
        }
        // xtime 的定义逐位可验证：左移一位，最高位为 1 时异或 0x87
        const uint128_t shifted = static_cast<uint128_t>(a << 1);
        const uint128_t want =
            ((a >> 127) & 1) ? static_cast<uint128_t>(shifted ^ 0x87u) : shifted;
        EXPECT_EQ(Gf128Xtime(a), want);
    }
}

// ---------------------------------------------------------------------------
// G2：域公理（交换 / 结合 / 分配 / 单位元 / 零元）
// ---------------------------------------------------------------------------

TEST(Gf128, FieldAxioms) {
    std::mt19937_64 g(12345);
    bool comm = true, assoc = true, dist = true, id = true, zero = true;
    for (int i = 0; i < 20000; ++i) {
        const uint128_t a = Rand(g), b = Rand(g), c = Rand(g);
        if (Gf128Mul(a, b) != Gf128Mul(b, a)) comm = false;
        if (Gf128Mul(Gf128Mul(a, b), c) != Gf128Mul(a, Gf128Mul(b, c))) assoc = false;
        if (Gf128Mul(a, b ^ c) != (Gf128Mul(a, b) ^ Gf128Mul(a, c))) dist = false;
        if (Gf128Mul(a, 1) != a) id = false;
        if (Gf128Mul(a, 0) != 0) zero = false;
    }
    EXPECT_TRUE(comm);
    EXPECT_TRUE(assoc);
    EXPECT_TRUE(dist);
    EXPECT_TRUE(id);
    EXPECT_TRUE(zero);

    // 平方（`Gf128SquarePow(a, 1)`）必须等于 `a · a`
    for (int i = 0; i < 2000; ++i) {
        const uint128_t a = Rand(g);
        EXPECT_EQ(Gf128SquarePow(a, 1), Gf128Mul(a, a));
        EXPECT_EQ(Gf128SquarePow(a, 0), a);            // a^(2^0)
    }
}

// ---------------------------------------------------------------------------
// G3：逆元与单射性（**xmac 能检出偏差的根本原因**）
// ---------------------------------------------------------------------------

TEST(Gf128, InverseAndInjectivity) {
    std::mt19937_64 g(999);
    for (int i = 0; i < 1000; ++i) {
        uint128_t a = Rand(g);
        if (a == 0) continue;
        if (Gf128Mul(a, Gf128Inv(a)) != 1) {
            TSB_FAIL_("a · a^{-1} != 1（a = " + Hex(a) + "）");
            return;
        }
    }
    // γ != 0 ⇒ 映射 x ↦ γ·x **单射**（等价形式：d != 0 ⇒ γ·d != 0）。
    // ⚠️ 这正是"环不行、必须用域"的落点：在 Z_{2^k} 上这条不成立，
    //    恶意服务器就能返回任意错值而校验照过（论文 :137-141）。
    for (int i = 0; i < 20000; ++i) {
        const uint128_t gamma = Rand(g) | 1;
        uint128_t d = Rand(g);
        if (d == 0) d = 1;
        if (Gf128Mul(gamma, d) == 0) {
            TSB_FAIL_("γ != 0 且 d != 0 却算出 γ·d == 0（非单射 ⇒ xmac 失效）");
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// G4：xmac 所需的同态性（`γ ⊙ (a ⊕ b) == γ⊙a ⊕ γ⊙b`）
// ---------------------------------------------------------------------------

TEST(Gf128, XorHomomorphism) {
    std::mt19937_64 g(4242);
    for (int i = 0; i < 20000; ++i) {
        const uint128_t gamma = Rand(g) | 1;
        const uint128_t a = Rand(g), b = Rand(g);
        if (Gf128Mul(gamma, a ^ b) != (Gf128Mul(gamma, a) ^ Gf128Mul(gamma, b))) {
            TSB_FAIL_("γ·(a⊕b) != γ·a ⊕ γ·b —— xmac 的核心等式不成立");
            return;
        }
    }
    // **论文 Lemma `lem:pir` 的场景**：两台一致偏移 δ ⇒ tag 偏差 ε = γ·δ。
    // δ != 0 ⇒ ε != 0 ⇒ **必然被检出**（这就是安全界 1/(2^128-1) 的来源）。
    for (int i = 0; i < 5000; ++i) {
        const uint128_t gamma = Rand(g) | 1;
        uint128_t delta = Rand(g);
        if (delta == 0) continue;
        if (Gf128Mul(gamma, delta) == 0) {
            TSB_FAIL_("非零偏差 δ 的 tag 偏差 γ·δ == 0（篡改会被静默放过）");
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// G5：不可约性的**严格证明**：验证 `x` 是乘法群的生成元
// ---------------------------------------------------------------------------
//
// 思路（不依赖任何查表或外部结论）：
//   * `2^128 − 1 = ∏ p_i`（下列素因子），若 `x^(2^128−1) == 1` 且对**每个** p_i
//     都有 `x^((2^128−1)/p_i) != 1`，则 `x` 的阶恰为 `2^128 − 1`；
//   * 阶 = 群阶 ⇒ `x` 生成整个乘法群 ⇒ 非零元全体可逆 ⇒ 商环是**域**
//     ⇒ `P(x) = x^128+x^7+x^2+x+1` **不可约**。
//   * 并且会先断言 `∏ p_i == 2^128 − 1`：否则上面的检验**不完整**，
//     必须让测试挂掉，而不是给出一个假的"通过"。

TEST(Gf128, Gf128IsIrreducibleByGeneratorOrder) {
    const std::vector<uint128_t> primes = {
        3ULL, 5ULL, 17ULL, 257ULL, 641ULL, 65537ULL,
        6700417ULL, 274177ULL, 67280421310721ULL};
    const uint128_t order = ~static_cast<uint128_t>(0);   // 2^128 − 1

    // ① 素因子分解必须自洽（**先查这个**，否则结论无效）
    uint128_t prod = 1;
    for (uint128_t p : primes) prod *= p;
    if (prod != order) {
        TSB_FAIL_("素因子分解不完整（∏p != 2^128−1）⇒ 下面的不可约性检验**不完整**，"
                  "不得当作通过");
        return;
    }

    // ② x^(2^128−1) == 1
    if (Gf128Pow(2 /* = x */, order) != 1) {
        TSB_FAIL_("x^(2^128−1) != 1 ⇒ x 的阶不整除群阶（乘法运算有误）");
        return;
    }

    // ③ 对每个素因子 p：x^((2^128−1)/p) != 1
    for (uint128_t p : primes) {
        const uint128_t e = order / p;
        if (Gf128Pow(2, e) == 1) {
            TSB_FAIL_("x 的阶整除 (2^128−1)/" + std::to_string(static_cast<uint64_t>(p)) +
                      " ⇒ 阶 < 2^128−1 ⇒ P **可约** ⇒ 这不是域 ⇒ xmac 不成立");
            return;
        }
    }
    // 到这里：x 的阶 = 2^128 − 1 ⇒ GF(2^128) 是域，P 不可约。
}

// ---------------------------------------------------------------------------
// G6：`Gf128SampleNonZero` —— 绝不给 0，且沿 PRNG 确定性推进
// ---------------------------------------------------------------------------

TEST(Gf128, SampleNonZeroNeverReturnsZeroAndAdvances) {
    // 同一个 key + nonce ⇒ 同一个流（`DeterministicPrng` 的构造签名是 key + nonce）。
    // ⚠️ 这里**就地**构造 AES 密钥（而非复用 `mpraq::MakeAesSeed`）：本测试只依赖
    //    `tsb_core`，不该为一个 core 层用例拖进整条 MPRAQ 的依赖链。
    std::array<uint8_t, kAesKeyBytes> key{};
    for (size_t i = 0; i < key.size(); ++i) key[i] = static_cast<uint8_t>('a' + i);
    random::DeterministicPrng a(key, /*nonce=*/0);
    random::DeterministicPrng b(key, /*nonce=*/0);
    for (int i = 0; i < 2000; ++i) {
        const uint128_t x = Gf128SampleNonZero(a);
        const uint128_t y = Gf128SampleNonZero(b);
        EXPECT_TRUE(x != 0);
        EXPECT_EQ(x, y);            // 同 seed ⇒ 逐位相同（铁律 D6）
    }
    // 不同 seed ⇒ 不同序列（万一实现忘了用 prng，这条会挂）
    std::array<uint8_t, kAesKeyBytes> key2 = key;
    key2[0] = static_cast<uint8_t>(key2[0] + 1);   // 只差一个字节 ⇒ 仍是不同的流
    random::DeterministicPrng c(key2, /*nonce=*/0);
    bool differs = false;
    random::DeterministicPrng d(key, /*nonce=*/0);
    for (int i = 0; i < 64; ++i) {
        if (Gf128SampleNonZero(d) != Gf128SampleNonZero(c)) differs = true;
    }
    EXPECT_TRUE(differs);
}
