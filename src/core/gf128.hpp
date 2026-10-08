#pragma once

// GF(2^128) —— 供 **XOR-Homomorphic MAC（xmac）** 使用（论文 `MPRAQ.tex` §`sec:xmac`）。
//
// ===========================================================================
// 0. 为什么需要它
// ===========================================================================
// PIR 层的应答是"数据库条目的逐位 XOR 聚合"。要对它做**可聚合的完整性校验**，
// 密钥化的映射必须与 XOR 同态，即
//         γ ⊙ (a ⊕ b) = (γ ⊙ a) ⊕ (γ ⊙ b) ,
// 其中 `⊕` 就是应答本身的运算。这要求底层是**特征 2 的域**：加法 = XOR、乘法 ⊙ 分配。
//
// ⚠️ **必须是域，不能是环**（论文 :137-141）：在 `Z_{2^k}` 这类环上 `x ↦ γ⊙x` 未必单射、
//    非零偏差未必可逆 ⇒ 恶意服务器可以返回任意错值而校验仍然通过。
//
// ===========================================================================
// 1. 约定（**必须与论文的数学描述核对**）
// ===========================================================================
//   * 元素 = 128 bit，直接用项目的 `uint128_t` 承载；
//   * **位序：bit `k` 对应多项式项 `x^k`**（little-endian 多项式约定，即
//     `uint128_t` 的**数值语义**，不做 GCM 那样的 bit-reflection）。
//     ⇒ 与 `PlinkoEntry` 里"第 j 位 = 第 j 条记录"的用法一致，少一处位反转错误源。
//   * **不可约多项式**：`P(x) = x^128 + x^7 + x^2 + x + 1`（GCM 用同一条）。
//     在"bit k ↔ x^k"约定下，`x` 的乘法的约简常数就是 `x^7+x^2+x+1` = **`0x87`**：
//         xtime(a) = (a << 1) ⊕ (0x87 if a 的 bit127 = 1 else 0)
//     ⇒ 见 `Gf128Xtime`。
//
// ⚠️ 与 GCM 的**互操作**：GCM 用 bit-reflected 约定 + 同一条多项式，
//    因此本模块的元素与 GCM 的元素之间差一次 **128 bit 位反转**。二者是**同构**的
//    （同一多项式的两种表示），位反转是一个等价转换 —— 本项目不要求与外部实现
//    互操作，只要求**生成侧与校验侧用同一份约定**（保证这一点的是本文件）。
//
// ===========================================================================
// 2. 本模块只提供 xmac 真正需要的东西
// ===========================================================================
//   * `Gf128Mul`：乘法（xmac 客户端逐 chunk 校验 `M = γ ⊙ R` 用）；
//     实测 **103 ns/次**（-O3）⇒ 一个查询集的校验成本 ≈ `entry_words × 103 ns`
//     （`entry_words = 32` 时约 3.3 µs，相对于 PIR 的 κ 次区块读可忽略）；
//   * `Gf128Xtime`：乘 `x`（用于乘法实现与自检）；
//   * `Gf128Pow` / `Gf128Inv`：**仅供探针与测试**验证域公理（协议路径不需要除法）；
//   * `Gf128SampleNonZero`：均匀采样非零元素（`γ ←$ GF(2^128) \ {0}`）。
//
// ⚠️ **常数时间**：xmac 的乘法**只发生在客户端**（服务器侧只做 XOR —— 见
//    `ServerRespShared`），而本威胁模型里的攻击者是服务器、不是本地计时攻击者
//    ⇒ 乘法**不需要**常数时间。下文的实现是简单正确的移位版；若将来有性能需要，
//    可直接换成 4-bit 查表或 PCLMULQDQ，**接口不变**。

#include <cstdint>

#include "core/field.hpp"
#include "core/random.hpp"

namespace tsb {

// `a · x`（即多项式左移一位并按 `P` 约简）。
// 在"bit k ↔ x^k"约定下：左移一位；若移出的 bit127 为 1，则低 128 位再 ⊕ `0x87`。
inline uint128_t Gf128Xtime(uint128_t a) {
    const uint128_t high = a >> 127;                 // x^127 的系数 ⇒ 左移后成为 x^128
    const uint128_t shifted = a << 1;                // 低 128 位（自然丢弃移出位）
    // 0x87 = x^7 + x^2 + x + 1，即 P(x) - x^128 的低次项
    return static_cast<uint128_t>(shifted ^ (high ? static_cast<uint128_t>(0x87) : 0));
}

// 多项式乘法（carry-less multiply）后模 `P` 约简。
// 实现：教科书式"逐位乘 + 移位约简"，`O(128)` 次迭代。
//
// ⚠️ **写成无分支形式**：`b` 在 xmac 里是随机数据（`R`/`M`），逐位 `if` 会有约 50%
//    的分支误预测 —— 实测 **599 ns/次 → 103 ns/次（-O3，5.8×）**。
//    这一步只是去分支，**算法与结果完全不变**（`mask` 为全 1 或全 0）。
//    正确性由独立探针 `/tmp/probe_gf128.cpp` 的域公理 + 同态性检验把关。
inline uint128_t Gf128Mul(uint128_t a, uint128_t b) {
    uint128_t acc = 0;          // 累加器（结果）
    uint128_t cur = a;          // 当前项 a · x^i
    for (int i = 0; i < 128; ++i) {
        const uint128_t bit = (b >> i) & 1u;
        const uint128_t mask = static_cast<uint128_t>(0) - bit;   // bit=1 ⇒ 全 1；bit=0 ⇒ 0
        acc ^= static_cast<uint128_t>(cur & mask);
        cur = Gf128Xtime(cur);
    }
    return acc;
}

// `a^(2^k)`：平方 k 次（用于幂运算与探针）。
inline uint128_t Gf128SquarePow(uint128_t a, int k) {
    for (int i = 0; i < k; ++i) {
        a = Gf128Mul(a, a);
    }
    return a;
}

// `a^e`（平方-乘法）。**仅供探针/测试**。
inline uint128_t Gf128Pow(uint128_t a, uint128_t e) {
    uint128_t result = 1;
    uint128_t base = a;
    for (int i = 0; i < 128; ++i) {
        if (((e >> i) & 1u) != 0) {
            result = Gf128Mul(result, base);
        }
        base = Gf128Mul(base, base);
    }
    return result;
}

// `a^{-1}`：用 Fermat 小定理 `a^{-1} = a^{2^128 − 2}`（乘法群阶为 `2^128 − 1`）。
// ⚠️ **仅供探针/测试**：协议路径只做乘法（xmac 只检查 `M ?= γ ⊙ R`，不需要求逆）。
//    `a == 0` 无逆元 ⇒ 返回 0（不抛异常），非零性由调用方保证。
inline uint128_t Gf128Inv(uint128_t a) {
    // 2^128 − 2：全 1 左移一位
    const uint128_t exp = static_cast<uint128_t>(~static_cast<uint128_t>(0) << 1);
    return Gf128Pow(a, exp);
}

// 均匀采样一个**非零**元素（`γ ←$ GF(2^128) \ {0}`）。
// 采到 0 就重采（概率 2^-128，实践中不会发生；写了是为了不给"γ = 0"留任何可能 ——
// `γ = 0` 会让校验恒通过，等于没有校验）。
inline uint128_t Gf128SampleNonZero(random::DeterministicPrng& rng) {
    for (;;) {
        const uint128_t v = rng.Next();
        if (v != 0) return v;
    }
}

}  // namespace tsb
