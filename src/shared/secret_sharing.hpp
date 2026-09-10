#pragma once

// 秘密共享。
//
// ⚠️ 本文件刻意提供**两套互不兼容**的共享方案，并用不同的强类型包装，
// 让"混用"在编译期就报错。这是决策 D3 的落地：
//
//   1. RingShare   —— 加法共享 over Z_{2^128}
//                     VMPQ 全部使用（one-hot 索引 + 属性值）；
//                     MPRAQ 用于属性值。
//   2. ModShare    —— 加法共享 over Z_q（奇模数，见决策 D11）
//                     MPRAQ 的 SecureMul / SPDZ MAC 使用。
//   3. XorBitShare —— XOR 共享（比特级）
//                     MPRAQ 的 LCTE 编码特征比特使用。
//
// 重建：RingShare 为相加（自然回绕），ModShare 为模 q 相加，
//       XorBitShare 为 XOR。

#include <cstdint>
#include <vector>

#include "core/field.hpp"

namespace tsb {

// ---------------------------------------------------------------------------
// 1. Z_{2^128} 加法共享
// ---------------------------------------------------------------------------

struct RingShare {
    uint128_t value = 0;
};

// 生成 (s0, s1) 使 s0 + s1 ≡ secret (mod 2^128)
std::pair<RingShare, RingShare> ShareRing(uint128_t secret);
uint128_t ReconstructRing(const RingShare& a, const RingShare& b);

// 批量版本，语义同上
std::pair<std::vector<RingShare>, std::vector<RingShare>> ShareRingBatch(
    const std::vector<uint128_t>& secrets);
std::vector<uint128_t> ReconstructRingBatch(const std::vector<RingShare>& a,
                                            const std::vector<RingShare>& b);

// ---------------------------------------------------------------------------
// 2. Z_q 加法共享（q 为奇模数，例如梅森素数 2^127-1）
// ---------------------------------------------------------------------------

struct ModShare {
    uint128_t value = 0;
};

// q 在整个会话中保持一致，作为显式参数传入以避免"忘记模数"的错误
std::pair<ModShare, ModShare> ShareMod(uint128_t secret, uint128_t q);
uint128_t ReconstructMod(const ModShare& a, const ModShare& b, uint128_t q);

// 生成 [0, q) 内与 q 互素的随机掩码（SecureMul 的 Beaver triple 需要）
uint128_t RandomUnitMod(uint128_t q);

// ---------------------------------------------------------------------------
// 3. XOR 共享（比特级）
// ---------------------------------------------------------------------------

struct XorBitShare {
    uint8_t value = 0;  // 0 或 1
};

std::pair<XorBitShare, XorBitShare> ShareXorBit(uint8_t bit);
uint8_t ReconstructXorBit(const XorBitShare& a, const XorBitShare& b);

// 任意字节宽度的 XOR 共享（用于打包的比特向量）
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> ShareXorBytes(
    const std::vector<uint8_t>& secret);
std::vector<uint8_t> ReconstructXorBytes(const std::vector<uint8_t>& a,
                                         const std::vector<uint8_t>& b);

// ---------------------------------------------------------------------------
// 一致性校验
// ---------------------------------------------------------------------------

// 重建两个向量的共享，验证与原始值一致（测试与自检用）
bool VerifyRingShares(const std::vector<uint128_t>& secrets,
                      const std::vector<RingShare>& a,
                      const std::vector<RingShare>& b);

}  // namespace tsb
