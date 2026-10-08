#pragma once

// 两方安全乘法（Beaver triple + SPDZ MAC）。
//
// 论文依据：
//   * VMPQ Algorithm 5（Multiply）
//   * MPRAQ §Aggregation 的 SecureMul
//
// ⚠️ **模数必须是奇数。** 理由已更新（2026-10-08，公式对齐新版论文后）：
//   **SPDZ MAC 需要域** —— `mac = α·z` 要求 α 可逆，而 `Z_{2^k}` 里 α 可能是偶数
//   ⇒ 非零偏差未必可逆 ⇒ 恶意服务器可返回任意错值而校验仍通过
//   （论文 `MPRAQ.tex` :137-141 对同类失败的说明）。
//   ⚠️ 历史上这条的理由是"`e·d·2^{-1}` 无定义"，**该理由已随公式对齐而消失**。
//   本函数只校验奇数（必要条件）；素数性由 D11 与 `core/field` 保证。
//   推荐 q = 2^127 - 1（梅森素数，core/field 已在该模数下全面测试通过）。
//
// 协议流程（两服务器 + 客户端中转，服务器之间零通信）：
//
//   预共享（客户端离线生成）：Beaver triple (a, b, c = a·b)
//     服务器 p 持有 ⟨a⟩_p, ⟨b⟩_p, ⟨c⟩_p 以及对应的 MAC 共享
//     ⟨α·a⟩_p, ⟨α·b⟩_p, ⟨α·c⟩_p
//
//   在线：
//     1. 客户端算 d = x − a，把 d 发给两台服务器
//     2. 服务器 p 算 ⟨e⟩_p = ⟨y⟩_p − ⟨b⟩_p，回给客户端
//     3. 客户端把 ⟨e⟩_0 转给服务器 1、⟨e⟩_1 转给服务器 0（服务器间不直接通信）
//     4. 服务器 p 算**纯线性**的两项（新版论文 :554）：
//          ⟨z⟩_p   = ⟨c⟩_p + d·⟨b⟩_p + e·⟨a⟩_p
//          ⟨mac⟩_p = ⟨αc⟩_p + d·⟨αb⟩_p + e·⟨αa⟩_p
//        ⚠️ 公开项 `e·d` **故意不折进服务端**：
//          ① 论文要求服务端表达式对其份额**纯线性**（soundness 论证所依赖的形式）；
//          ② 折进去需要 `2^{-1}`（两台各给一半），而 **GF(2^ℓ)/Z_{2^k} 里 2 不可逆**，
//             且特征 2 下"两台各加一次"恒为 `x⊕x = 0` —— 没有"各给一半"的类比。
//     5. 客户端重建 z = ⟨z⟩_0 + ⟨z⟩_1、mac = ⟨mac⟩_0 + ⟨mac⟩_1，
//        校验 mac == α·z（两侧都只含线性部分）；不等则 abort。
//        **通过之后**才补公开项：z ← z + e·d = f·E。
//        ⚠️ 顺序不能反（先补则校验必失败）；也不能省（省了 z 会静默偏小 e·d）。
//        ⚠️ 决策 D14 的旧勘误（"mac 末项不能乘 2^{-1}`"）在新公式下不再有落点，
//           但作为一条真结论保留在 `secure_mul_flow.hpp` §2 的历史说明里。

#include <cstdint>
#include <vector>

#include "core/field.hpp"
#include "shared/secret_sharing.hpp"
#include "shared/verify.hpp"

namespace tsb {

// 一个 Beaver triple 及各方的共享
struct BeaverTriple {
    uint128_t a = 0;
    uint128_t b = 0;
    uint128_t c = 0;  // = a·b mod q（客户端本地保存，用于生成 d）
};

// 服务器持有的三元组共享（含 MAC 共享）
struct TripleShare {
    ModShare a;
    ModShare b;
    ModShare c;
    ModShare alpha_a;  // ⟨α·a⟩
    ModShare alpha_b;  // ⟨α·b⟩
    ModShare alpha_c;  // ⟨α·c⟩
    ModShare alpha;    // ⟨α⟩
};

// 生成一个 triple 及其在两台服务器上的共享。
// q 必须为奇数。
std::pair<TripleShare, TripleShare> GenerateTripleShares(const MacKeyShares& keys,
                                                         uint128_t q);

// 单个服务器在 SecureMul 在线阶段的输入
struct SecureMulServerInput {
    ModShare y;         // ⟨y⟩_p：被乘的共享值
    TripleShare triple;  // 该服务器持有的 triple 共享
};

// 服务器第一阶段输出：⟨e⟩_p（需要经客户端中转给另一台服务器）
struct SecureMulRound1 {
    ModShare e;  // ⟨e⟩_p = ⟨y⟩_p − ⟨b⟩_p
};

// 服务器第二阶段输出
struct SecureMulRound2 {
    ModShare z;    // ⟨z⟩_p
    ModShare mac;  // ⟨mac⟩_p
};

// 服务器第 1 阶段：计算 ⟨e⟩_p
SecureMulRound1 SecureMulServerPhase1(const SecureMulServerInput& in, uint128_t q);

// 服务器第 2 阶段：已知 d（客户端下发）与 e（重建值），计算 ⟨z⟩_p 与 ⟨mac⟩_p
SecureMulRound2 SecureMulServerPhase2(const SecureMulServerInput& in, uint128_t d,
                                      uint128_t e, uint128_t q);

// 客户端侧：完整的 SecureMul 驱动（供单进程仿真与测试使用）。
//
//   x       客户端持有的乘数（例如 filter bit，取值 0/1）
//   share0  服务器 0 的输入
//   share1  服务器 1 的输入
//   triple  客户端本地的 Beaver triple
//   keys    MAC 密钥及分享
//
// 返回重建并验证后的乘积；验证失败时 ok = false。
struct SecureMulResult {
    bool ok = false;
    uint128_t z = 0;  // 重建出的乘积
    MacVerificationResult mac_result;
};

SecureMulResult SecureMulRun(uint128_t x, const SecureMulServerInput& share0,
                             const SecureMulServerInput& share1,
                             const BeaverTriple& triple, const MacKeyShares& keys,
                             uint128_t q);

// 便捷：给定两方对 y 的共享与客户端持有的 x，直接完成一次安全乘法
// （内部自动生成 triple）。仅用于测试与小规模场景。
SecureMulResult SecureMulSimple(uint128_t x, const ModShare& y0, const ModShare& y1,
                                const MacKeyShares& keys, uint128_t q);

// 校验：q 必须为奇数（决策 D11）
void RequireOddModulus(uint128_t q);

}  // namespace tsb
