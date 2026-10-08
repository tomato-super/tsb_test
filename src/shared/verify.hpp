#pragma once

// 结果验证机制。
//
// 两个协议各有一套验证，本模块提供两者的公共实现：
//
//   1. V-OO-PIR 的多集证明（VMPQ）
//      对应 doc/design/PIR_SPEC.md 的 Verify：
//          F ⊕ C = MAC(x, v) ⊕ MAC(fill, v_fill)
//      其中 F 是 hint 覆盖集合的标签之 XOR（客户端离线预存），
//      C 是服务器对查询子集计算的标签之 XOR，两者 XOR 后除目标项与填充项
//      之外全部抵消。客户端据此判定应答是否被篡改。
//
//   2. 单条记录的 HMAC 校验（MPRAQ）
//      论文 §Hash and MAC：MAC_k(i, v) = HMAC_k(domain ‖ i ‖ v)。
//      客户端用本地密钥对**重建出的明文**重算 MAC 并比对；由于密钥只存在
//      客户端，服务器无法伪造。
//
// ⚠️ SPDZ MAC 必须在**奇模数** q 下运算（决策 D11：Z_{2^k} 中 2 不可逆，
// 而 SPDZ MAC 需要 α 可逆）。因此本模块所有模运算接口都显式接收 q。
// ⚠️ 若 q > 2^127，core/field 的 modmul/reduce 会拒绝（见其接口注释）；
// 推荐 q = 2^127 - 1。

#include <cstdint>
#include <string>
#include <vector>

#include "core/field.hpp"
#include "core/hash.hpp"
#include "core/mset_hash.hpp"
#include "shared/secret_sharing.hpp"

namespace tsb {

// 标签与证明统一使用 128 位标签（见 core/hash.hpp 的 kMacTagBytes）
using MacTagV = MacTag;

// V-OO-PIR 中 hint 的证明 F_j
using HintProof = MacTag;
// 服务器返回的验证值 C
using VerifyValue = MacTag;

// ---------------------------------------------------------------------------
// 1. V-OO-PIR 多集证明
// ---------------------------------------------------------------------------

class PIRVerifier {
public:
    // mac_key 为客户端与服务端共享的 MAC 密钥（非空）
    explicit PIRVerifier(const std::vector<uint8_t>& mac_key);

    // 单条记录的标签 MAC(\u03c7, i, v)
    MacTag ItemTag(const std::string& domain, uint64_t index,
                   uint128_t value) const;

    // Mset-XOR-Hash 的空集基准值 H(0, r)。
    // \u26a0\ufe0f 注意：**不要**把它混进 F 或 C。验证等式要求 F 与 C 分别是
    // 各自集合上元素标签的纯 XOR；一旦某一边掺入基准值，两侧就无法抵消。
    // 基准值只在"多集哈希作为独立摘要"的场合使用（见 core/mset_hash）。
    MacTag BaseTag() const;

    // hint 覆盖集合的证明：F = \u2295_{i\u2208X} ItemTag(i, D[i])
    // X 是服务器为应答该 hint 会扫过的完整数据项集合。
    HintProof ComputeHintProof(
        const std::string& domain,
        const std::vector<std::pair<uint64_t, uint128_t>>& covered_items) const;

    // 服务器对查询子集计算的验证值：C = \u2295_{i\u2208S} ItemTag(i, D[i])
    VerifyValue ComputeSubsetValue(
        const std::string& domain,
        const std::vector<std::pair<uint64_t, uint128_t>>& subset_items) const;

    // 核心判定：F ⊕ C == MAC(x, v) ⊕ MAC(fill, v_fill)
    //
    //   proof       客户端预存的 F
    //   server_c    服务器返回的 C
    //   x, v        目标索引与其重建出的明文值
    //   fill, v_fill 填充索引与其明文值
    bool VerifyResponse(const std::string& domain, const HintProof& proof,
                        const VerifyValue& server_c, uint64_t x, uint128_t v,
                        uint64_t fill, uint128_t v_fill) const;

    // 直接按标签形式判定（便于测试与自定义域）
    static bool VerifyRelation(const HintProof& proof, const VerifyValue& server_c,
                               const MacTag& target_tag, const MacTag& filler_tag);

    const std::vector<uint8_t>& key() const { return mac_key_; }

private:
    std::vector<uint8_t> mac_key_;
    MSetXorHash mset_;
};

// 由两端标签计算 XOR（供自定义验证流程复用）
MacTag XorTags(const MacTag& a, const MacTag& b);

// ---------------------------------------------------------------------------
// 2. 单条记录的 HMAC 校验（MPRAQ）
// ---------------------------------------------------------------------------

class MacVerifier {
public:
    explicit MacVerifier(const std::vector<uint8_t>& mac_key);

    // 计算 MAC_k(i, v) = HMAC_k(domain ‖ i ‖ v)
    MacTag Compute(const std::string& domain, uint64_t index, uint128_t value) const;

    // 校验服务器给出的标签是否等于本地重算值（常量时间比较）
    bool Verify(const std::string& domain, uint64_t index, uint128_t value,
                const MacTag& claimed) const;

    // 批量校验一个 (索引, 值, 标签) 列表；全部通过才返回 true
    struct Item {
        uint64_t index;
        uint128_t value;
        MacTag tag;
    };
    bool VerifyBatch(const std::string& domain, const std::vector<Item>& items) const;

    // 多集聚合：把一批标签 XOR 成一个值（MPRAQ 的批量验证优化）
    static MacTag Aggregate(const std::vector<MacTag>& tags);

    const std::vector<uint8_t>& key() const { return mac_key_; }

private:
    std::vector<uint8_t> mac_key_;
};

// ---------------------------------------------------------------------------
// 3. SPDZ 风格 MAC（MPRAQ 的 SecureMul 验证）
// ---------------------------------------------------------------------------

// 单个服务器持有的认证共享
struct AuthenticatedShare {
    ModShare value;  // ⟨v⟩_p
    ModShare mac;    // ⟨α·v⟩_p
};

// 客户端持有的全局 MAC 密钥 α 及其分享
struct MacKeyShares {
    uint128_t alpha = 0;                  // 客户端本地保存，绝不下发给服务器
    std::vector<uint128_t> alpha_shares;  // 每个服务器一份 ⟨α⟩_p
};

// 生成 MAC 密钥及其分享（客户端在 Init 阶段执行）
MacKeyShares GenerateMacKey(size_t num_servers, uint128_t q);

// 为一个明文值生成两台服务器的认证共享（客户端在 Init 阶段执行）
std::pair<AuthenticatedShare, AuthenticatedShare> ShareAuthenticated(
    uint128_t value, const MacKeyShares& key_shares, uint128_t q);

// 批量版本
std::pair<std::vector<AuthenticatedShare>, std::vector<AuthenticatedShare>>
ShareAuthenticatedBatch(const std::vector<uint128_t>& values,
                        const MacKeyShares& key_shares, uint128_t q);

// 客户端重建 z 与 mac
uint128_t ReconstructAuthenticated(const AuthenticatedShare& a,
                                   const AuthenticatedShare& b, uint128_t q);

// 核心判定：mac == α · z (mod q)
bool VerifyMac(uint128_t z, uint128_t mac, uint128_t alpha, uint128_t q);

// 校验结果（含诊断信息，便于定位是哪一方出了问题）
struct MacVerificationResult {
    bool ok = false;
    uint128_t z = 0;
    uint128_t mac = 0;
    uint128_t expected_mac = 0;  // α · z mod q
};

MacVerificationResult VerifyAuthenticatedDetailed(
    const AuthenticatedShare& share0, const AuthenticatedShare& share1,
    uint128_t alpha, uint128_t q);

// 便捷：由两个服务器的认证共享重建并校验
bool VerifyAuthenticatedShares(const AuthenticatedShare& share0,
                               const AuthenticatedShare& share1, uint128_t alpha,
                               uint128_t q);

}  // namespace tsb
