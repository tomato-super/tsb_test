#include "shared/verify.hpp"

#include "core/random.hpp"

#include <stdexcept>

namespace tsb {

MacTag XorTags(const MacTag& a, const MacTag& b) {
    return MSetXorHash::XorTag(a, b);
}

// ---------------------------------------------------------------------------
// 1. PIRVerifier
// ---------------------------------------------------------------------------

PIRVerifier::PIRVerifier(const std::vector<uint8_t>& mac_key)
    : mac_key_(mac_key), mset_(mac_key) {
    if (mac_key_.empty()) {
        throw std::invalid_argument("PIRVerifier: MAC 密钥不能为空");
    }
}

MacTag PIRVerifier::ItemTag(const std::string& domain, uint64_t index,
                            uint128_t value) const {
    return mset_.ElementTag(domain, index, value);
}

MacTag PIRVerifier::BaseTag() const { return mset_.BaseTag(); }

HintProof PIRVerifier::ComputeHintProof(
    const std::string& domain,
    const std::vector<std::pair<uint64_t, uint128_t>>& covered_items) const {
    // F = ⊕_{i∈X} ItemTag(i, D[i])
    //
    // ⚠️ 这里**不能**掺入 BaseTag。验证等式是
    //     F ⊕ C = MAC(x,v) ⊕ MAC(fill,v_fill)
    // 它成立的前提是 F 与 C 都是各自集合上元素标签的纯 XOR——
    // 这样交集部分才会在 ⊕ 中两两抵消，只剩对称差。
    // 若任一侧多带一个基准值，两侧就无法抵消，验证必然失败。
    MacTag acc{};
    bool first = true;
    for (const auto& [idx, val] : covered_items) {
        const MacTag t = ItemTag(domain, idx, val);
        acc = first ? t : XorTags(acc, t);
        first = false;
    }
    return acc;
}

VerifyValue PIRVerifier::ComputeSubsetValue(
    const std::string& domain,
    const std::vector<std::pair<uint64_t, uint128_t>>& subset_items) const {
    // C = ⊕_{i∈S} ItemTag(i, D[i])，不含 BaseTag
    MacTag acc{};
    bool first = true;
    for (const auto& [idx, val] : subset_items) {
        const MacTag t = ItemTag(domain, idx, val);
        acc = first ? t : XorTags(acc, t);
        first = false;
    }
    return acc;
}

bool PIRVerifier::VerifyRelation(const HintProof& proof,
                                 const VerifyValue& server_c,
                                 const MacTag& target_tag,
                                 const MacTag& filler_tag) {
    // F ⊕ C 应当等于 MAC(x,v) ⊕ MAC(fill, v_fill)
    const MacTag lhs = XorTags(proof, server_c);
    const MacTag rhs = XorTags(target_tag, filler_tag);
    return ConstantTimeEquals(lhs, rhs);
}

bool PIRVerifier::VerifyResponse(const std::string& domain,
                                 const HintProof& proof,
                                 const VerifyValue& server_c, uint64_t x,
                                 uint128_t v, uint64_t fill,
                                 uint128_t v_fill) const {
    const MacTag target = ItemTag(domain, x, v);
    const MacTag filler = ItemTag(domain, fill, v_fill);
    return VerifyRelation(proof, server_c, target, filler);
}

// ---------------------------------------------------------------------------
// 2. MacVerifier
// ---------------------------------------------------------------------------

MacVerifier::MacVerifier(const std::vector<uint8_t>& mac_key) : mac_key_(mac_key) {
    if (mac_key_.empty()) {
        throw std::invalid_argument("MacVerifier: MAC 密钥不能为空");
    }
}

MacTag MacVerifier::Compute(const std::string& domain, uint64_t index,
                            uint128_t value) const {
    return ComputeMac(mac_key_.data(), mac_key_.size(), domain, index, value);
}

bool MacVerifier::Verify(const std::string& domain, uint64_t index,
                         uint128_t value, const MacTag& claimed) const {
    const MacTag expected = Compute(domain, index, value);
    return ConstantTimeEquals(expected, claimed);
}

bool MacVerifier::VerifyBatch(const std::string& domain,
                              const std::vector<Item>& items) const {
    for (const auto& it : items) {
        if (!Verify(domain, it.index, it.value, it.tag)) {
            return false;
        }
    }
    return true;
}

MacTag MacVerifier::Aggregate(const std::vector<MacTag>& tags) {
    MacTag acc{};
    for (const auto& t : tags) {
        acc = XorTags(acc, t);
    }
    return acc;
}

// ---------------------------------------------------------------------------
// 3. SPDZ MAC
// ---------------------------------------------------------------------------

MacKeyShares GenerateMacKey(size_t num_servers, uint128_t q) {
    if (num_servers == 0) {
        throw std::invalid_argument("GenerateMacKey: 服务器数必须为正");
    }
    if (q < 2) {
        throw std::invalid_argument("GenerateMacKey: 模数 q 必须 >= 2");
    }
    MacKeyShares out;
    // α 本身也需要是"随机"的；用 RandomUnitMod 保证它可逆，
    // 避免 α = 0 导致校验恒成立（那会让 SPDZ 完全失效）
    out.alpha = RandomUnitMod(q);

    // 把 α 加法共享给各服务器
    out.alpha_shares.resize(num_servers);
    uint128_t acc = 0;
    for (size_t i = 0; i + 1 < num_servers; ++i) {
        out.alpha_shares[i] = random::Below(q);
        acc = addMod(acc, out.alpha_shares[i], q);
    }
    out.alpha_shares[num_servers - 1] = subMod(out.alpha, acc, q);
    return out;
}

std::pair<AuthenticatedShare, AuthenticatedShare> ShareAuthenticated(
    uint128_t value, const MacKeyShares& key_shares, uint128_t q) {
    if (key_shares.alpha_shares.size() != 2) {
        throw std::invalid_argument(
            "ShareAuthenticated: 本函数面向双服务器，alpha_shares 必须恰好 2 份");
    }
    const uint128_t v = reduce(value, q);

    // ⟨v⟩ 的加法共享
    auto [v0, v1] = ShareMod(v, q);

    // ⟨α·v⟩ 的加法共享。注意要用**单独的掩码**，不能复用 v 的掩码，
    // 否则 ⟨α·v⟩ = α·⟨v⟩ 会泄露 α。
    const uint128_t av = mulMod(key_shares.alpha, v, q);
    auto [m0, m1] = ShareMod(av, q);

    return {AuthenticatedShare{v0, m0}, AuthenticatedShare{v1, m1}};
}

std::pair<std::vector<AuthenticatedShare>, std::vector<AuthenticatedShare>>
ShareAuthenticatedBatch(const std::vector<uint128_t>& values,
                        const MacKeyShares& key_shares, uint128_t q) {
    std::vector<AuthenticatedShare> a, b;
    a.reserve(values.size());
    b.reserve(values.size());
    for (uint128_t v : values) {
        auto [sa, sb] = ShareAuthenticated(v, key_shares, q);
        a.push_back(sa);
        b.push_back(sb);
    }
    return {std::move(a), std::move(b)};
}

uint128_t ReconstructAuthenticated(const AuthenticatedShare& a,
                                   const AuthenticatedShare& b, uint128_t q) {
    return ReconstructMod(a.value, b.value, q);
}

bool VerifyMac(uint128_t z, uint128_t mac, uint128_t alpha, uint128_t q) {
    // α = 0 会让 mac = 0 对任意 z 都成立，校验形同虚设——直接拒绝
    if (reduce(alpha, q) == 0) {
        throw std::invalid_argument("VerifyMac: MAC 密钥 alpha 不能为 0（退化参数）");
    }
    const uint128_t expected = mulMod(alpha, reduce(z, q), q);
    return reduce(mac, q) == expected;
}

MacVerificationResult VerifyAuthenticatedDetailed(
    const AuthenticatedShare& share0, const AuthenticatedShare& share1,
    uint128_t alpha, uint128_t q) {
    MacVerificationResult r;
    r.z = ReconstructMod(share0.value, share1.value, q);
    r.mac = ReconstructMod(share0.mac, share1.mac, q);
    r.expected_mac = mulMod(alpha, r.z, q);
    r.ok = (r.mac == r.expected_mac);
    return r;
}

bool VerifyAuthenticatedShares(const AuthenticatedShare& share0,
                               const AuthenticatedShare& share1, uint128_t alpha,
                               uint128_t q) {
    return VerifyAuthenticatedDetailed(share0, share1, alpha, q).ok;
}

}  // namespace tsb
