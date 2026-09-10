#include "shared/secret_sharing.hpp"

#include "core/random.hpp"

#include <stdexcept>

namespace tsb {

// ---------------------------------------------------------------------------
// 1. Z_{2^128} 加法共享
// ---------------------------------------------------------------------------

std::pair<RingShare, RingShare> ShareRing(uint128_t secret) {
    const uint128_t mask = random::Uint128();
    // 掩码均匀 ⇒ mask 与 secret - mask 的联合分布在给定 secret 下均匀
    return {RingShare{mask}, RingShare{static_cast<uint128_t>(secret - mask)}};
}

uint128_t ReconstructRing(const RingShare& a, const RingShare& b) {
    return static_cast<uint128_t>(a.value + b.value);
}

std::pair<std::vector<RingShare>, std::vector<RingShare>> ShareRingBatch(
    const std::vector<uint128_t>& secrets) {
    std::vector<RingShare> a(secrets.size()), b(secrets.size());
    for (size_t i = 0; i < secrets.size(); ++i) {
        auto [s0, s1] = ShareRing(secrets[i]);
        a[i] = s0;
        b[i] = s1;
    }
    return {std::move(a), std::move(b)};
}

std::vector<uint128_t> ReconstructRingBatch(const std::vector<RingShare>& a,
                                            const std::vector<RingShare>& b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("ReconstructRingBatch: 两个共享向量长度不一致");
    }
    std::vector<uint128_t> out(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        out[i] = ReconstructRing(a[i], b[i]);
    }
    return out;
}

bool VerifyRingShares(const std::vector<uint128_t>& secrets,
                      const std::vector<RingShare>& a,
                      const std::vector<RingShare>& b) {
    if (secrets.size() != a.size() || a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < secrets.size(); ++i) {
        if (ReconstructRing(a[i], b[i]) != secrets[i]) {
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// 2. Z_q 加法共享
// ---------------------------------------------------------------------------

std::pair<ModShare, ModShare> ShareMod(uint128_t secret, uint128_t q) {
    if (q < 2) {
        throw std::invalid_argument("ShareMod: 模数 q 必须 >= 2");
    }
    const uint128_t s = reduce(secret, q);
    const uint128_t mask = random::Below(q);
    return {ModShare{mask}, ModShare{subMod(s, mask, q)}};
}

uint128_t ReconstructMod(const ModShare& a, const ModShare& b, uint128_t q) {
    return addMod(a.value, b.value, q);
}

uint128_t RandomUnitMod(uint128_t q) {
    if (q < 2) {
        throw std::invalid_argument("RandomUnitMod: 模数 q 必须 >= 2");
    }
    // 拒绝采样直到取到与 q 互素的元素。
    // 对素数 q，失败概率仅 1/q；对一般的 q 也很快收敛。
    for (;;) {
        const uint128_t v = random::Below(q);
        if (v == 0) {
            continue;
        }
        try {
            (void)modInverse(v, q);  // 不可逆时抛异常
            return v;
        } catch (const std::invalid_argument&) {
            continue;
        }
    }
}

// ---------------------------------------------------------------------------
// 3. XOR 共享
// ---------------------------------------------------------------------------

std::pair<XorBitShare, XorBitShare> ShareXorBit(uint8_t bit) {
    if (bit > 1) {
        throw std::invalid_argument("ShareXorBit: 比特必须为 0 或 1");
    }
    const uint8_t mask = static_cast<uint8_t>(random::Uint128() & 1u);
    return {XorBitShare{mask}, XorBitShare{static_cast<uint8_t>(bit ^ mask)}};
}

uint8_t ReconstructXorBit(const XorBitShare& a, const XorBitShare& b) {
    return static_cast<uint8_t>(a.value ^ b.value);
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> ShareXorBytes(
    const std::vector<uint8_t>& secret) {
    std::vector<uint8_t> mask(secret.size());
    random::FillBytes(mask.data(), mask.size());
    std::vector<uint8_t> other(secret.size());
    for (size_t i = 0; i < secret.size(); ++i) {
        other[i] = static_cast<uint8_t>(secret[i] ^ mask[i]);
    }
    return {std::move(mask), std::move(other)};
}

std::vector<uint8_t> ReconstructXorBytes(const std::vector<uint8_t>& a,
                                         const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("ReconstructXorBytes: 两个共享向量长度不一致");
    }
    std::vector<uint8_t> out(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        out[i] = static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return out;
}

}  // namespace tsb
