#include "core/hash.hpp"

#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

#include <cstdio>
#include <cstring>

namespace tsb {

namespace {
namespace cry = CryptoPP;

Digest ToDigest(const std::string& raw) {
    Digest d{};
    std::memcpy(d.data(), raw.data(), kSha256Bytes);
    return d;
}
}  // namespace

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

Digest Sha256(const uint8_t* data, size_t len) {
    cry::SHA256 hash;
    std::string out;
    out.resize(kSha256Bytes);
    hash.CalculateDigest(reinterpret_cast<cry::byte*>(&out[0]), data, len);
    return ToDigest(out);
}

Digest Sha256(const std::vector<uint8_t>& data) {
    return Sha256(data.data(), data.size());
}

Digest Sha256(const std::string& data) {
    return Sha256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------

Digest HmacSha256(const uint8_t* key, size_t key_len, const uint8_t* msg,
                  size_t msg_len) {
    cry::HMAC<cry::SHA256> hmac(key, key_len);
    std::string out;
    out.resize(kSha256Bytes);
    hmac.CalculateDigest(reinterpret_cast<cry::byte*>(&out[0]), msg, msg_len);
    return ToDigest(out);
}

MacTag HmacTag(const uint8_t* key, size_t key_len, const uint8_t* msg,
               size_t msg_len) {
    const Digest full = HmacSha256(key, key_len, msg, msg_len);
    MacTag tag{};
    // 取前 kMacTagBytes 字节：PRF 输出的截断仍是 PRF
    std::memcpy(tag.data(), full.data(), kMacTagBytes);
    return tag;
}

// ---------------------------------------------------------------------------
// MAC_k(i, v) = HMAC_k(domain || i || v)
// ---------------------------------------------------------------------------

std::vector<uint8_t> EncodeMacMessage(const std::string& domain, uint64_t index,
                                      uint128_t value) {
    std::vector<uint8_t> msg;
    msg.reserve(domain.size() + 8 + 16);
    msg.insert(msg.end(), domain.begin(), domain.end());
    for (size_t i = 0; i < 8; ++i) {
        msg.push_back(static_cast<uint8_t>(index >> (8 * i)));
    }
    for (size_t i = 0; i < 16; ++i) {
        msg.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
    return msg;
}

MacTag ComputeMac(const uint8_t* key, size_t key_len, const std::string& domain,
                  uint64_t index, uint128_t value) {
    const std::vector<uint8_t> msg = EncodeMacMessage(domain, index, value);
    return HmacTag(key, key_len, msg.data(), msg.size());
}

MacTag ComputeMacBytes(const uint8_t* key, size_t key_len,
                       const std::string& domain, const uint8_t* data,
                       size_t len) {
    std::vector<uint8_t> msg;
    msg.reserve(domain.size() + len);
    msg.insert(msg.end(), domain.begin(), domain.end());
    if (len > 0) {
        msg.insert(msg.end(), data, data + len);
    }
    return HmacTag(key, key_len, msg.data(), msg.size());
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

bool ConstantTimeEquals(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

bool ConstantTimeEquals(const MacTag& a, const MacTag& b) {
    return ConstantTimeEquals(a.data(), b.data(), kMacTagBytes);
}

std::string ToHexString(const uint8_t* data, size_t len) {
    std::string s;
    s.reserve(2 * len);
    for (size_t i = 0; i < len; ++i) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", data[i]);
        s += buf;
    }
    return s;
}

}  // namespace tsb
