#include "core/mset_hash.hpp"

#include "core/aes_prf.hpp"

#include <stdexcept>

namespace tsb {

MSetXorHash::MSetXorHash(const std::vector<uint8_t>& key) : key_(key) {
    if (key_.empty()) {
        throw std::invalid_argument("MSetXorHash: 密钥不能为空");
    }
}

MSetXorHash MSetXorHash::WithRandomKey() {
    const auto k = AesPrf::GenerateKey();
    return MSetXorHash(std::vector<uint8_t>(k.begin(), k.end()));
}

MacTag MSetXorHash::ElementTag(const std::string& domain, uint64_t index,
                               uint128_t value) const {
    return ComputeMac(key_.data(), key_.size(), domain, index, value);
}

MacTag MSetXorHash::ElementTagBytes(const std::string& domain,
                                    const uint8_t* data, size_t len) const {
    return ComputeMacBytes(key_.data(), key_.size(), domain, data, len);
}

MacTag MSetXorHash::BaseTag() const {
    // H(0, r)：用一个与元素标签互不相同的域，保证基值与任何元素标签独立
    return ElementTagBytes(std::string(domain::kRecord) + "/base", nullptr, 0);
}

MacTag MSetXorHash::XorTag(const MacTag& a, const MacTag& b) {
    MacTag out{};
    for (size_t i = 0; i < kMacTagBytes; ++i) {
        out[i] = static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return out;
}

MacTag MSetXorHash::Combine(const MacTag& base,
                            const std::vector<MacTag>& element_tags) {
    MacTag acc = base;
    for (const auto& t : element_tags) {
        acc = XorTag(acc, t);
    }
    return acc;
}

MacTag MSetXorHash::HashDataSet(
    const std::string& domain,
    const std::vector<std::pair<uint64_t, uint128_t>>& items) const {
    MacTag acc = BaseTag();
    for (const auto& [idx, val] : items) {
        acc = XorTag(acc, ElementTag(domain, idx, val));
    }
    return acc;
}

}  // namespace tsb
