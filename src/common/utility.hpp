#pragma once

#include "config.hpp"
#include <tuple>
#include <string>

namespace utility {
    std::string uint128ToString(uint128_t val);
    std::string uint128ToHex(uint128_t val);
    uint128_t randomUint128();
    std::tuple<uint128_t, uint128_t> AdditiveShare(uint128_t val);
    uint128_t AdditiveReconstruct(const std::tuple<uint128_t, uint128_t>& shares);    
} // namespace utility
