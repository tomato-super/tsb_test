#pragma once

// VMPQ 参数。独立成文件以避免 vmpq.hpp 与 node.hpp 的循环包含。

#include <cstdint>
#include <stdexcept>
#include <vector>

#include "pir/voo_pir.hpp"

namespace tsb {

struct VmpqParams {
    uint32_t window_size = 0;              // N：窗口内记录数
    std::vector<uint32_t> attr_sizes;      // 每个属性的取值域大小 2^{l_a}
    uint32_t lambda = 80;                  // V-OO-PIR 的安全参数

    // 每个属性的列被切成多少个 128 位 word
    uint32_t words_per_column() const {
        return static_cast<uint32_t>((window_size + 127) / 128);
    }
    uint32_t num_attributes() const { return static_cast<uint32_t>(attr_sizes.size()); }

    // PIR 数据库的真实条目总数 = Σ_a 2^{l_a} × words_per_column
    uint64_t TotalEntries() const;

    // ⚠️ V-OO-PIR 要求 part_num × part_size == n 且两者都是 2 的幂，
    // 因此**数据库大小必须是 2 的幂**。真实条目数一般不是，需要向上补齐
    // （补齐部分填 0，不参与任何语义）。
    uint64_t PaddedEntries() const;

    void Validate() const;

    // 由属性域大小与窗口推导出 V-OO-PIR 参数
    VooPirParams DerivePirParams() const;
};

}  // namespace tsb
