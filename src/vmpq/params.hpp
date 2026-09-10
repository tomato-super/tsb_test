#pragma once

// VMPQ 参数。独立成文件以避免 vmpq.hpp 与 node.hpp 的循环包含。

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "pir/voo_pir.hpp"

namespace tsb {

struct VmpqParams {
    uint32_t window_size = 0;              // N：窗口内记录数
    std::vector<uint32_t> attr_sizes;      // 每个属性的取值域大小 2^{l_a}
    uint32_t lambda = 80;                  // V-OO-PIR 的安全参数

    // ⚠️ **仅供基准对比与性能测量**：置 true 后查询后不刷新 hint（也不禁止
    // 复用）。这会**泄露**查询分区与真实半区——同一条 hint 的真实半区偏移是
    // `PRF(h,k)`，跨轮恒定，服务器一比就能挑出来（决策 D17，证伪测试见
    // tests/test_voo_pir.cpp 的 HintReuseWithoutRefreshLeaks...）。
    // 生产与正确性测试**一律保持 false**。
    bool unsafe_disable_hint_refresh = false;

    // 每个属性的列被切成多少个 128 位 word
    uint32_t words_per_column() const {
        return static_cast<uint32_t>((window_size + 127) / 128);
    }
    uint32_t num_attributes() const { return static_cast<uint32_t>(attr_sizes.size()); }

    // 属性 a 的取值位宽 l_a = log2(2^{l_a})
    uint32_t bits_per_attr(uint32_t a) const {
        if (a >= attr_sizes.size()) {
            throw std::out_of_range("VmpqParams::bits_per_attr: 属性号越界");
        }
        uint32_t bits = 0;
        while ((1u << bits) < attr_sizes[a]) ++bits;
        if ((1u << bits) != attr_sizes[a]) {
            throw std::invalid_argument(
                "VmpqParams::bits_per_attr: 属性取值域不是 2 的幂");
        }
        return bits;
    }

    // ---- 扁平条目表布局 ----
    //
    //   [ one-hot 区：Σ_a 2^{l_a} · w ][ value plane 区：Σ_a l_a · w ][ 补齐 ]
    //
    // one-hot 区：每个 (属性, 取值) 一列，每列 w 个 128 位 word（按位打包）。
    // value plane 区：每个属性 l_a 个**比特面**，第 b 面的第 j 位 = 第 j 条记录
    //   在该属性上取值的第 b 个二进制位。它是 one-hot 各列的 XOR（各列互斥，
    //   故 XOR 即 OR），因此**不含任何 one-hot 表之外的额外信息**，服务器自己
    //   也能从共享推出来（见 tests/test_vmpq.cpp 的
    //   ValuePlanesAreXorOfOneHotColumns）。
    //
    // ⚠️ 有了比特面，SUM/矩 只需取回 l_a 个面即可在本地还原**每条记录的取值**，
    // 不必再对取值的每个可能值各做一次 Count（原来 SUM = |domain| × 2 × Count）。
    uint32_t num_planes() const;
    uint64_t OneHotEntries() const;  // Σ_a 2^{l_a} · w
    uint64_t PlaneEntries() const;   // Σ_a l_a · w
    uint64_t TotalEntries() const;   // = OneHotEntries() + PlaneEntries()

    // ⚠️ V-OO-PIR 要求 part_num × part_size == n 且两者都是 2 的幂，
    // 因此**数据库大小必须是 2 的幂**。真实条目数一般不是，需要向上补齐
    // （补齐部分填 0，不参与任何语义）。
    uint64_t PaddedEntries() const;

    void Validate() const;

    // 由属性域大小与窗口推导出 V-OO-PIR 参数
    VooPirParams DerivePirParams() const;
};

// 计算每个属性在扁平条目表里的基址：
//   attr_base[a]  = one-hot 区中属性 a 的起点
//   plane_base[a] = value-plane 区中属性 a 的起点
// 客户端与服务器必须用**同一套**布局（用同一个函数算，别各写一遍）。
void ComputeEntryLayout(const VmpqParams& params, std::vector<uint64_t>& attr_base,
                        std::vector<uint64_t>& plane_base);

}  // namespace tsb
