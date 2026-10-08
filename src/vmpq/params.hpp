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

    // ---- 扁平条目表布局（**旧：按 word 打包**，决策 D38 后仅作兼容保留）----
    //
    //   [ one-hot 区：Σ_a 2^{l_a} · w ][ value plane 区：Σ_a l_a · w ][ 补齐 ]
    //
    // ⚠️ 决策 D38 起，DB 布局改为**按列**（见下方"基于列的 DB 布局"）：
    //    一个 DB 条目 = 一整列 = N 个 128 位分量。下列方法保留供基准/兼容，
    //    新代码不要再用它们推导 PIR 几何。
    uint32_t num_planes() const { return static_cast<uint32_t>(plane_columns()); }
    uint64_t OneHotEntries() const;  // Σ_a 2^{l_a} · w（旧口径）
    uint64_t PlaneEntries() const;   // Σ_a l_a · w（旧口径）
    uint64_t TotalEntries() const;   // 旧口径 = OneHotEntries() + PlaneEntries()

    // ⚠️ V-OO-PIR 要求 part_num × part_size == n 且两者都是 2 的幂，
    // 因此**数据库大小必须是 2 的幂**。真实条目数一般不是，需要向上补齐
    // （补齐部分填 0，不参与任何语义）。
    uint64_t PaddedEntries() const;  // 旧口径（word 条目数补齐）

    // ---- 基于**列**的 DB 布局（决策 D38，当前生效）----
    //
    // 论文 §V-C 的复杂度口径：查询 √(2^l) 个偏移、服务器应答 **N 个元素**、
    // 服务器存储 |κ|·(N + N·2^l)、PIR 的 DB 条目数 n = 2^l（取值数）。
    // ⇒ 一个 DB 条目 = **一整列**（N 个 cell，每个 cell 是 Z_{2^128} 加法共享）。
    //
    //   [ one-hot：属性0 的 2^{l_0} 列, 属性1 的 2^{l_1} 列, ... ]
    //   [ bit 面：属性0 的 l_0 列, 属性1 的 l_1 列, ... ]
    //   [ 补齐列（全 0）]
    uint64_t one_hot_columns() const;  // Σ_a 2^{l_a}
    uint64_t plane_columns() const;    // Σ_a l_a
    uint64_t total_columns() const;    // 两者之和
    uint64_t padded_columns() const;   // NextPow2(total_columns())
    // 属性 a 的 one-hot 区首列（属性 0 从 0 开始，按属性顺序紧排）
    uint64_t one_hot_column_base(uint32_t a) const;
    // 属性 a 的 bit 面区首列（紧跟在全部 one-hot 列之后）
    uint64_t plane_column_base(uint32_t a) const;

    void Validate() const;

    // 由属性域大小与窗口推导出 V-OO-PIR 参数（n = padded_columns()、
    // entry_words = window_size、带 λ）
    VooPirParams DerivePirParams() const;
};

// 计算每个属性在**列**布局里的基址（决策 D38）：
//   attr_base[a]  = one-hot 区中属性 a 的首列
//   plane_base[a] = bit 面区中属性 a 的首列
// 客户端与服务器必须用**同一套**布局（用同一个函数算，别各写一遍）。
void ComputeEntryLayout(const VmpqParams& params, std::vector<uint64_t>& attr_base,
                        std::vector<uint64_t>& plane_base);

}  // namespace tsb
