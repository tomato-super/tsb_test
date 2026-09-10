#pragma once

// MSet-XOR-Hash（增量多集哈希）。
//
// 对应 VMPQ 论文 §preliminaries 的 Incremental Multi-set Hash（引 Clarke et al.）：
//   * 构造既约：H(r, X ∪ {d}) = H(r, X) ⊕ H(1, d)
//   * 展开形式：H(r, X) = H(0, r) ⊕ ( ⊕_{i=1}^{|X|} H(1, x_i) )
//   * 底层用 Mset-XOR-Hash（仅用 XOR），是效率最高的一种
//
// 在 V-OO-PIR 中，hint 的证明 F_j 就是"该 hint 覆盖的所有数据项的标签之 XOR"。
// 由于 XOR 可增量维护，F_j 可以在离线阶段边扫描边累加，不必二次遍历。
//
// 密钥 r 与 MAC 密钥 k 在 VMPQ 的实例化中是同一个客户端本地秘密。

#include <cstddef>
#include <cstdint>
#include <vector>

#include "core/field.hpp"
#include "core/hash.hpp"

namespace tsb {

class MSetXorHash {
public:
    // 用给定的 MAC 密钥构造。key 非空即可（HMAC 接受任意长度密钥）。
    explicit MSetXorHash(const std::vector<uint8_t>& key);

    // 用随机密钥构造（测试与本地使用）。
    static MSetXorHash WithRandomKey();

    // ---- 单元素标签 ----

    // H(1, value)：单个数据项在给定域下的标签
    MacTag ElementTag(const std::string& domain, uint64_t index,
                      uint128_t value) const;

    // 对任意字节串求标签（域分隔仍生效）
    MacTag ElementTagBytes(const std::string& domain, const uint8_t* data,
                           size_t len) const;

    // ---- 多集哈希 ----

    // H(0, r)：空集的基准值。XOR 进累加器即完成"初始化"。
    MacTag BaseTag() const;

    // H(r, X)：由元素标签列表计算完整多集哈希
    static MacTag Combine(const MacTag& base,
                          const std::vector<MacTag>& element_tags);

    // XOR 合并两个标签（增量维护的核心操作）
    static MacTag XorTag(const MacTag& a, const MacTag& b);

    // ---- 便捷：直接对一个数据集求值 ----

    // 计算 (H(0,r), ⊕ H(1, x_i)) 的最终值
    MacTag HashDataSet(const std::string& domain,
                       const std::vector<std::pair<uint64_t, uint128_t>>& items) const;

    const std::vector<uint8_t>& key() const { return key_; }

private:
    std::vector<uint8_t> key_;
};

}  // namespace tsb
