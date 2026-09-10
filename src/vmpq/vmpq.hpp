#pragma once

// VMPQ —— 隐私保护的多谓词聚合查询（半诚实版本）。
//
// 论文：doc/paper/VMPQ_*.pdf（IEEE TKDE 2026）。半诚实版按决策 D4 实现：
// 验证接口保留但默认关闭。
//
// 数据模型（论文 §IV-A）：
//   * 每个属性 a 有 2^{l_a} 个可能取值，窗口有 N 条记录
//   * 属性 a 的 one-hot 索引表尺寸为 N × 2^{l_a}，每个 (行, 列) 单元是
//     一个 0/1 指示位
//   * 属性值 E 另外以加法共享存储（供 SUM 用）
//
// ⚠️ **共享方案（决策 D12）**：one-hot 列的 parity 语义是 ⊕，因此这些
// 比特必须用 **XOR 共享**承载（等价于 Z_2 上的加法共享）。加法共享不保持
// XOR 同态，用它会导致两服务器的 XOR 结果无法重建明文。
// 属性值 E 走 Z_{2^128} 加法共享，供 SecureMul 使用。
//
// ⚠️ **检索粒度（与论文的一处工程差异，见 §7.9）**：
//   论文把"一整列"作为一次 PIR 检索的 entry（hint parity 可压缩到 1 比特）。
//   本实现把一列按 128 位打包成若干 word，**每个 word 是一次 PIR 检索**，
//   因此一次列查询需要 ⌈N/128⌉ 次 PIR。这样做的好处是复用已经验证过的
//   标量 entry PIR 层，不必改动其接口；代价是 hint 消耗按 word 数放大。
//   后续优化方向：把 V-OO-PIR 泛化为向量 entry。

#include <cstdint>
#include <string>
#include <vector>

#include "core/aes_prf.hpp"
#include "core/field.hpp"
#include "pir/voo_pir.hpp"
#include "shared/database.hpp"
#include "vmpq/node.hpp"
#include "vmpq/params.hpp"

namespace tsb {

// ---------------------------------------------------------------------------
// 服务器侧存储
// ---------------------------------------------------------------------------

// 一台服务器持有的 VMPQ 数据
class VmpqServerStore {
public:
    VmpqServerStore() = default;

    // 按 schema 分配存储（对应论文 Algorithm 2 的初始化）
    void Init(const VmpqParams& params);

    // 写入某属性某取值对应的整列（已打包为 word，且已是本服务器的共享）
    // 对应论文 Algorithm 3 的 Append：服务器接收 [I_i,j]_p
    void SetColumn(uint32_t attr_id, uint32_t attr_value,
                   const std::vector<uint128_t>& packed_words);

    // 读取整列（共享形式）
    const std::vector<uint128_t>& Column(uint32_t attr_id,
                                         uint32_t attr_value) const;

    // 按 PIR 的扁平条目号读写单个 word。
    // 扁平索引 = 该属性的基址 + value * words_per_column + word_index
    uint128_t Entry(uint64_t flat_index) const;
    void SetEntry(uint64_t flat_index, uint128_t v);

    // 属性值 E 的加法共享（供 SUM 用；VMP-04 使用）
    void SetAttributeValues(const std::vector<RingShare>& shared_values);
    const std::vector<RingShare>& AttributeValues() const { return attr_values_; }

    // 统计（entries_ 已按 PaddedEntries() 补齐）
    uint64_t NumEntries() const { return entries_.size(); }
    // 存储开销（按论文 Table I 的口径：属性值 + one-hot 索引）
    uint64_t StorageBytes() const;

    const VmpqParams& params() const { return params_; }

private:
    VmpqParams params_;
    std::vector<uint128_t> entries_;             // 扁平 one-hot 打包 word（共享）
    std::vector<uint64_t> attr_base_;            // 每个属性在 entries_ 中的基址
    std::vector<RingShare> attr_values_;         // 属性值加法共享
};

// ---------------------------------------------------------------------------
// 客户端
// ---------------------------------------------------------------------------

class VmpqClient {
public:
    // ⚠️ 半诚实版本**不需要 MAC 密钥**：所有 proof（hint 证明 F_j）都被移除，
    // 默认服务器不会篡改应答。若将来要支持恶意模型，应在此新增一个独立构造
    // 并显式启用证明，而不是把 proof 混进半诚实路径。
    //
    // 单进程模式：内部创建两个 VmpqNode 并以 LocalChannel 连接。
    VmpqClient(const VmpqParams& params, const AesPrf& prf);

    // 远程模式：用外部提供的通道（例如真实 gRPC）。通道的生命周期由调用方保证。
    VmpqClient(const VmpqParams& params, const AesPrf& prf, IVmpqChannel& channel0,
               IVmpqChannel& channel1);

    const VmpqParams& params() const { return params_; }

    // 只读访问底层 PIR 客户端（基准测试与诊断用；无副作用）
    const VooPirClient& pir() const { return pir_; }

    // ---- 初始化与装载（论文 Algorithm 2 / 3）----

    // 用给定的记录初始化。records[j][a] 是第 j 条记录在属性 a 上的取值。
    // 要求 records.size() == window_size。
    //
    // 该函数完成：
    //   1. 逐属性 one-hot 编码并按 128 位打包
    //   2. XOR 共享后分发给两台服务器
    //   3. 属性值的加法共享
    //   4. 对客户端本地明文表做 V-OO-PIR 离线 hint 生成
    void Init(const std::vector<std::vector<uint64_t>>& records);

    // 追加一批记录（论文 Algorithm 3 的 Append）。
    // 由于决策 D8：不做数据库更新/滑动窗口，本函数只用于**一次性装载**，
    // 且必须在 Init 之后、任何查询之前调用完毕。
    void Append(const std::vector<std::vector<uint64_t>>& records);

    // 单进程模式下访问本地节点（测试/诊断用）。远程模式下会抛异常。
    const VmpqNode& node(int server_id) const;
    VmpqNode& node(int server_id);

    // ---- 查询（论文 Algorithm 4）----

    // 单谓词 Count：统计属性 attr_id 取值等于 attr_value 的记录数。
    // 走 V-OO-PIR 逐 word 取回该列，再本地数比特。
    uint64_t CountSinglePredicate(uint32_t attr_id, uint64_t attr_value);

    // 把某个 (属性, 取值) 的 one-hot 列完整取回（N 位比特向量）。
    std::vector<uint8_t> RetrieveColumn(uint32_t attr_id, uint64_t attr_value);

    // 一次取回**多个**目标的整列。所有目标的全部 word 会在**单次** PirQuery
    // 调用中发往两台服务器（决策 Q5：把所有谓词的查询集一起发过去）。
    std::vector<std::vector<uint8_t>> RetrieveColumns(
        const std::vector<std::pair<uint32_t, uint64_t>>& targets);

    // 谓词：属性 attr_id 取值为 attr_value
    struct Predicate {
        uint32_t attr_id = 0;
        uint64_t attr_value = 0;
    };

    // 多谓词 Count（合取）：统计同时满足全部谓词的记录数。
    //
    // ⚠️ **与论文的实现差异（见 §7.9 G4）**：论文为合取查询设计了
    // Multiply 协议（Beaver triple，服务器间零通信），因为其 `Answer` 只
    // 返回单个计数值 [β]_p，客户端拿不到整列。本实现的检索粒度是**整列**
    // （逐 word PIR 取回），客户端本就能得到两个列向量，因此直接在本地做
    // 按位与即可，结果等价且不需要 MPC。
    uint64_t CountMultiPredicate(const std::vector<Predicate>& predicates);

    // SUM：对满足 filter 的记录的 sum_attr 取值求和。
    //
    // ⚠️ **实现思路（见 §7.9 G5）**：VMPQ 的数据模型里**每个属性都是
    // one-hot 索引**、取值域为 2^{l}。因此
    //     SUM = Σ_v  v · Count(filter ∧ (sum_attr == v))
    // 完全复用 Count 链路，无需 MPC。
    // 代价：需要 |domain(sum_attr)| 次 Count 查询；论文的 Multiply 只需
    // O(1) 次查询但需要 Beaver triple。此处取"正确优先、复用已验证链路"。
    uint64_t SumWithFilter(const std::vector<Predicate>& filter, uint32_t sum_attr);

    // AVG = SUM / COUNT（整数除法，向下取整）
    uint64_t AvgWithFilter(const std::vector<Predicate>& filter, uint32_t sum_attr);

    // 精确聚合量。设计目标要求"结果精确、无近似"，因此这里返回**整数矩**
    // 而不是 double：方差/标准差由调用方按需推导，避免引入浮点误差。
    //   population variance = sum_sq/count − (sum/count)^2
    //   sample variance     = (sum_sq − sum^2/count) / (count − 1)
    struct AggregateResult {
        uint64_t count = 0;
        uint64_t sum = 0;
        uint64_t sum_sq = 0;
    };

    // 一次取回 filter 命中的记录在 sum_attr 上的一阶与二阶矩
    AggregateResult Aggregate(const std::vector<Predicate>& filter, uint32_t sum_attr);

    // 便利：直接对一条记录做 one-hot 校验（测试用）
    static bool BitIsSet(const std::vector<uint128_t>& packed_words, uint32_t record);

private:
    VmpqParams params_;
    // 客户端本地的明文扁平表（离线阶段与调试用）
    std::vector<uint128_t> plain_entries_;
    std::vector<uint64_t> attr_base_;
    VooPirClient pir_;                     // 客户端持有的 hint 集合

    // 单进程模式下内部持有的节点；远程模式下为空
    std::vector<std::unique_ptr<VmpqNode>> owned_nodes_;
    std::vector<std::unique_ptr<IVmpqChannel>> owned_channels_;
    IVmpqChannel* channels_[2] = {nullptr, nullptr};

    uint32_t records_loaded_ = 0;

    uint64_t FlatIndex(uint32_t attr_id, uint32_t attr_value,
                       uint32_t word_index) const;
    void EncodeAndDistribute(uint32_t record_index,
                             const std::vector<uint64_t>& record);
};

// ---------------------------------------------------------------------------
// 打包辅助
// ---------------------------------------------------------------------------

// 把 N 位的列按 128 位打包成 word
std::vector<uint128_t> PackColumn(const std::vector<uint8_t>& bits);

// 取出某个 word 中第 b 位的值（b ∈ [0,128)）
inline bool GetPackedBit(uint128_t word, uint32_t b) {
    return ((word >> b) & 1u) != 0;
}

}  // namespace tsb
