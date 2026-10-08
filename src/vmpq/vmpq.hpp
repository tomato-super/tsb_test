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
// ⚠️ **共享方案（决策 D37，2026-09-11；取代 D12 在本协议的适用）**：one-hot 词与
// value plane 词都以 **`Z_{2^128}` 加法共享（RSS）** 承载，与 V-OO-PIR 的 parity 群
// （加法）**同群** —— 这正是论文 §IV-B 的口径（"x = [x]₁ + [x]₂，shares from a
// 128-bit ring"）。⚠️ **共享类型必须与累加运算同群**：用 XOR 共享配加法累加会静默错值
// （D12 的反例；实测见 `doc/design/vmpq_parity_alignment.md` §5）。
// 属性值 E 同样走 `Z_{2^128}` 加法共享（供论文口径的 Sum/MPC 用；当前 Sum 走 value plane）。
//
// ⚠️ **检索粒度（决策 D38，2026-09-11；取代早期的"按 word 打包"口径）**：
//   一个 DB 条目 = **一整列** = N 个 128 位 cell（每个 cell 是 Z_{2^128} 加法共享），
//   条目数 = `padded_columns()`（one-hot 列 + bit 面列，补齐到 2 的幂）。
//   ⇒ 一次列查询 = **1 次 PIR**（而不是 ⌈N/128⌉ 次）；服务器应答 N 个元素、
//   存储 `padded_columns()·N·16` 字节/台 —— 与论文 §V-C 的复杂度口径一致。
//   V-OO-PIR 层因此泛化为**向量条目**（`VooPirParams::entry_words = N`），
//   parity / 累加器 / 重建全部**逐分量**进行（群仍是 Z_{2^128} 加法，决策 D37）。

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
    //   1. 逐属性 one-hot 编码到**列**（每条记录在每个属性上恰好点亮一列的一个 cell），
    //      并生成 bit 面列（决策 D38：一条目 = 一整列 = N 个 cell）
    //   2. **逐 cell 加法共享**（RSS over Z_{2^128}，决策 D37）后分发给两台服务器
    //   3. 对客户端本地明文条目表做 V-OO-PIR 离线 hint 生成
    //   （属性值 E 的加法共享未上传：SUM 走 bit 面，见 §7.9 G2/G5）
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
    // 走 V-OO-PIR 取回该列（**1 次 PIR**，条目 = 整列），再本地数 cell。
    uint64_t CountSinglePredicate(uint32_t attr_id, uint64_t attr_value);

    // 把某个 (属性, 取值) 的 one-hot 列完整取回（N 位比特向量）。
    std::vector<uint8_t> RetrieveColumn(uint32_t attr_id, uint64_t attr_value);

    // 一次取回**多个**目标的整列（每个目标 = 1 个条目 = 1 个查询集）。
    // 所有目标的查询集会在**单次** PirQuery 调用中发往两台服务器
    // （决策 Q5：把所有谓词的查询集一起发过去）。
    std::vector<std::vector<uint8_t>> RetrieveColumns(
        const std::vector<std::pair<uint32_t, uint64_t>>& targets);

    // 取回某个属性的 **value plane 组**：l_a 个比特向量，第 b 面的第 j 位 =
    // 第 j 条记录在该属性上取值的第 b 个二进制位。
    std::vector<std::vector<uint8_t>> RetrieveValuePlanes(uint32_t attr_id);

    // 直接取回某个属性在**每条记录**上的明文取值（由 l_a 个比特面本地拼出）。
    // 这是 SUM/矩的公共底座：一次往返即可拿到取值向量。
    std::vector<uint64_t> RetrieveAttributeValues(uint32_t attr_id);

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
    // （每个谓词 1 次 PIR），客户端本就能得到两个列向量，因此直接在本地做
    // 按位与即可，结果等价且不需要 MPC。
    uint64_t CountMultiPredicate(const std::vector<Predicate>& predicates);

    // SUM：对满足 filter 的记录的 sum_attr 取值求和。
    //
    // ⚠️ **实现方式（决策 D18/D38）**：取回 sum_attr 的 l_a 个
    // **bit 面列** + filter 各列（每列 1 次 PIR），在客户端本地还原每条记录的
    // 取值后求和。PIR 次数 = (|filter| + l_a)，而早先的
    // `SUM = Σ_v v·Count(filter ∧ attr==v)` 需要 2^{l_a}·(|filter|+1) 个列。
    // 仍然不需要 MPC：本实现的检索粒度是整列，客户端本就拿得到取值向量。
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

    // 一次取回 filter 命中的记录在 sum_attr 上的一阶与二阶矩。
    // filter 允许为空（表示全部记录）。count/sum/sum_sq 在**同一次 PIR 往返**
    // 里全部得到。
    AggregateResult Aggregate(const std::vector<Predicate>& filter, uint32_t sum_attr);

    // 便利：对"按 128 位打包的列"取第 record 位（**旧 word 口径的遗留工具**；
    // 决策 D38 的列条目不再使用，保留供基准/兼容）。
    static bool BitIsSet(const std::vector<uint128_t>& packed_words, uint32_t record);

private:
    VmpqParams params_;
    // 客户端本地的**明文条目表**（决策 D38）：padded_columns() 个条目，
    // 每条目 = N 个 128 位 cell。plain_entries_[e][r] = 第 e 列在第 r 条记录上的 cell。
    // 离线阶段与调试用；真实部署中服务器只持有它的加法共享。
    std::vector<PirEntry> plain_entries_;
    std::vector<uint64_t> attr_base_;   // one-hot 区各属性的首列（列基址）
    std::vector<uint64_t> plane_base_;  // bit 面区各属性的首列（列基址）
    VooPirClient pir_;                     // 客户端持有的 hint 集合

    // 单进程模式下内部持有的节点；远程模式下为空
    std::vector<std::unique_ptr<VmpqNode>> owned_nodes_;
    std::vector<std::unique_ptr<IVmpqChannel>> owned_channels_;
    IVmpqChannel* channels_[2] = {nullptr, nullptr};

    uint32_t records_loaded_ = 0;

    // (属性, 取值) 对应的 one-hot 条目号（= 列号）
    uint64_t OneHotColumn(uint32_t attr_id, uint32_t attr_value) const;
    // 属性 attr_id 第 bit 个 bit 面条目号（= 列号）
    uint64_t PlaneColumn(uint32_t attr_id, uint32_t bit) const;
    void EncodeAndDistribute(uint32_t record_index,
                             const std::vector<uint64_t>& record);

    // 取回若干**条目**（每个条目 = 一整列 = N 个 cell），返回每条目重建后的
    // N 个分量。所有条目的查询集在**同一次 RPC** 里发往两台服务器（口径 Q5），
    // 并在收到应答后立刻刷新被消费的 hint（决策 D17）。
    std::vector<std::vector<uint128_t>> RetrieveEntries(
        const std::vector<uint64_t>& entry_ids);

    // 把某条目重建后的分量转成 N 位比特向量（cell != 0 ⇒ 1）
    std::vector<uint8_t> EntryToBits(const std::vector<uint128_t>& entry) const;

    // 用 offline server 的材料替换 q 命中的那条 hint（决策 D17）
    void RefreshSlot(const VooPirQuery& q, const std::vector<uint128_t>& value);
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
