#pragma once

// VMPQ 的服务器侧节点逻辑，以及与传输无关的通道抽象。
//
// 分层意图：`VmpqNode` 只负责"拿到查询集 → 算出 (acc0, acc1)"，
// 不关心消息是怎么送到它的。于是同一份 `VmpqClient` 代码既能跑在
// 进程内（测试、单机仿真），也能跑在真实 gRPC 上（VMP-08 demo）。
//
// ⚠️ 半诚实版本（决策 D16）：服务器只做 `Z_{2^128}` **加法**累加（决策 D37），
//    不计算任何验证值。检索粒度：一个查询集 = 一个条目 = 一整列（决策 D38）。

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

#include "core/field.hpp"
#include "vmpq/params.hpp"

namespace tsb {

// 一个 PIR 查询集：每个分区恰好一个偏移 + 一个分组比特
struct PirQuerySetData {
    std::vector<uint32_t> offsets;
    std::vector<uint32_t> groups;  // 取值 0/1
};

// 服务器应答：两组累加器的和，**逐分量**（Z_{2^128} 加法，决策 D37/D38）。
// 长度 = entry_words = N（一条目 = 一整列）。
struct PirAnswerData {
    std::vector<uint128_t> acc0;
    std::vector<uint128_t> acc1;
};

// ---------------------------------------------------------------------------
// 服务器节点
// ---------------------------------------------------------------------------

class VmpqNode {
public:
    VmpqNode() = default;

    // 按 schema 分配存储（决策 D38）：padded_columns() × N 个 128 位 cell。
    // 条目 e 的第 r 个分量在 entries_[e*N + r]。
    void InitTable(uint32_t window_size, const std::vector<uint32_t>& attr_sizes);

    // 写入一段共享（本服务器自己的那一半）。`base_entry` 是**条目号**
    // （第 0 个条目 = one-hot 区第一列）；`cells.size()` 必须是 N 的整数倍，
    // 覆盖条目 [base_entry, base_entry + cells.size()/N)。
    void UploadEntries(uint64_t base_entry, const std::vector<uint128_t>& cells);

    // 服务器侧应答：对每个查询集分别累加。每个查询集检索**一个条目 = 一整列**，
    // 服务器逐分量累加进 acc0/acc1（决策 D38）。
    std::vector<PirAnswerData> PirQuery(const std::vector<PirQuerySetData>& queries) const;

    bool initialized() const { return inited_; }
    // 条目数 = 列数（每个条目 = 一整列 = N 个 cell）
    uint64_t num_entries() const {
        return params_.window_size == 0
                   ? 0
                   : entries_.size() / params_.window_size;
    }

    // 统计（只增不减，用于测试与基准把"实际发生了多少次 PIR"量出来，
    // 而不是靠公式估算）：
    //   rpc_count()     —— PirQuery 被调用的次数（一次调用 = 一个网络往返批次）
    //   queries_served()—— 累计处理过的查询集个数（**每个条目/每列一个**）
    uint64_t rpc_count() const { return rpc_count_; }
    uint64_t queries_served() const { return queries_served_; }
    uint64_t storage_bytes() const { return entries_.size() * kUint128Bytes; }
    const VmpqParams& params() const { return params_; }

    // 读取单个 128 位 cell（按**扁平下标** `e*N + r`；仅本地模式/测试用）
    uint128_t Entry(uint64_t flat_index) const;
    // 读取整条目（一整列，N 个分量；仅本地模式/测试用）
    std::vector<uint128_t> EntryVector(uint64_t entry) const;

    void Clear();

private:
    bool inited_ = false;
    VmpqParams params_;
    // 扁平条目表（决策 D38）：entry e 的第 r 个分量在 entries_[e*N + r]
    std::vector<uint128_t> entries_;
    mutable uint64_t rpc_count_ = 0;
    mutable uint64_t queries_served_ = 0;
};

// ---------------------------------------------------------------------------
// 客户端 → 单台服务器的通道
// ---------------------------------------------------------------------------

class IVmpqChannel {
public:
    virtual ~IVmpqChannel() = default;

    virtual void InitTable(uint32_t window_size,
                           const std::vector<uint32_t>& attr_sizes) = 0;
    // `base_entry` = 条目号；cells 长度必须是 N 的整数倍（决策 D38）
    virtual void UploadEntries(uint64_t base_entry,
                               const std::vector<uint128_t>& cells) = 0;
    // ⚠️ 一次调用携带**全部**查询集（Q5：所有谓词的所有列一起发）
    virtual std::vector<PirAnswerData> PirQuery(
        const std::vector<PirQuerySetData>& queries) = 0;

    // 远程通道需要显式建立连接；进程内通道为空操作
    virtual void Connect() {}
};

// 进程内通道：直接调用本地节点，无序列化开销
class LocalChannel : public IVmpqChannel {
public:
    explicit LocalChannel(VmpqNode& node) : node_(node) {}

    void InitTable(uint32_t window_size,
                   const std::vector<uint32_t>& attr_sizes) override {
        node_.InitTable(window_size, attr_sizes);
    }
    void UploadEntries(uint64_t base_entry,
                       const std::vector<uint128_t>& cells) override {
        node_.UploadEntries(base_entry, cells);
    }
    std::vector<PirAnswerData> PirQuery(
        const std::vector<PirQuerySetData>& queries) override {
        return node_.PirQuery(queries);
    }

private:
    VmpqNode& node_;
};

// ---------------------------------------------------------------------------
// 查询集构造辅助（客户端与服务器共用同一套分组语义）
// ---------------------------------------------------------------------------

// 由 VooPirQuery 转成可上线传输的形式
PirQuerySetData ToWireQuery(const VooPirQuery& q);

}  // namespace tsb
