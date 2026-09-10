#pragma once

// VMPQ 的服务器侧节点逻辑，以及与传输无关的通道抽象。
//
// 分层意图：`VmpqNode` 只负责"拿到查询集 → 算出 (acc0, acc1)"，
// 不关心消息是怎么送到它的。于是同一份 `VmpqClient` 代码既能跑在
// 进程内（测试、单机仿真），也能跑在真实 gRPC 上（VMP-08 demo）。
//
// ⚠️ 半诚实版本（决策 D16）：服务器只做 XOR 累加，不计算任何验证值。

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

// 服务器应答：两组累加器的 XOR
struct PirAnswerData {
    uint128_t acc0 = 0;
    uint128_t acc1 = 0;
};

// ---------------------------------------------------------------------------
// 服务器节点
// ---------------------------------------------------------------------------

class VmpqNode {
public:
    VmpqNode() = default;

    // 按 schema 分配存储
    void InitTable(uint32_t window_size, const std::vector<uint32_t>& attr_sizes);

    // 写入一段共享（本服务器自己的那一半）
    void UploadEntries(uint64_t base_index, const std::vector<uint128_t>& entries);

    // 服务器侧应答：对每个查询集分别累加
    std::vector<PirAnswerData> PirQuery(const std::vector<PirQuerySetData>& queries) const;

    bool initialized() const { return inited_; }
    uint64_t num_entries() const { return entries_.size(); }
    uint64_t storage_bytes() const { return entries_.size() * kUint128Bytes; }
    const VmpqParams& params() const { return params_; }

    // 读取单个条目（仅本地模式/测试用；远程模式下服务器不会暴露它）
    uint128_t Entry(uint64_t i) const;

    void Clear();

private:
    bool inited_ = false;
    VmpqParams params_;
    std::vector<uint128_t> entries_;
};

// ---------------------------------------------------------------------------
// 客户端 → 单台服务器的通道
// ---------------------------------------------------------------------------

class IVmpqChannel {
public:
    virtual ~IVmpqChannel() = default;

    virtual void InitTable(uint32_t window_size,
                           const std::vector<uint32_t>& attr_sizes) = 0;
    virtual void UploadEntries(uint64_t base_index,
                               const std::vector<uint128_t>& entries) = 0;
    // ⚠️ 一次调用携带**全部**查询集（Q5：所有谓词的所有 word 一起发）
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
    void UploadEntries(uint64_t base_index,
                       const std::vector<uint128_t>& entries) override {
        node_.UploadEntries(base_index, entries);
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
