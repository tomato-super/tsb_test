#pragma once

// 真实 gRPC 通道（FND-10 / VMP-08）。
//
// `GrpcChannel` 实现 `IVmpqChannel`，把请求序列化后通过 vmpq.proto 定义的
// `VmpqService` 发往远端节点；`VmpqServiceImpl` 是服务器侧，把 RPC 落到
// 本地 `VmpqNode` 上。
//
// 分层要点：`VmpqClient` 只认识 `IVmpqChannel`，因此**同一份客户端代码**
// 既能跑进程内（`LocalChannel`），也能跑真实网络（`GrpcChannel`）。
//
// ⚠️ 半诚实版本：不使用 TLS、不做身份认证（决策 D4）。部署到真实环境前
//    必须补上传输安全，否则"两服务器不共谋"之外的攻击面是敞开的。

#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>

#include <atomic>

#include "net/grpc_limits.hpp"   // 收包上限常量（零依赖，不含任何 proto）
#include "vmpq.grpc.pb.h"
#include "vmpq/node.hpp"

namespace tsb {

// ---------------------------------------------------------------------------
// 服务器侧：把 VmpqService 的 RPC 落到本地节点
// ---------------------------------------------------------------------------

class VmpqServiceImpl final : public vmpq::VmpqService::Service {
public:
    explicit VmpqServiceImpl(VmpqNode& node) : node_(node) {}

    grpc::Status InitTable(grpc::ServerContext* ctx,
                           const vmpq::InitTableRequest* req,
                           vmpq::InitTableResponse* resp) override;

    grpc::Status UploadEntries(grpc::ServerContext* ctx,
                               const vmpq::UploadEntriesRequest* req,
                               vmpq::UploadEntriesResponse* resp) override;

    grpc::Status PirQuery(grpc::ServerContext* ctx,
                          const vmpq::PirQueryRequest* req,
                          vmpq::PirQueryResponse* resp) override;

    // 统计：服务器收到的查询集总数（诊断用）
    uint64_t queries_served() const { return queries_served_.load(std::memory_order_relaxed); }
    uint64_t rpc_count() const { return rpc_count_.load(std::memory_order_relaxed); }

private:
    VmpqNode& node_;
    // ⚠️ **并发安全（R7）**：本类的 RPC 处理器由 gRPC 的**线程池**调用（可能并发），
    //    因此计数必须是原子的。用 `memory_order_relaxed` 足够 —— 它是**纯计数**，
    //    没有通过它发布任何其它数据，不需要 acquire/release 语义。
    //    ⚠️ 原子化只修**计数**；`node_` 本身仍**不是**线程安全的（同一进程当前只支持
    //    一个客户端会话，见 `MPRAQ_IMPL` §6 限制②）。不要把这条当成"服务器已支持并发"。
    std::atomic<uint64_t> queries_served_{0};
    std::atomic<uint64_t> rpc_count_{0};
};

// ---------------------------------------------------------------------------
// 客户端侧：实现 IVmpqChannel
// ---------------------------------------------------------------------------

class GrpcChannel : public IVmpqChannel {
public:
    // 本通道**显式设置**的收包上限（账目/测试用；= `kGrpcClientMaxReceiveBytes`）。
    // ⚠️ 它曾经**漏设**（走 gRPC 默认 4 MiB）⇒ D38 之后 `N >= 2^17` 的一列应答会被拒。
    //    见 `net/grpc_limits.hpp`。
    static constexpr int max_receive_bytes() { return kGrpcClientMaxReceiveBytes; }

    // target 形如 "localhost:50051"
    explicit GrpcChannel(const std::string& target);

    void InitTable(uint32_t window_size,
                   const std::vector<uint32_t>& attr_sizes) override;
    // `base_entry` = 条目号；cells 长度必须是 N 的整数倍（决策 D38）
    void UploadEntries(uint64_t base_entry,
                       const std::vector<uint128_t>& cells) override;
    std::vector<PirAnswerData> PirQuery(
        const std::vector<PirQuerySetData>& queries) override;

    // 统计：本通道发出的 RPC 次数（用于验证"所有谓词一次发完"）
    uint64_t rpc_count() const { return rpc_count_; }

    // 建立连接并等待就绪；失败返回 false
    bool WaitForConnection(int timeout_ms);

private:
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<vmpq::VmpqService::Stub> stub_;
    uint64_t rpc_count_ = 0;
    // `InitTable` 时登记的 N；同时是条目宽度 entry_words（决策 D38）。
    // 由它填充 `PirQueryRequest.entry_words` 并按同一宽度解码应答。
    uint32_t window_size_ = 0;
};

// 启动一个监听 addr 的服务器进程内服务，返回可用的 Server 与内部节点。
// 主要供端到端测试在同一进程内起两台服务器用。
class InProcessNode {
public:
    // address 形如 "0.0.0.0:50051"
    explicit InProcessNode(const std::string& address);
    ~InProcessNode();

    VmpqNode& node() { return node_; }
    bool started() const { return started_; }
    const std::string& bound_port() const { return bound_port_; }

    // 该服务器收到的查询集总数
    uint64_t queries_served() const { return impl_.queries_served(); }

private:
    VmpqNode node_;
    VmpqServiceImpl impl_;
    std::unique_ptr<grpc::Server> server_;
    std::string bound_port_;
    bool started_ = false;
};

}  // namespace tsb
