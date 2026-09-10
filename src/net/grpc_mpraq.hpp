#pragma once

// 真实 gRPC 通道（MPRAQ 的传输层，`TASK_PLAN.md` §9.2 的 S5 前置）。
//
// 与 `src/net/grpc_vmpq.hpp` **同一分层手法**，只是承载的协议不同：
//   * `MpraqServiceImpl` —— 服务器侧：把 `proto/mpraq.proto` 的 4 条存储 RPC
//     落到本地 `MpraqNode` 上（`Relay` 落在 `grpc_transport.hpp` 里）；
//   * `GrpcMpraqChannel` —— 客户端侧：实现 `IMpraqChannel`，把请求序列化后发往远端；
//   * `InProcessMpraqNode` —— 在同一进程内起一台真实 gRPC 服务器（测试/demo 用），
//     **必须**支持临时端口（`127.0.0.1:0` + `bound_port()`）。
//
// 分层要点：`MpraqClient` 只认识 `IMpraqChannel`，因此**同一份客户端代码**
// （`MpraqClient::InitWithChannels` + `CreateColumnQuery` + `RunBatch`）既能跑
// 进程内（`LocalMpraqChannel`），也能跑真实网络（`GrpcMpraqChannel`）。
//
// ⚠️ 半诚实版本：不使用 TLS、不做身份认证（决策 D4，与 VMPQ 侧同一口径）。
//    部署到真实环境前必须补上传输安全。
// ⚠️ 不做验证层（决策 D16 / `TASK_PLAN.md` §7.13 待裁决）：本文件**没有**任何
//    proof / 验证值字段，只有 MPRAQ 自己那 4 条数据 RPC + 通用 `Relay`。

#include <chrono>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>

#include "mpraq.grpc.pb.h"
#include "mpraq/node.hpp"
#include "net/grpc_transport.hpp"

namespace tsb {

// ---------------------------------------------------------------------------
// 服务器侧：把 MpraqService 的 RPC 落到本地节点
// ---------------------------------------------------------------------------

// ⚠️ 错误口径与 `VmpqServiceImpl` 完全一致：**响应里带可读 error，同时返回非 OK
//    的 gRPC status**（`StatusCode::INTERNAL`）。客户端两条都检查 ⇒ 既不会因为
//    状态码丢失具体原因，也不会因为只看响应体而漏掉传输层失败。
//    ⚠️ **实测澄清（`MPA-08` 复核时发现，2026-09-10）**：gRPC 的 C++ 实现在返回
//    非 OK status 时**不发送**响应消息体 ⇒ 客户端侧 `resp.error()` 实际**读不到**
//    那条可读原因，原因只能从 `grpc::Status::error_message()` 读
//    （服务侧仍然要写 `resp.error()`：它对本进程内直接调用 service 的路径、
//    以及对日志/调试仍然有效）。`test_mpraq_grpc.cpp` 的
//    `EmptyBatchRequestIsRejectedNotSilentlyAccepted` 钉住了这一点。
//
// ⚠️ **一次 `ServerResp` RPC = 恰好一次 `MpraqNode::ServerRespBatch` 调用**
//    （`MPA-08` 裁决 1，2026-09-10）：此前服务侧把整批查询集**逐条**喂给标量
//    `MpraqNode::ServerResp` ⇒ node 层的 `batch_rpc_count()` 恒为 0，
//    "一次 RPC = 一次批量调用"这条 Q5/D24④ 口径在**服务侧**看不出来。
//    现在服务侧走同一个批量入口（`ServerRespBatch` 内部仍然是"**整批先校验**、
//    再逐条 `AnswerOne`"），并新增**服务侧**的批量计数 `batch_rpc_count()`：
//      一次成功受理的 `ServerResp` RPC ⇒ `rpc_count() +1` **且** `batch_rpc_count() +1`
//    ⇒ "每 RPC 恰好一次批量调用"在服务侧**可断言**。旧口径不再自相矛盾：
//    node 层 `rpc_count()`（标量）在 gRPC 部署下**恒为 0** 是**正确**的
//    —— 它数的就是"标量接口被直接调用"的次数，而服务侧不再调它。
// ⚠️ 空批次（`queries_size() == 0`）现在被**拒绝**（可读 error + 非 OK status）：
//    它在旧实现里会"静默返回 0 条应答"，而 `MpraqNode::ServerRespBatch` 早已把
//    空批次定义为非法（"整批 abort"）。合法客户端不可能构造它
//    （`GrpcMpraqChannel::ServerRespBatch` 在本地就拒绝空批）。
class MpraqServiceImpl final : public ::mpraqwire::MpraqService::Service {
public:
    explicit MpraqServiceImpl(mpraq::MpraqNode& node) : node_(node) {}

    grpc::Status InitTable(grpc::ServerContext* ctx,
                           const ::mpraqwire::InitTableRequest* req,
                           ::mpraqwire::InitTableResponse* resp) override;

    grpc::Status UploadFeatureWords(grpc::ServerContext* ctx,
                                    const ::mpraqwire::UploadFeatureWordsRequest* req,
                                    ::mpraqwire::UploadFeatureWordsResponse* resp) override;

    grpc::Status SetAttributeShares(grpc::ServerContext* ctx,
                                    const ::mpraqwire::SetAttributeSharesRequest* req,
                                    ::mpraqwire::SetAttributeSharesResponse* resp) override;

    grpc::Status ServerResp(grpc::ServerContext* ctx,
                            const ::mpraqwire::PirQueryRequest* req,
                            ::mpraqwire::PirQueryResponse* resp) override;

    // 统计（只增不减；只统计**成功**的调用，被拒绝的请求不计入，
    // 这样"一次 RunBatch 恰好 1 次 ServerResp"这类结构性断言才有意义）
    uint64_t rpc_count() const { return rpc_count_; }
    // 其中**批量入口**（`MpraqNode::ServerRespBatch`）的调用次数（见类注释的 ⚠️）
    uint64_t batch_rpc_count() const { return batch_rpc_count_; }
    // 累计受理的查询集个数（= Σ 请求里的 queries.size()，与 `MpraqNode::queries_served`
    // 的"区块数"口径不同：这里是**word 数**，别混用）
    uint64_t queries_served() const { return queries_served_; }

private:
    mpraq::MpraqNode& node_;
    uint64_t rpc_count_ = 0;
    uint64_t batch_rpc_count_ = 0;
    uint64_t queries_served_ = 0;
};

// ---------------------------------------------------------------------------
// 客户端侧：实现 IMpraqChannel
// ---------------------------------------------------------------------------

// ⚠️ 收包上限（`MPA-09` 任务 B）：本通道与 `GrpcTransportClient` 一样**显式**设置
//    `kGrpcClientMaxReceiveBytes`（256 MiB，见 `net/grpc_transport.hpp`）——gRPC 默认
//    只有 4 MiB，超限时**收包方**直接拒绝（fail-loudly，绝不静默截断）。
class GrpcMpraqChannel : public mpraq::IMpraqChannel {
public:
    // target 形如 "127.0.0.1:50051"（`GrpcChannel` 同一约定）
    explicit GrpcMpraqChannel(const std::string& target);

    // 本通道**显式设置**的收包上限（账目/测试用；= `kGrpcClientMaxReceiveBytes`）
    static constexpr int max_receive_bytes() { return kGrpcClientMaxReceiveBytes; }


    void InitTable(const mpraq::StoreParams& params) override;
    void UploadFeatureWords(uint64_t base_index,
                            const std::vector<uint128_t>& words,
                            size_t count) override;
    void SetAttributeShares(uint32_t attr_id,
                            const std::vector<ModShare>& shares) override;
    PlinkoAnswer ServerResp(const PlinkoQuery& q) override;

    // **整批一次往返**（Q5 / `MPRAQ_IMPL.md` §3）：整批查询集放进**一个**
    // `PirQueryRequest`（proto 的 `repeated PirQuerySet`），因此一次 `RunBatch`
    // （任意列数 × 每列任意 word 数）在远程部署下恒为 **1 次 RPC**。
    // ⚠️ 必须覆写：`IMpraqChannel` 的默认实现会退化成"每个查询集一次 RPC"
    //    （`N = 2^14` 的一列 = 128 次往返）。本覆写因此是 MPA-08 的性能前提。
    // 语义与 `LocalMpraqChannel` **逐条等价**：返回的应答与 `qs` 同长、同序，
    // 每条都等于对该查询集单独调 `ServerResp` 的结果。
    std::vector<PlinkoAnswer> ServerRespBatch(
        const std::vector<PlinkoQuery>& qs) override;

    // ⚠️ `IMpraqChannel::Connect()` 的语义：**阻塞直到连接就绪**，失败抛
    //    `std::runtime_error`（通道不可用时绝不静默继续 —— 与
    //    `PlaceholderRemoteMpraqChannel` 的"绝不静默退化"同一纪律）。
    void Connect() override;
    // 非抛出版本（照 `GrpcChannel::WaitForConnection`）。timeout_ms <= 0 表示不等待。
    bool WaitForConnection(int timeout_ms);

    // 本通道**已发出**的 RPC 次数（含 InitTable / UploadFeatureWords /
    // SetAttributeShares / ServerResp / ServerRespBatch）
    uint64_t rpc_count() const { return rpc_count_; }
    // 其中**标量** `ServerResp` 的次数
    uint64_t server_resp_calls() const { return server_resp_calls_; }
    // 其中**批量** `ServerRespBatch` 的次数（= 一次 `RunBatch` 一次）
    uint64_t server_resp_batch_calls() const { return server_resp_batch_calls_; }
    // 累计搬运过的查询集个数（所有批量调用的 queries.size() 之和）
    uint64_t queries_served() const { return queries_served_; }

    const std::string& target() const { return target_; }

private:
    // 一次 `PirQueryRequest` → 应答（标量与批量共用；`qs.size() >= 1`）
    // ⚠️ `is_batch` **必须**由入口显式传入，**不能**用 `qs.size() == 1` 反推：
    //    "批量里只有 1 个查询集"是完全合法的调用（一次 `RunBatch` 只取 1 个 word），
    //    它仍然是一次**批量** RPC（Q5/D28 口径：往返次数由入口决定，与批次大小无关）。
    std::vector<PlinkoAnswer> SendQuerySets(const std::vector<PlinkoQuery>& qs, bool is_batch);

    std::string target_;
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<::mpraqwire::MpraqService::Stub> stub_;
    uint64_t rpc_count_ = 0;
    uint64_t server_resp_calls_ = 0;
    uint64_t server_resp_batch_calls_ = 0;
    uint64_t queries_served_ = 0;
};

// ---------------------------------------------------------------------------
// 进程内真实 gRPC 服务器（照 `vmpq::InProcessNode` 的写法）
// ---------------------------------------------------------------------------

class InProcessMpraqNode {
public:
    // address 形如 "127.0.0.1:0"（临时端口）或 "0.0.0.0:50051"（固定端口，demo 用）
    // ⚠️ 测试**必须**用 `127.0.0.1:0`：固定端口会让并发跑第二份测试套件时绑定失败
    //    （`TASK_PLAN.md` §3.4 的已知坑）。
    explicit InProcessMpraqNode(const std::string& address);
    ~InProcessMpraqNode();

    InProcessMpraqNode(const InProcessMpraqNode&) = delete;
    InProcessMpraqNode& operator=(const InProcessMpraqNode&) = delete;

    mpraq::MpraqNode& node() { return node_; }
    const mpraq::MpraqNode& node() const { return node_; }
    bool started() const { return started_; }
    // 实际绑定的端口（`AddListeningPort(..., &bound)` 回填）
    const std::string& bound_port() const { return bound_port_; }
    // "127.0.0.1:<bound_port>"，直接喂给 `GrpcMpraqChannel`
    std::string local_address() const { return "127.0.0.1:" + bound_port_; }

    uint64_t rpc_count() const { return impl_.rpc_count(); }
    // **服务侧**批量入口（`MpraqNode::ServerRespBatch`）的调用次数（`MPA-08` 裁决 1）：
    // 每受理一次 `ServerResp` RPC 恰好 +1 ⇒ 与 `rpc_count()` 的查询部分同步增长。
    uint64_t batch_rpc_count() const { return impl_.batch_rpc_count(); }
    uint64_t queries_served() const { return impl_.queries_served(); }

private:
    mpraq::MpraqNode node_;
    MpraqServiceImpl impl_;
    std::unique_ptr<grpc::Server> server_;
    std::string bound_port_;
    bool started_ = false;
};

}  // namespace tsb
