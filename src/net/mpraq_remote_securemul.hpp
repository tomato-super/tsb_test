#pragma once

// `MPA-08` 的两进程链路：**真实 gRPC** 上的 `Sum` / `Avg`（服务器在**另一个进程**里）。
//
// ===========================================================================
// 0. 这个文件解决什么问题（为什么不能只靠 `SecureMulTransport`）
// ===========================================================================
// `MPA-06` 的批量 SecureMul（`mpraq/aggvalue.hpp`）在**单进程**里跑得很好：
// 它在客户端进程里建两张 `SecureMulBatchServerTable`，再用
// `ITransportServer::SetHandler` 把两个 handler 挂到传输上。
// 只要服务器**在同一个进程里**（`LocalTransport`，或进程内 gRPC 回环
// `GrpcTransportServer`），`SecureMulTransport{client, server}` 就够了。
//
// 但**跨进程**时那条路走不通，而且不是"配置问题"而是**语义问题**：
// `SetHandler` 收的是一个 `std::function` **闭包**，闭包里捕获的是**客户端进程**
// 的 state 表；服务器进程既拿不到那个闭包，也拿不到 state ⇒ 没有任何句柄能让它
// "执行客户端的 handler"。⇒ 跨进程只有一条路：把 state 与帧当成**数据**送过去，
// 让**服务器进程**自己跑 `MPA-05` 的服务端处理器。
//
// 于是本文件定义一条**极小的、只跑在已有 `Relay` 上的**数据协议：
//
//   * **标记封套**（`EncodeRelayFrame` / `DecodeRelayFrame`）：14 字节头
//     `magic(4) + kind(1) + count(4) + payload_len(4)`，内层 payload 就是
//     `aggvalue.hpp` 的**原样批量帧**（6 字节头 + N 条原样 MPA-05 消息）；
//   * **服务器进程侧**（`MpraqSecureMulServer`）：`Relay` handler 按 `kind` 分派两类事
//       - `kInstallSetups`：把客户端（**离线 dealer**）下发的 N 条
//         `SecureMulServerSetup` 装进一张 `SecureMulBatchServerTable`；
//       - `kPhase1Batch` / `kPhase2Batch`：把这**一帧**交给
//         `SecureMulBatchServerTable::HandleFrame`（**同一份**服务端逻辑，
//         与本地模式逐位一致），回一帧；
//     **没有新增任何 RPC**（`proto/mpraq.proto` 一个字节都没改），
//     服务器之间也**依然**零通信（每台只处理自己那一帧）。
//   * **客户端进程侧**（`RemoteSecureMulBatchEndpoint`，实现
//     `ISecureMulBatchEndpoint`）：把"安装 state"与"一轮帧"变成 `Relay` 请求，
//     并把应答封套拆回"上层能解码的批量帧"。
//
// ⇒ `SumOverFilter(..., ITransportClient&, ISecureMulBatchEndpoint&, …)` 的**同一份**
//    批量驱动就能跑两进程；往返数在服务器上仍是 **2**（第 1 轮 1 次、第 2 轮 1 次），
//    多出来的只有**安装阶段的 1 次/台**（见 §2 的账目口径）。
//
// ===========================================================================
// 1. 安全/正确性口径（如实写清）
// ===========================================================================
//   * 本协议**不含**任何验证/证明（决策 D16 / D29）：封套的 `count` 与 `kind` 只是
//     "结构性校验"（长度不符、类型不符一律**拒绝**，绝不静默接受），
//     **没有**密码学完整性保护 —— 与 `MPA-05`/`MPA-06` 的既有结论一致
//     （值层的防线是 SPDZ MAC + §4.5-A/B 两条纯客户端复核，本文件不新增防线）。
//   * `Relay` 仍然是**开放转发**（`proto/mpraq.proto` 的注释已写明）：任何连得上的
//     客户端都能递任意字节给 handler ⇒ **必须先补认证才能上生产**（决策 D4 同一口径）。
//   * **离线 dealer 模型**：N 条 `SecureMulServerSetup`（triple 共享 + ⟨E⟩_p + ⟨α⟩_p
//     + challenge）由**客户端**当场生成并**下发**给两台服务器。这正是 `MPA-05` 的
//     `MakeSetupsAndContext` 的场景（triple 由客户端生成 ⇒ §4.5-A 成立），
//     但**跨进程**意味着"预处理材料**每次查询**都过一次网"——
//     账目里如实报成 `install_bytes` / `install_rounds`（`MPA-09` 必须把它算进在线代价）。
//   * 服务器侧会话表是**每进程一张**、按 `(session → state)` 索引；一次安装帧会先
//     `Clear()` 再装（因为客户端的 session 号是 `kSecureMulBatchSessionBase + i`，
//     每次查询都一样）⇒ **同一时刻只支持一个客户端会话**（demo 的限制，
//     真实部署要按会话/连接隔离）。
//
// ===========================================================================
// 2. 账目口径（**测试按这个断言**）
// ===========================================================================
//   * 在线两轮：每台服务器 **1 次 Relay / 轮** ⇒ `rounds == 2`、`server_frames == 2`；
//   * 安装阶段：每台 **1 次 Relay**（一次装完 N 条）⇒ `install_frames == 2`（两台之和）、
//     `install_rounds == 2`、`install_bytes == 2 × (13 + 152·N)`（13 = `kRelayHeaderBytes`；
//     ⚠️ 此处原文曾误写为 `14`；以 `kRelayHeaderBytes == 13` 与 `MPA-09` 的实测为准，
//        见 `TASK_PLAN.md` D34 与 `tests/test_mpraq_e2e.cpp`（`2×(13+152N)`）。
//   * `messages == 2N`（单台视角）、`wire_messages == 4N`（线上 MPA-05 消息条数，
//     与本地模式**同一口径**：安装帧里的 setup 不计入 `wire_messages`，
//     它由 `install_bytes` 单独记账）。

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include <grpcpp/grpcpp.h>

#include "mpraq.grpc.pb.h"
#include "mpraq/aggvalue.hpp"
#include "mpraq/node.hpp"
#include "net/grpc_mpraq.hpp"
#include "net/transport.hpp"

namespace tsb {
namespace mpraq {

// ---------------------------------------------------------------------------
// 标记封套（见文件头 §0）
// ---------------------------------------------------------------------------

// 封套魔数 "MRQS"（MPRAQ Relay Secure-mul）：用来把本协议的字节与其它
// Relay 用法区分开（一个字节都不符 ⇒ 立刻拒绝，绝不"猜着解"）。
inline constexpr uint8_t kRelayFrameMagic[4] = {0x4D, 0x52, 0x51, 0x53};
// magic(4) + kind(1) + count(4, LE) + payload_len(4, LE)
inline constexpr size_t kRelayHeaderBytes = 13;
// 安装项：session(8) + record_index(8) + triple 7×16 + ⟨E⟩_p(16) + challenge(8)
inline constexpr size_t kInstallEntryBytes = 8 + 8 + 7 * 16 + 16 + 8;  // = 152

enum class RelayFrameKind : uint8_t {
    kInstallSetups = 0x31,  // 客户端 → 服务器：N 条 setup（一次装完）
    kInstallAck = 0x32,     // 服务器 → 客户端：count = 已安装条数
    kPhase1Batch = 0x41,    // 客户端 → 服务器：内层 = kPhase1Request 批量帧
    kPhase1Ack = 0x42,      // 服务器 → 客户端：内层 = kPhase1Response 批量帧
    kPhase2Batch = 0x43,
    kPhase2Ack = 0x44,
    kStatsRequest = 0x51,   // 客户端 → 服务器：服务器账目（**实测**值）
    kStatsAck = 0x52,
};

const char* RelayFrameKindName(RelayFrameKind kind);

struct RelayFrame {
    RelayFrameKind kind = RelayFrameKind::kPhase1Batch;
    uint32_t count = 0;
    Payload payload;
};

// 组帧：`payload_len` 由 payload 的实际长度填（调用方不必自己算）。
Payload EncodeRelayFrame(RelayFrameKind kind, uint32_t count, const Payload& payload);
// 解帧：魔数/长度/`payload_len` 与实际长度不符一律抛 `std::invalid_argument`
//（**绝不**静默截断或补零）。未知 `kind` 同样抛。
RelayFrame DecodeRelayFrame(const Payload& frame);

// 安装载荷（`count` 由封套头携带；这里再校验一次条数自洽）
Payload EncodeInstallPayload(const std::vector<uint64_t>& sessions,
                             const std::vector<SecureMulServerSetup>& setups);
struct InstallPayload {
    std::vector<uint64_t> sessions;
    std::vector<SecureMulServerSetup> setups;
};
InstallPayload DecodeInstallPayload(const Payload& payload, uint32_t count);

// ---------------------------------------------------------------------------
// 服务器账目（`kStatsRequest` / `kStatsAck`）
// ---------------------------------------------------------------------------
// 口径全部是**服务器进程实测**的值（不是客户端按公式算的）：
//   [0] initialized（0/1）
//   [1] storage_bytes        （= 16·m·entry_words + 16·n·|attrs|，含补齐条目）
//   [2] feature_storage_bytes（= 16·m·entry_words）
//   [3] attribute_storage_bytes（= 16·N·|attrs|）
//   [4] rpc_count（4 条数据 RPC 中成功的次数）
//   [5] queries_served（受理的**查询集**个数；与 RPC 次数无关）
//   [6] words_read（实际读过的 word 数）
//   [7] batch_rpc_count（ServerResp 批量 RPC 次数）
//   [8] relay_install_frames
//   [9] relay_phase_frames
//   [10] relay_records_processed（两轮累计处理的记录条数 = 2N）
//   [11] node_scalar_rpc_count（`MpraqNode` 层的**标量** `ServerResp` 次数）
//   [12] node_batch_rpc_count（`MpraqNode` 层的 `ServerRespBatch` 次数）
//   [13] service_batch_resp_calls（**服务侧** `MpraqServiceImpl::batch_rpc_count()`：
//        每受理一次 `ServerResp` RPC 恰好 +1 —— `MPA-08` 裁决 1 之后它就是
//        "服务侧确实走了批量入口"的直接证据）
// ⚠️ 这三个"层"的计数器**口径不同**（`D31` 的教训）：`rpc_count` 是 **gRPC 服务**受理的
//    数据 RPC 次数（含 Init/上传/属性共享），`queries_served` 是**查询集**个数，
//    而 node 层的两个计数器在 `MpraqNode::InitTable` 时会被**清零**（`MPA-03` 的设计），
//    因此"最近一次 Init 之后"才连续。报数时必须写清是哪一层，别混用。
inline constexpr size_t kServerStatsFields = 14;

struct ServerStats {
    bool initialized = false;
    uint64_t storage_bytes = 0;
    uint64_t feature_storage_bytes = 0;
    uint64_t attribute_storage_bytes = 0;
    uint64_t rpc_count = 0;
    uint64_t queries_served = 0;
    uint64_t words_read = 0;
    uint64_t batch_rpc_count = 0;
    uint64_t relay_install_frames = 0;
    uint64_t relay_phase_frames = 0;
    uint64_t relay_records_processed = 0;
    uint64_t node_scalar_rpc_count = 0;
    uint64_t node_batch_rpc_count = 0;
    uint64_t service_batch_resp_calls = 0;
};

// ---------------------------------------------------------------------------
// 服务器进程侧：批量会话服务（`Relay` handler 的分派器）
// ---------------------------------------------------------------------------

class MpraqSecureMulServer {
public:
    // `Relay` 的 handler 本体。失败一律**抛异常**（`Relay` 会把它转成
    // `RelayResponse.ok=false` + 可读 error ⇒ 客户端侧 `Response::Err`，绝不静默）。
    Payload Handle(const Payload& frame);

    // 账目（只增不减）
    uint64_t install_frames() const;
    uint64_t phase_frames() const;
    uint64_t install_records() const;
    uint64_t phase_records() const;
    uint64_t session_states() const;

private:
    // ⚠️ gRPC 服务器**多线程**并发进入 handler ⇒ 本对象自己加锁
    //    （`SecureMulBatchServerTable` 明确不加锁，见 aggvalue.hpp 的注释）。
    mutable std::mutex mu_;
    SecureMulBatchServerTable table_;
    uint64_t install_frames_ = 0;
    uint64_t phase_frames_ = 0;
    uint64_t install_records_ = 0;
    uint64_t phase_records_ = 0;
};

// ---------------------------------------------------------------------------
// 客户端进程侧：指向**服务器进程**的批量会话端点
// ---------------------------------------------------------------------------

class RemoteSecureMulBatchEndpoint final : public ISecureMulBatchEndpoint {
public:
    // `server_id` 是 `client` 的端点下标（0 = 第一台服务器进程）。
    RemoteSecureMulBatchEndpoint(ITransportClient& client, int server_id);

    RemoteSecureMulBatchEndpoint(const RemoteSecureMulBatchEndpoint&) = delete;
    RemoteSecureMulBatchEndpoint& operator=(const RemoteSecureMulBatchEndpoint&) = delete;

    // ---- ISecureMulBatchEndpoint ----
    void BeginSession() override;  // 本端点跨查询复用 ⇒ 每次会话开始都要清计数与缓冲
    void Install(uint64_t session, const SecureMulServerSetup& setup) override;
    void FlushInstalls() override;
    void SubmitFrame(const Payload& frame) override;
    Response UnwrapResponse(const Response& raw) override;
    uint64_t frames() const override { return phase_frames_; }
    uint64_t processed_phase1() const override { return processed_phase1_; }
    uint64_t processed_phase2() const override { return processed_phase2_; }
    uint64_t install_frames() const override { return install_frames_; }
    uint64_t install_bytes() const override { return install_bytes_; }
    void Close() override {}  // 远程模式：服务器表由下一次安装帧的 Clear() 覆盖

    // ---- 诊断 ----
    int server_id() const { return server_id_; }
    uint64_t relay_calls() const { return relay_calls_; }  // 本端点发出的 Relay 次数
    uint64_t install_entries() const { return sessions_.size(); }

private:
    ITransportClient* client_;
    int server_id_;
    std::vector<uint64_t> sessions_;
    std::vector<SecureMulServerSetup> setups_;
    uint64_t expected_records_ = 0;       // 本轮应有的记录条数（= 安装条数）
    uint64_t last_request_kind_ = 0;      // 上一次 SubmitFrame 的封套 kind
    uint64_t phase_frames_ = 0;
    uint64_t processed_phase1_ = 0;
    uint64_t processed_phase2_ = 0;
    uint64_t install_frames_ = 0;
    uint64_t install_bytes_ = 0;
    uint64_t relay_calls_ = 0;
};

// 向一台服务器索取**实测**账目（走 `Relay`，不新增 RPC）。
ServerStats QueryServerStats(ITransportClient& client, int server_id);

// ---------------------------------------------------------------------------
// 服务器进程的 gRPC 服务：4 条数据 RPC + Relay
// ---------------------------------------------------------------------------
// `MpraqServiceImpl` 只实现了 4 条数据 RPC（`Relay` 在 `net/grpc_transport.hpp`
// 的 `RelayEndpointService` 里），而**本 demo 的服务器进程必须同时**服务这两类
// 请求（客户端的 MPRAQ 通道和 SecureMul 的 Relay 通道连的是**同一个端口**）
// ⇒ 这里用**组合**（而不是继承）把两份实现拼在一个 service 上：
//   * 4 条数据 RPC → 转发给 `MpraqServiceImpl`（`tsb_net_mpraq`，**不改**它）；
//   * `Relay` → 转发给 `MpraqSecureMulServer`（本文件）。
class MpraqDemoService final : public ::mpraqwire::MpraqService::Service {
public:
    explicit MpraqDemoService(MpraqNode& node);

    grpc::Status InitTable(grpc::ServerContext* ctx,
                           const ::mpraqwire::InitTableRequest* req,
                           ::mpraqwire::InitTableResponse* resp) override;
    grpc::Status UploadFeatureWords(grpc::ServerContext* ctx,
                                    const ::mpraqwire::UploadFeatureWordsRequest* req,
                                    ::mpraqwire::UploadFeatureWordsResponse* resp) override;
    // ⚠️ 本类**逐条**实现 RPC（不继承 `MpraqServiceImpl`）⇒ 每新增一条 RPC 都必须在
    //    这里补一条转发，否则 gRPC 会走基类默认实现返回 **UNIMPLEMENTED**（消息为空，
    //    很难从客户端报错看出原因）。加 tag 上传时就踩过这个坑。
    grpc::Status UploadFeatureTags(grpc::ServerContext* ctx,
                                   const ::mpraqwire::UploadFeatureTagsRequest* req,
                                   ::mpraqwire::UploadFeatureTagsResponse* resp) override;
    grpc::Status SetAttributeShares(grpc::ServerContext* ctx,
                                    const ::mpraqwire::SetAttributeSharesRequest* req,
                                    ::mpraqwire::SetAttributeSharesResponse* resp) override;
    grpc::Status ServerResp(grpc::ServerContext* ctx,
                            const ::mpraqwire::PirQueryRequest* req,
                            ::mpraqwire::PirQueryResponse* resp) override;
    grpc::Status Relay(grpc::ServerContext* ctx, const ::mpraqwire::RelayRequest* req,
                       ::mpraqwire::RelayResponse* resp) override;

    const MpraqNode& node() const { return *node_; }
    MpraqServiceImpl& data() { return data_; }
    const MpraqServiceImpl& data() const { return data_; }
    MpraqSecureMulServer& securemul() { return securemul_; }
    const MpraqSecureMulServer& securemul() const { return securemul_; }
    uint64_t relay_calls() const { return relay_calls_; }
    uint64_t relay_errors() const { return relay_errors_; }

    // 本进程实测账目（`kStatsAck` 的载荷也走这个函数 ⇒ 与客户端看到的**同源**）
    ServerStats Stats() const;

private:
    MpraqNode* node_ = nullptr;
    MpraqServiceImpl data_;
    MpraqSecureMulServer securemul_;
    std::atomic<uint64_t> relay_calls_{0};
    std::atomic<uint64_t> relay_errors_{0};
};

}  // namespace mpraq
}  // namespace tsb
