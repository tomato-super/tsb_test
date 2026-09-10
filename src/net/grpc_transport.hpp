#pragma once

// gRPC 实现通用传输抽象（`net/transport.hpp` 的 `ITransportClient/ITransportServer`）。
//
// ===========================================================================
// 1. 为什么要这一层
// ===========================================================================
// `net/transport.hpp` 的文件头就写着"提供两种实现：LocalTransport（进程内）/
// GrpcTransport（真实网络）"，但在此之前只有 `LocalTransport` 落地 ⇒
// `MPA-05` 的 SecureMul 三方消息流（`mpraq/secure_mul_flow.hpp`：
// Phase1Request / Phase1Response / Phase2Request / Phase2Response 四条腿）
// 只能在**单进程**里跑。本文件把那条消息流接到真实 gRPC 上：
//
//   客户端线程 ── Submit(server 0/1) ──▶ 两台 gRPC 服务器的 `Relay` handler
//              ◀── Collect() 按序收 ───   （handler = MPA-05 的
//                                          ServerHandlePhase1/2）
//
// ===========================================================================
// 2. 结构性保证（与 `LocalTransport` 的对照）
// ===========================================================================
// * **"服务器之间零通信"仍然成立**：每台服务器是一个**独立的 `grpc::Server`
//   实例 + 独立的 `RelayServiceImpl`**，而每个 `RelayServiceImpl` 只持有
//   **它自己那一个** handler 指针。服务实例里没有另一台的引用、没有共享的
//   全局表（`ITransportServer` 侧的那份 `GrpcTransportServer` 只被**客户端
//   所在进程**持有，服务器进程不会看到它）⇒ 一台服务器**没有任何句柄**能触达
//   另一台。真实双进程部署时这一点是物理成立的。
// * **错误必须可表达**：handler 抛异常 / 未注册 handler / 入参非法 / 传输层
//   失败（连接断开、非 OK 的 gRPC status）一律变成 `Response::Err(...)`，
//   **绝不**把空 payload 当成成功应答返回。这一点是 `LocalTransport` 的
//   `drop_hook` 语义在真实链路上的对应物，也是 MPA-05 那些"篡改必须被检出"
//   用例在 gRPC 上的前提。
//
// ⚠️ 半诚实版本：无 TLS、无身份认证（决策 D4）。`Relay` 是**开放转发**（任何
//    连得上的客户端都能把任意字节递给 handler）——真实部署必须先补认证。

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <grpcpp/grpcpp.h>

#include "mpraq.grpc.pb.h"
#include "net/transport.hpp"

namespace tsb {

// 单端点的 `Relay` 服务实现（定义在 `grpc_transport.cpp`）。
// ⚠️ 这是**唯一**跑在服务器线程上的对象：它只持有"本端点 handler 的指针"+
//    两个原子计数，看不到客户端、也看不到别的端点 —— 见 .cpp 的说明。
class RelayEndpointService;

// 篡改钩子：在客户端**收到应答之后、交给调用方之前**就地对 payload 做修改。
// 与 `LocalTransportOptions::tamper_hook` 同一语义/同一签名，便于把
// `test_mpraq_securemul.cpp` 的篡改用例原样搬到真实 gRPC 链路上。
using TransportTamperHook = std::function<void(int server_id, Payload& response)>;

// ---------------------------------------------------------------------------
// 客户端 **收包上限**（`MPA-09` 任务 B）：这是"**能不能跑大规模**"的硬天花板
// ---------------------------------------------------------------------------
//
// gRPC 的默认 `max_receive_message_length` 只有 **4 MiB**（发送侧默认无上限）。
// MPRAQ 的 SecureMul 走**通用 `Relay`**，一次查询的两类**应答帧**都随 N 线性增长：
//   * Phase1 应答 = `13 + 6 + 43·N` 字节；
//   * Phase2 应答 = `13 + 6 + 58·N` 字节。
// ⇒ 客户端若用默认值，`N > 72 315` 时**第 1 轮**就会失败：
//     `CLIENT: Received message larger than max (5636122 vs. 4194304)`
//   （`MPA-09` 在 `N = 2^17` 上实测到；`N = 2^16` 的 3.80 MB 恰好还在 4 MiB 内 ⇒ 侥幸能跑）。
//
// 🔴 纪律：**服务器侧与客户端侧必须成对设置**，否则大帧会在**收包方**被拒绝 ——
//    * 服务器进程侧：`mpraq_server.cpp` / `test_mpraq_e2e.cpp` 的夹具已设 **256 MiB**；
//    * 客户端侧（本常量）：`GrpcTransportClient` 与 `GrpcMpraqChannel` 都显式设置。
//    任一侧漏设 ⇒ 大帧失败；**且失败是 fail-loudly 的**（gRPC 返回可读的
//    `RESOURCE_EXHAUSTED: Received message larger than max (X vs. Y)`，
//    经 `Response::Err` 冒到上层 ⇒ `SecureMulBatchAbort`，**绝不静默截断**）。
//
// ⚠️ 本常量只放宽**收包**上限；发送侧保持 gRPC 的默认（无限），因此不会给
//    "离线安装帧"（`2×(13+152·N)`）引入新的上限。
inline constexpr int kGrpcClientMaxReceiveBytes = 256 * 1024 * 1024;
// 默认 4 MiB 是 gRPC 的既有取值：这里断言我们**确实放宽了**（防止有人改小/删掉）
static_assert(kGrpcClientMaxReceiveBytes >= 4 * 1024 * 1024,
              "客户端收包上限必须 >= gRPC 默认的 4 MiB");

// ---------------------------------------------------------------------------
// 客户端侧：ITransportClient
// ---------------------------------------------------------------------------

class GrpcTransportClient final : public ITransportClient {
public:
    // endpoints[i] = 第 i 台服务器的 "host:port"（i = 0,1,...）
    // ⚠️ endpoint 的语义与 `ITransportClient::Submit(server_id, ...)` 的 server_id
    //    一一对应；server_id 越界一律抛 `std::out_of_range`（照 `LocalTransport`）。
    explicit GrpcTransportClient(std::vector<std::string> endpoints);

    // ---- ITransportClient ----
    void Submit(int server_id, Payload request) override;
    std::vector<Response> Collect() override;
    size_t PendingCount() const override { return pending_.size(); }
    void Abort() override { pending_.clear(); }

    // ---- 连接与诊断 ----

    // 阻塞直到**全部**服务器可连接；非抛出版本（照 `GrpcChannel::WaitForConnection`）
    bool WaitForConnection(int timeout_ms);
    // 抛出 `TransportError` 的版本
    void Connect(int timeout_ms = 5000);

    int NumServers() const { return static_cast<int>(endpoints_.size()); }
    // 本客户端**显式设置**的收包上限（= `kGrpcClientMaxReceiveBytes`；账目/测试用）
    static constexpr int max_receive_bytes() { return kGrpcClientMaxReceiveBytes; }
    const std::vector<std::string>& endpoints() const { return endpoints_; }
    // 各服务器上**已发出**的 RPC 次数（诊断：一次 SecureMul = 2 次/台）
    uint64_t RequestCount(int server_id) const;

    // 篡改注入（测试用；与 `LocalTransportOptions::tamper_hook` 同语义）
    void set_tamper_hook(TransportTamperHook hook);
    void clear_tamper_hook();

private:
    std::vector<std::string> endpoints_;
    std::vector<std::shared_ptr<grpc::Channel>> channels_;
    std::vector<std::unique_ptr<::mpraqwire::MpraqService::Stub>> stubs_;
    std::vector<uint64_t> request_count_;
    std::vector<std::pair<int, Payload>> pending_;
    std::mutex hook_mu_;
    TransportTamperHook tamper_hook_;
};

// ---------------------------------------------------------------------------
// 服务器侧：ITransportServer
// ---------------------------------------------------------------------------

// 多端点实现：在**同一进程**内为每台服务器起一个独立的 `grpc::Server`（各自
// 独立的监听端口 + 独立的服务实例）。用途：
//   * 测试/单机仿真：一个进程里跑"客户端 + 两台服务器"，但链路是真的 gRPC；
//   * 真实部署：`GrpcTransportServer({endpoint})` 只起一台（每进程一台），
//     客户端用 `GrpcTransportClient({ep0, ep1})` 跨进程连。
//
// ⚠️ `SetHandler` 必须在**开始接收请求之前**调用（服务端读、本对象写，没有加锁；
//    与 `LocalTransport` 的"先注册后提交"用法一致）。`SetHandler` 传入空函数
//    抛 `std::invalid_argument`（照 `LocalTransport`）。
class GrpcTransportServer final : public ITransportServer {
public:
    explicit GrpcTransportServer(std::vector<std::string> endpoints);
    ~GrpcTransportServer() override;

    GrpcTransportServer(const GrpcTransportServer&) = delete;
    GrpcTransportServer& operator=(const GrpcTransportServer&) = delete;

    // ---- ITransportServer ----
    void SetHandler(int server_id, ServerHandler handler) override;
    int NumServers() const override { return static_cast<int>(endpoints_.size()); }

    // ---- 诊断 ----
    const std::vector<std::string>& endpoints() const { return endpoints_; }
    // 各端点**实际绑定**的端口（`AddListeningPort` 的回填值，十进制字符串）。
    // 端点写成 ":0"（临时端口）时，真实端口只能从这里读回。
    const std::vector<std::string>& bound_ports() const { return bound_ports_; }
    // 每台服务器实际收到的 `Relay` 请求数
    uint64_t RelayCount(int server_id) const;
    // 每台服务器被 handler 拒绝/抛异常的请求数
    uint64_t ErrorCount(int server_id) const;

    bool started() const { return started_; }
    // 起服务器失败的原因（started() == false 时非空）
    const std::string& start_error() const { return start_error_; }

private:
    std::vector<std::string> endpoints_;
    std::vector<std::string> bound_ports_;             // 与 endpoints_ 同长，回填端口
    std::vector<ServerHandler> handlers_;              // 每端点一个（服务端只读）
    std::vector<std::unique_ptr<RelayEndpointService>> services_;
    std::vector<std::unique_ptr<grpc::Server>> servers_;
    bool started_ = false;
    std::string start_error_;
};

// 单端点 + **临时端口**（`host:0`）的便捷包装：照 `vmpq::InProcessNode` /
// `InProcessMpraqNode` 的写法，从 `AddListeningPort` 回填的端口读回真实端口。
// ⚠️ 测试**必须**用这个（`TASK_PLAN.md` §3.4 的已知坑：固定端口会让并发跑第二份
//    测试套件时绑定失败）。
class InProcessTransportServer {
public:
    // address 形如 "127.0.0.1:0"
    explicit InProcessTransportServer(const std::string& address);
    ~InProcessTransportServer();

    InProcessTransportServer(const InProcessTransportServer&) = delete;
    InProcessTransportServer& operator=(const InProcessTransportServer&) = delete;

    ITransportServer& server() { return *inner_; }
    bool started() const { return inner_ && inner_->started(); }
    const std::string& bound_port() const { return bound_port_; }
    const std::string& start_error() const { return start_error_; }
    // "127.0.0.1:<bound_port>"，直接喂给 `GrpcTransportClient`
    std::string local_address() const { return "127.0.0.1:" + bound_port_; }
    uint64_t relay_count() const { return inner_ ? inner_->RelayCount(0) : 0; }
    // handler 抛异常 / 未注册 handler 而被拒绝的请求数
    uint64_t error_count() const { return inner_ ? inner_->ErrorCount(0) : 0; }

private:
    std::unique_ptr<GrpcTransportServer> inner_;
    std::string bound_port_;
    std::string start_error_;
};

// ---------------------------------------------------------------------------
// 小工具（测试与 demo 都会用到）
// ---------------------------------------------------------------------------

// 把 "host:port" 拆成 (host, port)。支持 IPv6 的 "[::1]:50051" 写法。
// 格式非法抛 `std::invalid_argument`；port 非数字或 > 65535 同样抛。
std::pair<std::string, uint32_t> ParseEndpoint(const std::string& endpoint);

// 把端点里的端口替换为 0 得到"临时端口"端点："127.0.0.1:50051" → "127.0.0.1:0"。
std::string EphemeralEndpoint(const std::string& endpoint);

}  // namespace tsb
