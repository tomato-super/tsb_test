#pragma once

// 传输抽象。
//
// 两个协议（V-OO-PIR / Plinko）的在线阶段都是**非交互式请求-应答**：
//   客户端 → 服务器：查询集 q
//   服务器 → 客户端：(应答 P, 验证值 C)
//
// 特别地，VMPQ 的 Multiply 协议要求"用户先把请求发给两个服务器、
// 再把一方的中间值转给另一方"，因此接口必须允许**分阶段**：
//   Submit(a) / Submit(b) → Collect() → Submit(relay) → Collect()
//
// 提供两种实现：
//   * LocalTransport —— 进程内直连，支持注入延迟与篡改（测试/单机仿真）
//   * GrpcTransport  —— 真实网络（部署）
//
// 这样绝大多数开发与恶意行为测试无需启动真实服务，迭代速度提升一个量级。

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace tsb {

// 线上消息：不透明字节串。上层负责序列化。
using Payload = std::vector<uint8_t>;

// 服务器侧的处理函数：接收请求，返回应答。
// 允许抛异常——传输层会将其转换为错误返回给客户端。
using ServerHandler = std::function<Payload(const Payload& request)>;

// 传输错误（连接失败、服务器拒绝等）
class TransportError : public std::runtime_error {
public:
    explicit TransportError(const std::string& what) : std::runtime_error(what) {}
};

// 响应可能是值，也可能是错误
struct Response {
    bool ok = false;
    Payload payload;
    std::string error;

    static Response Ok(Payload p) {
        Response r;
        r.ok = true;
        r.payload = std::move(p);
        return r;
    }
    static Response Err(std::string msg) {
        Response r;
        r.ok = false;
        r.error = std::move(msg);
        return r;
    }
};

// ---------------------------------------------------------------------------
// 服务器侧：注册处理函数
// ---------------------------------------------------------------------------

class ITransportServer {
public:
    virtual ~ITransportServer() = default;

    // 注册/替换处理函数。server_id 是逻辑服务器编号（0/1）。
    virtual void SetHandler(int server_id, ServerHandler handler) = 0;

    // 服务器个数
    virtual int NumServers() const = 0;
};

// ---------------------------------------------------------------------------
// 客户端侧
// ---------------------------------------------------------------------------

class ITransportClient {
public:
    virtual ~ITransportClient() = default;

    // 提交一个不等待结果的请求。必须在 Collect 之前调用。
    virtual void Submit(int server_id, Payload request) = 0;

    // 收取已提交请求的应答，顺序与 Submit 的提交顺序一致。
    // 若还有未提交的请求未发出，可能阻塞等待网络。
    virtual std::vector<Response> Collect() = 0;

    // 便捷方法：提交并立即收取单个响应
    Response RoundTrip(int server_id, Payload request);

    // 已提交但未收取的请求数
    virtual size_t PendingCount() const = 0;

    // 丢弃所有未收取的请求（例如查询中止）
    virtual void Abort() = 0;
};

// ---------------------------------------------------------------------------
// 本地（进程内）实现
// ---------------------------------------------------------------------------

// 本地传输的行为配置。测试通过它注入延迟与恶意行为。
struct LocalTransportOptions {
    // 模拟网络延迟（每个方向）。默认 0。
    std::chrono::microseconds latency{0};

    // 篡改钩子：在服务器应答返回给客户端之前调用，可就地修改 payload。
    // 用于模拟恶意服务器（对应 FND-15 的恶意行为注入测试）。
    std::function<void(int server_id, Payload& response)> tamper_hook;

    // 丢弃钩子：返回 true 表示"丢掉这个应答"，客户端收到 TransportError。
    std::function<bool(int server_id)> drop_hook;
};

// 进程内传输。同时实现客户端与服务器两侧。
class LocalTransport : public ITransportServer, public ITransportClient {
public:
    explicit LocalTransport(int num_servers, LocalTransportOptions options = {});

    // ---- ITransportServer ----
    void SetHandler(int server_id, ServerHandler handler) override;
    int NumServers() const override { return num_servers_; }

    // ---- ITransportClient ----
    void Submit(int server_id, Payload request) override;
    std::vector<Response> Collect() override;
    size_t PendingCount() const override { return pending_.size(); }
    void Abort() override { pending_.clear(); }

    // ---- 测试辅助 ----

    // 运行期修改行为（便于在同一个测试里切换恶意模式）
    LocalTransportOptions& options() { return options_; }
    const LocalTransportOptions& options() const { return options_; }

    // 统计：各服务器收到的请求数（用于隐私性检查，如 PIR-03）
    uint64_t RequestCount(int server_id) const;

    // 统计：所有请求的原始字节（供隐私性分析）
    const std::vector<Payload>& RequestLog(int server_id) const;

    // 清空统计
    void ResetStats();

private:
    struct PendingRequest {
        int server_id;
        Payload request;
    };

    int num_servers_;
    LocalTransportOptions options_;
    std::vector<ServerHandler> handlers_;
    std::vector<PendingRequest> pending_;
    std::vector<std::vector<Payload>> request_log_;
};

}  // namespace tsb
