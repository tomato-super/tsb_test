#include "net/grpc_transport.hpp"

#include <atomic>
#include <cctype>
#include <stdexcept>
#include <utility>

namespace tsb {

// 单个端点的 Relay 服务实现。
//
// ⚠️ 这是**整个文件里唯一**跑在服务器线程上的东西，因此它只允许碰两样东西：
//   * `handler_` —— 指向 `GrpcTransportServer::handlers_[server_id]` 的指针
//     （服务端只读；`SetHandler` 必须在接收请求之前完成）；
//   * `relay_count_/error_count_` —— `std::atomic`（多线程并发写）。
// 它**看不到** `GrpcTransportClient`、看不到别的端点、也看不到 `endpoints_`
// ⇒ "一台服务器没有任何句柄能触达另一台"是结构性的。
class RelayEndpointService final : public ::mpraqwire::MpraqService::Service {
public:
    RelayEndpointService(int server_id, const ServerHandler* handler)
        : server_id_(server_id), handler_(handler) {}

    grpc::Status Relay(grpc::ServerContext*, const ::mpraqwire::RelayRequest* req,
                       ::mpraqwire::RelayResponse* resp) override {
        relay_count_.fetch_add(1, std::memory_order_relaxed);
        if (handler_ == nullptr || !*handler_) {
            // 与 `LocalTransport::Collect` 的 "服务器未注册处理函数" 对齐
            error_count_.fetch_add(1, std::memory_order_relaxed);
            resp->set_ok(false);
            resp->set_error("GrpcTransportServer: 服务器 " + std::to_string(server_id_) +
                            " 未注册处理函数");
            return grpc::Status::OK;
        }
        try {
            Payload answer = (*handler_)(Payload(req->payload().begin(),
                                                 req->payload().end()));
            resp->set_ok(true);
            resp->set_payload(answer.empty()
                                  ? std::string()
                                  : std::string(reinterpret_cast<const char*>(answer.data()),
                                                answer.size()));
            return grpc::Status::OK;
        } catch (const std::exception& e) {
            // 呼应 `net/transport.hpp`："允许抛异常——传输层会将其转换为错误返回给客户端"
            error_count_.fetch_add(1, std::memory_order_relaxed);
            resp->set_ok(false);
            resp->set_error(std::string("服务器异常: ") + e.what());
            return grpc::Status::OK;
        } catch (...) {
            error_count_.fetch_add(1, std::memory_order_relaxed);
            resp->set_ok(false);
            resp->set_error("服务器抛出未知异常");
            return grpc::Status::OK;
        }
    }

    uint64_t relay_count() const { return relay_count_.load(std::memory_order_relaxed); }
    uint64_t error_count() const { return error_count_.load(std::memory_order_relaxed); }

private:
    int server_id_ = 0;
    const ServerHandler* handler_ = nullptr;
    std::atomic<uint64_t> relay_count_{0};
    std::atomic<uint64_t> error_count_{0};
};

// ---------------------------------------------------------------------------
// 端点解析
// ---------------------------------------------------------------------------

std::pair<std::string, uint32_t> ParseEndpoint(const std::string& endpoint) {
    std::string host;
    std::string port_str;
    if (!endpoint.empty() && endpoint.front() == '[') {
        const size_t close = endpoint.find(']');
        if (close == std::string::npos) {
            throw std::invalid_argument("ParseEndpoint: IPv6 端点缺少 ']'：" + endpoint);
        }
        host = endpoint.substr(1, close - 1);
        if (close + 1 >= endpoint.size() || endpoint[close + 1] != ':') {
            throw std::invalid_argument("ParseEndpoint: 端点缺少端口部分：" + endpoint);
        }
        port_str = endpoint.substr(close + 2);
    } else {
        const size_t colon = endpoint.rfind(':');
        if (colon == std::string::npos || colon == 0 || colon + 1 >= endpoint.size()) {
            throw std::invalid_argument("ParseEndpoint: 端点必须是 host:port 形式：" +
                                        endpoint);
        }
        host = endpoint.substr(0, colon);
        port_str = endpoint.substr(colon + 1);
    }
    for (char c : port_str) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            throw std::invalid_argument("ParseEndpoint: 端口必须是非负整数：" + endpoint);
        }
    }
    const unsigned long port = std::stoul(port_str);
    if (port > 65535UL) {
        throw std::invalid_argument("ParseEndpoint: 端口超出 0..65535：" + endpoint);
    }
    return {host, static_cast<uint32_t>(port)};
}

std::string EphemeralEndpoint(const std::string& endpoint) {
    const auto [host, port] = ParseEndpoint(endpoint);
    (void)port;
    if (!host.empty() && host.front() == '[') {
        return host + ":0";
    }
    return host + ":0";
}

// ---------------------------------------------------------------------------
// GrpcTransportClient
// ---------------------------------------------------------------------------

GrpcTransportClient::GrpcTransportClient(std::vector<std::string> endpoints)
    : endpoints_(std::move(endpoints)) {
    if (endpoints_.empty()) {
        throw std::invalid_argument("GrpcTransportClient: 至少需要一个端点");
    }
    for (const std::string& ep : endpoints_) {
        (void)ParseEndpoint(ep);  // 早失败：格式非法当场抛，而不是首次请求时才发现
        // 🔴 必须显式放宽**收包**上限（gRPC 默认 4 MiB）：SecureMul 的一轮应答帧
        //    随 N 线性增长（Phase2 应答 = 19 + 58N），默认值会让 `N > 72 315`
        //    在第 1 轮就失败（`MPA-09` 在 N=2^17 实测到）。见头文件里
        //    `kGrpcClientMaxReceiveBytes` 的说明（**两侧必须成对设置**）。
        grpc::ChannelArguments args;
        args.SetMaxReceiveMessageSize(kGrpcClientMaxReceiveBytes);
        channels_.push_back(grpc::CreateCustomChannel(
            ep, grpc::InsecureChannelCredentials(), args));
        stubs_.push_back(::mpraqwire::MpraqService::NewStub(channels_.back()));
    }
    request_count_.assign(endpoints_.size(), 0);
}

bool GrpcTransportClient::WaitForConnection(int timeout_ms) {
    if (timeout_ms <= 0) {
        return false;
    }
    const auto deadline =
        std::chrono::system_clock::now() + std::chrono::milliseconds(timeout_ms);
    bool all_ready = true;
    for (const auto& ch : channels_) {
        if (!ch->WaitForConnected(deadline)) {
            all_ready = false;
        }
    }
    return all_ready;
}

void GrpcTransportClient::Connect(int timeout_ms) {
    if (!WaitForConnection(timeout_ms)) {
        std::string joined;
        for (size_t i = 0; i < endpoints_.size(); ++i) {
            joined += (i == 0 ? "" : ", ") + endpoints_[i];
        }
        throw TransportError("GrpcTransportClient::Connect: 无法连接到全部服务器 [" +
                             joined + "]（" + std::to_string(timeout_ms) + "ms 超时）");
    }
}

uint64_t GrpcTransportClient::RequestCount(int server_id) const {
    if (server_id < 0 || server_id >= static_cast<int>(endpoints_.size())) {
        return 0;
    }
    return request_count_[static_cast<size_t>(server_id)];
}

void GrpcTransportClient::set_tamper_hook(TransportTamperHook hook) {
    std::lock_guard<std::mutex> lock(hook_mu_);
    tamper_hook_ = std::move(hook);
}

void GrpcTransportClient::clear_tamper_hook() {
    std::lock_guard<std::mutex> lock(hook_mu_);
    tamper_hook_ = nullptr;
}

void GrpcTransportClient::Submit(int server_id, Payload request) {
    if (server_id < 0 || server_id >= static_cast<int>(endpoints_.size())) {
        throw std::out_of_range("GrpcTransportClient::Submit: server_id 越界 " +
                                std::to_string(server_id) + "（共 " +
                                std::to_string(endpoints_.size()) + " 台服务器）");
    }
    pending_.emplace_back(server_id, std::move(request));
}

std::vector<Response> GrpcTransportClient::Collect() {
    std::vector<Response> out;
    out.reserve(pending_.size());
    // 每次 round trip 一个**新建的** ClientContext（照 `GrpcChannel` 的写法：
    // 复用 ClientContext 是未定义行为）。
    for (const auto& [server_id, req_bytes] : pending_) {
        const size_t sid = static_cast<size_t>(server_id);
        request_count_[sid] += 1;

        ::mpraqwire::RelayRequest req;
        req.set_payload(req_bytes.empty()
                            ? std::string()
                            : std::string(reinterpret_cast<const char*>(req_bytes.data()),
                                          req_bytes.size()));
        ::mpraqwire::RelayResponse resp;
        grpc::ClientContext ctx;
        const grpc::Status st = stubs_[sid]->Relay(&ctx, req, &resp);
        if (!st.ok()) {
            // 传输层失败（含服务器不可达）⇒ 必须表达成错误，不能冒充成功
            out.push_back(Response::Err("Relay RPC 失败（" + endpoints_[sid] +
                                        "）: " + st.error_message()));
            continue;
        }
        if (!resp.ok()) {
            out.push_back(Response::Err("Relay 被服务器 " + std::to_string(server_id) +
                                        " 拒绝（" + endpoints_[sid] + "）: " +
                                        resp.error()));
            continue;
        }
        Payload answer(resp.payload().begin(), resp.payload().end());
        {
            TransportTamperHook hook;
            {
                std::lock_guard<std::mutex> lock(hook_mu_);
                hook = tamper_hook_;
            }
            if (hook) {
                hook(server_id, answer);
            }
        }
        out.push_back(Response::Ok(std::move(answer)));
    }
    pending_.clear();
    return out;
}

// ---------------------------------------------------------------------------
// GrpcTransportServer
// ---------------------------------------------------------------------------

GrpcTransportServer::GrpcTransportServer(std::vector<std::string> endpoints)
    : endpoints_(std::move(endpoints)) {
    if (endpoints_.empty()) {
        throw std::invalid_argument("GrpcTransportServer: 至少需要一个端点");
    }
    for (const std::string& ep : endpoints_) {
        (void)ParseEndpoint(ep);
    }
    // ⚠️ 顺序关键：先 `resize` handlers_（此后**不再**改动容量，指针保持有效），
    //    再让服务实例指向对应槽位。
    handlers_.resize(endpoints_.size());
    for (size_t i = 0; i < endpoints_.size(); ++i) {
        services_.push_back(std::make_unique<RelayEndpointService>(
            static_cast<int>(i), &handlers_[i]));
    }
    for (size_t i = 0; i < endpoints_.size(); ++i) {
        grpc::ServerBuilder builder;
        int bound = 0;
        builder.AddListeningPort(endpoints_[i], grpc::InsecureServerCredentials(), &bound);
        builder.RegisterService(services_[i].get());
        std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
        if (!server || bound == 0) {
            start_error_ = "GrpcTransportServer: 无法监听 " + endpoints_[i] +
                           "（端口被占用或地址非法；⚠️ 测试必须用临时端口 :0 —— "
                           "TASK_PLAN.md §3.4）";
            // 已经起来的那些照常析构（unique_ptr 会 Shutdown）
            servers_.clear();
            bound_ports_.clear();
            return;
        }
        servers_.push_back(std::move(server));
        bound_ports_.push_back(std::to_string(bound));
    }
    started_ = true;
}

GrpcTransportServer::~GrpcTransportServer() {
    for (auto& s : servers_) {
        if (s) {
            s->Shutdown();
        }
    }
    for (auto& s : servers_) {
        if (s) {
            s->Wait();
        }
    }
}

void GrpcTransportServer::SetHandler(int server_id, ServerHandler handler) {
    if (server_id < 0 || server_id >= static_cast<int>(endpoints_.size())) {
        throw std::out_of_range("GrpcTransportServer::SetHandler: server_id 越界");
    }
    if (!handler) {
        throw std::invalid_argument("GrpcTransportServer::SetHandler: 处理函数为空");
    }
    handlers_[static_cast<size_t>(server_id)] = std::move(handler);
}

uint64_t GrpcTransportServer::RelayCount(int server_id) const {
    if (server_id < 0 || server_id >= static_cast<int>(services_.size())) {
        return 0;
    }
    return services_[static_cast<size_t>(server_id)]->relay_count();
}

uint64_t GrpcTransportServer::ErrorCount(int server_id) const {
    if (server_id < 0 || server_id >= static_cast<int>(services_.size())) {
        return 0;
    }
    return services_[static_cast<size_t>(server_id)]->error_count();
}

// ---------------------------------------------------------------------------
// InProcessTransportServer
// ---------------------------------------------------------------------------

InProcessTransportServer::InProcessTransportServer(const std::string& address) {
    const std::string ephemeral = EphemeralEndpoint(address);
    inner_ = std::make_unique<GrpcTransportServer>(std::vector<std::string>{ephemeral});
    if (!inner_->started()) {
        start_error_ = inner_->start_error();
        return;
    }
    // 从 `AddListeningPort(..., &bound)` 的回填值读回内核分配的真实端口
    // （照 `vmpq::InProcessNode` / `InProcessMpraqNode` 的写法）。
    bound_port_ = inner_->bound_ports().empty() ? std::string() : inner_->bound_ports()[0];
    if (bound_port_.empty() || bound_port_ == "0") {
        start_error_ = "InProcessTransportServer: 未能从监听端口回填得到实际端口";
        inner_.reset();
    }
}

InProcessTransportServer::~InProcessTransportServer() = default;

}  // namespace tsb
