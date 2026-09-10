#include "net/transport.hpp"

#include <thread>

namespace tsb {

Response ITransportClient::RoundTrip(int server_id, Payload request) {
    Submit(server_id, std::move(request));
    auto responses = Collect();
    if (responses.size() != 1) {
        return Response::Err("RoundTrip: 应答数量与请求不一致");
    }
    return std::move(responses[0]);
}

// ---------------------------------------------------------------------------
// LocalTransport
// ---------------------------------------------------------------------------

LocalTransport::LocalTransport(int num_servers, LocalTransportOptions options)
    : num_servers_(num_servers), options_(std::move(options)) {
    if (num_servers_ <= 0) {
        throw std::invalid_argument("LocalTransport: 服务器数量必须为正");
    }
    handlers_.resize(static_cast<size_t>(num_servers_));
    request_log_.resize(static_cast<size_t>(num_servers_));
}

void LocalTransport::SetHandler(int server_id, ServerHandler handler) {
    if (server_id < 0 || server_id >= num_servers_) {
        throw std::out_of_range("LocalTransport::SetHandler: server_id 越界");
    }
    if (!handler) {
        throw std::invalid_argument("LocalTransport::SetHandler: 处理函数为空");
    }
    handlers_[static_cast<size_t>(server_id)] = std::move(handler);
}

void LocalTransport::Submit(int server_id, Payload request) {
    if (server_id < 0 || server_id >= num_servers_) {
        throw std::out_of_range("LocalTransport::Submit: server_id 越界");
    }
    pending_.push_back(PendingRequest{server_id, std::move(request)});
}

std::vector<Response> LocalTransport::Collect() {
    std::vector<Response> out;
    out.reserve(pending_.size());

    for (const auto& req : pending_) {
        const size_t sid = static_cast<size_t>(req.server_id);

        // 记录请求（隐私性分析用）
        request_log_[sid].push_back(req.request);

        // 模拟请求方向的延迟
        if (options_.latency.count() > 0) {
            std::this_thread::sleep_for(options_.latency);
        }

        // 丢包模拟
        if (options_.drop_hook && options_.drop_hook(req.server_id)) {
            out.push_back(Response::Err("LocalTransport: 应答被丢弃（模拟）"));
            continue;
        }

        if (!handlers_[sid]) {
            out.push_back(Response::Err("LocalTransport: 服务器未注册处理函数"));
            continue;
        }

        Response resp;
        try {
            Payload answer = handlers_[sid](req.request);

            // 模拟应答方向的延迟
            if (options_.latency.count() > 0) {
                std::this_thread::sleep_for(options_.latency);
            }

            // 恶意服务器篡改
            if (options_.tamper_hook) {
                options_.tamper_hook(req.server_id, answer);
            }
            resp = Response::Ok(std::move(answer));
        } catch (const std::exception& e) {
            resp = Response::Err(std::string("服务器异常: ") + e.what());
        } catch (...) {
            resp = Response::Err("服务器抛出未知异常");
        }
        out.push_back(std::move(resp));
    }

    pending_.clear();
    return out;
}

uint64_t LocalTransport::RequestCount(int server_id) const {
    if (server_id < 0 || server_id >= num_servers_) {
        return 0;
    }
    return request_log_[static_cast<size_t>(server_id)].size();
}

const std::vector<Payload>& LocalTransport::RequestLog(int server_id) const {
    if (server_id < 0 || server_id >= num_servers_) {
        throw std::out_of_range("LocalTransport::RequestLog: server_id 越界");
    }
    return request_log_[static_cast<size_t>(server_id)];
}

void LocalTransport::ResetStats() {
    for (auto& log : request_log_) {
        log.clear();
    }
}

}  // namespace tsb
