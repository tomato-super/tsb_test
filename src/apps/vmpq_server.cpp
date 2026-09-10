// VMPQ 服务器进程（VMP-08）。
//
// 用法：./vmpq_server <config.json>
//
// 配置示例（见 config/server_vmpq_0.json）：
//   { "server_id": 0, "host_port": "50051" }
//
// ⚠️ 半诚实模型：本进程只持有**自己那一半** XOR 共享。两台服务器之间不通信，
//    也不共谋（这是协议的安全前提）。传输使用不安全信道（决策 D4），
//    部署到真实环境前必须补上 TLS 与身份认证。

#include "core/config.hpp"
#include "net/grpc_vmpq.hpp"

#include <grpcpp/grpcpp.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

namespace {

std::atomic<bool> g_stop{false};

void OnSignal(int) { g_stop = true; }

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "用法: ./vmpq_server <config.json>\n";
        return EXIT_FAILURE;
    }

    try {
        const tsb::ServerConfig cfg = tsb::ServerConfig::FromFile(argv[1]);
        const std::string address = "0.0.0.0:" + cfg.host_port;

        tsb::VmpqNode node;
        tsb::VmpqServiceImpl service(node);

        grpc::ServerBuilder builder;
        builder.AddListeningPort(address, grpc::InsecureServerCredentials());
        builder.RegisterService(&service);
        std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
        if (!server) {
            std::cerr << "无法在 " << address << " 上启动服务器\n";
            return EXIT_FAILURE;
        }

        std::cout << "[vmpq_server] id=" << cfg.server_id << " 监听 " << address
                  << "\n[命中 Ctrl-C 退出]\n";

        std::signal(SIGINT, OnSignal);
        std::signal(SIGTERM, OnSignal);
        while (!g_stop.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        std::cout << "[vmpq_server] 关闭中……已处理 " << service.rpc_count()
                  << " 次 RPC、" << service.queries_served() << " 个查询集\n";
        server->Shutdown();
        server->Wait();
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << "服务器启动失败: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
}
