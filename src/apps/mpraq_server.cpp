// MPRAQ 服务器进程（任务 `MPA-08`：端到端 demo 的**服务器侧**）。
//
// 用法：
//   ./mpraq_server [--listen 127.0.0.1:0] [--id 0] [--port-file /tmp/x.port]
//
//   * **默认临时端口**（`127.0.0.1:0`）：固定端口是已知坑（`TASK_PLAN.md` §3.4）——
//     并发跑第二份 demo/测试时固定端口会绑定失败。端口由内核分配，本进程打印
//     `MPRAQ_SERVER_READY ... address=127.0.0.1:<port>`，并把端口写进 `--port-file`
//     （便于脚本/CI 抓取，**不依赖 parse 别人的 stdout**）。
//   * 本进程的服务实例**同时**服务两类请求（同一个端口，见 `MpraqDemoService`）：
//        1. `proto/mpraq.proto` 的 4 条数据 RPC（InitTable / UploadFeatureWords /
//           SetAttributeShares / ServerResp）→ 落到**本进程**的 `MpraqNode`；
//        2. 通用 `Relay` → `MPA-08` 的标记帧分派（安装 SecureMul state / 跑
//           `MPA-05` 处理器 / 报账目）。
//   * ⚠️ **半诚实版本**（决策 D4/D16）：无 TLS、无身份认证，`Relay` 是开放转发；
//     `MPA-07` 已如实声明"PIR 值层与 `Count` 完整性**没有**可用机制"。
//     本进程**不假装**有任何验证能力。
//   * 本进程**只持有自己那一半**共享；两台服务器之间**零通信**（结构性：本进程里
//     没有任何指向另一台的句柄）。

#include "net/mpraq_remote_securemul.hpp"

#include <grpcpp/grpcpp.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

namespace {

std::atomic<bool> g_stop{false};

void OnSignal(int) { g_stop = true; }

struct Options {
    std::string listen = "127.0.0.1:0";
    std::string port_file;
    int id = 0;
};

Options ParseArgs(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        const auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) {
                throw std::invalid_argument(std::string("缺少参数值: ") + what);
            }
            return argv[++i];
        };
        if (a == "--listen") {
            o.listen = next("--listen");
        } else if (a == "--port-file") {
            o.port_file = next("--port-file");
        } else if (a == "--id") {
            o.id = std::stoi(next("--id"));
        } else if (a == "--help" || a == "-h") {
            std::cout << "用法: ./mpraq_server [--listen 127.0.0.1:0] [--id N] "
                         "[--port-file PATH]\n";
            std::exit(EXIT_SUCCESS);
        } else {
            throw std::invalid_argument("未知参数: " + a);
        }
    }
    return o;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const Options opt = ParseArgs(argc, argv);

        tsb::mpraq::MpraqNode node;
        tsb::mpraq::MpraqDemoService service(node);

        grpc::ServerBuilder builder;
        int bound = 0;
        builder.AddListeningPort(opt.listen, grpc::InsecureServerCredentials(), &bound);
        builder.RegisterService(&service);
        // 帧尺寸：`N = 2^14` 的安装帧 = 13 + 152·16384 ≈ 2.5 MB、第 2 轮帧 ≈ 0.95 MB
        // ⇒ 默认的 4 MB 上限太贴边，显式放宽（**不是**为了掩盖错误：超限的请求会被
        //    gRPC 明确拒绝，而不是静默截断）。
        builder.SetMaxReceiveMessageSize(256 * 1024 * 1024);
        builder.SetMaxSendMessageSize(256 * 1024 * 1024);

        std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
        if (!server || bound == 0) {
            std::cerr << "无法在 " << opt.listen << " 上启动服务器（端口被占用或地址非法）\n";
            return EXIT_FAILURE;
        }
        const std::string address = "127.0.0.1:" + std::to_string(bound);
        if (!opt.port_file.empty()) {
            std::ofstream out(opt.port_file);
            if (!out) {
                std::cerr << "无法写端口文件: " << opt.port_file << "\n";
                return EXIT_FAILURE;
            }
            out << bound << "\n";
        }
        // 机器可读的 ready 行（脚本抓取用）+ 人读行
        std::printf("MPRAQ_SERVER_READY id=%d address=%s listen=%s\n", opt.id,
                    address.c_str(), opt.listen.c_str());
        std::fflush(stdout);
        std::cout << "[mpraq_server] id=" << opt.id << " 监听 " << address
                  << "（临时端口，端到端 demo 的服务器进程）\n"
                  << "[命中 Ctrl-C / SIGTERM 退出]\n";
        std::cout.flush();

        std::signal(SIGINT, OnSignal);
        std::signal(SIGTERM, OnSignal);
        while (!g_stop.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        const tsb::mpraq::ServerStats s = service.Stats();
        std::cout << "[mpraq_server] id=" << opt.id << " 关闭中……\n";
        std::cout << "[mpraq_server] 实测账目（本进程）：初始化=" << (s.initialized ? "是" : "否")
                  << " 存储=" << s.storage_bytes << " B（特征 " << s.feature_storage_bytes
                  << " + 属性 " << s.attribute_storage_bytes << "）\n";
        std::cout << "[mpraq_server] 服务侧：数据 RPC（Init/上传/属性共享/ServerResp 合计，"
                     "失败的调用不计入）=" << s.rpc_count
                  << "；受理查询集=" << s.queries_served << "\n";
        std::cout << "[mpraq_server] 服务侧批量入口（`MpraqNode::ServerRespBatch`）调用="
                  << s.service_batch_resp_calls
                  << "（口径：每受理一次 `ServerResp` RPC 恰好 +1 ⇒ 正常情况下等于上面的"
                     " `ServerResp` 次数）\n";
        std::cout << "[mpraq_server] node 层（⚠️ `InitTable` 会清零，故只覆盖最近一次 Init 之后）："
                     "批量 ServerRespBatch=" << s.node_batch_rpc_count
                  << "、**标量** ServerResp=" << s.node_scalar_rpc_count
                  << "（gRPC 部署下**恒 0**：服务侧只走批量入口 —— MPA-08 裁决 1）、"
                     "word 读取=" << s.words_read
                  << "\n";
        std::cout << "[mpraq_server] Relay：安装帧=" << s.relay_install_frames
                  << " 相位帧=" << s.relay_phase_frames
                  << " 累计处理记录=" << s.relay_records_processed
                  << "（客户端侧调用=" << service.relay_calls()
                  << "，被拒绝=" << service.relay_errors() << "）\n";
        std::cout.flush();
        server->Shutdown();
        server->Wait();
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << "服务器启动失败: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
}
