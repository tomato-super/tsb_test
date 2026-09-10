#pragma once

// 双服务器仿真测试框架。
//
// 在单进程内搭建"1 客户端 + 2 服务器"的完整环境，用于协议层测试：
//   * 服务器持有各自的秘密共享
//   * 传输走 LocalTransport（可注入延迟/篡改/丢包）
//   * 提供密文空间一致性断言（各方对同一明文的重建必须一致）
//
// 用途：milestone M1 的"共享 → 传输 → 重建"往返，以及后续
// V-OO-PIR / Plinko / SecureMul 的端到端测试。

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "core/field.hpp"
#include "net/transport.hpp"
#include "shared/database.hpp"
#include "shared/secret_sharing.hpp"

namespace tsb {

// 一台服务器持有的数据（均为共享形式）。
// 直接复用 shared/database 的表抽象，避免测试环境与生产路径存在两套结构。
struct ServerDatabase {
    // 变量列表：各索引的 Z_{2^128} 加法共享
    std::vector<RingShare> var_list;

    // 通用多表数据库（one-hot / LCTE 等）
    ShareDatabase tables;
};

class TestCluster {
public:
    // 创建含两个服务器的仿真环境
    TestCluster();

    // ---- 服务器数据 ----

    ServerDatabase& server_db(int server_id);
    const ServerDatabase& server_db(int server_id) const;

    // 客户端侧：把明文数据拆成两份共享并分发到两台服务器。
    // 这是 Init 阶段的仿真（不经过传输层，直接写入服务器状态）。
    void DistributeVarList(const std::string& id, const std::vector<uint128_t>& plain);
    void DistributeOneHotTable(const std::string& table_id, uint32_t num_bucket,
                               const std::vector<uint128_t>& rows_flat);

    // 客户端侧：把两台服务器的共享重建回明文（仅在测试中用来验证）
    std::vector<uint128_t> ReconstructVarList(const std::string& id) const;

    // ---- 传输 ----

    LocalTransport& transport() { return *transport_; }
    const LocalTransport& transport() const { return *transport_; }

    // 为指定服务器注册处理函数
    void SetHandler(int server_id, ServerHandler handler);

    // 便捷：两台服务器用各自的 ServerDatabase 处理同一个请求
    //   handler 形如 (const ServerDatabase&, const Payload&) -> Payload
    using DbHandler = std::function<Payload(const ServerDatabase&, const Payload&)>;
    void SetDbHandler(int server_id, DbHandler handler);

    // 客户端便捷调用
    Response RoundTrip(int server_id, Payload request) {
        return transport_->RoundTrip(server_id, request);
    }
    void Submit(int server_id, Payload request) {
        transport_->Submit(server_id, std::move(request));
    }
    std::vector<Response> Collect() { return transport_->Collect(); }

    // ---- 恶意行为注入 ----

    // 让指定服务器开始篡改应答
    void MakeMalicious(int server_id);
    // 让指定服务器开始丢弃应答
    void MakeUnresponsive(int server_id);
    // 恢复正常
    void RestoreAll();

    // ---- 断言辅助 ----

    // 检查两台服务器对同一变量列表的重建结果与期望一致
    bool VarListMatches(const std::string& id,
                        const std::vector<uint128_t>& expected) const;

private:
    std::vector<ServerDatabase> dbs_;
    std::unique_ptr<LocalTransport> transport_;
};

}  // namespace tsb
