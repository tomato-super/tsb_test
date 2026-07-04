#include "query_client.hpp"
#include "utility.hpp"
#include "common.hpp"
#include "json.hpp"
#include <iostream>
#include <fstream>
#include <string>

using json = nlohmann::json;

struct serverInfo {
    uint8_t id;
    string address;
};

struct cfgInfo {
    vector<serverInfo> servers;
    uint32_t window_size;
    uint32_t num_bucket;
};

void param_eval(const string& json_path, cfgInfo& cfg) {
    std::ifstream file(json_path);
    if(!file.is_open()) {
        throw std::runtime_error("can't open config: " + json_path);
    }

    auto json_cfg = json::parse(file);

    for(const auto& s : json_cfg["servers"]) {
        cfg.servers.push_back({s["id"], s["address"]});
    }

    cfg.window_size = json_cfg["params"]["window_size"];
    cfg.num_bucket = json_cfg["params"]["num_bucket"];
}

void test_init_table(QueryClient& client, string& table_id, 
                     uint32_t window_size, uint32_t num_bucket) {
    std::cout << "\n=== Test 1: InitTable ===" << std::endl;
    std::cout << "table_id=" << table_id 
              << " window_size=" << window_size 
              << " num_bucket=" << num_bucket << std::endl;

    client.InitSystem(table_id, window_size, num_bucket);
}

void test_add_varlist(QueryClient& client, string& var_list_id, 
                      size_t data_count) {
    std::cout << "\n=== Test 2: AddVarList ===" << std::endl;
    std::cout << "var_list_id=" << var_list_id 
              << " data_count=" << data_count << std::endl;

    vector<uint128_t> data(data_count);
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = static_cast<uint128_t>(1);  
    }

    client.AddValist(var_list_id, data);

    std::cout << "AddVarList 完成" << std::endl;
}

void test_add_table(QueryClient& client, string& table_id,
                    uint32_t window_size, uint32_t num_bucket) {
    std::cout << "\n=== Test 5: AddTable ===" << std::endl;
    std::cout << "table_id=" << table_id
              << " window_size=" << window_size
              << " num_bucket=" << num_bucket << std::endl;

    // 生成测试数据：每个值 < num_bucket，保证独热编码合法
    vector<uint128_t> raw(window_size);
    for (uint32_t i = 0; i < window_size; i++) {
        raw[i] = static_cast<uint128_t>(i % num_bucket);
    }

    std::cout << "原始数据: ";
    for (size_t i = 0; i < raw.size() && i < 10; i++) {
        std::cout << utility::uint128ToString(raw[i]) << " ";
    }
    if (raw.size() > 10) std::cout << "...";
    std::cout << std::endl;

    client.AddTable(table_id, num_bucket, raw);

    std::cout << "AddTable 完成" << std::endl;
}

int main(int argc, char const *argv[]) {
    
    if(argc < 2) {
        std::cerr << "Usage: ./query_client <cfg_path>" << std::endl;
        return EXIT_FAILURE;
    }

    cfgInfo cfg;
    param_eval(argv[1], cfg);

    // 打印配置信息
    std::cout << "=== 配置信息 ===" << std::endl;
    for (const auto& s : cfg.servers) {
        std::cout << "Server " << (int)s.id << ": " << s.address << std::endl;
    }
    std::cout << "window_size=" << cfg.window_size 
              << " num_bucket=" << cfg.num_bucket << std::endl;

    // 创建 channels
    std::vector<std::shared_ptr<grpc::Channel>> channels;
    for(const auto& server : cfg.servers) {
        channels.push_back(grpc::CreateChannel(
            server.address, grpc::InsecureChannelCredentials()
        ));
    }
    std::cout << "已创建 " << channels.size() << " 个 channel" << std::endl;

    QueryClient client(channels);

    // 测试用例
    string table_id = "test_table";

    // Test 1: 初始化表
    test_init_table(client, table_id, cfg.window_size, cfg.num_bucket);

    // Test 2: 发送变量列表
    test_add_varlist(client, table_id, cfg.window_size);

    // Test 3: 发送独热编码表
    test_add_table(client, table_id, cfg.window_size, cfg.num_bucket);


    std::cout << "\n=== 所有测试完成 ===" << std::endl;

    return 0;
}