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

void test_reinit_same_params(QueryClient& client, string& table_id,
                             uint32_t window_size, uint32_t num_bucket) {
    std::cout << "\n=== Test 3: Re-init with same params ===" << std::endl;
    
    client.InitSystem(table_id, window_size, num_bucket);
}

void test_reinit_diff_params(QueryClient& client, string& table_id,
                             uint32_t new_window_size, uint32_t new_num_bucket) {
    std::cout << "\n=== Test 4: Re-init with different params ===" << std::endl;
    std::cout << "new_window_size=" << new_window_size 
              << " new_num_bucket=" << new_num_bucket << std::endl;

    client.InitSystem(table_id, new_window_size, new_num_bucket);
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
    test_add_varlist(client, table_id, cfg.window_size);  // 发送 100 个元素


    std::cout << "\n=== 所有测试完成 ===" << std::endl;

    return 0;
}
