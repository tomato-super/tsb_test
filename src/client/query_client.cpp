#include "query_client.hpp"

void CheckRpcStatus(const grpc::Status& status, const std::string& rpc_name, int server_id) {
    if (!status.ok()) {
        std::cerr << "[" << rpc_name << "] RPC failed: "
                  << status.error_code() << " - "
                  << "Stub[" << server_id << "]: "
                  << status.error_message() << std::endl;
    } else {
        std::cout << "[" << rpc_name << "] RPC successful: "
                  << "Stub[" << server_id << "]" << std::endl;
    }
}

QueryClient::QueryClient(vector<shared_ptr<grpc::Channel>> channels) {
    for(auto i = 0; i < channels.size(); i++) {
        this->Stub_[i] = PIRService::NewStub(channels[i]);
    }
}

void QueryClient::InitSystem(string& id, uint32_t windowSize, uint32_t numbucket) {
    InitTableRequest reqs[NUM_SERVERS];
    InitTableResponse resps[NUM_SERVERS];
    grpc::ClientContext context[NUM_SERVERS];
    grpc::Status status[NUM_SERVERS];

    for(auto i = 0; i < NUM_SERVERS; i++) {
        reqs[i].set_tableid(id);
        reqs[i].set_windowsize(windowSize);
        reqs[i].set_numbucketsize(numbucket);
    }

    for(auto i = 0; i < NUM_SERVERS; i++) {
        status[i] = Stub_[i]->InitTable(&context[i], reqs[i], &resps[i]);
        CheckRpcStatus(status[i], "initTable", i);
        
    }
}

void QueryClient::AddValist(string& id, const vector<uint128_t>& data) {
    // 1. 全部秘密共享
    vector<uint128_t> share0(data.size()), share1(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        auto [s0, s1] = utility::AdditiveShare(data[i]);
        share0[i] = s0;
        share1[i] = s1;
    }

    // 2. 分块发送
    const size_t chunk_size = 10000;  // 每块 10000 个元素，约 160KB
    size_t offset = 0;
    // uint128_t sum = 0;
    // uint128_t tmp = 0;

    while (offset < data.size()) {
        size_t end = std::min(offset + chunk_size, data.size());

        UpdateBatchVarListRequest reqs[NUM_SERVERS];
        UpdateBatchVarListResponse resps[NUM_SERVERS];
        grpc::ClientContext contexts[NUM_SERVERS];

        for (int s = 0; s < NUM_SERVERS; s++) {
            reqs[s].set_varlistid(id);
            auto& list = *reqs[s].mutable_list();

            for (size_t i = offset; i < end; i++) {
                auto* item = list.Add();
                item->set_varlistid(id);
                item->set_idx(i);  // 全局索引，服务器知道位置
                const uint128_t& share = s == 0 ? share0[i] : share1[i];
                item->set_val(reinterpret_cast<const char*>(&share), sizeof(uint128_t));
            }
        }

        for (int i = 0; i < NUM_SERVERS; i++) {
            auto status = Stub_[i]->UpdateBatchVarList(&contexts[i], reqs[i], &resps[i]);
            // tmp = 0;
            // std::memcpy(&tmp, resps[i].res().data(), sizeof(uint128_t));
            // sum += tmp;
            CheckRpcStatus(status, "UpdateBatchVarList chunk " + std::to_string(offset), i);
        }
        offset = end;
    }

    // std::cout << "sum = " << utility::uint128ToString(sum) << std::endl;
}

void QueryClient::AddTable(string &id, uint32_t num_bucket, const vector<uint128_t> &raw) {
    

}