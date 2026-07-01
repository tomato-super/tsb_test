#include "query_client.hpp"
#include "utility.hpp"

void CheckRpcStatus(const grpc::Status& status, const std::string& rpc_name) {
    if (!status.ok()) {
        std::cerr << "[" << rpc_name << "] RPC failed: "
                  << status.error_code() << " - "
                  << status.error_message() << std::endl;
    }
}

QueryClient::QueryClient(vector<shared_ptr<grpc::Channel>> channels) {
    for(auto i = 0; i < channels.size(); i++) {
        this->Stub_[i] = VMPQService::NewStub(channels[i]);
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
        if (!status[i].ok()) {
            CheckRpcStatus(status[i], "initTable");
        }
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
            CheckRpcStatus(status, "UpdateBatchVarList chunk " + std::to_string(offset));
        }

        offset = end;
    }
}


