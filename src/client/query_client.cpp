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
    
}


