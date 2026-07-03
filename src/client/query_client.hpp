#pragma once

#include "vmpq_comm.grpc.pb.h"
#include "common.hpp"
#include <grpcpp/grpcpp.h>
#include <memory>
#include <string>
#include <vector>

using namespace VMPQ;
using std::vector;
using std::shared_ptr;
using std::unique_ptr;
using std::string;


class QueryClient 
{
public:
    QueryClient(vector<shared_ptr<grpc::Channel>> channels);

    void InitSystem(string& id, uint32_t windowSize, uint32_t numbucket);
    void AddValist(string& id, const vector<uint128_t>& data);
    void AddTable(string& id, uint32_t num_bucket, const vector<uint128_t>& raw);

private:
    unique_ptr<VMPQService::Stub> Stub_[NUM_SERVERS];

};
