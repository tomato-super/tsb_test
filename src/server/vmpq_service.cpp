#include "vmpq_service.hpp"
#include "common.hpp"
#include "utility.hpp"
#include <iostream>

using namespace VMPQ;
using grpc::ServerContext;
using grpc::Status;

VMPQServiceImpl::VMPQServiceImpl(VMPQServer &server) : server_(server) {}

Status VMPQServiceImpl::InitTable(
    ServerContext *context, const InitTableRequest *req, InitTableResponse *resp
)
{   
    std::cout << "[RPC] InitTable"
              << " table_id=" << req->tableid()
              << " window=" << req->windowsize()
              << " bucket=" << req->numbucketsize()
              << " peer=" << context->peer()        // 客户端地址
              << std::endl;

    try {
        server_.initTable(req->tableid(), req->windowsize(), req->numbucketsize());
        resp->set_res("ok");
        return grpc::Status::OK;
    } catch (const std::exception& e) {
        std::cerr << "[RPC] InitTable FAILED: " << e.what() << std::endl;
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
}

Status VMPQServiceImpl::UpdateVarList(
    ServerContext* context, const UpdateVarListRequest* req, UpdateVarListResponse* resp
)
{

    return Status::OK;
}

Status VMPQServiceImpl::UpdateTableVar(
    ServerContext *context, const UpdateTableVarRequest *req, UpdateTableVarResponse *resp
)
{
    return Status::OK;
}

Status VMPQServiceImpl::UpdateBatchTable(
    ServerContext* context, const UpdateBatchTableRequest* req, UpdateBatchTableResponse* resp
)
{
    return Status::OK;
}

Status VMPQServiceImpl::UpdateBatchVarList(
    ServerContext *context, const UpdateBatchVarListRequest *req, UpdateBatchVarListResponse *resp
)
{
    if (req->varlistid().empty()) {
        return Status(grpc::StatusCode::INVALID_ARGUMENT, "varlistid is empty");
    }

    std::vector<std::pair<uint32_t, uint128_t>> shares;
    shares.reserve(req->list().size());

    for (const auto& item : req->list()) {
        if (item.val().size() != sizeof(uint128_t)) {
            return Status(grpc::StatusCode::INVALID_ARGUMENT, "val size mismatch");
        }
        uint128_t share;
        std::memcpy(&share, item.val().data(), sizeof(uint128_t));
        shares.emplace_back(item.idx(), share);
    }

    // ← 打印收到的数据摘要
    std::cout << "[RPC] UpdateBatchVarList"
              << " varlistid=" << req->varlistid()
              << " count=" << shares.size()
              << " idx_range=[" << (shares.empty() ? 0 : shares.front().first)
              << "," << (shares.empty() ? 0 : shares.back().first) << "]"
              << " peer=" << context->peer()
              << std::endl;

    try {
        server_.updateBatchVarList(req->varlistid(), shares);
        resp->set_res("ok");
        return Status::OK;
    } catch (const std::exception& e) {
        std::cerr << "[RPC] UpdateBatchVarList FAILED: " << e.what() << std::endl;
        return Status(grpc::StatusCode::INTERNAL, e.what());
    }
}
