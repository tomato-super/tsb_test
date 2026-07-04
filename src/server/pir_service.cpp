#include "pir_service.hpp"
#include "common.hpp"
#include "utility.hpp"
#include <iostream>

using namespace pir;
using grpc::ServerContext;
using grpc::Status;

PIRServiceImpl::PIRServiceImpl(VMPQServer &server) : server_(server) {}

Status PIRServiceImpl::InitTable(
    ServerContext *context, const InitTableRequest *req, InitTableResponse *resp
)
{   
    std::cout << "[RPC] InitTable"
              << " table_id=" << req->tableid()
              << " window=" << req->windowsize()
              << " bucket=" << req->numbucketsize()
              << " peer=" << context->peer()
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

Status PIRServiceImpl::UpdateBatchTable(
    ServerContext* context, const UpdateBatchTableRequest* req, UpdateBatchTableResponse* resp
)
{
    if (req->tableid().empty()) {
        return Status(grpc::StatusCode::INVALID_ARGUMENT, "tableid is empty");
    }

    std::vector<std::vector<uint128_t>> rows;
    rows.reserve(req->update().size());

    for (const auto& update : req->update()) {
        size_t col_count = update.val_size();
        std::vector<uint128_t> row(col_count);
        for (size_t j = 0; j < col_count; j++) {
            std::memcpy(&row[j], update.val(j).data(), sizeof(uint128_t));
        }
        rows.push_back(std::move(row));
    }

    std::cout << "[RPC] UpdateBatchTable"
              << " tableid=" << req->tableid()
              << " rows=" << rows.size()
              << " cols=" << (rows.empty() ? 0 : rows[0].size())
              << " peer=" << context->peer()
              << std::endl;

    try {
        server_.updateBatchTable(req->tableid(), rows);
        resp->set_res("ok");
        return Status::OK;
    } catch (const std::exception& e) {
        std::cerr << "[RPC] UpdateBatchTable FAILED: " << e.what() << std::endl;
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
}

Status PIRServiceImpl::UpdateBatchVarList(
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
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
}