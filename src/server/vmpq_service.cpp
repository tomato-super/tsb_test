#include "vmpq_service.hpp"
#include "config.hpp"

using namespace VMPQ;
using grpc::ServerContext;
using grpc::Status;

VMPQServiceImpl::VMPQServiceImpl(VMPQServer &server) : server_(server) {}

Status VMPQServiceImpl::InitTable(
    ServerContext *context, const InitTableRequest *req, InitTableResponse *resp
)
{   
    server_.initTable(req->tableid(), req->windowsize(), req->numbucketsize());

    return Status::OK;
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
    return Status::OK;
}
