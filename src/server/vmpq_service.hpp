#pragma once

#include "vmpq_comm.grpc.pb.h"
#include "vmpq_server.hpp"
#include <grpcpp/grpcpp.h>



class VMPQServiceImpl final : public VMPQ::VMPQService::Service 
{
public:
    explicit VMPQServiceImpl(VMPQServer& server);

    grpc::Status InitTable(
        grpc::ServerContext* context, const VMPQ::InitTableRequest* req,
        VMPQ::InitTableResponse* resp) override;

    grpc::Status UpdateVarList(
        grpc::ServerContext* context, const VMPQ::UpdateVarListRequest* req,
        VMPQ::UpdateVarListResponse* resp) override;

    grpc::Status UpdateBatchVarList(
        grpc::ServerContext* context, const VMPQ::UpdateBatchVarListRequest* req,
        VMPQ::UpdateBatchVarListResponse* resp) override;

    grpc::Status UpdateTableVar(
        grpc::ServerContext* context, const VMPQ::UpdateTableVarRequest* req,
        VMPQ::UpdateTableVarResponse* resp) override;

    grpc::Status UpdateBatchTable(
        grpc::ServerContext* context, const VMPQ::UpdateBatchTableRequest* req,
        VMPQ::UpdateBatchTableResponse* resp) override;


private:
    VMPQServer& server_;

};

