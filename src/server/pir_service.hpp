#pragma once

#include "pir_comm.grpc.pb.h"
#include "vmpq_server.hpp"
#include <grpcpp/grpcpp.h>



class PIRServiceImpl final : public pir::PIRService::Service 
{
public:
    explicit PIRServiceImpl(VMPQServer& server);

    grpc::Status InitTable(
        grpc::ServerContext* context, const pir::InitTableRequest* req,
        pir::InitTableResponse* resp) override;

    grpc::Status UpdateBatchVarList(
        grpc::ServerContext* context, const pir::UpdateBatchVarListRequest* req,
        pir::UpdateBatchVarListResponse* resp) override;

    grpc::Status UpdateBatchTable(
        grpc::ServerContext* context, const pir::UpdateBatchTableRequest* req,
        pir::UpdateBatchTableResponse* resp) override;


private:
    VMPQServer& server_;

};