# gRPC 接口定义。
#
# 历史说明：早期的 pir_comm.proto（表上传接口）已随 src/common、src/client、
# src/server 一并移除（决策 D9）。当前只有 vmpq.proto 一个协议文件，
# 服务于 src/apps 的端到端 demo 与真实 gRPC 通道。

set(_PROTOBUF_PROTOC "$ENV{HOME}/.local/bin/protoc")
set(_GRPC_CPP_PLUGIN "$ENV{HOME}/.local/bin/grpc_cpp_plugin")

file(MAKE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/gen/vmpq")
set(VMPQ_PROTO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vmpq.proto")
set(VMPQ_GEN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/gen/vmpq")

add_custom_command(
    OUTPUT
        "${VMPQ_GEN_DIR}/vmpq.pb.cc"
        "${VMPQ_GEN_DIR}/vmpq.pb.h"
        "${VMPQ_GEN_DIR}/vmpq.grpc.pb.cc"
        "${VMPQ_GEN_DIR}/vmpq.grpc.pb.h"
    COMMAND ${_PROTOBUF_PROTOC}
        --proto_path=${CMAKE_CURRENT_SOURCE_DIR}
        --cpp_out=${VMPQ_GEN_DIR}
        --grpc_out=${VMPQ_GEN_DIR}
        --plugin=protoc-gen-grpc=${_GRPC_CPP_PLUGIN}
        ${VMPQ_PROTO_FILE}
    DEPENDS ${VMPQ_PROTO_FILE}
    COMMENT "Generating C++/gRPC sources for vmpq"
)

add_library(vmpq_proto
    "${VMPQ_GEN_DIR}/vmpq.grpc.pb.cc"
    "${VMPQ_GEN_DIR}/vmpq.pb.cc"
)
target_include_directories(vmpq_proto PUBLIC ${VMPQ_GEN_DIR})
target_link_libraries(vmpq_proto PUBLIC protobuf::libprotobuf gRPC::grpc++)
