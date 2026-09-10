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

# ---- MPRAQ 协议（MPA-08 的传输层；与 vmpq 完全独立的包/服务）----
#
# ⚠️ 生成目录必须与 vmpq **分开**：protoc 的输出文件名只取决于 .proto 的文件名，
#    两个包共用同一个 `--cpp_out` 目录会让 vmpq.pb.cc ←→ mpraq.pb.cc 互相覆盖式
#    的构建规则冲突（"multiple rules generate the same file"）。
file(MAKE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/gen/mpraq")
set(MPRAQ_PROTO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mpraq.proto")
set(MPRAQ_GEN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/gen/mpraq")

add_custom_command(
    OUTPUT
        "${MPRAQ_GEN_DIR}/mpraq.pb.cc"
        "${MPRAQ_GEN_DIR}/mpraq.pb.h"
        "${MPRAQ_GEN_DIR}/mpraq.grpc.pb.cc"
        "${MPRAQ_GEN_DIR}/mpraq.grpc.pb.h"
    COMMAND ${_PROTOBUF_PROTOC}
        --proto_path=${CMAKE_CURRENT_SOURCE_DIR}
        --cpp_out=${MPRAQ_GEN_DIR}
        --grpc_out=${MPRAQ_GEN_DIR}
        --plugin=protoc-gen-grpc=${_GRPC_CPP_PLUGIN}
        ${MPRAQ_PROTO_FILE}
    DEPENDS ${MPRAQ_PROTO_FILE}
    COMMENT "Generating C++/gRPC sources for mpraq"
)

add_library(mpraq_proto
    "${MPRAQ_GEN_DIR}/mpraq.grpc.pb.cc"
    "${MPRAQ_GEN_DIR}/mpraq.pb.cc"
)
target_include_directories(mpraq_proto PUBLIC ${MPRAQ_GEN_DIR})
target_link_libraries(mpraq_proto PUBLIC protobuf::libprotobuf gRPC::grpc++)
