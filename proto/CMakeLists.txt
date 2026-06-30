set(_PROTOBUF_PROTOC "$ENV{HOME}/.local/bin/protoc")
set(_GRPC_CPP_PLUGIN "$ENV{HOME}/.local/bin/grpc_cpp_plugin")

file(MAKE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/gen/vmpq")
set(VMPQ_PROTO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vmpq_comm.proto")
set(VMPQ_GEN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/gen/vmpq")

get_filename_component(PROTO_NAME ${VMPQ_PROTO_FILE} NAME_WE)
add_custom_command(
    OUTPUT
        "${VMPQ_GEN_DIR}/${PROTO_NAME}.pb.cc"
        "${VMPQ_GEN_DIR}/${PROTO_NAME}.pb.h"
        "${VMPQ_GEN_DIR}/${PROTO_NAME}.grpc.pb.cc"
        "${VMPQ_GEN_DIR}/${PROTO_NAME}.grpc.pb.h"
    COMMAND ${_PROTOBUF_PROTOC}
        --proto_path=${CMAKE_CURRENT_SOURCE_DIR}
        --cpp_out=${VMPQ_GEN_DIR}
        --grpc_out=${VMPQ_GEN_DIR}
        --plugin=protoc-gen-grpc=${_GRPC_CPP_PLUGIN}
        ${VMPQ_PROTO_FILE}
    DEPENDS ${VMPQ_PROTO_FILE}
    COMMENT "Generating C++/gRPC sources for ${PROTO_NAME}"
)

list(APPEND VMPQ_SRCS
    "${VMPQ_GEN_DIR}/${PROTO_NAME}.grpc.pb.cc"
    "${VMPQ_GEN_DIR}/${PROTO_NAME}.pb.cc"
)

list(APPEND VMPQ_HDRS
    "${VMPQ_GEN_DIR}/${PROTO_NAME}.grpc.pb.h"
    "${VMPQ_GEN_DIR}/${PROTO_NAME}.grpc.pb.h"
)

add_library(vmpq_proto ${VMPQ_SRCS} ${VMPQ_HDRS})
target_include_directories(vmpq_proto PUBLIC ${VMPQ_GEN_DIR})
target_link_libraries(vmpq_proto PUBLIC protobuf::libprotobuf gRPC::grpc++)
