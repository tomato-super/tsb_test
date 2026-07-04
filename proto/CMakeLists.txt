set(_PROTOBUF_PROTOC "$ENV{HOME}/.local/bin/protoc")
set(_GRPC_CPP_PLUGIN "$ENV{HOME}/.local/bin/grpc_cpp_plugin")

file(MAKE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/gen/pir")
set(PIR_PROTO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/pir_comm.proto")
set(PIR_GEN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/gen/pir")

get_filename_component(PROTO_NAME ${PIR_PROTO_FILE} NAME_WE)
add_custom_command(
    OUTPUT
        "${PIR_GEN_DIR}/${PROTO_NAME}.pb.cc"
        "${PIR_GEN_DIR}/${PROTO_NAME}.pb.h"
        "${PIR_GEN_DIR}/${PROTO_NAME}.grpc.pb.cc"
        "${PIR_GEN_DIR}/${PROTO_NAME}.grpc.pb.h"
    COMMAND ${_PROTOBUF_PROTOC}
        --proto_path=${CMAKE_CURRENT_SOURCE_DIR}
        --cpp_out=${PIR_GEN_DIR}
        --grpc_out=${PIR_GEN_DIR}
        --plugin=protoc-gen-grpc=${_GRPC_CPP_PLUGIN}
        ${PIR_PROTO_FILE}
    DEPENDS ${PIR_PROTO_FILE}
    COMMENT "Generating C++/gRPC sources for ${PROTO_NAME}"
)

list(APPEND PIR_SRCS
    "${PIR_GEN_DIR}/${PROTO_NAME}.grpc.pb.cc"
    "${PIR_GEN_DIR}/${PROTO_NAME}.pb.cc"
)

list(APPEND PIR_HDRS
    "${PIR_GEN_DIR}/${PROTO_NAME}.grpc.pb.h"
    "${PIR_GEN_DIR}/${PROTO_NAME}.grpc.pb.h"
)

add_library(pir_proto ${PIR_SRCS} ${PIR_HDRS})
target_include_directories(pir_proto PUBLIC ${PIR_GEN_DIR})
target_link_libraries(pir_proto PUBLIC protobuf::libprotobuf gRPC::grpc++)