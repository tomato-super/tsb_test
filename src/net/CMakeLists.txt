# 共享底座：net —— 传输抽象（进程内 + gRPC）

add_library(tsb_net STATIC
    local_transport.cpp
    grpc_vmpq.cpp
)

target_include_directories(tsb_net PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

# grpc_vmpq 需要生成的 vmpq proto 与 gRPC
target_link_libraries(tsb_net PUBLIC tsb_core tsb_vmpq vmpq_proto)
target_include_directories(tsb_net PUBLIC ${CMAKE_SOURCE_DIR}/proto/gen/vmpq)
