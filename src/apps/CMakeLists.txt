# 可执行入口（VMP-08 与 MPA-08）。
# ⚠️ MPRAQ 的两进程链路（非可执行部分）在 `src/net/mpraq_remote_securemul.*`（库 `tsb_net_mpraq_remote`）；
#    基准在 `bench/bench_mpraq.cpp`（目标 `bench_mpraq`）。

set(APPS_OUTPUT_DIR ${PROJECT_BIN_OUTPUT_DIR})

add_executable(vmpq_server vmpq_server.cpp)
target_link_libraries(vmpq_server PRIVATE tsb_net tsb_vmpq vmpq_proto)
set_target_properties(vmpq_server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${APPS_OUTPUT_DIR})

add_executable(vmpq_client vmpq_client.cpp)
target_link_libraries(vmpq_client PRIVATE tsb_net tsb_vmpq vmpq_proto)
set_target_properties(vmpq_client PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${APPS_OUTPUT_DIR})


# 服务器进程：真实 gRPC、**临时端口**（127.0.0.1:0）、打印实际端口
add_executable(mpraq_server mpraq_server.cpp)
target_link_libraries(mpraq_server PRIVATE tsb_net_mpraq_remote tsb_net_mpraq tsb_mpraq)
set_target_properties(mpraq_server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${APPS_OUTPUT_DIR})

# 客户端进程：连两台服务器进程，跑范围查询 + 多谓词合取 + Count/Sum/Avg
add_executable(mpraq_client mpraq_client.cpp)
target_link_libraries(mpraq_client PRIVATE tsb_net_mpraq_remote tsb_net_mpraq tsb_mpraq)
set_target_properties(mpraq_client PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${APPS_OUTPUT_DIR})


