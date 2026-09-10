# 可执行入口（VMP-08）。

set(APPS_OUTPUT_DIR ${PROJECT_BIN_OUTPUT_DIR})

add_executable(vmpq_server vmpq_server.cpp)
target_link_libraries(vmpq_server PRIVATE tsb_net tsb_vmpq vmpq_proto)
set_target_properties(vmpq_server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${APPS_OUTPUT_DIR})

add_executable(vmpq_client vmpq_client.cpp)
target_link_libraries(vmpq_client PRIVATE tsb_net tsb_vmpq vmpq_proto)
set_target_properties(vmpq_client PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${APPS_OUTPUT_DIR})
