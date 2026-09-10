# 测试与基准。
#
# 约定：每个模块一个独立的测试可执行文件（各自注册用例集），
# 公共入口在 support/test_main.cpp，用例文件里不要写 main。
#
# 测试支撑代码（框架 + TestCluster）编成静态库 tsb_test_support：
#   * 静态库的 PUBLIC 依赖会自动传递给链接方，不必在每个 target 上重复声明
#   * 避免把 support 源文件塞进每个可执行文件（会重复编译并放大依赖）

add_library(tsb_test_support STATIC
    support/test_framework.cpp
    support/test_main.cpp
    support/test_cluster.cpp
)

target_include_directories(tsb_test_support PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/support
    ${CMAKE_SOURCE_DIR}/src
)

# TestCluster 依赖传输层与秘密共享；PUBLIC 依赖会传递给所有测试
target_link_libraries(tsb_test_support PUBLIC tsb_core tsb_net tsb_shared)

# 便捷函数：add_tsb_test(<名字> <用例文件...> [LIBS <额外库...>])
# 注意：必须先取出第一个位置参数（名字），再把剩余参数交给 cmake_parse_arguments；
# 否则 LIBS 会被当作位置参数消费掉，源文件列表反而丢失。
function(add_tsb_test name)
    set(sources ${ARGN})
    cmake_parse_arguments(ARG "" "" "LIBS" ${sources})
    add_executable(${name} ${ARG_UNPARSED_ARGUMENTS})
    target_link_libraries(${name} PRIVATE tsb_test_support ${ARG_LIBS})
    set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BIN_OUTPUT_DIR}
    )
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# ---- 第 1 层：core ----
add_tsb_test(test_field test_field.cpp)
add_tsb_test(test_aes_prf test_aes_prf.cpp)
add_tsb_test(test_hash test_hash.cpp)
add_tsb_test(test_config test_config.cpp)

# ---- 第 1/2 层：net 与 shared ----
add_tsb_test(test_secret_sharing test_secret_sharing.cpp)
add_tsb_test(test_transport test_transport.cpp)
add_tsb_test(test_database test_database.cpp)
add_tsb_test(test_verify test_verify.cpp)

# ---- 恶意行为注入（FND-15）----
add_tsb_test(test_adversary test_adversary.cpp)
add_tsb_test(test_mpc test_mpc.cpp)

# ---- 检索原语（PIR-01）----
add_tsb_test(test_voo_pir test_voo_pir.cpp LIBS tsb_pir)

# ---- 第 3 层：VMPQ 协议 ----
add_tsb_test(test_vmpq test_vmpq.cpp LIBS tsb_vmpq tsb_pir)

# ---- 真实 gRPC 端到端（FND-10 / VMP-08）----
add_tsb_test(test_grpc_e2e test_grpc_e2e.cpp LIBS tsb_net tsb_vmpq vmpq_proto)

# ---- 双服务器仿真框架 ----
add_tsb_test(test_cluster test_cluster.cpp)
