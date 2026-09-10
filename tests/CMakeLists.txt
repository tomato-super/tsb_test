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

# ---- 第 5 层：MPRAQ（MPA-01 LCTE 编码 + MPA-02 谓词解析）----
add_tsb_test(test_mpraq_lcte test_mpraq_lcte.cpp LIBS tsb_mpraq)

# ---- 第 1 层：core/iprf（FND-06，MPRAQ 检索底座）----
add_tsb_test(test_iprf test_iprf.cpp)

# ---- 第 5 层：MPRAQ（MPA-05 SecureMul 三方消息流）----
add_tsb_test(test_mpraq_securemul test_mpraq_securemul.cpp LIBS tsb_mpraq tsb_net)

# ---- 检索原语（PIR-04）：Plinko 六算法（MPRAQ 的检索底座）----
add_tsb_test(test_plinko test_plinko.cpp LIBS tsb_pir)

# ---- 第 5 层：MPRAQ（MPA-03 Init：服务器共享表 + 客户端七步）----
add_tsb_test(test_mpraq_init test_mpraq_init.cpp LIBS tsb_mpraq tsb_pir tsb_net)
add_tsb_test(test_mpraq_count test_mpraq_count.cpp LIBS tsb_mpraq tsb_pir tsb_net)
# ---- 第 5 层：MPRAQ（MPA-06 Sum/Avg：批量 SecureMul 聚合）----
add_tsb_test(test_mpraq_sum test_mpraq_sum.cpp LIBS tsb_mpraq tsb_pir tsb_net)
# ---- 第 5 层：MPRAQ（MPA-07 恶意模型验证路径：系统级篡改注入矩阵 + 验证边界）----
add_tsb_test(test_mpraq_malicious test_mpraq_malicious.cpp LIBS tsb_mpraq tsb_pir tsb_net)

# ---- 第 5 层：MPRAQ（§9.2 S5 前置：MPRAQ 的传输层 = 真实 gRPC）----
add_tsb_test(test_mpraq_grpc test_mpraq_grpc.cpp LIBS tsb_net_mpraq tsb_mpraq tsb_pir mpraq_proto)

# ---- 第 5 层：MPRAQ（MPA-08 端到端 demo：真实 gRPC、客户端 + 两台服务器实例）----
# 复用 `src/net/mpraq_remote_securemul.*`（两进程链路）与 `tests/support/mpraq_baseline.hpp`
add_tsb_test(test_mpraq_e2e test_mpraq_e2e.cpp LIBS tsb_net_mpraq_remote)

# ---- 第 5 层：MPRAQ（MPA-09 参数与复杂度验证：确定性公式/账目不变量）----
# ⚠️ 只用结构/账目/公式类断言（铁律 D6，**不含计时断言**）；用例 ⑥⑧ 会**驱动 `bench_mpraq`
# 二进制**（断言"超预算拒绝运行"与"`--json` 可解析"——这两条是**程序/契约**行为，
# 在进程内调库函数证明不了）⇒ 必须依赖 `bench_mpraq` 目标并把它的路径编译进来。
add_tsb_test(test_mpraq_scaling test_mpraq_scaling.cpp
    LIBS tsb_net_mpraq_remote tsb_net_mpraq tsb_mpraq tsb_pir tsb_net)
add_dependencies(test_mpraq_scaling bench_mpraq)
target_compile_definitions(test_mpraq_scaling PRIVATE
    MPRAQ_BENCH_BIN="$<TARGET_FILE:bench_mpraq>")

# ---- 第 5 层：MPRAQ（规模配置层：行数/每属性列数/谓词数 ⇒ 其余自动派生）----
# ⚠️ 确定性、**无计时断言**（铁律 D6）；用例 ⑧ 会读仓库内的示例配置
# `config/mpraq_scale.json` ⇒ 把它的绝对路径编译进来（不依赖运行目录）。
add_tsb_test(test_mpraq_scale_config test_mpraq_scale_config.cpp
    LIBS tsb_mpraq tsb_pir tsb_net)
target_compile_definitions(test_mpraq_scale_config PRIVATE
    MPRAQ_SCALE_CONFIG_PATH="${CMAKE_SOURCE_DIR}/config/mpraq_scale.json")
