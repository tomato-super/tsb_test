# 测试与基准。
#
# 约定：每个模块一个独立的测试可执行文件（各自注册用例集），
# 公共入口在 support/test_main.cpp，用例文件里不要写 main。
#
# ===========================================================================
# ⚠️ 现状（2026-10-08）：**用例文件已全部删除**，待 MPRAQ 列粒度迁移时重写
# ===========================================================================
# 原因：负责人指令"现有的测试太多，且都已经过时了，删掉，后面迁移代码时重写"。
# 背景：新版论文把 MPRAQ 的 PIR 条目粒度从「128 位 word」改成「一整列向量」
#       （条目数 = LCTE 层数 m，PIR index = 列索引），现有 26 个用例里与几何/
#       账目/查询集数相关的断言全部作废，逐条改造成本高于重写。
#
# 已删除的 26 个用例文件（**在 git 里，可用 `git checkout -- tests/` 恢复**）：
#   test_field test_aes_prf test_hash test_config test_secret_sharing test_transport
#   test_database test_verify test_adversary test_mpc test_voo_pir test_vmpq
#   test_grpc_e2e test_cluster test_mpraq_lcte test_iprf test_mpraq_securemul
#   test_plinko test_mpraq_init test_mpraq_count test_mpraq_sum test_mpraq_malicious
#   test_mpraq_grpc test_mpraq_e2e test_mpraq_scaling test_mpraq_scale_config
#
# ⚠️ **`support/` 保留，不能删**：`tests/support/mpraq_baseline.hpp` 是
#    `bench/bench_mpraq.cpp` 与 `src/apps/mpraq_client.cpp` 的**真实 #include 依赖**
#    （经 `tsb_net_mpraq_remote` 的 PUBLIC include 目录），删掉会让 benchmark 与 demo
#    直接编译失败。它承载"独立明文基准"（铁律 D6），不是测试专用物。
#    ⇒ 迁移时应把 `mpraq_baseline.hpp` 移到非 tests 的位置（它已被生产目标使用）。
#
# 重写时的纪律（沿用，勿改）：
#   * 每个算法都要有**确定性随机源下的期望值测试**（铁律 D6），只验"跑通"不算。
#   * 口径要变成**可执行断言**（本仓库反复受益：D28/D31/D32/D35 都是被断言逼出来的）。
#   * 计时类断言不进测试（结果不稳定）；计时只进 bench。
#   * 运行期输出只出裸 `key=value`，解释文字进注释（决策 D40）。

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

# ---------------------------------------------------------------------------
# 用例注册区
# ---------------------------------------------------------------------------

# 列粒度迁移的**条目精确性契约**（不变量 I1–I4）+ D40 print 护栏。
# 这是迁移后第一批重写的用例（负责人：测试在迁移时重写）。
add_tsb_test(test_mpraq_entry test_mpraq_entry.cpp LIBS tsb_mpraq tsb_pir tsb_net tsb_net_mpraq tsb_net_mpraq_remote mpraq_proto)

# 待重写（分层清单见文件末尾注释）：
#   第 1 层 core   → test_field / test_aes_prf / test_hash / test_config / test_iprf
#   第 2 层 shared → test_secret_sharing / test_database / test_mpc / test_verify
#                     / test_adversary / test_transport
#   第 3 层 pir    → test_voo_pir / test_plinko
#   第 4 层 vmpq   → test_vmpq / test_grpc_e2e
#   第 5 层 mpraq  → test_mpraq_lcte / test_mpraq_init / test_mpraq_count
#                     test_mpraq_securemul / test_mpraq_sum / test_mpraq_malicious
#                     test_mpraq_grpc / test_mpraq_e2e / test_mpraq_scaling
#                     test_mpraq_scale_config
