# 基准测试。默认随主工程构建，产物放在 bin/ 下。
# 运行：./build/bin/bench_vmpq [--quick]

add_executable(bench_vmpq bench_vmpq.cpp)

target_include_directories(bench_vmpq PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)
target_include_directories(bench_vmpq PRIVATE
    ${CMAKE_SOURCE_DIR}/third_parts/json
)

target_link_libraries(bench_vmpq PRIVATE tsb_vmpq tsb_pir tsb_shared tsb_core)

set_target_properties(bench_vmpq PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BIN_OUTPUT_DIR}
)

# ---------------------------------------------------------------------------
# MPRAQ 参数与复杂度基准（`MPA-09`）—— 从 `src/apps/mpraq_bench.cpp` 迁入（工程整理）
# ---------------------------------------------------------------------------
# 支持 `--json`/`--json-out` 机器可读输出与 **L14 预检**（超预算拒绝运行、退出码 3）。
# 运行：./build/bin/bench_mpraq --exp all --rows 1024,2048,4096 --json
# ⚠️ 可执行名曾为 `mpraq_bench`（历史证据文档 `doc/evidence/mpa09/` 里仍是旧名，见该目录 README）。
add_executable(bench_mpraq bench_mpraq.cpp)
target_include_directories(bench_mpraq PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(bench_mpraq PRIVATE tsb_net_mpraq_remote tsb_net_mpraq tsb_mpraq tsb_pir tsb_net)
set_target_properties(bench_mpraq PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BIN_OUTPUT_DIR})
