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
