cmake_minimum_required(VERSION 3.20)

set(CRYPTOPP_ROOT "$ENV{HOME}/.local/cryptopp")
set(CRYPTOPP_LIBRARY_TYPE "STATIC")
list(APPEND CMAKE_MODULE_PATH
    "${CMAKE_SOURCE_DIR}/cmake"
)
list(APPEND CMAKE_PREFIX_PATH 
    "$ENV{HOME}/.local"
)

set(PROJECT_BIN_OUTPUT_DIR "${CMAKE_BINARY_DIR}/bin")

project(
    tsdb
    LANGUAGES CXX
    VERSION 0.1.0
)

# ⚠️ 默认按 **Release（-O3）** 配置。
#
# 不设这一项时 CMake 的构建类型是空的 ⇒ **不加任何优化**，实测会让所有延迟差 2 倍以上
# （同一台机器、同一份代码：N=1024 的 Init 8.5 ms（无优化） vs 4.1 ms（-O3））。
# 文档 §7.10/§7.11 报的都是 -O3 的数字，因此必须让文档里的
#     cmake -S . -B build && cmake --build build
# 这两条命令直接产出可比的结果，而不是要求读者自己去猜构建类型。
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "构建类型（默认 Release）" FORCE)
    message(STATUS "未指定 CMAKE_BUILD_TYPE ⇒ 默认使用 Release（-O3）")
endif()

# ctest 必须在顶层启用，否则 build/CTestTestfile.cmake 不会生成，
# `ctest` 会报告 "No tests were found"。
enable_testing()

find_package(Cryptopp REQUIRED)
find_package(protobuf REQUIRED)
find_package(gRPC REQUIRED)



add_subdirectory(proto)
add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(bench)
