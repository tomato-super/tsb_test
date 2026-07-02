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

find_package(Cryptopp REQUIRED)
find_package(protobuf REQUIRED)
find_package(gRPC REQUIRED)



add_subdirectory(proto)
add_subdirectory(src)
