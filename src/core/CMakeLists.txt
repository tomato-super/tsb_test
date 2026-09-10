# 共享底座：第 1 层 core —— 纯工具，无协议语义

add_library(tsb_core STATIC
    field.cpp
    aes_prf.cpp
    hash.cpp
    mset_hash.cpp
    random.cpp
    config.cpp
    iprf.cpp
)

target_include_directories(tsb_core PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_compile_features(tsb_core PUBLIC cxx_std_17)

# 配置系统需要 nlohmann/json（单头文件，见 third_parts/）
target_include_directories(tsb_core PRIVATE
    ${CMAKE_SOURCE_DIR}/third_parts/json
)

# AES-PRF 依赖 Crypto++（FindCryptopp 在顶层已 find_package）
target_link_libraries(tsb_core PUBLIC Cryptopp::Cryptopp)
