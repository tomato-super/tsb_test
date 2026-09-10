# 共享底座：第 2 层 shared —— 两个协议共用的服务

add_library(tsb_shared STATIC
    secret_sharing.cpp
    database.cpp
    verify.cpp
    mpc.cpp
)

target_include_directories(tsb_shared PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(tsb_shared PUBLIC tsb_core)
