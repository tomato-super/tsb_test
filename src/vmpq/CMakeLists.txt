# 第 3 层：VMPQ 协议（半诚实版本）

add_library(tsb_vmpq STATIC
    vmpq.cpp
    node.cpp
)

target_include_directories(tsb_vmpq PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(tsb_vmpq PUBLIC tsb_core tsb_shared tsb_pir)
