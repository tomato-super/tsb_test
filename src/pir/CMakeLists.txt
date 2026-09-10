# 第 2/3 层：检索原语
#
#   voo_pir  —— V-OO-PIR（VMPQ 的检索底座）
#   plinko   —— Plinko（MPRAQ 的检索底座）※待实现，阻塞于决策 Q9

add_library(tsb_pir STATIC
    voo_pir.cpp
)

target_include_directories(tsb_pir PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(tsb_pir PUBLIC tsb_core tsb_shared)
