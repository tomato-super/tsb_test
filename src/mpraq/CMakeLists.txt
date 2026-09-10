# 第 5 层：MPRAQ 协议（完整）
#
#   lcte      —— LCTE 编码 + 阈值对齐 + XOR 分片辅助（MPA-01）
#   predicate —— 谓词解析：操作符 → LCTE 列索引 + 取反标记、本地布尔组合（MPA-02）
#   node/init —— 服务器侧存储 + 通道抽象（node）+ 客户端 Init（MPA-03）
#
# ⚠️ 命名空间为 `tsb::mpraq`（不是 `tsb` 顶层）：`core/config.hpp` 已在 `tsb`
# 里定义了同名的 `PredicateOp`/`Predicate`/`ParsePredicateOp`，详见 lcte.hpp 顶部。

add_library(tsb_mpraq STATIC
    lcte.cpp
    predicate.cpp
    secure_mul_flow.cpp
    node.cpp
    init.cpp
    aggquery.cpp
    aggvalue.cpp
    verification.cpp
    # 规模配置层（面向规模测试：行数/每属性列数/谓词数 ⇒ 其余全自动派生）
    scale_config.cpp
)

target_include_directories(tsb_mpraq PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(tsb_mpraq PUBLIC tsb_core tsb_shared)
