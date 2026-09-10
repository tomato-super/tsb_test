# 共享底座：net —— 传输抽象（进程内 + gRPC）

add_library(tsb_net STATIC
    local_transport.cpp
    grpc_vmpq.cpp
)

target_include_directories(tsb_net PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

# grpc_vmpq 需要生成的 vmpq proto 与 gRPC
target_link_libraries(tsb_net PUBLIC tsb_core tsb_vmpq vmpq_proto)
target_include_directories(tsb_net PUBLIC ${CMAKE_SOURCE_DIR}/proto/gen/vmpq)

# ---- MPRAQ 的 gRPC 通道与通用 gRPC 传输（MPA-08 前置 / §9.2 S5）----
#
# ⚠️ 为什么**不**把这两份源码塞进 `tsb_net`：`grpc_mpraq.*` 需要 `tsb_mpraq`
#    （`MpraqNode` / `IMpraqChannel` / `StoreParams`），而 `tsb_mpraq` 反过来
#    依赖 `tsb_net`（`mpraq/secure_mul_flow.*` 用 `net/transport.hpp`）⇒
#    放进 tsb_net 会形成**静态库依赖环**（CMake 直接拒绝）。
#    因此单开一个目标，依赖方向保持单向：tsb_net ← tsb_mpraq ← tsb_net_mpraq。
add_library(tsb_net_mpraq STATIC
    grpc_mpraq.cpp
    grpc_transport.cpp
)

target_include_directories(tsb_net_mpraq PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/proto/gen/mpraq
)

target_link_libraries(tsb_net_mpraq PUBLIC tsb_net tsb_mpraq mpraq_proto)

# ===========================================================================
# MPRAQ 两进程链路（`MPA-08` 的跨进程胶水层）—— 从 `src/apps/` 迁入（工程整理）
# ===========================================================================
#
# 它既被两个 app（`mpraq_server`/`mpraq_client`）用、也被 `bench_mpraq` 与
# `tests/test_mpraq_e2e.cpp`/`test_mpraq_scaling.cpp` 用 ⇒ 只编一份，避免多份拷贝漂移。
# **不是 app**（没有 main），所以放在 `net/`：它是传输/协议胶水，不是可执行入口。
add_library(tsb_net_mpraq_remote STATIC
    mpraq_remote_securemul.cpp
)
target_include_directories(tsb_net_mpraq_remote PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests/support   # `mpraq_baseline.hpp`（明文基准，供使用者对照）
)
target_link_libraries(tsb_net_mpraq_remote PUBLIC tsb_net_mpraq tsb_mpraq tsb_pir)
