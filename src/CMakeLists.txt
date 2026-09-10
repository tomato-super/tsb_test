# 分层架构（TASK_PLAN.md §4）：共享底座 + 协议模块 + 可执行入口

add_subdirectory(core)     # 第 1 层：环运算、AES-PRF、哈希、随机、配置
add_subdirectory(shared)   # 第 2 层：秘密共享、表抽象、SecureMul、验证
add_subdirectory(pir)      # 第 2/3 层：V-OO-PIR
add_subdirectory(mpraq)    # 第 5 层：MPRAQ（LCTE 编码 + 谓词解析，MPA-01/02）
add_subdirectory(vmpq)     # 第 3 层：VMPQ（半诚实）
add_subdirectory(net)      # 传输：进程内 + gRPC
add_subdirectory(apps)     # 可执行入口

# 注：早期的 src/common、src/client、src/server 已按决策 D9 删除。
# 其功能分别由 core/、pir/ + vmpq/、apps/ 取代（见 TASK_PLAN §3.3 的资产迁移表）。
