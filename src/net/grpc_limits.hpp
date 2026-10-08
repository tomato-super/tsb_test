#pragma once

// gRPC 的**收包上限**常量 —— 刻意放在一个**零依赖**的小头文件里。
//
// ⚠️ 存在的理由（踩过的坑）：这个常量原本只写在 `net/grpc_transport.hpp` 里，
//    而那个头文件为了 `GrpcTransportClient` **include 了 MPRAQ 的 proto**
//    （`mpraq.grpc.pb.h`）。于是 `tsb_net` 里的 `grpc_vmpq.cpp` **无法**复用它 ——
//    编译期报 `fatal error: mpraq.grpc.pb.h: No such file or directory`
//    （`tsb_net` 不依赖 `mpraq_proto`）。
//    ⇒ 把常量抽到这里：谁都能用，且不会把 proto 依赖传染出去。
//
// 收包上限本身的口径见下面整段说明（原样搬自 `grpc_transport.hpp`）。

// ---------------------------------------------------------------------------
// 客户端 **收包上限**（`MPA-09` 任务 B）：这是"**能不能跑大规模**"的硬天花板
// ---------------------------------------------------------------------------
//
// gRPC 的默认 `max_receive_message_length` 只有 **4 MiB**（发送侧默认无上限）。
// MPRAQ 的 SecureMul 走**通用 `Relay`**，一次查询的两类**应答帧**都随 N 线性增长：
//   * Phase1 应答 = `13 + 6 + 43·N` 字节；
//   * Phase2 应答 = `13 + 6 + 58·N` 字节。
// ⇒ 客户端若用默认值，`N > 72 315` 时**第 1 轮**就会失败：
//     `CLIENT: Received message larger than max (5636122 vs. 4194304)`
//   （`MPA-09` 在 `N = 2^17` 上实测到；`N = 2^16` 的 3.80 MB 恰好还在 4 MiB 内 ⇒ 侥幸能跑）。
//
// 🔴 纪律：**服务器侧与客户端侧必须成对设置**，否则大帧会在**收包方**被拒绝 ——
//    * 服务器进程侧：`mpraq_server.cpp` / `test_mpraq_e2e.cpp` 的夹具已设 **256 MiB**；
//    * 客户端侧（本常量）：`GrpcTransportClient`、`GrpcMpraqChannel`、
//      **`GrpcChannel`（VMPQ 的数据通道）** 都必须显式设置；
//    * 服务端侧：`mpraq_server` 与 `vmpq_server` 都要 `SetMaxReceiveMessageSize`。
//      ⚠️ VMPQ 的 `GrpcChannel` 曾经**漏设**（用无参 `CreateChannel` 走默认 4 MiB），
//      而 D38 之后一列应答 `2·N·16` B ⇒ **N >= 2^17 恰好在 4 MiB 越界**。已修。
//    任一侧漏设 ⇒ 大帧失败；**且失败是 fail-loudly 的**（gRPC 返回可读的
//    `RESOURCE_EXHAUSTED: Received message larger than max (X vs. Y)`，
//    经 `Response::Err` 冒到上层 ⇒ `SecureMulBatchAbort`，**绝不静默截断**）。
//
// ⚠️ 本常量只放宽**收包**上限；发送侧保持 gRPC 的默认（无限），因此不会给
//    "离线安装帧"（`2×(13+152·N)`）引入新的上限。
inline constexpr int kGrpcClientMaxReceiveBytes = 256 * 1024 * 1024;
// 默认 4 MiB 是 gRPC 的既有取值：这里断言我们**确实放宽了**（防止有人改小/删掉）
static_assert(kGrpcClientMaxReceiveBytes >= 4 * 1024 * 1024,
              "客户端收包上限必须 >= gRPC 默认的 4 MiB");

