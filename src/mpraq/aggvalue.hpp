#pragma once

// MPRAQ 的 `AggQuery` – **`Sum` / `Avg`**（任务 `MPA-06`）—— `MPRAQ_IMPL.md` §4 的四步。
//
// ===========================================================================
// 0. 这个文件解决什么问题
// ===========================================================================
//   Sum = Σ_{i=1..N} f_i · E_i   (mod q)      ← 论文 AggQuery 的 `result ← Σ z_i`
//   Count 已由 `MPA-04` 给出（`CountResult::count` = popcount(filter)）
//   Avg = Sum / Count（**整数向下取整**；`count == 0` 抛 `std::domain_error`）
//
// 每条记录的 `z_i = f_i · E_i` 就是一次 `MPA-05` 的 SecureMul（SPDZ Beaver + MAC）。
// 但 `MPA-05` 是**严格逐记录**的（其文件头 §6.1 已实测确认）：
//   * `ClientRunPhase1/2` 硬断言"恰好 2 条应答"（`EvaluateCollect`）；
//   * `RegisterSecureMulServers` 每台服务器只挂**一个** state；
//   * 线格式是单记录定长（34/27/58/43 B），解码器 `RequireSize` 严格校验，
//     **没有** count / 数组 / 前缀，也没有 record index。
// ⇒ 逐记录发就是 `2N` 个往返（`N = 2^14` 时 3 万次）
//   ⇒ 本文件按 `MPA-05` §6.1 的要求**自建一层批量会话**（cp. 红队原型
//      `/tmp/mpa05_red/red_main.cpp` 的 `ModeBatch`）：
//        自定义批量帧 + `(session → state)` 分派表 + 自己的 fan-out/收集，
//        **复用 `MPA-05` 的编解码与 `SecureMulServerState` 语义**。
//     本文件**不修改** `secure_mul_flow.*` 的任何语义与消息格式（只 include 与调用）。
//
// ===========================================================================
// 1. 批量帧格式（本层自定义；**不引入新的 proto**，**不改 MPA-05 的线格式**）
// ===========================================================================
// 一个"批量帧"= 6 字节头 + `count` 条**原样的** MPA-05 定长消息：
//
//   [0]      批量帧版本 `kBatchWireVersion`
//   [1]      批量帧类型 `SecureMulBatchMsgType`
//   [2..6)   `count`（uint32 小端）
//   [6..)    count 条 MPA-05 消息（逐条 `EncodePhase1Request` / … 的原样字节；
//            Phase1Request 34 B、Phase1Response 27 B、Phase2Request 58 B、
//            Phase2Response 43 B ⇒ 帧长 = 6 + count × 上述长度，**严格校验**）
//
//   * 每条子消息**自己带** `session`，因此第 1 轮之后不需要"顺序"这个隐含假设：
//     分派一律走 `session → state` 查表（查不到 ⇒ 结构化拒绝，见 §4）；
//   * 帧头里的 `count` 是**批量层**的元数据，MPA-05 的解码器看不到它
//     （它们只会收到精确切片的定长子消息）⇒ MPA-05 的语义/格式零改动；
//   * `EncodeBatchFrame` / `DecodeBatchFrame` 公开导出：便于测试做定点篡改，
//     也便于后续 `MPA-08` 的 gRPC 通道直接复用。
//
// ===========================================================================
// 2. 一次批量会话的 6 步（与 `MPRAQ_IMPL.md` §4 的 1–4 步对应）
// ===========================================================================
//   ① 离线：逐记录生成 Beaver triple（`prng` 确定性源）+
//      `MakeSetupsAndContext`（⟨E⟩_p 用调用方给的两份加法共享、
//      challenge 由 `MakeChallenge(i, salt)` 派生）⇒ 每台服务器预装 `N` 个
//      `SecureMulServerState`（**预装 2N 个**，两轮之间保活）；
//   ② 在线第 1 轮：客户端把 `N` 条 Phase1Request 打进**一个**帧 ⇒ 每台服务器
//      **一次** `Submit`，`Collect()` **一次**；服务器按 session 分派、逐条
//      `ServerHandlePhase1`，把 `N` 条 Phase1Response 打进一个应答帧；
//   ③ 客户端逐条取 ⟨e⟩_p，算 `e = ⟨e⟩_0 + ⟨e⟩_1`；
//   ④ 在线第 2 轮：同样一个帧承载 `N` 条 Phase2Request（各自带**自己那份**
//      `e_check`）⇒ 再一次 `Submit`/`Collect`；
//   ⑤ 逐记录 `VerifyAndReconstruct`（**必须传 `bundle.ctx`**，否则退回"只有 MAC"，
//      会接受"一致偏移"的错值 —— `MPA-05` §4.5 / 文件头 §6.7 的 ⚠️）；
//   ⑥ 逐记录用 `ok` 把关；**`ok == false` 的记录的 `z` 一律置 0 且不参与累加**
//      （`VerifyAndReconstruct` 在 MAC 失败时仍会写出重建值，见 `MPA-05` §6.3）。
//
// ===========================================================================
// 3. 账目口径（**测试要按这个口径断言，不是靠注释**）
// ===========================================================================
//   * `records`  = `N`（= `f_bits.size()`；**不剪枝**，`f = 0` 也照发，见 §5.4）；
//   * `rounds`   = `ITransportClient::Collect()` 的**实际调用次数**（本层恒为 2）；
//   * `phase1_messages` / `phase2_messages`
//                = **单台服务器视角**每轮的记录消息条数（各 = N）
//                  ⇒ 与任务书"每个方向 N 条消息"一致（方向 = 第 1 轮 / 第 2 轮）；
//   * `messages` = `phase1_messages + phase2_messages` = **2N**（单台服务器视角）；
//   * `wire_messages`（追加字段）= **线上真实条数** = 2 台服务器 × 2N = **4N**
//     （两台都要收到每一轮的 N 条 ⇒ 这是 `MPA-05` 的"1 客户端 + 2 服务器"拓扑
//      决定的；任务书的 `messages == 2N` 是单台口径，两者不冲突，但必须同时报）；
//   * `server_records_processed[2]` / `server_records_processed_phase2[2]`
//     = 每台服务器在**第 1 轮 / 第 2 轮**实际处理的记录条数
//     ⇒ 常量模式（不剪枝）的证据：四个数都必须等于 `N`；
//   * `server_frames[2]` = 每台服务器收到的**批量帧**数：批量路径恒为 **2**
//     （逐记录路径是 `2N` 条单记录消息 ⇒ `2N` 个帧）；测试用
//     `LocalTransport::RequestCount(server)` 独立复核这一点；
//   * `frame_bytes_phase1/2` = 单帧字节数（6 + 34N / 6 + 58N）；
//   * `server_state_peak_bytes` = **每台**服务器预装 state 的**常驻字节口径**
//     = `N × (7 × 16 B triple 共享 + 16 B ⟨E⟩_p) = 128·N` B
//     （⚠️ 这是"材料字节"口径，**不是** RSS/`sizeof` 口径；`sizeof` 口径另见
//      `server_state_allocated_bytes`。逐记录路径的峰值只有 1 条记录的材料）；
//   * `offline_triple_ms` = **只**预生成 `N` 组 Beaver triple 的耗时；
//     `offline_setup_ms`（追加字段）= `MakeSetupsAndContext` + 装 state 的耗时；
//   * `online_ms` = 两轮在线（建帧 + Submit + Collect + 解码）的墙钟；
//   * `verify_ms` = 逐记录 `VerifyAndReconstruct` 的墙钟。
//
// ===========================================================================
// 4. 失败语义（**绝不返回部分和**）
// ===========================================================================
//   * `RunSecureMulBatch` 返回**结构化**结果（`ok[i]`、`failure[i]`、
//     `error_kind[i]`、`first_failure`），**不抛**"校验失败"异常 —— 它把判定权
//     交给上层；但它**绝不**把失败记录的 `z` 当成有效值（`z[i] = 0`）。
//   * `SumOverFilter` 是**上层入口**：只要有任何一条记录 `!ok`，就抛
//     `SecureMulBatchAbort`（携带 `SecureMulFailure` 分类 + 记录序号 +
//     `SecureMulBatchError` 细类），**不返回任何 `SumResult`**
//     （论文 AggQuery：`If z_i = null → abort`）。
//   * 分类一律走**枚举**（`SecureMulFailure` / `SecureMulBatchError`），
//     **禁止**字符串匹配 `"MAC"`（`MPA-05` §6.3 的 D4 教训：
//     e 检查的报错文本里也含 "MAC"）。
//   * 传输层/帧层失败的细类（`SecureMulBatchError`）：`kTransportError`
//     （应答 `ok == false`）、`kFrameDecodeError`（帧版本/类型/长度不符）、
//     `kRecordCountMismatch`（应答帧条数 ≠ 请求条数）、`kSessionNotFound`
//     （请求的 session 查不到对应记录，服务器以 `kPhaseError` 拒绝）。
//     ⚠️ 这些细类在 `SecureMulFailure` 里统一映射为 `kServerReported`
//     （"对端/协议层拒绝"），因为 `SecureMulFailure` 的枚举值由 `MPA-05` 固定，
//     本层不擅自扩展它。
//   * 会话结束后本层会把两台服务器的 handler 换成一个**拒绝一切**的桩
//     （`std::logic_error`），避免 handler 捕获的 state 表在返回后悬垂。
//
// ===========================================================================
// 5. 施工要点（逐条对应 `MPA-05` 文件头 §6 的红队结论）
// ===========================================================================
//   5.1 批量**自建**（§6.1）：见 §1/§2，未改动 `MPA-05` 一个字节。
//   5.2 校验必须**逐记录**（§6.2）：绝不能"整列一次校验" —— `Σ mac == α·Σ z`
//       恰恰是恶意服务器能保持的不变量（一致偏移），会静默接受被污染的整列。
//       本层对每条第 `VerifyAndReconstruct`，并用 `ok` 逐条把关。
//       ⚠️ **边界（代数结论，测试里有实证）**：篡改第 2 轮中转的 `e` 会让
//       `Δz = δ·f`、`Δmac = α·δ·f` —— 当 `f = 0` 时两者都为 0，
//       **既不可检出也不需要检出**（该记录的正确答案本来就是 0）。
//       `f = 1` 时 `Δz = δ ≠ 0`，由 §4.5-A（`z ≠ f·(e_sent + b)`）当场检出
//       ⇒ 这也正是"必须传 `ctx`"的直接原因（本层的注入用例断言了这个分类）。
//   5.3 MAC 失败时 `r.z` **不可累加**（§6.3）：本层先判 `ok` 再累加，
//       失败记录的 `z` 直接置 0。
//   5.4 **不得剪枝 `f = 0`**（§6.4）：论文是**无条件** `For i = 1..N`；
//       跳过 `f = 0` 会让"消息条数/会话号"泄露 COUNT。本层的 `records`、
//       `messages`、`server_records_processed` 与 `filter` 的内容**无关**。
//   5.5 session 非零（`kSecureMulBatchSessionBase + i`）+ challenge 用
//       `MakeChallenge(i, salt)`：**盐必须每次查询都换**（由调用方负责，
//       `challenge_salt` 就是这个盐；本层把它展开成 8 字节小端喂 `MakeChallenge`）。
//       测试里有"跨查询重放旧帧 ⇒ 被 challenge 拒绝"的用例。
//   5.6 α **全局一份**（§6.6）：本层只**读** `SecureMulClientState`（含 ⟨α⟩_p），
//       绝不重新生成 α；每条记录下发的 ⟨α⟩_p 逐位一致。
//   5.7 最小示例：见 §6。
//
// ===========================================================================
// 6. 最小示例
// ===========================================================================
//     // ---- Init（一次性）----
//     auto client = MpraqClient::Init(schema, records, params);
//     SecureMulClientState mac(client->mac_key_shares(), client->modulus());
//     LocalTransport net(2);
//     random::DeterministicPrng prng(seed_key, /*nonce=*/11);
//
//     // ---- 一次查询：Count（MPA-04）→ Sum（本层）----
//     const CountResult c = CountPredicates(*client, schema, preds);
//     const uint64_t salt = prng.Next() ...;            // **每次查询换新盐**
//     const SumResult s = SumOverFilter(c, schema, /*attr_id=*/1, *client, net, mac,
//                                      prng, salt);
//     const uint128_t avg = AvgOverFilter(s);           // count == 0 ⇒ std::domain_error
//     // s.securemul.rounds == 2、s.securemul.messages == 2N、wire_messages == 4N
//
// ===========================================================================
// 7. 边界与异常（全部有确定性用例）
// ===========================================================================
//   * `f_bits` 为空 ⇒ `std::invalid_argument`；
//   * `f_bits[i] ∉ {0,1}` ⇒ `std::invalid_argument`；
//   * `f_bits.size() != e_server0.size()` 或 `!= e_server1.size()` ⇒
//     `std::invalid_argument`（"长度不匹配"）；
//   * `SumOverFilter` 里 `attr_id` 不在 `schema` 中 ⇒ `std::out_of_range`；
//   * `CountResult::count != popcount(filter)` ⇒ `std::invalid_argument`
//     （调用方手搓的 `CountResult` 与 MPA-04 的口径不一致）；
//   * `CountResult::filter.size() != AttributeShares(...).size()` ⇒
//     `std::invalid_argument`（filter 与属性列不是同一个 `N`）；
//   * `schema` 里该属性声明了 `lcte.window_size` 且 ≠ N ⇒ `std::invalid_argument`；
//   * `AvgOverFilter` 在 `count == 0` 时 ⇒ **`std::domain_error`**（见 §8）。
//
// ===========================================================================
// 8. 与 `mpraq_baseline` 的**口径差异（显式裁决点）**
// ===========================================================================
//   `tests/support/mpraq_baseline.hpp` 的 `Avg(...)` 在"零命中"时**返回 0**
//   （与 VMPQ 的 `AvgWithFilter` 同约定）；本层按任务书要求改为**抛
//   `std::domain_error`**：零命中时"平均值"在数学上无定义，静默返回 0 会把
//   "没有记录满足谓词"伪装成"均值 0"（后者是一个**可达的真实值**）⇒ 二者不可区分。
//   ⇒ 非零命中时两者口径完全一致（整数向下取整），测试只用非零命中的用例
//     对照 baseline，零命中单独测异常。
//
// ===========================================================================
// 9. 明确的边界与**不在本层范围内**的事（如实列出，避免被当成已解决）
// ===========================================================================
//   * `f_bits` 只接受 `0/1`（非比特值抛 `std::invalid_argument`）。
//     `MPA-05` 的 SecureMul 本身把 `f` 当 `Z_q` 元素接受；若将来要做加权和
//     （例如 `Σ w_i·E_i`），需要放开这个检查并把 `f_bits` 换成 `vector<uint128_t>`。
//   * `Sum` 是 **mod q = 2^127−1** 的和（`MPRAQ_IMPL.md` §0/§4 的口径）⇒
//     真实整数和一旦 ≥ q 就会**回绕**，此时 `Avg` 也失去意义。本层**不检查**
//     这一点：判断是否回绕需要知道明文和（= 结果本身），本层没有、也不该有
//     额外的明文信息。⇒ 使用方需保证 `Σ f_i·E_i < q`（对 128 位字段、
//     `N ≤ 2^14`、属性值 ≤ 2^100 这类常规参数恒成立）。
//   * **`CountResult` 自身的完整性不在本层范围内**：`filter`/`count` 来自
//     `MPA-04`，而 `Count` 的完整性在论文框架内**没有**可用机制
//     （`MPA-04` §1、`MPRAQ_IMPL.md` §5 的 "❌ 待 V2"）⇒ 本层**信任**调用方
//     传入的 `filter`，只对 SecureMul 的每条结果做 MAC + 纯客户端复核。
//     本层不写任何"验证 Count"的假象。
//   * `challenge_salt` 为 0 **不报错**（0 也是合法的派生输入）：**"每次查询换新盐"
//     是调用方的责任**（本层只能保证每条记录的 challenge 由 `(记录号, 盐)` 派生）。
//     测试里有"换盐后重放旧帧会被 challenge 拒绝"的用例固化这条语义。
//
// ===========================================================================
// 10. 传输接口化与"服务端在另一个进程"（`MPA-08` 的授权改动；见 §11）
// ===========================================================================
// 本层的三个入口原先只接受具体的 `LocalTransport&`，因此**端到端 demo 的
// Sum/Avg 走不了真实 gRPC**（`MPA-05` 早就只认 `ITransportClient&/ITransportServer&`）。
// `MPA-08` 授权做一处**源兼容**的改动：
//
//   * `SecureMulTransport{client, server}` —— 组合视图（client 负责 Submit/Collect，
//     server 负责 SetHandler/NumServers）。既有的 `LocalTransport&` 重载**原样保留**，
//     内部转调新实现 ⇒ 现有调用方（`MPA-06`/`MPA-07` 的 36 个用例）零改动。
//   * `SecureMulBatchServerTable` —— 把文件内部的 `ServerTable` **公开化**：
//     "安装 state + 按 session 分派 + 回一帧"这套服务端逻辑只有**一份**实现，
//     本地模式与两进程模式的服务器进程都调它（绝不复刻第二份）。
//   * `ISecureMulBatchEndpoint` —— **客户端侧持有的一台服务器的批量会话端点**。
//     为什么要它：两进程模式下 `ITransportServer::SetHandler` 的语义**无法表达** ——
//     它接收的是一个 `std::function` **闭包**，而闭包捕获的服务端 state 表在
//     **客户端进程**里；服务器进程既拿不到那个闭包、也拿不到 state。
//     ⇒ 远程模式的端点只能把"安装 state"与"一轮帧"当成**数据**通过已有的通用
//     `Relay` 送过去（`MPA-08` 的 `src/apps/mpraq_securemul_remote.*` 实现它）。
//
// 两种实现（本地 = `LocalSecureMulBatchEndpoint`，在 aggvalue.cpp 内部；
// 远程 = `RemoteSecureMulBatchEndpoint`，在 `MPA-08` 的新文件里）：
//   * 本地：`Install` 直接进本进程的表、`SubmitFrame` 把**原样的批量帧** Submit、
//     `UnwrapResponse` 是恒等 ⇒ 与改动前的字节流**逐位相同**；
//   * 远程：`Install` 进缓冲、`FlushInstalls` 一次 RoundTrip 把 N 条 setup 送到
//     服务器进程、`SubmitFrame` 把批量帧包进带标记的封套、`UnwrapResponse` 拆封套。
//
// ⚠️ 账目口径的一处**显式区分**（远程模式才非零，本地模式恒为 0）：
//   * `install_rounds` = 安装 state 阶段的 `Collect()` 次数（本地 0；远程 2，每台一次）；
//   * `install_bytes`   = 安装帧的线上字节（两台之和）。
//     这两项是"客户端在**每次查询**都把 N 条预处理材料下发"的直接代价（离线
//     dealer 模型；真实部署应由离线阶段在服务器侧产出，本 demo 如实报出来）。
//   * 在线两轮的 `rounds` 仍然恒为 **2**（口径不变）。

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/field.hpp"
#include "core/random.hpp"
#include "mpraq/aggquery.hpp"
#include "mpraq/secure_mul_flow.hpp"
#include "net/transport.hpp"
#include "shared/secret_sharing.hpp"

namespace tsb {
namespace mpraq {

// ---------------------------------------------------------------------------
// 批量帧的常量（格式见文件头 §1）
// ---------------------------------------------------------------------------

// 批量帧头的版本号（与 `MPA-05` 的 `kSecureMulWireVersion` 是**两个独立**的版本轴：
// 前者是"批量容器"的版本，后者是"单记录消息"的版本；本层同时校验两者）。
inline constexpr uint8_t kBatchWireVersion = 1;

// 批量帧的消息类型（wire 上第 2 个字节）
enum class SecureMulBatchMsgType : uint8_t {
    kPhase1Request = 0x11,
    kPhase1Response = 0x12,
    kPhase2Request = 0x13,
    kPhase2Response = 0x14,
};

// 批量帧头长度：版本(1) + 类型(1) + count(4, 小端)
inline constexpr size_t kBatchFrameHeaderBytes = 6;

// 批量会话的 session 基准值：**非零**（`MPA-05` §6.5 的建议）+ 按记录号递增。
// ⚠️ 与记录号绑定（**不随查询变化**）：这样"跨查询重放旧帧"会命中同一个 state，
//    从而由 **challenge（= 盐派生）** 拒绝 —— 这正是"每次查询换盐"要挡住的东西。
inline constexpr uint64_t kSecureMulBatchSessionBase = 0x0000004D50524151ULL;  // "MPRAQ" 风格常量，非零

// 每台服务器预装一条记录所需的**材料字节数**（口径见文件头 §3）：
// 7 个 triple 共享（⟨a⟩⟨b⟩⟨c⟩⟨αa⟩⟨αb⟩⟨αc⟩⟨α⟩）+ ⟨E⟩_p，各 16 B。
inline constexpr uint64_t kServerStateMaterialBytesPerRecord = 7 * 16 + 16;

// MPA-05 的单记录定长消息字节数（**只读**引用它的布局：本层不改这些数字，
// 并且在编解码时用 `MPA-05` 的编码器实测复核，防止两边漂移）。
size_t SecureMulBatchMessageBytes(SecureMulBatchMsgType type);

// 批量帧编解码。
//   * `EncodeBatchFrame`：逐条校验子消息长度与 `type` 是否自洽（不符抛
//     `std::invalid_argument`），再拼成 `6 + Σlen` 的帧；
//   * `DecodeBatchFrame`：严格校验版本/类型/总长度（长度不符**显式抛**
//     `std::invalid_argument`，绝不静默截断），返回**逐条定长切片**。
Payload EncodeBatchFrame(SecureMulBatchMsgType type,
                         const std::vector<Payload>& messages);
std::vector<Payload> DecodeBatchFrame(const Payload& frame,
                                      SecureMulBatchMsgType expected);

// ---------------------------------------------------------------------------
// 传输接口化（文件头 §10）：组合视图 + 服务端会话表 + 端点抽象
// ---------------------------------------------------------------------------

// 组合视图：**client** 负责 `Submit`/`Collect`，**server** 负责 `SetHandler`/`NumServers`。
//
// ⚠️ 引用成员 ⇒ 本类型是"调用期内有效"的视图（照 `std::span` 的用法）：
//    不要把它的引用存下来跨调用使用。
// ⚠️ `LocalTransport` **同时**实现两个接口，因此 `SecureMulTransport{net, net}`
//    是合法的（但那不是主要用法：它的语义与既有的 `LocalTransport&` 重载相同）。
struct SecureMulTransport {
    ITransportClient& client;
    ITransportServer& server;
};

// 一台服务器的**批量会话表**（= 文件头 §1/§2 的服务端一侧）。
//
// 语义（逐条对应文件头 §1）：
//   * `Install(session, setup)`：把客户端下发的 `SecureMulServerSetup` 变成一条
//     常驻的 `SecureMulServerState`（两轮之间保活）；同一 session 装两次 ⇒ 抛；
//   * `HandleFrame(frame)`：解**一个**批量帧（版本/类型/长度严格校验）→ 逐条按
//     session 查表分派到 `MPA-05` 的 `ServerHandlePhase1/2` → 回**一个**应答帧；
//     单条失败（查不到 session / 单条解码失败）转成**结构化拒绝**的应答，
//     而帧级的版本/长度错误**直接抛**（绝不静默截断）；
//   * `Clear()`：清空整表（**两进程模式**下一次查询开始前复用同一张表；
//     本地模式每次调用新造一张，因此不需要它）。
//
// ⚠️ 线程安全：**本类不加锁**。本地模式是单线程调用；服务器进程（`mpraq_server`）
//    里 gRPC 会在**多个线程**上并发进入 → 调用方（`MPA-08` 的 Relay 分派器）
//    自己加互斥（见 `src/apps/mpraq_securemul_remote.*`）。
class SecureMulBatchServerTable {
public:
    explicit SecureMulBatchServerTable(uint128_t q = kSecureMulModulus) : q_(q) {}

    void Install(uint64_t session, const SecureMulServerSetup& setup);
    Payload HandleFrame(const Payload& frame);
    void Clear();

    size_t size() const { return states_.size(); }
    uint64_t frames() const { return frames_; }                  // 收到的批量帧数
    uint64_t processed_phase1() const { return processed_phase1_; }  // 第 1 轮分派的记录数
    uint64_t processed_phase2() const { return processed_phase2_; }  // 第 2 轮分派的记录数

private:
    uint128_t q_ = kSecureMulModulus;
    std::vector<SecureMulServerState> states_;
    std::unordered_map<uint64_t, size_t> by_session_;
    uint64_t processed_phase1_ = 0;
    uint64_t processed_phase2_ = 0;
    uint64_t frames_ = 0;
};

// **客户端侧**持有的一台服务器的批量会话端点（文件头 §10）。
//
// 两个实现：
//   * 本地（`aggvalue.cpp` 内部）：直接操作本进程的 `SecureMulBatchServerTable`
//     + 通过 `ITransportServer::SetHandler` 注册 handler；
//   * 远程（`MPA-08` 的 `src/apps/mpraq_securemul_remote.*`）：把 state 与帧通过
//     已有的通用 `Relay` 送到**服务器进程**，由那边的 `SecureMulBatchServerTable`
//     处理（服务器进程**没有**、也**不可能有**客户端的闭包）。
class ISecureMulBatchEndpoint {
public:
    virtual ~ISecureMulBatchEndpoint() = default;

    // **会话开始**：把"本次会话"的计数器与缓冲清零（驱动在每一轮安装之前调用一次）。
    //   * 本地：空操作（端点对象本身就是"一次会话一个"，表与计数天然是新的）；
    //   * 远程：端点对象会被**跨查询复用**（它只绑到一台服务器），因此必须显式
    //     重置"本次会话"的计数与缓冲 —— 否则账目会累加（`install_frames` 变成 2/4/6…）。
    virtual void BeginSession() = 0;
    // 安装一条记录的服务端 state（本地：立即进表；远程：进缓冲，等 FlushInstalls）
    virtual void Install(uint64_t session, const SecureMulServerSetup& setup) = 0;
    // 把缓冲的安装落线（本地：空操作；远程：一次 Submit + Collect，并校验回执条数）
    virtual void FlushInstalls() = 0;
    // 提交**一轮**的批量帧（本地：原样 Submit；远程：包上标记封套后 Submit）
    virtual void SubmitFrame(const Payload& frame) = 0;
    // 把本轮收到的原始应答变成"上层能解码的应答"：
    //   * 本地：恒等返回；
    //   * 远程：校验标记封套（类型/条数），剥出内层应答帧；**顺带**把服务器自报的
    //     "本轮实际处理的子消息数"记进 `processed_phase1/2`（服务器侧**实测**，不是估算）。
    // ⚠️ 校验失败**必须**返回 `Response::Err(...)`（绝不返回空 payload 冒充成功）。
    virtual Response UnwrapResponse(const Response& raw) = 0;

    // ---- 账目 ----
    virtual uint64_t frames() const = 0;            // 服务器侧收到/本端发出的批量帧数
    virtual uint64_t processed_phase1() const = 0;  // 第 1 轮实际处理的记录数
    virtual uint64_t processed_phase2() const = 0;  // 第 2 轮实际处理的记录数
    virtual uint64_t install_frames() const = 0;    // 安装帧数（本地 0；远程 1）
    virtual uint64_t install_bytes() const = 0;     // 安装帧字节（本地 0）
    // **已收到的应答字节**（下行；本地 0 —— 进程内没有"线上字节"，语义正确）。
    // ⚠️ Sum 的**下行大头不是 PIR 应答而是这里**：Phase1Response(27B/条)
    //    + Phase2Response(43B/条) ⇒ 每台 `70·N` 字节量级。
    virtual uint64_t recv_bytes() const = 0;
    // 会话结束：本地把 handler 换成"拒绝一切"的失效桩（避免悬垂捕获）；
    // 远程为空操作（服务器进程的表由下一次安装帧的 Clear() 覆盖）。
    virtual void Close() = 0;
};

// ---------------------------------------------------------------------------
// 账目 / 结果
// ---------------------------------------------------------------------------

// 账目（口径见文件头 §3；`wire_messages`/`server_records_processed`/… 是追加字段）
struct SecureMulBatchStats {
    uint64_t records = 0;            // = N（**不剪枝**，即使 filter 全 0）
    uint64_t rounds = 0;             // `Collect()` 的实际调用次数（期望恰为 2）
    uint64_t messages = 0;           // 期望恰为 2N（单台服务器视角：每轮 N 条）
    uint64_t phase1_messages = 0;    // = N
    uint64_t phase2_messages = 0;    // = N
    uint64_t server_state_peak_bytes = 0;  // 每台服务器预装 state 的常驻材料字节（= 128·N）
    double offline_triple_ms = 0.0;  // 预生成 N 组 Beaver triple 的耗时
    double online_ms = 0.0;          // 两轮在线（建帧 + Submit + Collect + 解码）
    double verify_ms = 0.0;          // 逐记录 VerifyAndReconstruct

    // ---- 追加字段（口径见文件头 §3，测试会逐条断言）----
    uint64_t wire_messages = 0;             // 线上真实消息条数 = 4N（两台 × 两个方向）
    // 每台**实际处理**的记录条数：第 1 轮 / 第 2 轮各自计数（常量模式证据）。
    // 批量路径两个数组都必须是 N（**不剪枝**：与 filter 的内容无关）。
    uint64_t server_records_processed[2] = {0, 0};         // 第 1 轮
    uint64_t server_records_processed_phase2[2] = {0, 0};  // 第 2 轮
    uint64_t server_frames[2] = {0, 0};              // 每台收到的批量帧数（批量路径恒 2）
    uint64_t frame_bytes_phase1 = 0;        // 单个 Phase1 帧字节数（6 + 34N）
    uint64_t frame_bytes_phase2 = 0;        // 单个 Phase2 帧字节数（6 + 58N）
    uint64_t server_state_allocated_bytes = 0;  // 每台 `sizeof(SecureMulServerState) · N`（实测口径）
    double offline_setup_ms = 0.0;          // MakeSetupsAndContext + 装 state（不含 triple 生成）
    uint64_t collect_calls_phase1 = 0;      // 第 1 轮的 Collect 次数（恒 1）
    uint64_t collect_calls_phase2 = 0;      // 第 2 轮的 Collect 次数（恒 1）

    // ---- 追加字段（MPA-08 的传输接口化；口径见文件头 §10）----
    // ⚠️ 本地/同进程模式恒为 0；只有"服务端在另一个进程"的远程模式才非零。
    uint64_t install_frames = 0;   // 安装帧数（两台之和；远程 = 2）
    uint64_t install_rounds = 0;   // 安装 state 阶段的 Collect 次数（远程 = 2，每台一次）
    uint64_t install_bytes = 0;    // 安装帧的线上字节（两台之和）
    // **下行**：两轮相位回执的字节（两台之和）。
    // ⚠️ Sum 的**下行大头在这里**，不是 PIR 应答：每台约 `70·N`
    //    （Phase1Response 27 B/条 + Phase2Response 43 B/条）。
    uint64_t recv_bytes = 0;
};

// 帧层/传输层的失败细类（`failure[i]` 之外的第二根轴；见文件头 §4）
enum class SecureMulBatchError : uint8_t {
    kNone = 0,
    kTransportError = 1,       // 应答 `ok == false`（丢包 / 服务器抛异常）
    kFrameDecodeError = 2,     // 应答帧版本/类型/长度不符
    kRecordCountMismatch = 3,  // 应答帧条数 ≠ 请求条数
    kSessionNotFound = 4,      // 子消息的 session 查不到对应记录（跨记录串味/注入）
};

// 分类名的**人读**渲染（诊断/报告用；⚠️ 判定一律走枚举值，禁止字符串匹配）。
const char* SecureMulBatchFailureName(SecureMulFailure f);
const char* SecureMulBatchErrorName(SecureMulBatchError e);

// 一次批量 SecureMul 的结果。
//   * `z[i]` **只在 `ok[i]` 为真时**有意义；失败记录一律置 0（不向外泄露错值）；
//   * 失败分类走 `failure[i]`（`MPA-05` 的枚举）+ `error_kind[i]`（本层细类），
//     **禁止**字符串匹配；
//   * `first_failure` = 第一个失败记录的序号（`SIZE_MAX` = 全部通过）。
struct SecureMulBatchOutcome {
    std::vector<uint128_t> z;
    std::vector<uint8_t> ok;
    std::vector<SecureMulFailure> failure;
    std::vector<SecureMulBatchError> error_kind;
    std::vector<std::string> detail;  // 人读原因（**不参与判定**）
    SecureMulBatchStats stats;
    size_t first_failure = SIZE_MAX;

    bool all_ok() const { return first_failure == SIZE_MAX; }
    size_t size() const { return z.size(); }

    // 只有当 `all_ok()` 时才给出 Σ z（mod q）；否则抛 `std::logic_error`
    // （**绝不**返回部分和 —— 见文件头 §4）。
    uint128_t SumOrThrow(uint128_t q) const;
};

// 批量会话里任一记录校验失败时抛出的异常（携带分类 + 序号，见文件头 §4）。
// ⚠️ 这是 `SumOverFilter` 的"abort 整个查询"路径：**绝不**返回部分和。
class SecureMulBatchAbort : public std::runtime_error {
public:
    SecureMulBatchAbort(const std::string& what, SecureMulFailure failure,
                        size_t record_index, SecureMulBatchError error_kind);
    SecureMulFailure failure() const { return failure_; }
    size_t record_index() const { return record_index_; }
    SecureMulBatchError error_kind() const { return error_kind_; }

private:
    SecureMulFailure failure_ = SecureMulFailure::kNone;
    size_t record_index_ = 0;
    SecureMulBatchError error_kind_ = SecureMulBatchError::kNone;
};

// ---------------------------------------------------------------------------
// 批量驱动（= `MPRAQ_IMPL.md` §4 的 1–3 步；第 4 步的 abort 由 `SumOverFilter` 负责）
// ---------------------------------------------------------------------------

// 整列 `N` 条记录 = **恰好 2 个往返**（每个方向 N 条消息，见文件头 §3 的口径）。
//
// 输入：
//   * `f_bits[i] ∈ {0,1}` —— **客户端明文**的过滤位（来自 `CountResult::filter`）；
//   * `e_server0[i] / e_server1[i]` —— 属性值 `E_i` 的两份 mod q 加法共享
//     （来自 `MpraqClient::AttributeShares(attr_id, server)`；**必须**满足
//      ⟨E⟩_0 + ⟨E⟩_1 ≡ E mod q，否则 §4.5-A/B 会拒绝 —— 这正是防线）；
//   * `net` —— 两台服务器（`LocalTransport(2)`；真实部署换 gRPC 通道）；
//   * `mac` —— **全局一份**的 α/⟨α⟩_p（只在 Init 生成一次）；
//   * `prng` —— 确定性随机源（triple 的 a/b 与各共享掩码）；
//   * `challenge_salt` —— **每次查询都要换**的盐（§5.5）。
//
// `net` 的两台服务器 handler 由本函数安装（会话结束后换成拒绝桩，见 §4）。
SecureMulBatchOutcome RunSecureMulBatch(const std::vector<uint8_t>& f_bits,
                                        const std::vector<ModShare>& e_server0,
                                        const std::vector<ModShare>& e_server1,
                                        LocalTransport& net, SecureMulClientState& mac,
                                        random::DeterministicPrng& prng,
                                        uint64_t challenge_salt);

// **接口版**（`MPA-08` 授权改动，文件头 §10）：语义、账目与上面**逐位相同**，
// 只是把具体的 `LocalTransport` 换成 `ITransportClient` + `ITransportServer`。
// 用途：进程内 gRPC 回环（`GrpcTransportClient` + `GrpcTransportServer` 在同一
// 进程里）等"服务端一侧仍在**本进程**"的部署。
SecureMulBatchOutcome RunSecureMulBatch(const std::vector<uint8_t>& f_bits,
                                        const std::vector<ModShare>& e_server0,
                                        const std::vector<ModShare>& e_server1,
                                        SecureMulTransport net, SecureMulClientState& mac,
                                        random::DeterministicPrng& prng,
                                        uint64_t challenge_salt);

// **两进程版**（`MPA-08`）：服务端在**另一个进程**里，因此由调用方提供两个端点
// （`RemoteSecureMulBatchEndpoint`）；`client` 只用来 `Collect()`（`Submit` 由端点做，
// 顺序恒为"先 server0、后 server1"）。
// ⚠️ `server0`/`server1` 必须是**两个不同的**端点对象（同一对象 ⇒ 抛
// `std::invalid_argument`：那等于一台服务器冒充两台）。
SecureMulBatchOutcome RunSecureMulBatch(const std::vector<uint8_t>& f_bits,
                                        const std::vector<ModShare>& e_server0,
                                        const std::vector<ModShare>& e_server1,
                                        ITransportClient& client,
                                        ISecureMulBatchEndpoint& server0,
                                        ISecureMulBatchEndpoint& server1,
                                        SecureMulClientState& mac,
                                        random::DeterministicPrng& prng,
                                        uint64_t challenge_salt);

// **逐记录参考驱动**（用于"批量 ≡ 逐记录"的等价性测试与对照实验）：
// 语义与 `RunSecureMulBatch` 完全一致（同样的输入、同样的 `ok` 判定、
// 同样的"失败不累加"），但走 `MPA-05` 的逐记录路径
// （`RegisterSecureMulServers` + `SecureMulFlowRunRecord`），
// ⇒ `rounds == 2N`、`server_frames == 2N`、`messages == 2N`（单台视角）。
// ⚠️ 逐记录路径的 `server_state_peak_bytes` 只有 1 条记录的材料（state 用一条装一条）。
SecureMulBatchOutcome RunSecureMulPerRecord(const std::vector<uint8_t>& f_bits,
                                            const std::vector<ModShare>& e_server0,
                                            const std::vector<ModShare>& e_server1,
                                            LocalTransport& net, SecureMulClientState& mac,
                                            random::DeterministicPrng& prng,
                                            uint64_t challenge_salt);

// **接口版**（`MPA-08` 授权改动）：同上，只是传输换成接口。
// ⚠️ 本重载**只**支持"服务端一侧在本进程"的部署（`RegisterSecureMulServers` 走的
//    就是 `ITransportServer`）；跨进程的逐记录路径不存在 —— 两进程模式一律用批量路径
//    （逐记录路径的 `2N` 个往返在跨进程下毫无意义）。
SecureMulBatchOutcome RunSecureMulPerRecord(const std::vector<uint8_t>& f_bits,
                                            const std::vector<ModShare>& e_server0,
                                            const std::vector<ModShare>& e_server1,
                                            SecureMulTransport net, SecureMulClientState& mac,
                                            random::DeterministicPrng& prng,
                                            uint64_t challenge_salt);

// ---------------------------------------------------------------------------
// Sum / Avg（`MPRAQ_IMPL.md` §4 的 3–4 步）
// ---------------------------------------------------------------------------

struct SumResult {
    uint128_t sum = 0;      // Σ_i f_i·E_i (mod q)；**只在没有 abort 时存在**
    uint64_t count = 0;     // = `CountResult::count`（MPA-04 的 popcount(filter)）
    double sum_ms = 0.0;    // 本次 Sum 的墙钟（含批量 SecureMul 全过程）
    SecureMulBatchStats securemul;  // 往返/消息/耗时账目（口径见文件头 §3）
};

// Sum：对属性 `attr_id` 的取值按 `filter` 求和。
//   * `filter` / `count` **全部取自 `MPA-04`**（`CountResult`）——
//     本层**不**自己重算谓词、**不**自己检索列（`aggquery.hpp` §3 的硬预算）；
//   * ⟨E⟩ 的两份共享取自 `client.AttributeShares(attr_id, server)`，并且会
//     复核"返回长度 == N"（属性值语义见文件头 §0/§7）；
//   * **任一记录校验失败 ⇒ 抛 `SecureMulBatchAbort`**（绝不返回部分和）。
SumResult SumOverFilter(const CountResult& c, const Schema& schema, uint32_t attr_id,
                        MpraqClient& client, LocalTransport& net,
                        SecureMulClientState& mac, random::DeterministicPrng& prng,
                        uint64_t challenge_salt);

// **接口版**（`MPA-08` 授权改动）：语义、账目与上面逐条相同，传输换成接口。
SumResult SumOverFilter(const CountResult& c, const Schema& schema, uint32_t attr_id,
                        MpraqClient& client, SecureMulTransport net,
                        SecureMulClientState& mac, random::DeterministicPrng& prng,
                        uint64_t challenge_salt);

// **两进程版**（`MPA-08`）：服务端在另一个进程里 ⇒ 调用方提供两个端点。
// ⚠️ 其余纪律完全不变：`filter`/`count` 一律取自 `MPA-04`；任一记录校验失败 ⇒
//    抛 `SecureMulBatchAbort`（绝不返回部分和）。
SumResult SumOverFilter(const CountResult& c, const Schema& schema, uint32_t attr_id,
                        MpraqClient& client, ITransportClient& transport,
                        ISecureMulBatchEndpoint& server0,
                        ISecureMulBatchEndpoint& server1,
                        SecureMulClientState& mac, random::DeterministicPrng& prng,
                        uint64_t challenge_salt);

// Avg = Sum / Count（**整数向下取整**，与 VMPQ 的 `AvgWithFilter` 同口径）。
// ⚠️ `count == 0` ⇒ **`std::domain_error`**（不得静默返回 0/NaN，见文件头 §8）。
uint128_t AvgOverFilter(const SumResult& r);

}  // namespace mpraq
}  // namespace tsb
