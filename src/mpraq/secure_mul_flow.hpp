#pragma once

// MPRAQ 的 SecureMul 三方消息流（任务 MPA-05）。
//
// ===========================================================================
// 0. 这个文件解决什么问题
// ===========================================================================
// `shared/mpc` 已经实现了 SecureMul 的**代数内核**（Beaver triple + SPDZ MAC），
// 但它是"单进程仿真"形态：两阶段的服务器函数与客户端驱动都在同一个进程里
// 顺着调用，没有"消息"这个概念。MPRAQ 的真实部署是 **1 客户端 + 2 服务器**，
// 客户端在两台服务器之间**中转**，**服务器之间没有任何通信路径**。
//
// 本模块把那个内核落成**真实的消息流**：
//   * 定义可序列化的扁平消息结构（**不引入新的 proto 文件**）；
//   * 定义轮次（谁在第几轮说什么）、以及每条消息的编解码；
//   * 提供服务器侧的状态与两个阶段的处理函数、客户端侧的驱动；
//   * 用 `net/transport.hpp` 的 `ITransportClient` 走真实链路（进程内是
//     `LocalTransport`，部署是 gRPC），因此"服务器零通信"是**结构性**保证：
//     服务器的处理函数只拿到客户端递过来的字节，**没有任何句柄能触达另一台
//     服务器**（见 §5 的论证与 `tests/test_mpraq_securemul.cpp` 的计数断言）。
//
// ⚠️ 本模块**不修改** `shared/mpc` 的任何语义与签名，只在它之上做搬运与
//    序列化。数值语义完全来自 `SecureMulServerPhase1/2` 与
//    `VerifyAuthenticatedDetailed`。
//
// ===========================================================================
// 1. 数值语义
// ===========================================================================
//   z = f · E   (mod q)
//   mac = α · z (mod q)          ← SPDZ MAC，客户端持有 α，服务器只持有 ⟨α⟩_p
//
//   * `f` 是**客户端明文持有**的过滤位（列向量在客户端本地重建，论文
//     §Multi-Predicate Filtering："The client only needs to retrieve the column
//     vectors ... perform Boolean operations locally, and obtain the final
//     filter vector"）。本模块按论文口径把 f 当作 Z_q 元素接受（0/1 是主用法）。
//   * `E` 是两台服务器**加法共享**的属性值：⟨E⟩_0 + ⟨E⟩_1 ≡ E (mod q)。
//   * `α` 是**全局一份**的 MAC 密钥（TASK_PLAN §7.6 Q3 的裁决 (a)），在 `Init`
//     阶段由客户端生成（`tsb::GenerateMacKey`），本地保存 α、把 ⟨α⟩_p 分发给
//     两台服务器。**每个查询重新生成 α 是错的**，会破坏"MAC 密钥全局一份"的
//     性质；本模块的接口强制 α 与模数在 setup 阶段就固定下来。
//
// 模数 q = 2^127 − 1（梅森素数，TASK_PLAN §7.6 Q1 的裁决 (b)、决策 D11）。
// **q 必须是奇数**：SPDZ MAC 需要**域**（`mac = α·z` 要求 α 可逆；`Z_{2^k}` 里 α 可能
// 是偶数 ⇒ 非零偏差未必可逆 ⇒ 校验可被绕过）。本模块在入口显式校验并抛
// `std::invalid_argument`；注意该检查只保证"奇数"（必要条件），**素数性**由 D11 与
// `core/field` 保证。
//
// ⚠️ **历史上这条检查的理由是"`e·d·2^{-1}` 无定义"，该理由已随公式对齐而消失**
//    （见 §2）。现在它只由 SPDZ MAC 的域要求驱动。
//
// ===========================================================================
// 2. ⚠️ SecureMul 公式（改公式前务必读完）
// ===========================================================================
// **现行公式（2026-10-08 起，与新版论文 `doc/paper/MPRAQ.tex` :554 一致）**：
//
//   服务端  z_p   = ⟨c⟩_p + d·⟨b⟩_p + e·⟨a⟩_p              （纯线性，**无** e·d 项）
//          mac_p = ⟨αc⟩_p + d·⟨αb⟩_p + e·⟨αa⟩_p            （纯线性，**无** ⟨α⟩_p·e·d）
//   客户端  mac ?= α·z   ⇒ 失败即 abort
//          通过后 z ← z + e·d                             ← 公开项由客户端补
//
// 推导：记 d = f − a、e = E − b，由 c = a·b 得
//       f·E = (a+d)(b+e) = c + d·b + e·a + d·e
// 两台求和：z = Σ_p z_p = c + d·b + e·a（线性部分），
//          mac = Σ_p mac_p = α·(c + d·b + e·a) = α·z ✔
// ⇒ **先**校验 `mac ?= α·z`（两侧都只含线性部分），**通过之后**客户端补 `e·d` 得 f·E。
//
// ⚠️ 为什么 `e·d` 必须留在客户端（两条理由指向同一做法）：
//   ① 论文 :556-557 明确：公开常数 `e·d` **故意**不折进服务端表达式 ——
//      "keeps the servers' expressions purely linear in their shares,
//       which is the form the soundness argument relies on"；
//   ② 若折进服务端，两台必须"各给一半"才能凑成整份 ⇒ 需要 `2^{-1}`，
//      而 **GF(2^ℓ) / Z_{2^k} 这类特征 2 的设定里 `2` 不可逆**；更强的是，
//      特征 2 下"两台各加一次"恒为 `x ⊕ x = 0` ⇒ **根本没有"各给一半"的类比**。
//      客户端补 `e·d` 则与特征无关，任何域/环都成立。
//
// ⚠️ 两处"顺手改动"都会坏（改前请看这里）：
//   ① **不要在客户端补 `e·d` 之前校验**：`mac` 只覆盖线性部分，先补会让
//      `mac ?= α·z` 两侧不等 ⇒ 诚实流程也失败；
//   ② **不要省掉客户端那次加法**：省掉后 `z` 会**静默偏小 `e·d`** ⇒ 聚合结果全错。
//
// 历史（**已作废**，仅供追溯）：旧实现在服务端折入 `e·d·2^{-1}`（z 侧）与
// `⟨α⟩_p·e·d`（mac 侧）；在 `Z_q`（奇素数）下结果等价，但破坏了 ① 的形式、
// 且把公式绑死在奇特征上。决策 **D14** 的勘误在旧写法下成立（"mac 末项**绝不能再乘**
// `2^{-1}`"，否则 `mac ≠ α·z` 恒失败）；新写法下两侧都不含 `2^{-1}`，该问题自然消失。
//
// **落地位置**：两条公式都在 `tsb::SecureMulServerPhase2`（`shared/mpc.cpp`）；
// 客户端补公开项在 `VerifyAndReconstruct()`（`secure_mul_flow.cpp`）。
// 本模块**不重新实现**公式，只做消息搬运。
//
// ===========================================================================
// 2b. 与论文 Algorithm 5 的**完整差异清单**（v3 补齐；行号以 `doc/paper/MPRAQ.tex` 为准）
// ===========================================================================
// 语义级差异（S = 影响取值/安全/谁能看到什么；E = 工程）：
//
//  S1 | **已消除**（2026-10-08）| 新版论文已把 z 的末项 `e·d` 整项移到客户端；本实现
//     随之对齐（服务端只算线性部分）。见 §2。旧论文 `:494`/`:590` 的写法已作废。
//  S2 | **已消除**（2026-10-08）| 新版论文的 mac 末项不再带 `e·d`/`2^{-1}`，本实现一致。
//     ⚠️ 旧的 D14 勘误（"mac 末项不能乘 `2^{-1}`"）**仍然是一条真结论**，只是在新
//     公式下不再有落点（两侧都不含 `2^{-1}`）。
//  S3 | `:582`/`:584` 的共享生成/发送清单**漏写 `⟨a⟩_p`**，而 `:590` 的
//     `e·⟨a⟩_p` 要用它 | 本实现发全 7 个分量（`TripleShare`）。**这是论文的真错**：
//     照抄无法计算 z_p。
//  S4 | **部分已修**：新版论文 :72-79 已明确两个代数设定，MPC 层写 `Z_q`、
//     "q ≈ 2^128 大素数"；但 :510 仍写 "a 128-bit element in a finite field"，
//     **且全文仍未给出 q 的具体值** | 本实现固定 **q = 2^127−1**（奇素数；
//     `≤ 2^127` 是 `core/field` 的硬约束）。注意是 **127** bit ⇒ 与 :510 的措辞
//     差一位。裁决见 `doc/design/D41_PAPER_RECONCILE.md` §5（建议**改论文措辞**）。
//  S5 | `:555-556` 是**逐记录** `For i = 1..N` 调 SecureMul，`:561` 求和；全文
//     **不提批量化** | 本模块逐记录（`SecureMulFlowRunRecord`）。⚠️ 与
//     `doc/design/MPRAQ_IMPL.md:82-85`（"必须批量化…2 个往返处理整列"）冲突 ⇒
//     批量层必须由 MPA-06 自建（见 §6 的施工要点）。
//  S6 | `:452` "The protocol ensures that **any** tampering with the multiplication
//     result can be detected by the client" | **该声明不成立**（§4.5 的修正项：
//     一致偏移下 `mac == α·z` 恒成立）。本模块用四层校验把它变成事实（单台口径）。
//  S7 | `:476`/`:580` 只说 α 是 "global MAC key" | 本实现按 TASK_PLAN §7.6 Q3(a)
//     在 Init 阶段生成一次（`GenerateMacKey`）。这是双服务器 SPDZ 的固定做法，
//     论文没写生成/分发流程 —— 属**补全**而非差异。
//
// 工程/协议扩展差异：
//
//  E1 | `:587-589` 的中转是"客户端把**对方那一份** `⟨e⟩_{p+1}` 转给 `S_p`，
//     每台自己重建 e" | 本实现让客户端算出 `e = ⟨e⟩_0+⟨e⟩_1` 后**发同一个 e
//     给两台**。语义等价；差别是"服务器是否看到对方的份额"。⚠️ 注意：即使按
//     论文的转发方式，诚实服务器**也**发现不了被偏移的 `⟨e⟩_{S*}` —— 所以这不是
//     §4.5 漏洞的成因，改成论文写法也修不好。
//  E2 | `:583-584` 的 `d` 只发一次 | 本实现第 2 轮**重发** `d`（+16 B/记录），
//     换来服务器侧无隐藏状态 + 可以做"d 跨轮一致性检查"（v3）。
//  E3 | `:579-584` 把 triple 生成/共享/发送都放在一次 SecureMul 调用内 | 本实现把
//     与 f、E 无关的量放到 Init 阶段安装（在线只传 d/e/e_check），并且协议**不再是
//     自包含的**：需要调用方预先安装 per-record 的服务器状态（`MakeServerState`）。
//  E4 | 论文没有 `session`/`challenge`/`status`/一次性语义 | 本实现全部有（v3 起
//     阶段机是显式的：`Stage::kFresh → kPhase1Done → kConsumed`）。
//  E5 | 论文没有线格式 | 本实现用扁平小端 POD + 版本/类型字节（v3：34/27/58/43 B）。
//  E6 | 论文没有 `e_check` / `status` / 线版本 v2/v3 | **这些是本模块对论文的
//     协议级扩展**（服务器侧的通道篡改卫生设施 + 客户端侧的两条纯客户端复核所需的
//     上下文）。它们不计入"复现论文"，是有意为之的加固，必须与论文区分开。
//  E7 | `MPARQ.tex:576` 的 `\Require` 只列 `f, ⟨E⟩_1, ⟨E⟩_2` | 本实现的在线接口
//     还需要 `session`/`challenge`/triple/transport/client/ctx（见 §6 的签名）。
//
// ⚠️ 已**删除**的两条"伪差异"（v2 曾列为差异 (b)(c)，实为非差异）：
//   * "论文把 SecureMul 写成一次调用、本实现拆两阶段" —— 论文 `:583-592` 本身就是
//     2 往返 / 4 条腿的流程，往返数相同，只是 C++ 函数拆分不同；
//   * "论文未指定 `⟨α⟩_p·e·d` 的乘法顺序" —— 域上乘法可交换/结合，顺序无关。
//
// ===========================================================================
// 3. 轮次与消息结构
// ===========================================================================
// 一次 SecureMul 共 **2 个往返（4 条消息）**，全部在"客户端 ↔ 单台服务器"
// 的链路上，**没有任何服务器 ↔ 服务器的消息**：
//
//   ┌── Init 阶段（离线，非本模块的在线轮次）──────────────────────────────┐
//   │ 客户端：GenerateMacKey(2, q) → (α, ⟨α⟩_0, ⟨α⟩_1)                    │
//   │ 客户端：为每条记录生成 Beaver triple (a, b, c=a·b) 及其共享          │
//   │ 客户端 → S_0 / S_1：ServerState（⟨a⟩,⟨b⟩,⟨c⟩,⟨αa⟩,⟨αb⟩,⟨αc⟩,⟨α⟩）   │
//   └──────────────────────────────────────────────────────────────────────┘
//
//   ┌── 在线阶段（每条记录一次，论文 AggQuery 的 Σ_i SecureMul(f_i, …)）──┐
//   │ 轮 1（client → server）  Phase1Request    ：d = f − a                │
//   │ 轮 1（server → client）  Phase1Response   ：⟨e⟩_p = ⟨E⟩_p − ⟨b⟩_p     │
//   │ 轮 2（client → server）  Phase2Request    ：d、e（中转）、e_check    │
//   │ 轮 2（server → client）  Phase2Response   ：status、z_p、mac_p        │
//   │ 客户端：先查两台的 status（§4.5）、再查 e 的一致性，最后               │
//   │        z = z_0 + z_1、mac = mac_0 + mac_1，校验 mac == α·z；          │
//   │        任一步失败则 abort（`SecureMulFlowResult::ok == false`）       │
//   └──────────────────────────────────────────────────────────────────────┘
//
// 消息是**扁平 POD + 显式小端编码**，不依赖编译器对齐/字节序，不用 protobuf：
// 每条消息都很小且字段固定，手写编解码更可控、无构建负担，也便于测试直接
// 对字节做篡改注入。各消息的准确长度（v3）与字段偏移：
//
//   Phase1Request  : ver(0) type(1) session(2..9) challenge(10..17) d(18..33)                = 34 B
//   Phase1Response : ver(0) type(1) session(2..9) e_computed(10..25) status(26)             = 27 B
//   Phase2Request  : ver(0) type(1) session(2..9) d(10..25) e(26..41) e_check(42..57)       = 58 B
//   Phase2Response : ver(0) type(1) session(2..9) z_share(10..25) mac_share(26..41) status(42) = 43 B
//
// ⚠️ 线格式**没有完整性保护**（无长度域/无 AEAD/无消息级 MAC）：帧内任意字节翻转
//    都会被解码层放过，只能靠 §4.5 的四层校验在协议层发现。
//
// ===========================================================================
// 4. 半诚实安全性（论证）与恶意模型的可选加固
// ===========================================================================
// **半诚实模型**下服务器严格按协议执行但会记录一切所见。逐条看服务器能看到什么：
//
//   * `Phase1Request` 只含 `d = f − a`。`a` 是 triple 的随机分量，在 Z_q 上均匀
//     分布且**服务器从未见过 a 的明文**（它只有 ⟨a⟩_p）。因此 d 在 Z_q 上均匀，
//     与 f 独立 ⇒ **零信息**（一次一密）。同理客户端在第 2 轮中转的 `e` 不泄露
//     任何东西给"另一台"服务器：e 是**两台**服务器各自计算的一半之和，而
//     e = E − b 本身也是均匀随机的（b 均匀且服务器不知道 b）。
//   * `Phase1Response`（⟨e⟩_p）与 `Phase2Response`（z_p, mac_p）都是**共享**，
//     单个共享在信息论意义上与所共享的值独立（掩码是独立均匀随机的：
//     `GenerateTripleShares` 为 ⟨αa⟩/⟨αb⟩/⟨αc⟩ 各取了**独立**掩码，没有复用
//     ⟨a⟩/⟨b⟩/⟨c⟩ 的掩码，见 `shared/mpc.cpp:71-85` 的注释）。
//   * ⟨α⟩_p 与 α 的关系：服务器拿到的只有一份 ⟨α⟩_p，α 本身只在客户端。
//     ⚠️ 这一点要说得准确：单台**可以**把 (z_p, mac_p) 按 §4.5 的公式
//     "同步偏移"成一个自洽的对（见 §4.6），但它**不能**为任意目标 z 单独造出
//     一个 mac 分片 —— 那需要 α 或另一台的 mac 分片。MAC 保证的是"两台之间
//     以及 z 与 mac 之间的一致性"，不是"结果一定正确"（§4.6 讲清了边界）。
//   * 服务器之间**没有信道**：即使某台服务器想旁路，它也只能通过客户端中转，
//     而客户端只中转 `e`（协议规定的标量），不会替服务器转发任意载荷。
//
// **恶意模型**需要额外的机制（本模块**不实现**，仅按"为将来预留"的形态留出字段）：
//   * `Phase1Request.challenge` / `ServerState.pending_challenge`：服务器侧的
//     "挑战—应答"防重放/防乱序锚点。半诚实模型下它只是卫生设施（保证同一
//     session 不被复用两次、消息不被重排/重放）；要变成真正的恶意模型保证，
//     还需要**客户端对 d 的承诺**（先发 commit(d)，第 2 轮再 reveal，
//     防止客户端按 e 的结果事后挑一个 d）以及**双份 e 的一致性检查**
//     （两台服务器各报一次对方共享的校验值，客户端比对）。
//   * `ServerState.consumed`：一次性语义（同一条记录的状态不能被两次查询复用），
//     半诚实下也是卫生设施，恶意模型下是必需的（否则服务器可以重放第 2 轮）。
//
// ===========================================================================
// 4.5 ⚠️ 论文 Algorithm 5 的**正确性漏洞**与我们的处置（v3 的四层校验）
// ===========================================================================
// **漏洞（数学事实，已实测）**：论文的 SecureMul 只让客户端校验 `mac == α·z`。
// 这条校验能抓住"z 与 mac 不匹配"的篡改，**但抓不住"z 与 mac 一起被改对"的情形**。
// 后者是协议的**结构性后果**，而且**不需要知道 α**：
//
//   设某台恶意服务器 S* 让两台都用一个偏移后的值（e 改成 e+δ，或 d 改成 d+Δ）：
//       z' = z + δ·(a+d) = z + δ·f            （因 a+d = f）
//       或 z' = z + Δ·(b+d) = z + Δ·E
//       mac' = α·z'                            （两台分片同步偏移 ⇒ 恒自洽）
//   于是 `mac == α·z` **依然成立**，客户端接受一个自己算不出来的 z'。
//   S* 只需要按公开的协议公式把自己的分片重算一遍即可，**不需要 α**。
//
// 论文 §Aggregation 声称 "any tampering with the multiplication result can be
// detected by the client"，就 Algorithm 5 的校验式而言**这个说法不成立**
// （论文只有这一个检查点）。这是与 D14 同级的协议级问题：D14 是"照抄会恒失败"，
// 本条是"照抄会**恒通过**"。
//
// ---------------------------------------------------------------------------
// v3 的四层校验（前两层"服务器自报"只能当卫生设施，后两层才是安全保证）
// ---------------------------------------------------------------------------
// 第 1 层 **服务器自报状态**（`SecureMulStatus`）：纯卫生设施。status 由被检查方
//        自己给出，因此它只对"通道篡改 + 服务器诚实执行"有保证。
// 第 2 层 **§4.5-B 复核每台自报的 ⟨e⟩_p**（**纯客户端**，v3 新增）：
//        客户端在 Init 阶段**自己安装**了两台的 ⟨E⟩_p 与 ⟨b⟩_p，因此可以独立复核
//              Phase1Response.e_computed  ?=  ⟨E⟩_p − ⟨b⟩_p
//        判据不依赖任何自报值。**这一层才挡得住"说谎的服务器"** —— 服务器侧的
//        `e_check` 回执检查是**自证**的（客户端把收到的值原样带回，谎报的那台
//        自己就是裁判），对抗性验证 E2 已证实它可以照常报 kOk。
// 第 3 层 **§4.5-A 复核 z 与客户端本地视角一致**（**纯客户端**，v3 新增）：
//        ⚠️ 修正一处 v2 的错误论断：v2 的头文件写"客户端看不到 E，所以无法算出
//        z 的真值" —— **前提是错的**。在本模块里 triple 由客户端生成，客户端知道
//        b，且它知道自己中转出去的 e_sent，于是它**能**算出
//              E_local = e_sent + b
//        并要求 `z == f · E_local`。任何让两台一致使用偏移 d/e 的攻击都会破坏
//        这个等式（`z' = z + Δ·f`），当场被检出，**零条新消息**。
//        ⚠️ 前提：triple 必须由客户端生成。若将来移到第三方 dealer / 离线服务器，
//           客户端不再知道 b ⇒ 本条复核失效，`d` 偏移重新不可检出（那时才需要
//           承诺机制）。第 2 层不受此影响。
// 第 4 层 **SPDZ MAC**（`mac == α·z`）：抓"z 与 mac 不一致"的那一类。
//
// **实测（`tests/test_mpraq_securemul.cpp`）**：
//   * `BitFlipMatrixIsFullyDetected`：**1024 格**（z_p / mac_p / e_computed / d
//     各 128 位 × 2 台）全部被检出，零静默接受；
//   * `RedTeamBothServersOneBitEOffsetIsDetectedEndToEnd`：两台一致改 e 的最低
//     bit（红队 E1 的最小复现）**f=1 的 8/8 全部检出**，零错值被接受
//     （v2 时这 8 轮**全部**被接受错值）；
//   * `RedTeamBothServersOneBitDOffsetIsDetectedEndToEnd` / `RedTeamMultiBitOffsetIsDetected`：
//     d 一致偏移（红队 E3）与"任意 Δ"的版本同样 100% 检出；
//   * `ServerSelfReportedCheckIsSelfWitnessing`（红队 E2）：固化服务器侧 e_check
//     的**效力边界**，并证明纯客户端复核 B 能独立检出；
//   * `HonestPeerIsNotDeniedByASelfishZeroReport`：v3 删掉了 v2 的
//     `e != e_check` 判据 —— 它给单台服务器一个**零成本否决权**（把自己的
//     ⟨e⟩_p 报成 0 ⇒ 诚实那台刚好 e == e_check ⇒ 整条查询 abort，对抗性验证
//     §5.3 的 DoS）。删掉后诚实那台照常放行。
//
// ⚠️ **仍然无法检出的一类（必须知道）**：**两台服务器共谋**（互相约定同一个
//    偏移），或恶意客户端与服务器合作。此时第 2、3 层用的基准值本身也被污染。
//    这超出"单台恶意 + 客户端诚实"的威胁模型，任何基于加法共享的方案都如此；
//    论文 `MPARQ.tex:150` 也明确假设 "The two servers do not collude"。
//
// ⚠️ **一条连带的口径问题（如实记录）**：既然客户端能算 `E_local = e_sent + b`，
//    那么"SecureMul 让客户端拿不到属性值"的隐私动机在本模块的实现里**不成立** ——
//    客户端对**每条真正走了 SecureMul 的记录**都能还原出一个属性值。
//    在 MPRAQ 的威胁模型里这**不是隐私缺陷**（客户端本来就是数据所有者），
//    但论文若把"服务器不知道 E"当成安全卖点，需要明确这一点；
//    若要让客户端也不知道 E，必须把 triple 生成移出客户端（代价：第 3 层复核消失）。
//
// ⚠️ 消息层**没有完整性保护**：线格式无长度域、无 AEAD、无消息级 MAC，帧内任意
//    字节翻转都会被解码层放过（对抗性验证 fuzz：3203/3203），全部依赖上面的
//    第 2–4 层在协议层检出。若要抗 MITM/重放，必须显式加（论文把 MITM 排除在
//    威胁模型外，见 `MPARQ.tex:150`）。
//
// ===========================================================================
// 4.6 边界小结（v3 收窄后的准确口径）
// ===========================================================================
//   * 单台服务器偏离（无论改 d、e、z_p、mac_p，无论单点还是多点，**逐比特**）：
//     **100% 被检出并 abort**（1024 格矩阵 + 端到端反例，见 §4.5 的实测清单）。
//   * 两台服务器共谋 / 恶意客户端：**不在威胁模型内**，会被第 2、3 层用被污染的
//     基准值"自洽地"通过 —— 需要完整恶意模型 MPC 才能覆盖。
//   * triple 生成被移出客户端（第三方 dealer）：第 3 层复核失效，`d` 一致偏移
//     重新变成不可检出 ⇒ 那时必须补"客户端对 d 的承诺 + 服务器校验 reveal"。
//   * 半诚实模型下第 1–3 层**永不触发**（诚实服务器总是自洽、诚实客户端总是对
//     自己的视角自洽），因此不影响诚实路径的数值语义与性能口径。
//
// ===========================================================================
// 4.7 代价
// ===========================================================================
//   * Phase2Request 多 16 字节（`e_check`）；Phase1Response 多 1 字节（`status`）。
//   * 客户端收尾多做 2 次 subMod + 1 次 addMod + 2 次 mulMod（常数时间）。
//   * **零**条新增消息、**零**次新增往返、服务器之间**零**通信。
//
// ===========================================================================
// 5. "服务器之间零通信"的证明方式（结构性 + 可断言）
// ===========================================================================
// **结构性论证**：服务器侧的一切逻辑都收在 `SecureMulServerState` 里。该类：
//   * 只持有本方的共享（⟨E⟩_p 与那份 triple 共享）、模数 q、本次会话的
//     challenge、第 1 轮收到的 d、以及一次性/阶段机标志；
//   * 唯一的输入是 `Phase1Request` / `Phase2Request` 的**反序列化副本**
//     （由 `DecodePhase1Request` / `DecodePhase2Request` 产生）；
//   * 唯一的输出是 `Phase1Response` / `Phase2Response`，由
//     `EncodePhase1Response` / `EncodePhase2Response` 编码后**交还给调用方**
//     （真实部署里是 gRPC 的应答，进程内是 `LocalTransport` 的 handler 返回值）；
//   * 类内**没有任何** `ITransportClient`、socket、文件、全局注册表或其他
//     `SecureMulServerState` 的引用，也没有静态可变状态 ⇒ **本实现里的服务器
//     没有任何可达另一台服务器的句柄**。
//     ⚠️ 但要把话说准：这是"**本实现如此**"，**不是类型系统强制的**。红队指出
//     `ServerHandler = std::function<Payload(const Payload&)>` 是不受限的可调用体，
//     进程内拓扑里 `LocalTransport` 更是"一个对象同时充当客户端与两台服务器"，
//     因此**没有任何类型层面的东西**阻止某个 handler 去捕获 transport、另一台的
//     state 或一个全局变量（他们用 `[Part D]` 演示了 handler → handler 的直接调用）。
//     本模块的两个 handler 只捕获各自的 `SecureMulServerState&`（见
//     `RegisterSecureMulServers`），所以现状是干净的；但若要**强制**这一点，
//     需要改 `net/transport.hpp` 的 handler 签名（例如只传 `const Payload&` 并禁止
//     捕获）—— 那超出本任务的文件边界，留给后续裁决。
//     不变量终究是"**运行期用计数断言可验证**"的，而不是"编译期免费的"。
//
// ⚠️ **口径收窄（v3，对抗性验证 D6）**：上面证明的是"**没有直连信道、没有额外
//    消息、没有第三端点**"，**不是**"服务器之间无法传递信息"。事实上协议强制的
//    `e` 中转本身就是一条 **可用、无噪、双向、约 127 bit/记录**的隐信道：
//    S0 把自己第 1 轮自报的 ⟨e⟩_0 直接设成载荷 v，客户端按协议算出
//    `e = v + ⟨e⟩_1` 并中转给两台，S1 用 `e − ⟨e⟩_1 = v` 逐位还原。
//    该隐信道的**使用前提是两台共谋**（互相约定"自报值即载荷"），而
//    `MPARQ.tex:150` 明确假设 "The two servers do not collude" 并把共谋排除
//    ⇒ 危害有界。单台恶意时对端无法区分"消息"与"诚实随机份额"。
//    如实写在这里，避免以后有人把"零通信"当成"无隐信道"来做安全论证。
//   客户端侧只经由 `ITransportClient::Submit(server_id, payload)` 与各服务器
//   通信，而客户端唯一的"转发"动作是把轮 1 收到的两个 `⟨e⟩_p` 相加得到 e
//   再下发给两台（协议规定的中转），不会原样转发任何服务器的整条消息。
//   （客户端确实会把每台自己的 `⟨e⟩_p` 作为 `e_check` 分别回给对应服务器，
//     这是协议规定的回执，不是服务器间通信。）
//
// **可断言的证据**（`tests/test_mpraq_securemul.cpp`）：
//   * `CountingTransport`：包装 `ITransportClient`，按 server_id 统计并记录
//     每一条**真正上链**的请求字节，同时统计"非 0/1 的 server_id"调用次数
//     （服务器之间若存在通路，只可能表现为对第三个端点的寻址或对
//     `LocalTransport` 的越界 Submit）。
//   * 断言 `ThirdPartyCount() == 0`、`SubmitCount(0) + SubmitCount(1) == 总消息数`
//     （没有第三个端点、也没有匿名去向），且每台服务器**恰好**收到两条消息、
//     其序列严格等于协议规定的 `[Phase1Request, Phase2Request]`
//     —— 不存在"多出来的消息"充当服务器间信道。
//   * 由于 `LocalTransport::SetHandler` 的 handler 只接收 `(server_id, request)`
//     且返回值即应答，测试里两台服务器的 handler 之间**没有共享变量**
//     （除只读常量外），篡改用例也各自独立注入 ⇒ 不存在隐藏旁路。
//
// ===========================================================================
// 6. 与上层 MPA-06（Sum / Avg）的接法 + **施工要点**（会直接决定 MPA-06 的实现）
// ===========================================================================
// MPA-06 的 Sum = 论文 AggQuery 的 `result ← Σ_{i=1..N} z_i`，每条记录一次 SecureMul。
//
// ---------------------------------------------------------------------------
// 6.1 ⚠️ 批量必须由 MPA-06 **自建一层**（本模块不提供批量帧）
// ---------------------------------------------------------------------------
// 事实（对抗性验证已实测）：本模块是**严格逐记录**的 ——
//   * `ClientRunPhase1/2` 硬断言"恰好 2 条应答"（`EvaluateCollect`），逐记录 = `2N` 往返；
//   * `RegisterSecureMulServers` 每台服务器只挂**一个** state；
//   * 线格式是单记录定长（34/27/58/43 B），解码器 `RequireSize` 严格校验，**没有**
//     count/数组/前缀，也没有 record index（只有 `session`/`challenge`）；
//   * 每条记录的 state 一次性（`Stage::kConsumed`），批量必须**预装 2N 个 state**
//     并在两轮之间保活；每台 ≈ `N × (7×16 B triple + 16 B ⟨E⟩)` 常驻。
// ⇒ 要达到 `MPRAQ_IMPL.md:82-85` 的"2 个往返处理整列"，MPA-06 必须自己加一层：
//   自定义批量帧 + 自建 `(session → state)` 分派表 + 自己的 fan-out/收集，
//   **复用本模块的编解码与 `SecureMulServerState` 语义**，不要把逐记录循环当批量用。
//   （红队原型 `red_main batch 512` 已证明该做法可行：512 条 = 2 往返 / 2048 条消息。）
//
// ---------------------------------------------------------------------------
// 6.2 校验必须**逐记录**，绝不能"整列一次校验"
// ---------------------------------------------------------------------------
// `Σ mac == α·Σ z` 恰恰是恶意服务器能保持的不变量（§4.5 的所有一致偏移都满足它）
// ⇒ 整列一次校验会**静默接受被污染的整列**。必须对每条记录单独调
// `VerifyAndReconstruct`，并用它的 `ok` 逐条把关。
//
// ---------------------------------------------------------------------------
// 6.3 失败时 `r.z` 里可能仍是**错值** ⇒ 不可累加
// ---------------------------------------------------------------------------
// `VerifyAndReconstruct` 在 **MAC 失败**时仍会把重建值写进 `r.z`（值是对的但与 MAC
// 不匹配），而 `status != kOk` 时 `z` 保持 0。因此：
//     if (!r.ok) abort;              // 论文口径：`If z_i = null → abort`
//     sum = addMod(sum, r.z, q);     // 只在 ok 为真时才累加
// `SecureMulFlowResult::failure` 给出**结构化**的失败分类（`SecureMulFailure`），
// MPA-06/MPA-07 请用它分类，**不要**用 `error.find("MAC")` 之类的字符串匹配
// （v2 的 e 检查报错文本里也含 "MAC"，会把两类失败混为一谈，对抗性验证 D4）。
//
// ---------------------------------------------------------------------------
// 6.4 不要剪枝 `f = 0`
// ---------------------------------------------------------------------------
// 论文 `:555-556` 是**无条件** `For i = 1..N`。若按 `filter[i] == 0` 跳过，则
// "消息条数/会话号"会泄露 **COUNT**（服务器能从"发了几条 SecureMul"数出命中数）。
// 要常量模式就整列都发（f=0 时 z=0 是正确的、经 MAC 认证的结果）。
//
// ---------------------------------------------------------------------------
// 6.5 会话与挑战
// ---------------------------------------------------------------------------
//   * 每条记录一个**非零** `session`（`session = 0` 曾与"未初始化"混淆，v3 起
//     阶段机已修，但仍建议避开 0 以免与诊断口径混淆）；
//   * `challenge` 用**每次查询都换的随机盐**（`MakeChallenge(record_index, salt)`）。
//     ⚠️ v2 的示例用常量盐 ⇒ challenge 与查询无关 ⇒ 跨查询重放可行；v3 已把
//     "challenge 必须安装"变成硬错误，但**盐的随机性仍由调用方负责**。
//
// ---------------------------------------------------------------------------
// 6.6 α 全局一份
// ---------------------------------------------------------------------------
// 只在 Init 生成一次（`SecureMulClientState::GenerateMacKey(q)`），所有记录复用；
// 每条记录下发的 `⟨α⟩_p` 必须逐位一致（见用例 `GlobalAlphaIsReusedAcrossRecords`）。
//
// ---------------------------------------------------------------------------
// 6.7 最小示例（**逐记录**版本；批量版按 6.1 自建）
// ---------------------------------------------------------------------------
//     // ---- Init（一次性）----
//     SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
//     LocalTransport net(2);                 // 真实部署换 gRPC 客户端
//
//     // ---- 每条记录（在线）----
//     uint128_t sum = 0;
//     for (size_t i = 0; i < N; ++i) {       // 注意 6.4：**整列都发**，不剪枝
//         const uint64_t challenge = MakeChallenge(i, session_salt);
//         auto material = GenerateBeaverTriple(client.keys(), kQ, prng);   // Q2(a)
//         auto shares   = ShareMod(E[i], kQ);                              // ⟨E_i⟩
//         const auto bundle = MakeSetupsAndContext(i, material, shares, challenge);
//         SecureMulServerState s0 = MakeServerState(bundle.server0, kQ);
//         SecureMulServerState s1 = MakeServerState(bundle.server1, kQ);
//         RegisterSecureMulServers(net, s0, s1);
//         const auto r = SecureMulFlowRunRecord(/*session=*/1000 + i, challenge,
//                                               filter[i], material.client_triple,
//                                               net, client, &bundle.ctx);
//         if (!r.ok) throw std::runtime_error("SecureMul 校验失败：abort 当前查询");
//         sum = addMod(sum, r.z, kQ);
//     }
//     // Avg = sum / Count（Count 由 MPA-04 对 filter 直接计数，不走 SecureMul）
//
// ⚠️ `bundle.ctx` **必须**传（它承载 §4.5-A/B 两条纯客户端复核所需的
//    ⟨E⟩_p 与 ⟨b⟩_p）；不传等于退回 v2 的"只有 MAC"，会接受一致偏移的错值。
//    Q2(b) 的离线批量预生成只需把 `GenerateBeaverTriple` 挪到离线循环、
//    结果存进 `std::vector<SecureMulTripleMaterial>`，在线按 `i` 取用即可。
//
// ===========================================================================
// 7. 记录：FND-13 对 D14 的记账
// ===========================================================================
// TASK_PLAN 决策 D14 的描述（"论文末项**多乘了一个** 2^{-1}"）在字面上与
// Algorithm 5 不符：论文的 z 与 mac 末项**都**带 2^{-1}（见 (P-z)/(P-mac)）。
// 复核后确认 D14 的**结论**（MAC 末项不应带 2^{-1}）是对的，但**理由**要按
// 本文件 §2 的推导来理解——关键是"z 侧的 2^{-1} 由两台服务器各贡献一次而抵消"，
// 而不是"论文在 mac 末项多乘了一个"。修复只落在 mac 末项（`shared/mpc.cpp:110-123`），
// **不能**顺手把 z 末项的 2^{-1} 也去掉（那样 z 会变成 f·E + d·e，恒错）。
// 本模块不重复该修复逻辑，只调用 `shared/mpc` 并在此固化推导，防止反复。

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "core/aes_prf.hpp"
#include "core/field.hpp"
#include "core/random.hpp"
#include "net/transport.hpp"
#include "mpraq/security_mode.hpp"
#include "shared/mpc.hpp"
#include "shared/secret_sharing.hpp"
#include "shared/verify.hpp"

namespace tsb {
namespace mpraq {

// ---------------------------------------------------------------------------
// 常量与消息格式
// ---------------------------------------------------------------------------

// MPRAQ 的 SecureMul 模数：q = 2^127 − 1（梅森素数，奇）。
// 见 TASK_PLAN §7.6 Q1 的裁决 (b) 与决策 D11。
inline constexpr uint128_t kSecureMulModulus = (static_cast<uint128_t>(1) << 127) - 1;

// 消息编码的版本号（首字节）。编解码不匹配时**显式报错**而不是静默按旧布局解析。
//   v1：无任何本地校验（论文 Algorithm 5 的原样）
//   v2：第 1 轮应答带回服务器自算的 ⟨e⟩_p，第 2 轮请求带回 e 的校验值
//       （服务器侧加固）
//   v3：新增**纯客户端**校验所需的上下文（`SecureMulRecordContext`），
//       并把服务器侧的实例状态机补严（阶段判定 / 一次性语义）
inline constexpr uint8_t kSecureMulWireVersion = 3;

// 第 2 轮响应里的校验状态码（服务器自报是否通过 e 一致性检查）
enum class SecureMulStatus : uint8_t {
    kOk = 0,            // 一切正常
    kECheckFailed = 1,  // 收到的 e 与第 1 轮的 ⟨e⟩_p 回执不一致（见 §4.5）
    kDCheckFailed = 2,  // 第 2 轮的 d 与第 1 轮收到的不同（见 §4.5 末段）
    kPhaseError = 3,    // 阶段错误：状态已被消费 / 第 2 轮先到 / 未安装依赖
                        // （⚠️ 与 std::invalid_argument 的区别：本状态是"实例
                        //   状态机拒绝"，异常用于"调用方用错了 API"）
};

// 每台服务器在本模块中的逻辑编号（与 net/transport 的 server_id 一致）
inline constexpr int kServer0 = 0;
inline constexpr int kServer1 = 1;

// 消息类型标签（wire 上第 2 个字节）
enum class SecureMulMsgType : uint8_t {
    kPhase1Request = 1,
    kPhase1Response = 2,
    kPhase2Request = 3,
    kPhase2Response = 4,
};

// 设计说明：消息**不用** proto，而是"1 字节版本 + 1 字节类型 + 固定长度小端字段"。
// 原因是字段固定且很小（最多 5×16 B），手写编解码比引入 proto 更省事、更可控，
// 也让测试可以直接对字节做定点篡改（见测试的 `Tamper` 工具）。

// ---------------------------------------------------------------------------
// 1) 客户端 → 服务器：第 1 轮
// ---------------------------------------------------------------------------
struct Phase1Request {
    uint64_t session = 0;    // 一次 SecureMul 的会话号（防重放/乱序；测试可断言）
    uint64_t challenge = 0;  // 与安装状态时约定的挑战值绑定（§4）
    uint128_t d = 0;         // d = f − a mod q（掩码后的一次性随机量）

    // 便于测试与日志的相等比较（不参与协议语义）
    bool operator==(const Phase1Request& o) const {
        return session == o.session && challenge == o.challenge && d == o.d;
    }
};

// ---------------------------------------------------------------------------
// 2) 服务器 → 客户端：第 1 轮
// ---------------------------------------------------------------------------
struct Phase1Response {
    uint64_t session = 0;
    // ⟨e⟩_p = ⟨E⟩_p − ⟨b⟩_p，由**本服务器自己**按协议算出（不是从消息里拿到的）。
    // 名字从 v1 的 e_share 改为 e_computed，强调它是"本方的计算值"，
    // 因为 §4.5 的一致性检查正是拿它与客户端的 e 比对。
    uint128_t e_computed = 0;
    // 服务器自报状态（v3 新增）。第 1 轮也会拒绝消息（重复/跨会话重放/challenge
    // 不符），这些拒绝必须能**结构化**地表达给客户端，所以第 1 轮应答也带 status。
    uint8_t status = 0;  // SecureMulStatus::kOk == 0

    bool operator==(const Phase1Response& o) const {
        return session == o.session && e_computed == o.e_computed &&
               status == o.status;
    }
};

// ---------------------------------------------------------------------------
// 3) 客户端 → 服务器：第 2 轮（客户端中转 e = ⟨e⟩_0 + ⟨e⟩_1）
// ---------------------------------------------------------------------------
// ⚠️ `d` 要在第 2 轮**重发**一次。论文把 d 与 e 都作为服务器第二阶段的输入
//    （z_p 的公式里同时出现 d 与 e），但 d 在第 1 轮已经发过：真实部署里服务器
//    当然可以把 d 暂存在会话状态里（省 16 字节），本实现选择**随请求重发**，
//    让 `RunPhase2` 保持无隐藏状态、便于对消息做独立篡改注入与重放测试。
//    两种做法在安全性上没有差别（d 本来就是下发给服务器的量）。
struct Phase2Request {
    uint64_t session = 0;
    uint128_t d = 0;        // d = f − a mod q（与第 1 轮相同）
    uint128_t e = 0;        // e = ⟨e⟩_0 + ⟨e⟩_1 mod q（客户端中转）
    // ⚠️ §4.5 的一致性检查：本服务器在第 1 轮自算出的 ⟨e⟩_p。
    //    服务器要求 `e − e_computed ⊕ …`（见 SecureMulServerState::RunPhase2）
    //    与自己第 1 轮报出的值相符，否则说明中转的 e 被篡改过，直接拒绝。
    uint128_t e_check = 0;

    bool operator==(const Phase2Request& o) const {
        return session == o.session && d == o.d && e == o.e &&
               e_check == o.e_check;
    }
};

// ---------------------------------------------------------------------------
// 4) 服务器 → 客户端：第 2 轮
// ---------------------------------------------------------------------------
struct Phase2Response {
    uint64_t session = 0;
    uint128_t z_share = 0;    // z_p
    uint128_t mac_share = 0;  // mac_p
    // 服务器自报的校验状态（§4.5）。kOk 之外的状态意味着这台服务器拒绝继续，
    // 客户端必须 abort；此时 z_share/mac_share 无意义。
    uint8_t status = static_cast<uint8_t>(SecureMulStatus::kOk);

    bool operator==(const Phase2Response& o) const {
        return session == o.session && z_share == o.z_share &&
               mac_share == o.mac_share && status == o.status;
    }
};

// ---------------------------------------------------------------------------
// 编解码（全部显式小端；长度不符/版本不符/类型不符一律抛 std::invalid_argument）
// ---------------------------------------------------------------------------

Payload EncodePhase1Request(const Phase1Request& m);
Payload EncodePhase1Response(const Phase1Response& m);
Payload EncodePhase2Request(const Phase2Request& m);
Payload EncodePhase2Response(const Phase2Response& m);

Phase1Request DecodePhase1Request(const Payload& p);
Phase1Response DecodePhase1Response(const Payload& p);
Phase2Request DecodePhase2Request(const Payload& p);
Phase2Response DecodePhase2Response(const Payload& p);

// ---------------------------------------------------------------------------
// ⚠️ §4.5-A / §4.5-B：**纯客户端**的两条复核所需的上下文（v3 新增）
// ---------------------------------------------------------------------------
// 这是本模块对论文最重要的加固，也是与"服务器自报检查"的本质区别：
// 两条判据**全部由客户端独立计算**，被检查方的自报值不参与判据。
//
//   * 复核 A（检出 `d`/`e` 的"一致偏移"类攻击）：客户端自己就能算出属性值
//         E_local = e_sent + b        （e_sent 是它自己中转的值、b 是它生成的 triple 分量）
//     于是要求 `z == f · E_local`。任何让两台服务器一致使用偏移后 `d`/`e` 的
//     攻击都会破坏这个等式（`z' = z + Δ·f` 或 `z + δ·f`），当场被检出。
//     ⚠️ **前提**：triple 由客户端自己生成（本模块 API 即如此）。若将来把 triple
//        生成移到第三方 dealer、客户端不再知道 `b`，本条复核失效，`d` 偏移重新
//        变成不可检出（此时才需要承诺机制）。
//
//   * 复核 B（检出单台谎报 `⟨e⟩_p`）：客户端在 Init 阶段**自己安装**了两台的
//     ⟨E⟩_p 与 ⟨b⟩_p，因此可以复核 `Phase1Response.e_computed == ⟨E⟩_p − ⟨b⟩_p`。
//     这条不依赖 triple 的生成方，只要客户端知道它安装了什么就成立。
//     ⚠️ 每条记录下发给两台服务器的 `e_check` 必须**逐位等于客户端当场收到的
//        回执**；否则"谎报的那台"的身份会被掩盖（红队 E2 的攻击正是靠客户端
//        原样回显）。
struct SecureMulServerVerifyContext {
    ModShare attribute_share{};  // ⟨E⟩_p（Init 阶段由客户端安装的那一份）
    ModShare b_share{};          // ⟨b⟩_p（客户端为该记录生成的 triple 分量的共享）
};

struct SecureMulRecordContext {
    SecureMulServerVerifyContext server0{};
    SecureMulServerVerifyContext server1{};
};

// ---------------------------------------------------------------------------
// 服务器侧状态（Init 阶段由客户端安装；**只含本方信息**）
// ---------------------------------------------------------------------------

// 一条记录的 SecureMul 在**某一台**服务器上所需的全部静态材料。
//
// ⚠️ 注意这里**没有** α 本身（只有 ⟨α⟩），也**没有**另一台服务器的任何共享。
//    该类的构造函数与成员函数都不接受、也不持有任何通信对象，因此
//    "服务器之间零通信"是类型层面的结论，而不是靠自觉遵守纪律。
class SecureMulServerState {
public:
    // record_index 仅用于日志/诊断；q 必须为奇数（D11）。
    SecureMulServerState(uint64_t record_index, const TripleShare& triple,
                         uint128_t q);

    uint64_t record_index() const { return record_index_; }
    uint128_t modulus() const { return q_; }

    // ---- Init 阶段：安装 ⟨E⟩_p（属性值的加法共享）----
    // 必须在第一次 RunPhase1 之前调用；重复安装抛 std::logic_error。
    void InstallAttributeShare(const ModShare& e_share);

    // ---- Init 阶段：安装本次会话的挑战值（防重放/防乱序的锚点）----
    void InstallChallenge(uint64_t challenge);

    // ---- 在线阶段 ----
    // 第 1 阶段：校验会话/挑战（乱序、重复、跨会话重放一律抛
    // `std::invalid_argument`），按 `SecureMulServerPhase1` 算 ⟨e⟩_p。
    Phase1Response RunPhase1(const Phase1Request& req);

    // 第 2 阶段：按 `SecureMulServerPhase2` 算 (z_p, mac_p)。
    // 必须先成功跑过 RunPhase1（否则抛 std::logic_error）。
    //
    // ⚠️ 算之前先做 §4.5 的 **e 一致性检查**：
    //    * `req.e_check` 必须逐位等于本方第 1 轮报出的 ⟨e⟩_p；
    //    * `req.e` 必须与 `req.e_check` 不同（相等意味着另一端贡献为 0，
    //      概率 1/q；按拒绝处理，避免"两台都被改成同一个值"这种退化绕过）。
    //    任一不满足 ⇒ **不计算**，直接返回 `SecureMulStatus::kECheckFailed`
    //    的响应（z_share / mac_share 保持 0，客户端必须 abort）。
    //    ⚠️ 这是本模块对论文的**加固**，不是论文原有的步骤（见 §4.5）。
    Phase2Response RunPhase2(const Phase2Request& req);

    // 本服务器第 1 轮报出的 ⟨e⟩_p（供客户端构造 Phase2Request::e_check）。
    // 尚未跑过第 1 轮时抛 std::logic_error。
    const ModShare& computed_e_share() const;

    // 供测试与诊断：本方持有的 ⟨E⟩_p / 状态机阶段
    const ModShare& attribute_share() const { return attribute_share_; }
    bool consumed() const { return stage_ == Stage::kConsumed; }
    bool challenge_installed() const { return challenge_installed_; }
    bool phase1_ran() const { return e_computed_; }

private:
    uint64_t record_index_ = 0;
    uint128_t q_ = kSecureMulModulus;
    TripleShare triple_{};
    ModShare attribute_share_{};
    bool attribute_installed_ = false;
    bool challenge_installed_ = false;
    uint64_t challenge_ = 0;
    // 阶段机：kFresh →（RunPhase1 成功）→ kPhase1Done →（RunPhase2）→ kConsumed。
    // ⚠️ 用显式枚举而不是"session==0 表示没跑过"：后者会让 session=0 的第 2 轮
    //    请求绕过阶段判定（对抗性验证 D1）。
    enum class Stage : uint8_t { kFresh, kPhase1Done, kConsumed };
    Stage stage_ = Stage::kFresh;
    uint64_t last_session_ = 0;
    uint128_t phase1_d_ = 0;  // 第 1 轮收到的 d（第 2 轮跨轮一致性检查用）
    bool e_computed_ = false;
    ModShare e_computed_share_{};  // 本方第 1 轮报出的 ⟨e⟩_p（§4.5 的比对基准）
};

// ---------------------------------------------------------------------------
// 客户端侧状态（Init 阶段由客户端生成并长期持有）
// ---------------------------------------------------------------------------

// 客户端在 `Init` 阶段生成、**全局一份**的材料（TASK_PLAN §7.6 Q3(a)）：
//   * α 与它的两份分享（α 本地保存，⟨α⟩_p 分发给服务器）；
//   * 模数 q。
// 每个查询、每条记录都复用同一个 α —— 这正是 SPDZ 的要求。
class SecureMulClientState {
public:
    // 生成全局 MAC 密钥（内部调用 tsb::GenerateMacKey(2, q)，双服务器）。
    // q 必须为奇数（否则抛 std::invalid_argument）。
    static SecureMulClientState GenerateMacKey(uint128_t q);

    // 由已有密钥构造（用于测试固定 α 的场景；α=0 抛 std::invalid_argument）。
    SecureMulClientState(uint128_t alpha, std::vector<uint128_t> alpha_shares,
                         uint128_t q);

    // 由 MacKeyShares 构造（要求恰好 2 份 ⟨α⟩，且两份之和 == α）。
    // 便于测试直接复用 shared/verify 的 GenerateMacKey 产物。
    //
    // ⚠️ **档位必须显式传入**（没有默认值）：忘记传 = **编译错误**。
    //    给默认值会让"忘了设"静默变成某一档 —— 若静默变成半诚实档就是**静默降级安全性**，
    //    正是本仓库最忌讳的失败模式。判定结果见 `security_mode()`。
    SecureMulClientState(MacKeyShares keys, uint128_t q, MpraqSecurityMode mode);

    uint128_t alpha() const { return keys_.alpha; }
    // 运行方式（安全档位）。**半诚实档下 `VerifyAndReconstruct` 不做任何验证**
    // （跳过 SPDZ MAC 与 §4.5-A/B）—— 这是如实声明的边界，不是缺陷。
    MpraqSecurityMode security_mode() const { return security_mode_; }
    const MacKeyShares& keys() const { return keys_; }
    uint128_t modulus() const { return q_; }

    // ⟨α⟩_p（供安装到服务器；越界抛 std::out_of_range）
    const ModShare& AlphaShare(int server_id) const;

private:
    MacKeyShares keys_{};
    uint128_t q_ = kSecureMulModulus;
    // 默认恶意档（**安全侧**）：即使某条路径漏设，也是"多校验"而不是"少校验"。
    // 生产路径由构造函数**强制**显式给出（见上面的 ⚠️）。
    MpraqSecurityMode security_mode_ = kDefaultMpraqSecurityMode;
    // AlphaShare() 返回引用的落点（ModShare 是 POD，这里只是让返回类型
    // 保持 const ModShare& 而不必对外暴露裸 uint128_t）
    mutable std::array<ModShare, 2> alpha_share_cache_{};
};

// 一个 Beaver triple 的**客户端本地**视图（a、b、c 明文）+ 两台服务器的共享。
//
// Q2 裁决 (a)"每查询现生成"：调用 `GenerateBeaverTriple` 即可。
// 为将来"离线批量预生成"（Q2 (b) / 决策 D10）预留：把它放进一个
// `std::vector<SecureMulTripleMaterial>` 里循环消费即可，本模块的在线接口
// 只认"一条材料"，不关心它是现生成还是预先批量生成的。
struct SecureMulTripleMaterial {
    tsb::BeaverTriple client_triple{};  // a、b、c（客户端本地，绝不下发）
    TripleShare server0{};              // S_0 的 ⟨a⟩,⟨b⟩,⟨c⟩,⟨αa⟩,⟨αb⟩,⟨αc⟩,⟨α⟩
    TripleShare server1{};              // S_1 同上
};

// 消费型来源：为第 record_index 条记录产出 triple 材料。
// 主路径是 `GenerateBeaverTriple(keys, q, prng)`（每查询现生成）；
// 预生成路径只需在外部把预先算好的材料按 record_index 返回。
using SecureMulTripleSource =
    std::function<SecureMulTripleMaterial(uint64_t record_index)>;

// **生产路径**：用系统 CSPRNG 生成一个 triple 及其在两台服务器上的共享。
// ⚠️ α 的分享取自 `keys`（全局一份），绝不在此重新生成 α。
SecureMulTripleMaterial GenerateBeaverTriple(const MacKeyShares& keys, uint128_t q);

// **确定性路径**（测试与可复现实验用，兼作"离线批量预生成"的入口）：
// 全部随机量都取自传入的 `prng`，因此同一种子下逐位可复现。
// 与 `tsb::GenerateTripleShares` 的唯一区别就是随机源可控；
// 掩码独立性等安全性质保持一致（每个共享分量都用**独立的** PRNG 输出）。
SecureMulTripleMaterial GenerateBeaverTriple(const MacKeyShares& keys, uint128_t q,
                                             random::DeterministicPrng& prng);

// 把 (种子, 记录号) 展开成 DeterministicPrng 的密钥/随机数种子（便于测试复现）。
std::array<uint8_t, kAesKeyBytes> MakeAesSeed(std::vector<uint8_t> seed_bytes);

// ---------------------------------------------------------------------------
// Init 阶段的安装
// ---------------------------------------------------------------------------

// 服务器在一次会话中需要知道的一切（都来自客户端，**不来自另一台服务器**）。
struct SecureMulServerSetup {
    uint64_t record_index = 0;
    TripleShare triple{};  // 本方的那一份
    ModShare e_share{};    // ⟨E⟩_p
    uint64_t challenge = 0;
};

// 为两台服务器分别产出安装信息（客户端在 Init / 每次预处理时调用）。
// 返回 (setup_for_server0, setup_for_server1)。
std::pair<SecureMulServerSetup, SecureMulServerSetup> MakeServerSetups(
    uint64_t record_index, const SecureMulTripleMaterial& material,
    const std::pair<ModShare, ModShare>& attribute_shares, uint64_t challenge);

// **v3 推荐入口**：一次拿到"服务器安装信息" + "客户端复核上下文"。
//   * `SetupsAndContext` 返回 {setups, ctx}；ctx 里带上客户端安装的
//     ⟨E⟩_p 与 ⟨b⟩_p，供 `VerifyAndReconstruct` 执行 §4.5-A/B 两条纯客户端复核。
//   * `...FromPrng` 版本连 ⟨E⟩ 的共享掩码都走确定性源 ⇒ **整条 transcript 逐位
//     可复现**（含线上全部字节），用于可复现实验与"同种子逐位一致"的强口径测试。
// ⚠️ 生产路径请用第一个（`ShareMod` = 系统 CSPRNG）。
struct SecureMulSetupBundle {
    SecureMulServerSetup server0{};
    SecureMulServerSetup server1{};
    SecureMulRecordContext ctx{};
};

SecureMulSetupBundle MakeSetupsAndContext(
    uint64_t record_index, const SecureMulTripleMaterial& material,
    const std::pair<ModShare, ModShare>& attribute_shares, uint64_t challenge);

SecureMulSetupBundle MakeSetupsAndContextFromPrng(
    uint64_t record_index, const SecureMulTripleMaterial& material, uint128_t e_value,
    uint64_t challenge, uint128_t q, random::DeterministicPrng& prng);

// 便捷：直接构造服务器状态（Init 阶段用）。
SecureMulServerState MakeServerState(const SecureMulServerSetup& setup, uint128_t q);

// **逐位确定性**的 ⟨E⟩ 安装（v3 新增，供"整条 transcript 可复现"的测试与实验用）。
// 与 `ShareMod` 的唯一区别是掩码取自调用方给的确定性源；语义完全一致
// （⟨E⟩_0 + ⟨E⟩_1 ≡ E mod q，掩码独立均匀）。
// ⚠️ 生产路径用 `ShareMod`（系统 CSPRNG）；本函数只用于可复现实验。
std::pair<ModShare, ModShare> ShareValueDeterministic(uint128_t value, uint128_t q,
                                                      random::DeterministicPrng& prng);

// 挑战值：由记录号与一个随机盐派生，保证同一记录的不同会话挑战不同。
uint64_t MakeChallenge(uint64_t record_index, const std::vector<uint8_t>& salt);

// ---------------------------------------------------------------------------
// 在线阶段
// ---------------------------------------------------------------------------

// 客户端第 1 轮的产物：两台的应答 + **本轮实际使用的 d**。
//
// ⚠️ `d` 必须由此处带出，不能在别处用 `f − a` 重新算一遍：
//    第 2 轮的 d 必须与第 1 轮**下发的那个**逐位相同，否则两台服务器会用
//    两个不同的 d（第 1 轮收到一个、第 2 轮用另一个），那是一个真实的协议错
//    误（会让"篡改第 1 轮 d"这类注入被静默忽略，FND 阶段实测踩到过）。
struct SecureMulPhase1Out {
    Phase1Response server0{};
    Phase1Response server1{};
    uint128_t d = 0;  // 本轮下发给两台服务器的 d = f − a mod q
    // 本轮**实际下发**给各服务器的 e_check（= 客户端收到的该台回执，逐位原样）。
    // §4.5-B 的纯客户端复核要用它来判断"某台是否谎报了自己的 ⟨e⟩_p"。
    uint128_t e_check_sent0 = 0;
    uint128_t e_check_sent1 = 0;
    // 客户端在本轮**实际中转**出去的 e（= 两台回执之和）。
    // §4.5-A 的纯客户端复核要用它算 `E_local = e + b`。
    uint128_t e_sent = 0;
};

// 客户端收尾的结果。
//
// ⚠️ 失败时的语义（与论文、与 TASK_PLAN §6 的"不允许可区分的失败路径"一致）：
//    **要么 ok=true 且 z 是正确且经 MAC 认证的乘积，要么 ok=false 且必须 abort**。
//    绝不存在"ok=true 但值可能被污染"的第三种状态。
// 失败原因的分类（**结构化**，不靠错误字符串；v3 新增）。
// ⚠️ 测试与 MPA-06 必须用它分类，不要用 `error.find("MAC")` 之类的字符串匹配：
//    v2 的 e 检查报错文本里也含 "MAC" 字样，会把两类失败混为一谈（对抗性验证 D4）。
enum class SecureMulFailure : uint8_t {
    kNone = 0,                 // ok = true
    kSessionMismatch = 1,      // 应答 session 与请求不一致
    kServerReported = 2,       // 服务器自报 status ≠ kOk（拒绝服务/阶段错误/自证检查）
    kEShareMismatch = 3,       // §4.5-B：某台谎报 ⟨e⟩_p（纯客户端复核检出）
    kClientLocalCheckFailed = 4,  // §4.5-A：z ≠ f·(e_sent + b)（纯客户端复核检出）
    kMacMismatch = 5,          // SPDZ MAC 失败
};

struct SecureMulFlowResult {
    bool ok = false;             // MAC 校验是否通过（通过才可采信 z）
    SecureMulFailure failure = SecureMulFailure::kNone;  // 失败分类（见上）
    uint128_t z = 0;             // 重建出的乘积（仅在 ok=true 时有意义）
    uint128_t mac = 0;           // 重建出的 MAC（诊断用）
    uint128_t expected_mac = 0;  // α·z（诊断用）
    std::string error;           // 失败原因（ok=true 时为空）
};

// 客户端第 1 轮：算 d = f − a，向两台服务器各发一条 Phase1Request，
// 收到两条 Phase1Response 后校验 session 一致并返回。
// `transport` 为 nullptr、f 越界、应答缺失/错误一律抛异常。
SecureMulPhase1Out ClientRunPhase1(uint64_t session, uint64_t challenge,
                                   uint128_t f, const tsb::BeaverTriple& triple,
                                   ITransportClient& transport, uint128_t q);

// 服务器第 1 轮：解码请求 → `SecureMulServerState::RunPhase1` → 编码应答。
// 这个函数就是 `LocalTransport::SetHandler` / gRPC 服务端的 handler 本体：
// **它的参数只有客户端递来的字节**，没有别的服务器。
Payload ServerHandlePhase1(SecureMulServerState& state, const Payload& request);

// 客户端第 2 轮：e = ⟨e⟩_0 + ⟨e⟩_1，向两台服务器各发一条 Phase2Request，
// 收到两条 Phase2Response 后返回。
// ⚠️ 会把两台服务器在第 1 轮各自报出的 ⟨e⟩_p 作为 `Phase2Request::e_check`
//    带回给**对应的**服务器（§4.5）。因此每台收到的 e_check 都是它自己那一份。
std::pair<Phase2Response, Phase2Response> ClientRunPhase2(
    uint64_t session, const SecureMulPhase1Out& phase1, ITransportClient& transport,
    uint128_t q);

Payload ServerHandlePhase2(SecureMulServerState& state, const Payload& request);

// 客户端收尾：z = z_0 + z_1、mac = mac_0 + mac_1，校验 mac == α·z。
// ⚠️ 这里就是 §2 的公式检查点；`error` 会区分两类失败：
//    * "MAC 校验失败" —— 值重建出来了但与 α·z 不符（服务器篡改 / 共享不一致）；
//    * "服务器返回错误" / "会话不一致" —— 传输或协议层失败（必须 abort）。
// `ctx` 非空时执行 §4.5-A/B 两条**纯客户端**复核（v3）；为空时退化为 v2 行为
// （只做 status 检查 + SPDZ MAC）。生产路径一律应传 ctx。
SecureMulFlowResult VerifyAndReconstruct(
    uint64_t session, const std::pair<Phase2Response, Phase2Response>& phase2,
    const SecureMulClientState& client,
    const SecureMulRecordContext* ctx = nullptr,
    uint128_t f = 0, uint128_t e_sent = 0, const tsb::BeaverTriple* triple = nullptr,
    uint128_t phase1_e_check0 = 0, uint128_t phase1_e_check1 = 0);

// 单台响应里的校验状态 → 是否可接受（供上层复用；不可接受时 error 给出原因）
bool SecureMulStatusIsOk(uint8_t status, std::string* error);

// 端到端便捷驱动（**半诚实路径**）：一条记录一次完整的两阶段消息流。
//
// ⚠️ 本函数**只走 transport**，不接触 `SecureMulServerState` 对象 —— 服务器状态
//    由调用方通过 `RegisterSecureMulServers` 挂在 `ITransportServer` 上。
//    这既是接口洁癖，也是"客户端无法直接观测服务器内部"的结构性保证。
//    ⚠️ 传进来的 transport 必须真的连到两台服务器（进程内用 LocalTransport(2)）；
//       应答数量不符时本函数会抛异常，不会静默降级。
SecureMulFlowResult SecureMulFlowRunRecord(
    uint64_t session, uint64_t challenge, uint128_t f,
    const tsb::BeaverTriple& triple, ITransportClient& transport,
    const SecureMulClientState& client, const SecureMulRecordContext* ctx = nullptr);

// 服务器 handler 的注册辅助：把两台服务器的处理函数挂到 `ITransportServer` 上。
// 注意：两个 handler 之间**不共享任何可变状态**（只有各自的 state 引用），
// 这正是"服务器之间零通信"在代码层面的体现。
void RegisterSecureMulServers(ITransportServer& server, SecureMulServerState& s0,
                              SecureMulServerState& s1);

}  // namespace mpraq
}  // namespace tsb
