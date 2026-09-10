#pragma once

// MPRAQ 的**验证边界**（任务 `MPA-07`）—— 把"本系统实际具备的验证能力"
// 固化成**可执行、可断言、可审计**的代码，而不是散落在文档里的散文。
//
// ===========================================================================
// 0. 为什么要有这个文件（它解决的是"口径漂移"而不是密码学）
// ===========================================================================
// 论文 `doc/paper/MPARQ.tex:452` 声称 "The protocol ensures that **any** tampering
// with the multiplication result can be detected by the client"。这句话**不成立**：
//   * `MPA-05` 发现 SecureMul 的结构性漏洞 —— 两台服务器**一致地**偏移中转量
//     （`e → e+δ` 或 `d → d+Δ`）时 `mac == α·z` **恒成立**（`secure_mul_flow.hpp` §4.5），
//     照抄论文只有这一个检查点 ⇒ 会接受错值。v3 用两条**纯客户端**复核封住了
//     **单台偏离**这一类（§4.5-A/§4.5-B，决策 D25/D27），但**两台共谋**仍不可检出。
//   * 论文 `:527` 的 "对 ⟨E⟩_p 算 HMAC"（PIR 值层的多集证明）在**共享域上不成立**
//     （决策 D24① / 台账 L9）⇒ 已裁决**不做**（D29/V1）。
//   * `Count` 的完整性在论文框架内**没有**可用机制（SPDY MAC 只覆盖 SecureMul，
//     决策 D29/V2）⇒ 已裁决**如实声明 + 附可执行反例**。
//
// 风险在于：这些结论只写在注释/文档里，代码里**没有任何东西**能把它们钉住 ——
// 于是很容易出现两种漂移：
//   (a) 后人（或论文）把"不可检出"当成"已检出"来写安全声明（**过度声明**）；
//   (b) 后人把"已经能检出"的当成"不可检出"而漏掉回归（**欠声明**，会让保护被删掉）。
//
// 本文件用**两个方向**同时钉住：
//   1. `MpraqVerificationBoundary()` 返回**逐项布尔能力表** + 每项的口径与依据
//      （决策号 / 文件行号 / **用例名**）；判定一律由 `tests/test_mpraq_malicious.cpp`
//      用**可执行注入**复核（"代码里写 true"与"测试里真的注入了并检出"必须同时成立）。
//   2. 每条**不可检出**项必须在 `notes` 里写清"**为什么**不可检出"，并指向
//      `tests/test_mpraq_malicious.cpp` 里那条**可执行反例**用例的名字。
//
// ⚠️ 铁律（与 `MPRAQ_IMPL.md` §5 / 决策 D16 的先例一致）：
//   **不得**为了让矩阵"全绿"而实现一个数学上不成立的检查；
//   **不得**把"不可检出"写成"已检出"。任何一项取 `true` 都必须有一份
//   注入用例证明"注入被检出并 abort"，任何一项取 `false` 都必须有一份
//   反例用例证明"注入未被检出且后果如此"。
//
// ===========================================================================
// 1. 三项字段与真实验证机制的对应关系（读这张表就能看懂 8 个 bool）
// ===========================================================================
//   * `spdz_mac_on_securemul` / `securemul_client_local_checks` / `batch_per_record_verification`
//     —— 描述的是**同一条链路**（`Sum`/`Avg` 的 SecureMul）上的三层机制，
//        分别对应 `secure_mul_flow.hpp` §4.5 的第 4 层（SPDZ MAC）、第 2/3 层
//        （纯客户端复核 A/B）、以及 `aggvalue.hpp` §5.2（批量层**逐记录**校验，
//        绝不"整列一次校验"）。
//   * `pir_value_layer` —— 论文的 HMAC 多集证明（值层完整性）。**没有实现**。
//   * `count_integrity` —— `Count` 结果的完整性。**没有实现**。
//   * `e_or_d_offset_independent` —— 红队 E1/E3 那一类"一致偏移"（单台口径）
//        **是否是一项独立的能力位**。取值 `false` = "**不是独立能力位**"：
//        **能力本身是具备的**（已由 D25/D27 的 v3 两条检查封住），由
//        `securemul_client_local_checks = true` 表达 ⇒ 这里只是**不重复计数**。
//        ⚠️ 名字里的 `_independent` 是**语义的一部分**：这个字段回答"它是不是一项
//        独立的检查机制"，**不**回答"能不能检出"。历史上它叫 `e_or_d_offset`
//        （读起来像"能不能检出"），而 `e`/`d` 偏移**是能检出的**，属于本项目反复
//        吃亏的"字段名与口径不符" ⇒ 已改名为无歧义形式（主 agent 裁决，见
//        `TASK_PLAN.md` §5 的字段语义裁决与 §7.19）。
//   * `f_zero_record_e_tamper_detectable` —— `f = 0` 记录被篡改 `e`
//        **是否可检出**。取值 `false` = "**不可检出但无害**"
//        （`Δz = δ·f = 0`、`Δmac = α·δ·f = 0`；该记录的正确答案本就是 0）。
//        ⚠️ 同理，后缀 `_detectable` 是语义的一部分（这一条问的**正是**能不能检出，
//        答案是不可检出，但后果为零）。
//
//   ⇒ 一句话的对外口径（论文可直接引用）：
//     **"值/聚合层（Sum/Avg 的每条 SecureMul）具备 SPDZ MAC + 两条纯客户端复核 +
//       逐记录批量校验；单台偏离 100% 检出并 abort。PIR 值层与 Count 的完整性
//       在论文框架内没有可用机制，如实声明并各附可执行反例；f=0 的记录被篡改 e
//       不可检出但无害；两台服务器共谋不在威胁模型内（论文 `:150` 同假设）。"**

#include <string>
#include <vector>

namespace tsb {
namespace mpraq {

// 本系统**实际**具备的验证能力。
//
// ⚠️ 每个 `true` / `false` 都必须有**可执行证据**：`true` ⇒ 有注入用例证明
//    "检出并 abort"；`false` ⇒ 有反例用例证明"未被检出 + 后果"。
//    证据用例名一律写在 `notes` 里（同一条注记里写明文件与用例名）。
struct VerificationBoundary {
    // Sum/Avg：每条记录的 SecureMul 都校验 `mac == α·z`（SPDZ MAC）。
    // ✅ true —— `secure_mul_flow.hpp` §4.5 第 4 层；实测 `BitFlipMatrixIsFullyDetected`。
    bool spdz_mac_on_securemul = false;

    // §4.5-A/§4.5-B 两条**纯客户端**复核（v3）：
    //   A：`z ?= f·(e_sent + b)`      —— 抓 `d`/`e` 的"两台一致偏移"（零新增消息）
    //   B：`e_computed ?= ⟨E⟩_p − ⟨b⟩_p` —— 抓"某台谎报 ⟨e⟩_p"
    // ✅ true —— 决策 D25/D27；实测 `RedTeamBothServersOneBitEOffsetIsDetectedEndToEnd`。
    bool securemul_client_local_checks = false;

    // 批量层**逐记录**校验（拒绝"整列一次校验"）。
    // ✅ true —— `aggvalue.hpp` §5.2：`Σ mac == α·Σ z` 恰恰是恶意服务器能保持的
    //   不变量（一致偏移），整列一次校验会静默接受被污染的整列。
    bool batch_per_record_verification = false;

    // 论文 PIR 值层的 HMAC 多集证明（"对 ⟨E⟩_p 算 HMAC"，`:527`）。
    // ❌ false —— 该写法在**共享域上不成立**（`F` 建在明文、`C` 建在共享；
    //   决策 D24① / 台账 L9）⇒ 决策 D29/V1 裁决**不做**。
    //   **不可检出**，反例见 `tests/test_mpraq_malicious.cpp` 的
    //   `MpraqMaliciousCount, FeatureWordTamperIsSilentlyCounted`。
    bool pir_value_layer = false;

    // `Count` 结果的完整性（filter 向量 / popcount 的可信性）。
    // ❌ false —— SPDZ MAC 只覆盖 SecureMul；论文框架内**没有** Count 的机制
    //   （决策 D29/V2）⇒ 如实声明，不伪造。
    //   **不可检出**，反例见上面两条 `Count` 注入用例。
    bool count_integrity = false;

    // 红队 E1/E3 的"单台一致改 `d` / 改 `e`"——问的是**它是不是一项独立的检查机制**。
    //
    // ✅ 能力本身**具备**：v3 起由 §4.5-A 检出（`kClientLocalCheckFailed`），
    //    **零新增消息**；这是红队证伪 v2 "不可检"结论的直接产物（D24③ → D25/D27）。
    // ❌ 取值仍为 `false`，"**不是独立能力位**"（= 不重复计数）：检出它的是
    //    `securemul_client_local_checks`（本身就是 `true`），没有、也不需要
    //    第二个机制。
    //
    // ⚠️ **为什么改名为 `..._independent`（主 agent 裁决）**：原名 `e_or_d_offset`
    //    会被读成"能不能检出"，而 `e`/`d` 偏移**是能检出的** —— 这正是本项目
    //    反复吃亏的"字段名与口径不符"。`bool` 表达不了第三态（"不适用/不独立计数"），
    //    所以**不用 `bool` 硬塞**，改为**让名字显式表达语义**：本字段问的是
    //    "独立性"，`false` 只意味着"不作为一项独立能力计数"。
    //    ⇒ 想知道"能不能检出"，请看 `securemul_client_local_checks`（= true）。
    bool e_or_d_offset_independent = false;

    // `f = 0` 的记录被篡改 `e`：**是否可检出**。
    // ❌ false（**不可检出**）——但 ⚪ **无害**：`Δz = δ·f = 0`、`Δmac = α·δ·f = 0`，
    //   两台一致 ⇒ `mac == α·z` 仍成立、`z` 也不变；而该记录的正确答案**本来就是 0**。
    //   ⇒ 期望值不变即"无需检出"，数学上**不需要**也不可能用这条注入区分。
    //   （`f = 1` 时同一注入 `Δz = δ ≠ 0`，被 §4.5-A 当场检出 ⇒ 必须按 `f` 分档。）
    // ⚠️ 后缀 `_detectable` 是**语义的一部分**（主 agent 裁决）：这一条问的**正是**
    //    "能不能检出"，答案是"不可检出但无害"；不像上一个字段那样是"不独立计数"。
    //    改名前的 `f_zero_record_e_tamper` 让人分不清"不可检出"与"不需要独立机制"，
    //    两档混在一起读。⇒ 现在两个字段的名字都能自解释（各自注记也写明这一点）。
    bool f_zero_record_e_tamper_detectable = false;

    // 每条的**口径与依据**（决策号 / 文件行号 / 用例名）。
    // 约定：每条注记以 `[字段名]` 开头，便于审计脚本逐项对照；
    // 不可检出项必须含"为什么不可检出"与**反例用例名**。
    std::vector<std::string> notes;

    // ---- 便捷查询（纯函数，供测试与报告使用）----
    // 7 个能力位的取值个数（**实测口径，不是声明**：
    // `MpraqMaliciousBoundary.BoundaryMatchesExecutableEvidence` 会把它与
    // 独立算出的期望值逐项对照）。
    //   * `true_count()`  = 3：spdz_mac_on_securemul / securemul_client_local_checks /
    //                       batch_per_record_verification（Sum/Avg 链路上的三层机制）；
    //   * `false_count()` = 4：pir_value_layer / count_integrity（两项**不可检出**，
    //                       已裁决如实声明 D29）、
    //                       e_or_d_offset_independent / f_zero_record_e_tamper_detectable
    //                       （两项"**不必**检出"：前者已由 §4.5-A 覆盖、后者无害
    //                       ⇒ 不作为独立能力计数）。
    // ⚠️ `false_count()` **不**等于"缺陷数"：其中 2 项是**已裁决的诚实边界**（D29），
    //    2 项是**不需要**独立机制/无害的情形。区别写在各自的 note 里。
    int true_count() const;
    int false_count() const;
    // 取某项的注记（按字段名，例如 "pir_value_layer"）；找不到返回空串。
    std::string note_for(const std::string& field) const;
    // 一行的对外声明（论文/报告可直接引用；不是安全证明，只是口径）。
    std::string headline() const;
};

// 本系统实际的验证边界。**纯函数、无副作用、不抛异常**（可以随便调用）。
VerificationBoundary MpraqVerificationBoundary();

}  // namespace mpraq
}  // namespace tsb
