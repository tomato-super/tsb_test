// `MPA-07`：验证边界的**可执行定义**（纯函数，无副作用）。
//
// 本文件只做三件事：
//   ① 把"本系统实际具备的验证能力"写成 8 个 bool；
//   ② 给每一项配一条注记（口径 + 依据 + **可执行证据的用例名**）；
//   ③ 提供几个纯查询函数（`true_count` / `false_count` / `note_for` / `headline`）。
//
// ⚠️ 本文件**不是**验证机制的实现 —— 任何验证逻辑都不在这里，也不允许在这里
//    "补一个检查"来让能力表变绿。它是一份**随代码一起编译、随测试一起断言**的
//    诚实口径表：`tests/test_mpraq_malicious.cpp` 的
//    `MpraqMaliciousBoundary.BoundaryMatchesExecutableEvidence` 会逐项核对
//    "这里写 true 的，测试里真的注入过并检出；这里写 false 的，测试里有反例"。
//
// 字段取值与依据的**完整版**写在 `verification.hpp` 的注释与 `notes` 里；
// 本文件顶部不再重复，避免两处口径漂移（改口径请只改一处并同步 `notes`）。

#include "mpraq/verification.hpp"

#include <string>
#include <vector>

namespace tsb {
namespace mpraq {

namespace {

// 注记的构造：`[字段名] ...`。字段名与 `VerificationBoundary` 的成员逐一对应，
// 便于审计脚本/测试逐项 grep。
std::string Note(const char* field, const char* text) {
    return std::string("[") + field + "] " + text;
}

// 一条"可检出"项的注记模板（机制 + 依据 + 用例名）。
std::string DetectNote(const char* field, const char* what, const char* how,
                       const char* ref, const char* case_name) {
    return Note(field, (std::string(what) + " ✅**可检出**：" + how + "。依据：" + ref +
                        "。可执行证据：`tests/test_mpraq_malicious.cpp` 的 `" + case_name +
                        "`（注入 ⇒ 检出 ⇒ abort，且 `SumOverFilter` **不返回任何结果**）。")
                           .c_str());
}

}  // namespace

VerificationBoundary MpraqVerificationBoundary() {
    VerificationBoundary b;

    // -----------------------------------------------------------------------
    // ✅ 三项真实存在的机制（`Sum` / `Avg` 链路）
    // -----------------------------------------------------------------------
    b.spdz_mac_on_securemul = true;
    b.securemul_client_local_checks = true;
    b.batch_per_record_verification = true;

    // -----------------------------------------------------------------------
    // ❌ 两项已裁决的诚实边界（决策 D29/V1、D29/V2）
    // -----------------------------------------------------------------------
    b.pir_value_layer = false;
    b.count_integrity = false;

    // -----------------------------------------------------------------------
    // ⚪ 两项"不是独立能力位 / 不必检出"的情形（字段名已按主 agent 裁决改成自解释形式）
    // -----------------------------------------------------------------------
    // 单台一致偏移（改 d / 改 e）：**已可检出**——但**能力**由
    // `securemul_client_local_checks = true` 表达；本字段问的是"**是不是一项独立的
    // 检查机制**"，答案是"不是"（`securemul_client_local_checks` 已经覆盖它，
    // 没有也不需要第二个机制）⇒ 取 `false` 且**不重复计数**。
    // ⚠️ 名字里的 `_independent` 是语义的一部分：**不要**把它读成"能不能检出"。
    b.e_or_d_offset_independent = false;
    // f = 0 的记录被篡改 e：问的是"**能不能检出**"，答案是**不可检出但无害**
    //（`Δz = δ·f = 0`、`Δmac = α·δ·f = 0`，且该记录正确答案本就是 0）⇒ 取 `false`。
    b.f_zero_record_e_tamper_detectable = false;

    // -----------------------------------------------------------------------
    // notes：每条的口径 + 依据 + 可执行证据
    // -----------------------------------------------------------------------
    b.notes.clear();

    b.notes.push_back(DetectNote(
        "spdz_mac_on_securemul",
        "Sum/Avg 的每条记录都校验 `mac == α·z`（SPDZ MAC，α 全局一份）",
        "`VerifyAndReconstruct` 重建 `z = z_0+z_1`、`mac = mac_0+mac_1` 后校验 "
        "`mac == α·z`；失败分类 `SecureMulFailure::kMacMismatch`，上层 `SumOverFilter` "
        "抛 `SecureMulBatchAbort`",
        "`secure_mul_flow.hpp` §4.5 第 4 层；`MPRAQ_IMPL.md` §5 的 ✅ 行",
        "MpraqMaliciousOffset.SingleServerMacShareFlipAbortsSum"));

    b.notes.push_back(DetectNote(
        "securemul_client_local_checks",
        "§4.5-A/§4.5-B 两条纯客户端复核（v3）",
        "A：`z ?= f·(e_sent + b)`（抓 `d`/`e` 的两台一致偏移，"
        "`kClientLocalCheckFailed`）；"
        "B：`e_computed ?= ⟨E⟩_p − ⟨b⟩_p`（抓某台谎报 `⟨e⟩_p`，`kEShareMismatch`）。"
        "两条判据全部由客户端独立计算、**零新增消息**、被检查方的自报值不参与判据",
        "决策 D25/D27（红队证伪 v2 的 D24③ 不可检 结论）；`secure_mul_flow.hpp` §4.5-A/B",
        "MpraqMaliciousOffset.BothServersConsistentEOffsetIsDetectedEndToEnd"));

    b.notes.push_back(DetectNote(
        "batch_per_record_verification",
        "批量层**逐记录**校验（绝不 整列一次校验）",
        "`RunSecureMulBatch` 对每条记录单独调 `VerifyAndReconstruct` 并用 `ok[i]` 把关；"
        "`ok[i] == false` 的记录 `z[i]` 置 0 且**不参与累加**，`SumOverFilter` 随即 abort。"
        "理由：`Σ mac == α·Σ z` 恰恰是恶意服务器能保持的不变量（一致偏移），"
        "整列一次校验会**静默接受被污染的整列**",
        "`aggvalue.hpp` §5.2（`MPA-05` §6.2 的红队结论）；`MPRAQ_IMPL.md` §4",
        "MpraqMaliciousOffset.BothServersConsistentEOffsetIsDetectedEndToEnd"));

    b.notes.push_back(Note(
        "pir_value_layer",
        "❌**不可检出**（决策 D29/V1 裁决**不做**）：论文 `:527` 的 HMAC 多集证明在"
        "**共享域上不成立** —— 多集证明要在同一域里比较 `F`（按论文建在**明文**特征表上）"
        "与 `C`（服务器只有 XOR/加法**共享**），共享与明文之间没有任何可计算的等式"
        "（决策 D24① / 台账 L9）。"
        "**为什么不可检出**：`Count` 路径的服务器应答（`PlinkoAnswer::r0/r1`）是**纯异或累加**，"
        "客户端 `ClientRecon` 只做 `a = p ⊕ r_b`、**不校验任何一致性**（`pir/plinko.cpp` 的 "
        "`ClientRecon` 全程无 `throw`）⇒ 篡改一个 word 的应答会让重建出的 word 直接变成"
        "`word ⊕ mask`，客户端**无法区分**它与诚实应答。"
        "可执行反例：`tests/test_mpraq_malicious.cpp` 的 "
        "`MpraqMaliciousCount.FeatureWordTamperIsSilentlyCounted`（篡改 1 个 bit ⇒ "
        "`Count` 静默从 38 变成 37，**不抛任何异常**）与 "
        "`MpraqMaliciousCount.SingleBitFlipChangesCountByExactlyOne`（逐位对照）。"));

    b.notes.push_back(Note(
        "replay_challenge_binding",
        "✅**可检出**（矩阵项 3；属于 `securemul_client_local_checks` 之外的一层，"
        "由服务器侧的 challenge/session 绑定提供）：把上一次查询的第 1 轮消息整条重放"
        "进新查询 ⇒ 服务器按 `session → state` 分派到**同一条记录**的 state，"
        "但**challenge（= 每次查询新盐派生）不等** ⇒ `kPhaseError` ⇒ 客户端 abort；"
        "session 与记录号绑定、**不随查询变化** ⇒ 挡住重放的**不是** session 而是 challenge。"
        "⚠️ 反向边界（实测）：旧消息若在**同一个盐**下重放（内容逐位相同），"
        "两道检查都放行 —— 此时它等价于诚实消息；真正被拒的是「state 已被消费」"
        "（一次性语义）与「challenge 不同」两种情形。"
        "可执行证据：`tests/test_mpraq_malicious.cpp` 的 "
        "`MpraqMaliciousReplay.ReplayedFirstRoundMessageIsRejected`、"
        "`MpraqMaliciousReplay.CrossRecordSessionTransplantIsRejected`、"
        "`MpraqMaliciousReplay.ReusedSessionStateOnSecondQueryIsRejected`（本条不属于"
        "`VerificationBoundary` 的能力位，作为矩阵项 3 的证据单列）。"));

    b.notes.push_back(Note(
        "count_integrity",
        "❌**无可用机制**（决策 D29/V2：如实声明 + 附反例）：SPDZ MAC 只覆盖 "
        "`SecureMul`（值层），`Count = popcount(filter)` 的 `filter` 完全来自 PIR 应答 + "
        "客户端本地布尔组合 ⇒ 论文框架内**没有**任何机制能验证它。"
        "**为什么不可检出**：`Count` 路径没有任何认证量（没有 MAC、没有承诺、"
        "没有 `Verify` 实现 —— `PlinkoClient::Verify` 甚至直接抛 "
        "`PlinkoVerificationUnsupported`，绝不返回假的 通过，见 `TASK_PLAN.md` §7.14 检查 8）。"
        "可执行反例：`MpraqMaliciousCount.FeatureWordTamperIsSilentlyCounted`（篡改 1 bit ⇒ "
        "静默错值）与 `MpraqMaliciousCount.SingleBitFlipChangesCountByExactlyOne`"
        "（对**同一条**查询逐位翻转 word 的每一位 ⇒ 期望值、实测值一一钉住）。"
        "⇒ 论文的安全声明**不得**沿用 `MPARQ.tex:452` 的 \"any tampering can be detected\"。"));

    b.notes.push_back(Note(
        "e_or_d_offset_independent",
        "⚪**不是独立能力位**（字段名里的 `_independent` 就是语义本身：本字段回答"
        "「该攻击**是否**由一项独立的检查机制负责」，**不**回答「能不能检出」）："
        "单台服务器一致偏移 `d`/`e`（红队 E1/E3 的最小复现）**已被检出**，"
        "但检出它的是 `securemul_client_local_checks`（§4.5-A）本身，"
        "**没有**、也不需要一个独立机制 ⇒ 不与 `securemul_client_local_checks` 重复计数。"
        "⇒ 想知道「能不能检出」，请看 `securemul_client_local_checks`（= `true`）。"
        "依据：同一注入在 v2（无 §4.5）**8/8 静默接受错值**，v3（有 §4.5-A）**8/8 检出**"
        "（`TASK_PLAN.md` §7.16 的 E1/E3 行；决策 D25/D27）。"
        "可执行证据：`tests/test_mpraq_malicious.cpp` 的 "
        "`MpraqMaliciousOffset.BothServersConsistentEOffsetIsDetectedEndToEnd`。"
        "⚠️ 边界：**两台服务器共谋**（互相约定偏移）不在威胁模型内（论文 `:150` 同假设）—— "
        "此时 §4.5-A/B 用的基准值本身也被污染。"
        "🔴 改名说明（主 agent 裁决）：原名 `e_or_d_offset` 会被读成「能不能检出」，"
        "而 `e`/`d` 偏移**是**能检出的 —— 这正是本项目反复吃亏的「字段名与口径不符」。"
        "`bool` 表达不了第三态（「不适用/不独立计数」）⇒ 不用 `bool` 硬塞，"
        "改为**让名字显式表达语义**。"));

    b.notes.push_back(Note(
        "f_zero_record_e_tamper_detectable",
        "⚪❌**不可检出但无害**（后缀 `_detectable` 是语义的一部分：这一条问的**正是**"
        "「能不能检出」，答案是「不能，但后果为零」；且**不应**被当成缺陷）："
        "两台服务器一致篡改第 2 轮中转的 "
        "`e`（`e → e+δ`）时，代数上有\n"
        "    `Δz   = δ·(a + d) = δ·f`     （因 `a + d = f`）\n"
        "    `Δmac = α·δ·f`\n"
        "⇒ `f = 0` 的记录上 `Δz = Δmac = 0`：`z` 与 `mac` **都不变**，"
        "`mac == α·z` 仍成立，§4.5-A（`z ?= f·(e_sent+b)`）也仍成立（两侧都乘了 `f`）⇒ "
        "**数学上不可检出**；但该记录的正确答案**本来就是 0**（`z = f·E = 0`）"
        "⇒ **不可检出但无害**，无需也不应 检出。"
        "**必须按 `f` 分档**：`f = 1` 时同一注入 `Δz = δ ≠ 0`，被 §4.5-A 当场检出"
        "（`kClientLocalCheckFailed`）。依据：`MPA-06` 的实测与裁决 3（`TASK_PLAN.md` §7.18）、"
        "`aggvalue.hpp` §5.2 的代数论证、`MPRAQ_IMPL.md` §5 的 ⚪ 行。"
        "可执行证据：`tests/test_mpraq_malicious.cpp` 的 "
        "`MpraqMaliciousFTier.FOneRecordTamperIsDetectedAndAborts`（f=1 ⇒ 检出 + abort，"
        "且 `Sum` 一个数都不返回）与 `MpraqMaliciousFTier.FZeroRecordTamperIsSilentButHarmless`"
        "（f=0 ⇒ 不检出，但 `z[i] == f_i·E_i` 逐条成立、`Sum == 38` 与明文基准逐值相等）。"));

    return b;
}

int VerificationBoundary::true_count() const {
    int n = 0;
    n += spdz_mac_on_securemul ? 1 : 0;
    n += securemul_client_local_checks ? 1 : 0;
    n += batch_per_record_verification ? 1 : 0;
    n += pir_value_layer ? 1 : 0;
    n += count_integrity ? 1 : 0;
    n += e_or_d_offset_independent ? 1 : 0;
    n += f_zero_record_e_tamper_detectable ? 1 : 0;
    return n;
}

int VerificationBoundary::false_count() const {
    // 能力位共 7 个（8 个字段里 `notes` 不是能力位）。用"总数 − true"算，
    // 保证将来加字段时不会漏算。
    constexpr int kCapabilityFields = 7;
    return kCapabilityFields - true_count();
}

std::string VerificationBoundary::note_for(const std::string& field) const {
    const std::string prefix = "[" + field + "] ";
    for (const std::string& n : notes) {
        if (n.compare(0, prefix.size(), prefix) == 0) return n;
    }
    return std::string();
}

std::string VerificationBoundary::headline() const {
    // ⚠️ 措辞与字段语义严格对齐（主 agent 裁决后收紧过一次）：
    //   * "单台偏离 100% 检出" —— 这句话**不**依赖 `e_or_d_offset_independent`；
    //     一致偏移 d/e 的检出能力由 `securemul_client_local_checks = true` 表达，
    //     那个字段只是"不重复计数"，所以这里必须写清"由 §4.5-A 覆盖"，
    //     避免读者把两个字段读成同一件事。
    //   * `true_count = 3` 的口径 = **独立能力位**的个数（不是"检出能力的个数"）。
    std::string s;
    s += "MPRAQ 验证边界（MPA-07，随代码编译/随测试断言）：";
    s += "值/聚合层（Sum/Avg 的每条 SecureMul）具备 SPDZ MAC + §4.5-A/B 两条纯客户端";
    s += "复核 + 逐记录批量校验 —— 单台服务器偏离（含逐比特篡改 z_p/mac_p/e_computed/d、";
    s += "一致偏移 d/e、谎报 ⟨e⟩_p、跨记录串味、跨查询重放）100% 检出并 abort，";
    s += "绝不返回部分和或错值（⚠️ 一致偏移 d/e 由 §4.5-A 覆盖，不再单列为一项独立机制";
    s += " ⇒ 独立能力位计数为 " + std::to_string(true_count()) + "）。";
    s += "❌ PIR 值层（论文 :527 的 HMAC 多集证明）在共享域上不成立（D24①/L9）、";
    s += "❌ Count 的完整性在论文框架内无可用机制（D29/V2）⇒ 二者如实声明并各附";
    s += "可执行反例，不伪造验证层。";
    s += "⚪ f=0 的记录被篡改 e 不可检出但无害（Δz=δ·f、Δmac=α·δ·f ⇒ 恒 0；";
    s += "正确答案本就是 0）⇒ 注入矩阵必须按 f 分档。";
    s += "两台服务器共谋 / 恶意客户端不在威胁模型内（论文 :150 同假设）。";
    s += " [字段口径：前 3 位 = 独立能力位；后 4 位 = ";
    s += "e_or_d_offset_independent（不是独立能力位，能力由纯客户端复核 A 表达）、";
    s += "f_zero_record_e_tamper_detectable（不可检出但无害）⇒ true_count=";
    s += std::to_string(true_count());
    s += " / false_count=";
    s += std::to_string(false_count());
    s += "]";
    return s;
}

}  // namespace mpraq
}  // namespace tsb
