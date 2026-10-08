#pragma once

// Plinko —— 单服务器 offline/online PIR，MPRAQ 的检索底座（任务 PIR-04，主线 §9.2 的 S2）。
//
// ============================ 依据 ============================
//   * 规格书：`doc/design/PLINKO_SPEC.md`（参数几何 §1、数据结构 §2、六算法 §3、
//     正确性要点 §4、失效模式 §5、复杂度 §6、测试计划 §7、**6 条勘误 §8**）
//   * 论文：`doc/paper/Plinko.pdf` §5.2（p.20–22）与 **Figure 7**（p.31）
//     （提取文本 `doc/evidence/q9_iprf/plinko.txt`）
//   * 底座：`core/iprf`（FND-06，决策 D21/D22）—— `IF: [λw+q] → [w]`、`IF = PMNS ∘ PRP`
//   * 裁决：D8（**不做**数据库更新 / 摊销式离线）、D17（hint 生命周期）、D19-6（entry = 128 位
//     word）、D21/D22（iPRF 口径）、**D6**（确定性随机源下的期望值测试）
//
// ============================ 1. 参数几何（符号向论文看齐）============================
//
//   m   **PIR 条目数** = LCTE 层数（一个条目 = **一整列向量**，n bit）
//       ⚠️ 这是 Plinko 原文的 DB 大小 `n`；本仓库向论文看齐，一律写 `m`。
//   n   记录数 = 列长（bit）。**Plinko 层不需要 n**，只需要条目宽度 `entry_words = ⌈n/128⌉`
//       （`n` 由 MPRAQ 层持有，避免与 Plinko 原文的 `n` 撞名）。
//   entry_words  条目宽度（128 位字数）—— 一个条目 = 一整列 = entry_words 个字
//   w   **区块大小**（w 个连续**条目**一块），必须是 2 的幂（D21 硬约束）
//   κ   **区块数** κ := m/w —— ⚠️ 论文的 `r` 只表示"客户端存储位数"，
//       区块数一律写 κ（勘误 ④：`MPRAQ.tex` 存在 r 的符号冲突）
//   λ   安全参数（论文部署值 80）
//   λw  **常规（主）hint 数**；N_T **备份 hint 数** = λw/2（本项目取，与 `MPRAQ.tex` 一致）
//   H  := λw + N_T —— iPRF 的定义域 `[H)`；常规与备份**共用同一张下标空间**：
//       槽位 0..λw-1 = 常规 hint，λw..λw+N_T-1 = 备份 hint（提升后**保留下标**）
//   每条常规 hint 选 κ/2+1 个区块，每条备份 hint 选 κ/2 个区块
//
//   ⚠️ **κ 必须是偶数**：`κ/2+1` 与补集 `[κ]\(P_j\{α})` 的规模只有在 κ 为偶数时才相等
//      （`|P_j\{α}| = κ/2`、`|[κ]\(P_j\{α})| = κ/2`），这是 §5.5 的对称性硬要求。
//
//   ⚠️ **一次列查询 = 1 个查询集**：PIR 的 index 就是**列索引**（∈ [0,m)），
//      服务器对该条目（整列 entry_words 个字）逐字 XOR 累加，客户端逐字重建。
//      不变量 I1：条目恰好 entry_words 个字（不多不少）；I4：宽度不符即拒绝。
//
// ============================ 2. 数据结构（PLINKO_SPEC §2）============================
//
//   客户端：K[c]（**每区块一把** iPRF 密钥，勘误 ①/⑤）、H[λw+q]（主/备共用下标空间）、
//           T（备份的 ℓ/r 两个 parity）、Q（重复查询缓存）
//   服务器：只有数据库（MPRAQ 里是 LCTE 特征表的 XOR 共享），**不持有任何 hint**
//
//   ⚠️ 子集的**紧凑表示**（勘误 ⑥）：本实现用**按位图**（每槽位 ⌈c/64⌉ 个 uint64）而不是显式
//      区块列表。PLINKO_SPEC §8-⑥ 明确允许"PRF 派生 + cutoff **或按位图**"；位图的优点是
//      **无损、恒为 c/2+1（或 c/2）位、无拒绝采样**，且 `α ∈ P_j` 检查退化为一次位测试。
//      显式存 `uint64_t` 列表会把每条 hint 的存储从 O(c/8) 抬到 O(c)，破坏 §6 的存储口径。
//
// ============================ 3. 六个算法（PLINKO_SPEC §3）============================
//
//   HintInit(db)           离线：**只用 IF⁻¹**（每条记录 1 次，流式扫一遍 DB）
//   GetHint(α, β)          1× IF⁻¹ 取候选 + 对选中的候选 1 趟 c× IF 算偏移向量
//   QueryGen(x)            返回 (q, h)；q 是服务器可见的全部信息
//   ServerResp(q, share)   按分组累加，返回两个 parity（可作用在 XOR 共享上）
//   ClientRecon(h, r)      a = p ⊕ r_b；消费被用的 hint + 提升一条备份 hint；维护缓存
//   Verify(...)            ⚠️ **Plinko 原文没有 Verify**（§3.6）：本模块不实现任何验证，
//                          调用即抛异常（绝不返回假的"通过"）。MPRAQ 的验证（HMAC 多集证明
//                          + SPDZ MAC）在 `shared/verify`、由上层 MPA-07 实施。
//
// ============================ 4. 与论文的差异（落地时必须知道）============================
//
//   ①（勘误）`K[i] ← iF.Gen` 是**每区块一把**（Fig 7 为准），不是"每条 hint 一把"
//     ⇒ `GenBlockKeys(c)` + 按区块长期持有 c 个求值器（D22-4：构造期预计算轮常数）。
//   ②（勘误）`GetHint` 必须检查 **α ∈ P_j**：`IF⁻¹` 返回的候选里只有约一半真的包含 α
//     ⇒ 漏检会让约一半查询拿到不覆盖目标的 hint，**静默返回错误值**。
//   ③（勘误）必须跳过 `H[j] == ⊥`（未填充/已消费/已被预留）的槽位。
//   ④（勘误）区块数写 c；`c/2+1`、`c/2` 都是**区块数**。
//   ⑤（勘误）种子/密钥是**每区块**一把（同 ①；论文 §5.2 正文的表述易误读）。
//   ⑥（勘误）子集必须紧凑表示 ⇒ 本实现用按位图（见 §2 注释）。
//
//   ⑦【本实现的补充修正】提升（promoted）hint 的分支在论文 Fig 7 里**同样漏检**、且**忽略 η**：
//      论文只跳过 `α = α' 且 β ≠ β'`，然后返回 `P ∪ {α'}`。但
//        (a) η = 1 时有效区块集是 `([c]\B_j) ∪ {α'}`，返回 `B_j ∪ {α'}` 是错的；
//        (b) α ∉ B_j 且 α ≠ α' 时该 hint 根本不覆盖目标，必须跳过（与勘误 ② 同理）；
//      ⇒ 本实现按 `E = η ? (([c]\B_j) ∪ {α'}) : (B_j ∪ {α'})` 求有效集，并统一做
//         "α ∈ E" 检查。论文的 `β ≠ β'` 跳过条件**是正确的**（提升块的 α' 位置只覆盖
//         被提升进来的那一条记录 x，其偏移被"补丁"为 β'），予以保留。
//   ⑧【本实现的补充修正】论文 QueryGen 的即打印文本（"For j ∈ P′: o_j ←$ [w]"）若照抄，
//      会把**哑偏移**放到 hint 自己的覆盖集上，而把 `p ⊕ r_b = D[x]` 所依赖的 iF 偏移放到
//      补集上 ⇒ **重建必然错值**。论文 §5.2 正文的 S/Ŝ 定义（S 用 iF 偏移、Ŝ 用随机项）
//      与本实现的 §3 口径一致：**S = E\{α} 用 hint 的 iF 偏移，补集（含 α）用全新哑偏移**；
//      累加器 b 恰好装着 S ⇒ `a = p ⊕ r_b`。
//
// ============================ 5. 失效模式（PLINKO_SPEC §5）============================
//
//   1. 找不到覆盖 x 的 hint（概率 2^{-λ} 量级）⇒ 抛 `PlinkoHintCoverageFailure`。
//      ⚠️ **绝不**回退到明文取值等**可区分**的失败路径 —— 那会把"正确性失败"升级为"隐私泄露"。
//   2. 备份 hint 用尽（第 q+1 次查询）⇒ 抛 `PlinkoBackupsExhausted`。
//      D8 明确**不实现**摊销式离线（`n/q` 流式），因此必须显式报错、由上层重跑离线；
//      `backup_remaining()` / `backups_low(margin)` 供上层在逼近 q 时提前告警。
//   3. w 非 2 的幂 ⇒ `core/iprf` 直接抛异常（D21）。
//   4. 哑偏移必须每轮新鲜（D17 的教训：可聚类的重复结构会泄露）。
//   5. 同一条 hint **不得**被两条查询复用：`QueryGen` 立刻**预留**命中的槽位，未 `ClientRecon`
//      的槽位不可再被选中（决不允许"同一 hint 出两次查询"这一 D17 类缺陷）。
//
// ============================ 6. 与上层（MPRAQ）的分工 ============================
//
//   * 双服务器实例化：把同一条 `PlinkoQuery` 发给两台服务器，各自在自己的 **XOR 共享**上跑
//     `ServerRespShared`，客户端 `XorAnswers` 合并（⊕ 与 XOR 共享线性相容，D12/D3），
//     服务器之间**零通信**。
//   * 数据库更新 / 摊销式离线：**不做**（D8）⇒ 用尽 q 次后必须重跑 `HintInit`。
//   * `Verify`：上层 MPA-07（`shared/verify` 的 HMAC 多集证明 + SPDZ MAC）。
//   * `Sum` / 聚合：上层把 PIR 次数归约后自行组合（D18 的 value plane 口径）。

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "core/aes_prf.hpp"
#include "core/field.hpp"
#include "core/iprf.hpp"
#include "core/random.hpp"

namespace tsb {

// ---------------------------------------------------------------------------
// 哨兵
// ---------------------------------------------------------------------------
inline constexpr size_t kPlinkoNoSlot = std::numeric_limits<size_t>::max();
inline constexpr uint64_t kPlinkoNoIndex = std::numeric_limits<uint64_t>::max();

// ---------------------------------------------------------------------------
// 失败模式（PLINKO_SPEC §5）
// ---------------------------------------------------------------------------

// 查询索引**未被任何可用 hint 覆盖**：协议层面的致命失败（概率 2^{-λ} 量级）。
// ⚠️ 绝不可回退到明文取值等可区分的失败路径 —— 必须由上层重跑离线阶段。
class PlinkoHintCoverageFailure : public std::runtime_error {
public:
    explicit PlinkoHintCoverageFailure(const std::string& what) : std::runtime_error(what) {}
};

// 备份 hint 用尽（第 q+1 次查询）。D8：本项目**不实现**摊销式离线，必须重跑离线阶段。
class PlinkoBackupsExhausted : public std::runtime_error {
public:
    explicit PlinkoBackupsExhausted(const std::string& what) : std::runtime_error(what) {}
};

// Verify 的占位语义：本层**没有**验证算法（PLINKO_SPEC §3.6）。
class PlinkoVerificationUnsupported : public std::logic_error {
public:
    explicit PlinkoVerificationUnsupported(const std::string& what) : std::logic_error(what) {}
};

// ---------------------------------------------------------------------------
// 参数
// ---------------------------------------------------------------------------

struct PlinkoParams {
    uint64_t m = 0;              // PIR 条目数 = LCTE 层数（一个条目 = 一整列向量）
    uint64_t entry_words = 1;    // 条目宽度（128 位字数）= ⌈n/128⌉（n = 记录数 = 列长 bit）
    uint64_t w = 0;              // 区块大小（w 个连续**条目**一块）：**必须是 2 的幂**（D21）
    uint32_t lambda = 80;        // 安全参数
    double prp_epsilon = 1e-10;  // iPRF 的 PRP 目标 ε（D22-1：默认 1e-10；测试可调小）

    // 按 §1 的默认口径派生：w = 2^⌈log₂√m⌉、λw 条主 hint、N_T = λw/2 条备份。
    // ⚠️ 要求 `m = κ·w` 且 κ 为偶数；不满足时抛 std::invalid_argument 并给出"应补齐到多少"。
    //    （补齐条目是**上层**的事，见 D15(a)，本层不偷偷改 m。）
    static PlinkoParams Derive(uint64_t m, uint32_t lambda = 80, double prp_epsilon = 1e-10,
                               uint64_t entry_words = 1);

    // 校验：m ≥ 1、entry_words ≥ 1、w 为 2 的幂、m % w == 0、κ = m/w ≥ 2 且**为偶数**、
    //       λ ≥ 1、ε ∈ (0,1)、H = 3λw/2 ≤ 2³²（iPRF 定义域上界）。违反时抛 std::invalid_argument。
    void Validate() const;

    uint64_t blocks() const { return w == 0 ? 0 : m / w; }                          // κ
    uint64_t main_hints() const { return static_cast<uint64_t>(lambda) * w; }        // λw
    uint64_t backup_hints() const { return main_hints() / 2; }                       // N_T
    uint64_t hint_slots() const { return main_hints() + backup_hints(); }            // H = λw+N_T
    uint64_t main_hint_blocks() const { return blocks() / 2 + 1; }                    // κ/2+1
    uint64_t backup_hint_blocks() const { return blocks() / 2; }                      // κ/2
    uint64_t block_of(uint64_t index) const { return index / w; }                    // α
    uint64_t offset_of(uint64_t index) const { return index % w; }                   // β
    // 交给 core/iprf 的参数：domain = H（hint 下标空间）、range = w（区块大小）
    IprfParams iprf() const;
};

// ---------------------------------------------------------------------------
// 条目（= 一整列向量）：128 位字打包，长度恒为 entry_words
// ---------------------------------------------------------------------------

using PlinkoEntry = std::vector<uint128_t>;   // size() == m 条目的 entry_words == ⌈n/128⌉

// 逐字 XOR：dst[i] ⊕= src[i]（长度必须相同）。这是"整列一次 XOR"的类型级操作。
inline void XorInto(PlinkoEntry& dst, const uint128_t* src) {
    for (size_t i = 0; i < dst.size(); ++i) {
        dst[i] = static_cast<uint128_t>(dst[i] ^ src[i]);
    }
}
inline void XorInto(PlinkoEntry& dst, const PlinkoEntry& src) { XorInto(dst, src.data()); }
inline PlinkoEntry XorEntries(const PlinkoEntry& a, const PlinkoEntry& b) {
    PlinkoEntry out(a.size());
    for (size_t i = 0; i < a.size(); ++i) out[i] = static_cast<uint128_t>(a[i] ^ b[i]);
    return out;
}

// ---------------------------------------------------------------------------
// hint 槽位（主/备共用一张下标空间 H[λw+q]）
// ---------------------------------------------------------------------------

enum class PlinkoSlotKind : uint8_t {
    kEmpty = 0,     // ⊥：未填充 / 已被消费
    kRegular = 1,   // H[j]，j < λw：常规 hint (P_j, p_j)
    kBackup = 2,    // T[j]，j ≥ λw：备份 hint (B_j, ℓ_j, r_j)，**不在 H 中**（不可被查询选中）
    kPromoted = 3,  // H[j]，j ≥ λw：提升后的备份 hint (B_j, η, x, p_j)，下标保留
};

struct PlinkoHintSlot {
    PlinkoSlotKind kind = PlinkoSlotKind::kEmpty;
    // ⚠️ parity 是**整列**：长度 entry_words（一个条目 = 一整列 = n bit）
    PlinkoEntry parity;                // 常规 / 提升：有效区块集上的 parity
    PlinkoEntry backup_parity_in;      // ℓ_j：B_j 上的 parity（仅 kBackup）
    PlinkoEntry backup_parity_out;     // r_j：([κ]\B_j) 上的 parity（仅 kBackup）
    uint8_t eta = 0;                   // η ∈ {0,1}（仅 kPromoted）
    uint64_t promoted_index = kPlinkoNoIndex;  // x：被提升进来的查询索引（仅 kPromoted）
    // QueryGen 已**预留**、等待 ClientRecon 消费：预留期间该槽位不可再被选中
    // （PLINKO_SPEC §0 的 hint 生命周期：同一条 hint 不得被两条查询复用）。
    bool reserved = false;

    bool valid() const { return kind != PlinkoSlotKind::kEmpty; }
    // 是否出现在 H 中（可被 GetHint 选中）：常规 hint 与提升后的备份 hint
    bool in_hint_table() const {
        return kind == PlinkoSlotKind::kRegular || kind == PlinkoSlotKind::kPromoted;
    }
};

// GetHint 的返回：命中一条 hint 所需的全部信息（PLINKO_SPEC §3.2 的 (P, p, o)）
struct PlinkoHintSelection {
    bool found = false;
    size_t slot = kPlinkoNoSlot;       // 命中的槽位下标（提升后保留下标）
    bool promoted = false;             // 是否为提升过的备份 hint
    PlinkoEntry parity;                // p（整列，长度 entry_words）
    std::vector<uint64_t> blocks;      // **有效**区块集 E（升序；κ/2+1 个）
    std::vector<uint64_t> offsets;     // o_0..o_{κ-1}：每个区块的偏移（提升 hint 已打补丁）
    // 诊断（PLINKO_SPEC §7.3 的"候选检查"回归用例）：|IF⁻¹| 与其中真正包含 α 的个数
    uint64_t candidates_examined = 0;
    uint64_t candidates_containing = 0;
};

// ---------------------------------------------------------------------------
// 查询 / 应答
// ---------------------------------------------------------------------------

// ⚠️ **服务器可见的全部信息**：κ 个区块各自的分组比特与偏移，别的一律不含
// （不含目标索引、不含命中的 hint 槽位、不含 parity —— 它们都在 handle 里）。
struct PlinkoQuery {
    std::vector<uint64_t> offsets;  // 长度 κ，每个 ∈ [0,w)
    std::vector<uint8_t> groups;    // 长度 κ，0/1：该区块归入累加器 r0 / r1
    // 几何（服务器本来就知道 m 与 w；写进查询里使 ServerResp 自足，也便于校验）
    uint64_t blocks = 0;            // κ
    uint64_t block_size = 0;        // w（**条目**/块，不是字/块）
    // 条目宽度（字）。⚠️ 不变量 I4：服务端据此校验应答宽度，不符即拒绝（防"静默错 128 倍"）
    uint64_t entry_words = 1;

    bool well_formed() const {
        if (offsets.size() != blocks || groups.size() != blocks) return false;
        if (entry_words < 1) return false;
        for (uint64_t o : offsets) {
            if (o >= block_size) return false;
        }
        for (uint8_t g : groups) {
            if (g > 1) return false;
        }
        return true;
    }
};

// 应答：两个累加器，各自是**整列**（长度 entry_words 个字）。
// ⚠️ 两个 parity（S 与补集）是**隐私所必需**的，不属于"多余"。
struct PlinkoAnswer {
    PlinkoEntry r0;
    PlinkoEntry r1;
};

// 客户端私有的查询句柄 h = (i', i, b) + 内部簿记
struct PlinkoQueryHandle {
    uint64_t owner = 0;                // 所属客户端的标识（防止跨客户端误用）
    uint64_t target = 0;               // i：本次真正做 PIR 的索引
    uint64_t requested = 0;            // i'：调用方请求的索引（重复查询时 ≠ i）
    uint8_t b = 0;                     // 累加器选择位：a = p ⊕ r_b
    size_t hint_slot = kPlinkoNoSlot;  // 命中的槽位（已被预留）
    PlinkoEntry hint_parity;           // p（整列，长度 entry_words；ClientRecon 不再重跑 GetHint）
    bool cache_hit = false;            // true ⇒ i' 早已答复，本次结果取自缓存 Q[i']
    bool consumed = false;             // ClientRecon 是否已完成（防止重复重建）
    // ---- 以下由 ClientRecon 回填（诊断/测试用）----
    size_t promoted_slot = kPlinkoNoSlot;  // 本次提升的备份槽位 j'
    uint8_t promotion_eta = 0;             // 该次提升走了哪条分支
    // ---- 诊断（来自 GetHint）----
    uint64_t candidates_examined = 0;
    uint64_t candidates_containing = 0;
};

// ---------------------------------------------------------------------------
// 客户端
// ---------------------------------------------------------------------------

// ⚠️ 启动/构造成本：构造 `c` 个 `Iprf` 求值器（每个预计算 MR14 轮常数，≈50~70 µs/把），
//    在 `HintInit` 里一次性完成并**长期持有**（D22-4）—— 绝不要每次查询重建。
class PlinkoClient {
public:
    // 确定性随机源（铁律 D6）：同一 seed 在**任何进程/任何次运行**都给出逐位相同的
    // 区块密钥、随机子集、哑偏移与 b 位。测试与可复现实验用这个构造函数。
    PlinkoClient(const PlinkoParams& params, uint64_t seed);

    // 部署路径：区块密钥与随机流都取自 CSPRNG（不可复现）。
    static PlinkoClient Deployed(const PlinkoParams& params);

    PlinkoClient(PlinkoClient&&) = default;
    PlinkoClient& operator=(PlinkoClient&&) = default;
    PlinkoClient(const PlinkoClient&) = delete;
    PlinkoClient& operator=(const PlinkoClient&) = delete;

    const PlinkoParams& params() const { return p_; }

    // ======================= 算法 1：HintInit（离线）=======================
    //
    // **只用 IF⁻¹**：流式扫一遍 DB，每条**条目**（= 一整列）1 次求逆，把该条目
    // XOR 进所有"在该区块取该偏移"的 hint 的 parity（PLINKO_SPEC §3.1）。
    // ⚠️ 数据库是**扁平**的：`db.size() == m * entry_words`，条目 i 占
    //    `[i*entry_words, (i+1)*entry_words)`；parity 是整列 XOR（逐字）。
    // 复杂度 O(λm)。
    void HintInit(const std::vector<uint128_t>& db);

    // 同上，但区块密钥由外部提供（真实部署：`HintInit` 跑在持有 DB 的 **offline server** 上，
    // 由它生成 K[κ] 并发给客户端；两种做法产出的 hint 完全相同）。
    void HintInitWithKeys(const std::vector<uint128_t>& db,
                          const std::vector<IprfKey>& block_keys);

    // ======================= 算法 2：GetHint(α, β) =======================
    //
    // 找一条覆盖第 x = αw+β 条记录的 hint（1× IF⁻¹ 取候选 + 1 趟 c× IF 算偏移向量）。
    // ⚠️ 两个必做检查：`α ∈ P_j`（勘误 ②，漏检 ⇒ 约一半查询静默错值）与槽位非空/未预留（勘误 ③）。
    // 本方法**不改变状态**（const）；命中后的消费/预留由 `QueryGen` 负责。
    PlinkoHintSelection GetHint(uint64_t alpha, uint64_t beta) const;
    PlinkoHintSelection GetHint(uint64_t index) const {
        return GetHint(p_.block_of(index), p_.offset_of(index));
    }

    // ======================= 算法 3：QueryGen(x) =======================
    //
    // 返回 (q, h)。b 随机置换两半；**哑偏移每轮全新随机**；命中的槽位立刻被预留。
    // 抛出：`PlinkoBackupsExhausted`（备份用尽，D8，**在发出查询之前**报错）、
    //       `PlinkoHintCoverageFailure`（找不到覆盖 x 的 hint，致命）。
    std::pair<PlinkoQuery, PlinkoQueryHandle> QueryGen(uint64_t index);

    // 用**指定的** hint 槽位为 index 构造查询（不做缓存重采样；槽位不覆盖该索引则抛异常）。
    // `QueryGen` 内部即 `GetHint` + 本函数；暴露出来供上层做定点检查与"提升后立刻复用该槽位"
    // 这类测试（PLINKO_SPEC §7.6）。
    std::pair<PlinkoQuery, PlinkoQueryHandle> QueryViaSlot(size_t slot, uint64_t index);

    // ======================= 算法 4：ServerResp(q; D) =======================
    //
    // 按分组累加：分组为 1 的区块进 r1，其余进 r0（PLINKO_SPEC §3.4）。
    // ⚠️ 每次读的是**整条目**（entry_words 个字），逐字 XOR 累加。
    // `db` 必须是扁平的 m*entry_words 个字。
    static PlinkoAnswer ServerResp(const PlinkoQuery& q, const std::vector<uint128_t>& db);

    // XOR 共享版本（MPRAQ 的双服务器实例化）：`entry(i)` 返回第 i 条 entry 的
    // **一个共享分量**的起始指针（指向 entry_words 个连续 word）。
    // 共享是 XOR ⇒ `ServerRespShared(q, s0) ⊕ ServerRespShared(q, s1) == ServerResp(q, 明文)`。
    template <typename Fn>
    static PlinkoAnswer ServerRespShared(const PlinkoQuery& q, Fn&& entry, size_t entry_words) {
        PlinkoAnswer a;
        a.r0.assign(entry_words, 0);
        a.r1.assign(entry_words, 0);
        for (size_t i = 0; i < q.offsets.size(); ++i) {
            const uint64_t idx = q.offsets[i] + static_cast<uint64_t>(i) * q.block_size;
            const uint128_t* v = entry(idx);
            PlinkoEntry& acc = q.groups[i] ? a.r1 : a.r0;
            for (size_t j = 0; j < entry_words; ++j) {
                acc[j] = static_cast<uint128_t>(acc[j] ^ v[j]);
            }
        }
        return a;
    }

    // 两台服务器的应答合并（⊕ 与 XOR 共享线性相容，D12/D3），随后直接送 ClientRecon。
    static PlinkoAnswer XorAnswers(const PlinkoAnswer& a, const PlinkoAnswer& b) {
        PlinkoAnswer out;
        out.r0 = XorEntries(a.r0, b.r0);
        out.r1 = XorEntries(a.r1, b.r1);
        return out;
    }

    // ======================= 算法 5：ClientRecon(h, r) =======================
    //
    // a = p ⊕ r_b（整列逐字 XOR）；消费被用的 hint；提升一条备份 hint（下标保留，
    // η 记录并入哪一半）；维护重复查询缓存 Q。返回本次查询的整列值。
    // 抛出：`PlinkoBackupsExhausted`（备份用尽）。
    PlinkoEntry ClientRecon(PlinkoQueryHandle& h, const PlinkoAnswer& r);

    // ======================= 算法 6：Verify =======================
    //
    // ⚠️ Plinko 原文**没有** Verify（PLINKO_SPEC §3.6）：本层**不实现**任何验证，
    // 调用即抛 `PlinkoVerificationUnsupported`（语义见 plinko.cpp 的实现处）。
    [[noreturn]] static void Verify(const PlinkoQueryHandle& h, const PlinkoQuery& q,
                                    const PlinkoAnswer& r);

    // ------------------------------------------------------------------
    // 诊断 / 测试支撑（PLINKO_SPEC §7 的验收用例直接用这些）
    // ------------------------------------------------------------------

    size_t hint_slot_count() const { return slots_.size(); }                 // H
    PlinkoSlotKind slot_kind(size_t slot) const;
    const PlinkoHintSlot& slot(size_t slot) const;
    // 槽位的区块子集（提升 hint 按 η 折算成**有效**集 E；备份 hint 即 B_j）
    bool slot_contains_block(size_t slot, uint64_t block) const;
    // 该槽位是否**语义上覆盖**索引 x（含提升 hint 的"提升块只覆盖 β'"规则）
    bool hint_covers(size_t slot, uint64_t index) const;
    // 槽位覆盖的全部索引（每个区块一条；提升 hint 的 α' 块用补丁偏移 β'）
    std::vector<uint64_t> covered_indices(size_t slot) const;
    // 全量覆盖掩码（长度 m）：成本 = H×κ 次 IF（比 m 次 IF⁻¹ 便宜得多）
    std::vector<uint8_t> coverage_mask() const;

    size_t regular_hint_count() const;   // 槽位 j < λw 且仍为常规 hint 的个数
    size_t promoted_hint_count() const;  // 槽位 j ≥ λw 且已提升的备份 hint 数
    // **论文的关键不变量**：H 中"可用 hint 总数"恒为 λw（每轮消耗 1 条 + 提升 1 条）
    size_t hints_in_table() const;
    size_t usable_hint_count() const;    // 同 hints_in_table()，但排除已被 QueryGen 预留的槽位
    size_t backup_remaining() const { return static_cast<size_t>(p_.hint_slots() - next_backup_); }
    bool backups_low(size_t margin = 64) const { return backup_remaining() <= margin; }
    uint64_t promotion_count_eta0() const { return eta0_; }
    uint64_t promotion_count_eta1() const { return eta1_; }
    uint64_t query_count() const { return query_count_; }

    // (α, β) 的 iPRF 候选槽位（升序；与 GetHint 内部同源）
    std::vector<uint64_t> candidates(uint64_t alpha, uint64_t beta) const;
    std::vector<uint64_t> candidates(uint64_t index) const {
        return candidates(p_.block_of(index), p_.offset_of(index));
    }
    // 覆盖 index 的**可用**槽位（诊断/测试用）
    std::vector<size_t> covering_slots(uint64_t index) const;
    // 该区块的 iPRF 偏移 IF(K[block], hint_slot)
    uint64_t iprf_offset(uint64_t block, uint64_t hint_slot) const;
    const Iprf& block_iprf(uint64_t block) const;

    // 重复查询缓存 Q
    bool cached(uint64_t index) const;
    PlinkoEntry cached_value(uint64_t index) const;
    size_t cached_slot(uint64_t index) const;
    uint64_t answered_count() const { return answered_; }

    // 存储口径（PLINKO_SPEC §6）：实际分配的状态字节 / 按 §2 表口径的"每条 hint 开销"
    size_t hint_state_bytes() const;
    double logical_hint_bytes() const;

private:
    // 内部构造：随机流密钥 + nonce + 区块密钥来源
    PlinkoClient(const PlinkoParams& params, const std::array<uint8_t, kAesKeyBytes>& stream_key,
                 uint64_t nonce, bool csprng_block_keys);

    void InitializeHintTables();
    void InitializeEvaluators(const std::vector<IprfKey>& keys);
    void RandomSubset(size_t slot, uint64_t count);

    // 由槽位构造 (blocks, offsets, parity)；若不覆盖 x=(α,β) 则 found = false
    PlinkoHintSelection SelectFromSlot(size_t slot, uint64_t alpha, uint64_t beta) const;
    // 由选中的 hint 为 target 构造查询并**立刻预留**槽位；requested 是调用方请求的索引
    std::pair<PlinkoQuery, PlinkoQueryHandle> BuildQuery(const PlinkoHintSelection& sel,
                                                        uint64_t target, uint64_t requested);
    // 位图访问
    size_t bitmap_base(size_t slot) const { return slot * subset_words_; }
    bool bit_test(size_t slot, uint64_t block) const;
    void bit_set(size_t slot, uint64_t block);
    void bit_clear(size_t slot);
    uint64_t bit_count(size_t slot) const;

    PlinkoParams p_;
    std::unique_ptr<random::DeterministicPrng> rng_;
    std::array<uint8_t, kAesKeyBytes> stream_key_{};
    uint64_t nonce_ = 0;
    bool csprng_block_keys_ = false;
    uint64_t owner_id_ = 0;

    std::vector<std::unique_ptr<Iprf>> block_iprf_;  // c 个求值器（长期持有，D22-4）
    std::vector<PlinkoHintSlot> slots_;              // H 个槽位（主/备共用下标空间）
    std::vector<uint64_t> subsets_;                  // H × ⌈c/64⌉ 的位图（紧凑子集表示，勘误 ⑥）
    size_t subset_words_ = 0;
    std::vector<uint64_t> scratch_;                  // 子集采样/候选枚举的复用缓冲

    // Q：重复查询缓存（每条目一整列）
    std::vector<PlinkoEntry> cache_value_;
    std::vector<uint8_t> cache_valid_;
    std::vector<uint64_t> cache_slot_;
    uint64_t answered_ = 0;

    size_t next_backup_ = 0;  // 下一条待提升的备份槽位（= λw + 已提升数，即 arg min T[j] ≠ ⊥）
    uint64_t eta0_ = 0;
    uint64_t eta1_ = 0;
    uint64_t query_count_ = 0;
};

// ---------------------------------------------------------------------------
// 算法 6 的自由函数形式（PLINKO_SPEC §3.6）
// ---------------------------------------------------------------------------

// ⚠️ Plinko 原文没有 Verify。MPRAQ 的 Verify（`shared/verify`：HMAC 多集证明 + SPDZ MAC）
// 由上层 MPA-07 对**上层的秘密共享数据**实施，不改变 Plinko 的 parity 结构。
// 本函数**只表达"本层不提供验证"这一语义**：永远抛异常，绝不返回一个假的"通过"。
[[noreturn]] void Verify(const PlinkoQueryHandle& h, const PlinkoQuery& q, const PlinkoAnswer& r);

}  // namespace tsb
