#pragma once

// V-OO-PIR —— 可验证的 offline/online PIR（VMPQ 论文 §III）。
//
// 实现依据：doc/design/PIR_SPEC.md（由 S3PIR 官方实现交叉核对）。
// 关键规格裁决（决策 D7）：阈值规则以 S3PIR 的 `FindCutoff` 为准，**不取 median**。
//
// ⚠️ **群运算：`Z_{2^128}` 环上加法（决策 D37，2026-09-11）。** 重建只依赖
// "hint 覆盖集与应答子集的**对称差**恰为 `{x}`，两者在群里相消" ⇒ 对任何阿贝尔群都成立。
// 本模块统一取 `(Z_{2^128}, +, −)`（`core/field.hpp` 的 `add`/`sub`/`neg`）：
//   * 服务器累加 `acc += entry`；两台合并 `acc = add(acc0, acc1)`；
//   * 客户端重建 `β = sub(hint_parity, acc)`。
// ⚠️ **共享类型必须与累加运算同群**：entry 必须是 `Z_{2^128}` 加法共享（RSS），
// 不能用 XOR 共享（`(a⊕b) + ((s−a)⊕(t−b)) ≠ s⊕t`，见决策 D12 的反例与
// `doc/design/vmpq_parity_alignment.md` §5 的实测：ASS + ⊕ 累加 = 0% 正确）。
// 与论文的关系：论文 §IV-B 的 one-hot 就是 `Z_{2^k}` 加法共享，但其 Algorithm 1 写成 ⊕
// ⇒ 本模块取"加法贯穿到底"的自洽读法（论文自身三处不一致见台账 L15）。
// ⚠️ 证明层 `F_j`（Mset-XOR-Hash）**仍走 XOR**（论文原文），与数据面是两条独立通道。
//
// 参数（n = 数据库条目数，σ = 每分区条目数，P = 分区数）：
//   P = n / σ               分区数，必须为偶数
//   σ、P 都取 2 的幂（掩码代替取模）
//   M = λ·√n                主 hint 数（备份 hint 仅单服务器方案需要）
//
// ⚠️ 数据库更新明确不做（决策 D8）：hint 与 DB 内容强绑定，
// 任何数据变动都必须重跑离线阶段。但 hint 的在线 Refresh 必须实现。

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include "core/aes_prf.hpp"
#include "core/field.hpp"

namespace tsb {

// ---------------------------------------------------------------------------
// 向量条目（决策 D38）
// ---------------------------------------------------------------------------
//
// 一个 DB 条目由 `VooPirParams::entry_words` 个 128 位分量组成：
//   * `entry_words == 1` ⇒ 标量条目（一个 16 B 环元素）；
//   * VMPQ 取 `entry_words == N`（一条目 = 一整列 = N 个 cell），
//     于是**一次 PIR 取回一整列**，与论文 §V-C 的复杂度口径一致
//     （查询 `√(2^l)`、服务器应答 `N` 个元素、存储 `|κ|·(N + N·2^l)`）。
// 群运算仍是 `Z_{2^128}` 加法（决策 D37），**逐分量**进行。

// 一个 PIR 条目：entry_words 个 128 位分量
using PirEntry = std::vector<uint128_t>;
// PIR 数据库：n 个条目（每个条目是一个 PirEntry）
using PirDatabase = std::vector<PirEntry>;

// 查询子集中"没有额外项"的哨兵值
constexpr uint64_t kNoExtraIndex = std::numeric_limits<uint64_t>::max();

// ---------------------------------------------------------------------------
// 致命失败类型
// ---------------------------------------------------------------------------

// 查询索引**未被任何 hint 覆盖**：协议层面的致命失败（概率 < e^{−λ/2}，
// 见 PIR_SPEC §5.3）。⚠️ 绝不可回退到明文取值等可区分的失败路径 ——
// 那会把"正确性失败"升级为"隐私泄露"。
class HintCoverageFailure : public std::runtime_error {
public:
    explicit HintCoverageFailure(const std::string& what)
        : std::runtime_error(what) {}
};

// 覆盖该索引的 hint **都已在本轮批次中被消费**，必须先 `Refresh` 才能继续。
// ⚠️ 这不是失败：每轮查询消费一条 hint 是协议要求（决策 D17），
// 调用方（例如 VmpqClient::RetrieveColumns）应当在拿到重建值后立刻刷新。
class HintsExhausted : public std::runtime_error {
public:
    explicit HintsExhausted(const std::string& what) : std::runtime_error(what) {}
};

// ---------------------------------------------------------------------------
// hint 生命周期策略（⚠️ 决策 D17）
// ---------------------------------------------------------------------------
//
// **为什么默认禁止复用**：同一条 hint 的真实半区偏移由 `PRF_off(h,k)` 决定，
// 因此**跨轮恒定**；而哑组各分区与查询分区 ℓ 的偏移每轮重新随机。若客户端
// 反复使用同一条 hint（查询后不刷新），服务器把几轮偏移向量放在一起比就能：
//   ① 挑出"跨轮恒定"的分区 ⇒ 真实半区（`flip` 的随机置换失效）；
//   ② 逐轮判定真实组；
//   ③ 找出"恰好在某一轮掉出真实组"的分区 ⇒ 该轮的查询分区 ℓ，
//      目标索引从 n 个候选缩到 σ = part_size 个候选。
// 可执行证据见 `tests/test_voo_pir.cpp` 的
// `VooPirPrivacy.HintReuseWithoutRefreshLeaksRealHalfAndQueryPartition`。
//
// 协议正确用法（对齐官方 `TwoSVClient::Online`）：**每轮查询后立即 Refresh**，
// 用一条全新的 hint（新 hint_id、新 cutoff、新半区划分）替换被消费的槽位。
enum class HintReusePolicy {
    // 默认：`Query` 消费槽位，刷新前不得再次选中它（协议正确、部署用法）
    kForbidReuse = 0,
    // ⚠️ 显式不安全：允许反复选中同一条 hint。**仅供"纯正确性"扫描测试与
    // "证明复用会泄露"的证伪测试**，任何部署路径都不得使用。
    kAllowUnsafeForTesting = 1,
};

// ---------------------------------------------------------------------------
// 参数
// ---------------------------------------------------------------------------

struct VooPirParams {
    uint64_t n = 0;        // 数据库条目数
    uint32_t part_num = 0;  // 分区数 P（2 的幂、偶数）
    uint32_t part_size = 0;  // 每分区条目数 σ（2 的幂）
    uint32_t lambda = 80;    // 安全参数，M = lambda * sqrt(n)

    // ⭐ **条目宽度（分量数）**：一个 DB 条目由多少个 128 位分量组成（决策 D38）。
    //   * `entry_words == 1` ⇒ 标量条目（一个 16 B 环元素）；
    //   * VMPQ 取 `entry_words == N`（一条目 = 一整列 = N 个 cell），
    //     于是**一次 PIR 取回一整列**，服务器对每个分量分别做环上加法，
    //     hint 的 parity 也是 N 个分量各一份。
    // 这对应论文 §V-C 的复杂度：查询 `√n`、应答 `N` 个元素、服务器存储 `|κ|·N·2^l`。
    uint64_t entry_words = 1;

    static VooPirParams Derive(uint64_t n, uint32_t lambda);

    void Validate() const;

    uint64_t num_hints() const;  // M
    uint32_t log2_part_size() const;
};

// ---------------------------------------------------------------------------
// hint
// ---------------------------------------------------------------------------

struct VooPirHint {
    uint64_t hint_id = 0;      // J：PRF 输入的 hint 标识
    uint32_t select_cutoff = 0;  // c_j；0 表示该 hint 无效
    bool indicator = true;     // β：真实半区是 "v < c" (true) 还是 "v >= c" (false)
    uint32_t extra_part = 0;   // e_j 所在分区
    uint32_t extra_offset = 0;  // e_j 在分区内的偏移
    // P_j：覆盖集在 Z_{2^128} 上的**逐分量和**（决策 D37/D38）。
    // 长度 = `VooPirParams::entry_words`；标量条目时长度为 1。
    std::vector<uint128_t> parity;

    bool valid() const { return select_cutoff != 0 || hint_id != 0; }
};

// ---------------------------------------------------------------------------
// 查询
// ---------------------------------------------------------------------------

struct VooPirQuery {
    // 每个分区恰好一项：偏移向量
    std::vector<uint16_t> offsets;
    // 每个分区的分组比特：true 表示归入累加器 1
    std::vector<uint8_t> groups;
    // 客户端重建所需的信息
    uint64_t target_index = 0;
    // 本条查询命中的 hint 槽位。Refresh 需要它来替换被消费的槽位
    // （注意：LastQuerySlot() 只反映**最后一次** Query，批量生成查询时必须用
    //  这个字段逐条对应，否则会刷新错槽位）。
    size_t hint_slot = std::numeric_limits<size_t>::max();
    // 填充索引：哑组中"本应属于 hint 真实集合、但被替换掉"的那一项。
    // 它同时出现在 hint parity 与应答子集中，因此在重建时抵消。
    // case A（目标是 extra 项）时为 kNoExtraIndex。
    uint64_t filler_index = kNoExtraIndex;
    // P_h：覆盖集在 Z_{2^128} 上的**逐分量和**（决策 D37/D38）。
    // 长度 = `VooPirParams::entry_words`；标量条目时长度为 1。
    std::vector<uint128_t> hint_parity;
    bool take_accumulator_1 = false;  // 真实组落在累加器 1（否则累加器 0）
    // 命中方式：true = case A（查询索引恰为 hint 的 extra 项）
    bool hit_via_extra = false;
};

// 服务器应答：两个累加器，每个都是"逐分量和"（长度 = entry_words）
struct VooPirAnswer {
    std::vector<uint128_t> acc0;
    std::vector<uint128_t> acc1;
};

// ---------------------------------------------------------------------------
// 客户端持有的 hint 集合与本地状态
// ---------------------------------------------------------------------------

class VooPirClient {
public:
    // ⚠️ **VMPQ 只做半诚实**（决策 **D39**，2026-09-11 负责人裁决）：本模块
    // **没有**证明层 —— 不接收 MAC 密钥、不计算 `F_j`、不提供 `proof()`。
    // 理由：论文的验证层本身不成立（Mset-XOR-Hash 的 `F ⊕ C` 在共享域上不闭合，
    // 见决策 D16 与 `doc/design/mparq_review/REPORT.md`），而半诚实模型下服务器
    // 默认不篡改 ⇒ 保留一个"用不了"的接口只会误导。恶意模型由 MPRAQ 那条线做。
    VooPirClient(const VooPirParams& params, const AesPrf& prf);

    const VooPirParams& params() const { return params_; }

    // ---- hint 生命周期（决策 D17）----

    // 默认 kForbidReuse：Query 消费槽位，Refresh 之前不得再次选中。
    void SetHintReusePolicy(HintReusePolicy policy) { policy_ = policy; }
    HintReusePolicy hint_reuse_policy() const { return policy_; }

    // 槽位是否已被消费（kForbidReuse 下由 Query 置位，Refresh 清除）
    bool hint_consumed(size_t slot) const {
        return slot < consumed_.size() && consumed_[slot] != 0;
    }
    // 仍可被 Query 选中的 hint 数（kAllowUnsafeForTesting 下等于有效 hint 数）
    size_t FreeHintCount() const;

    // ---- 离线阶段 ----
    //
    // 客户端本地生成全部 hint。db 只需提供按**条目**取值的能力：第 i 个条目
    // 是 `entry_words` 个 128 位分量（决策 D38）。对测试与单机仿真即明文；
    // 真实部署中由两服务器的共享重建。
    void HintInit(const PirDatabase& db);

    const std::vector<VooPirHint>& hints() const { return hints_; }
    // 有效 hint 数（select_cutoff != 0）
    size_t ValidHintCount() const;

    // ---- 在线阶段 ----

    // 生成查询。注意本函数会消耗一个 dummy 偏移计数器。
    //
    // ⚠️ **会消费被选中的 hint 槽位**（kForbidReuse，默认）：拿到重建值后
    // 必须调用 `Refresh(q.hint_slot, q, material, value)` 把它换掉，否则该槽位
    // 不可再用（再次需要时抛 `HintsExhausted`）。理由见 HintReusePolicy 的注释。
    //
    // 抛出：`HintCoverageFailure`（索引未被任何 hint 覆盖，致命）
    //       `HintsExhausted`（覆盖它的 hint 都已被消费，需先 Refresh）
    VooPirQuery Query(uint64_t index);

    // 客户端重建：由两服务器应答恢复明文。
    //
    // ⚠️ 群运算是 `Z_{2^128}` 加法（决策 D37）：`β = sub(P_h, acc_true)`。
    // 依据：hint 覆盖集与应答子集的对称差恰为 `{x}`，在阿贝尔群中相消
    // ⇒ `Σ_覆盖集 − Σ_应答集 = DB[x]`（**方向固定**，实测见
    // `doc/design/vmpq_parity_alignment.md` §5：`parity − acc` 正确、反向恒错，
    // 且与 case A/B 无关）。
    //
    // 注意：本实现的构造保证 `filler_index` 项**不参与重建**（它只在验证等式里用），
    // 故半诚实路径下 `filler_value` 恒为 0。
    struct Reconstructed {
        // DB[x]：entry_words 个 128 位分量（标量条目时长度为 1）
        std::vector<uint128_t> value;
        uint128_t filler_value = 0;
    };
    Reconstructed Reconstruct(const VooPirQuery& q, const VooPirAnswer& a0,
                              const VooPirAnswer& a1);
    // 同义别名（保留以便调用方表达"不做验证"的语义；VMPQ 无验证层，D39）
    Reconstructed ReconstructRaw(const VooPirQuery& q, const VooPirAnswer& a0,
                                 const VooPirAnswer& a1) {
        return Reconstruct(q, a0, a1);
    }

    // Refresh：用 offline server 的输出替换被消耗的 hint 槽位。
    // 同时**清除该槽位的"已消费"标记**，使其重新可用（决策 D17）。
    struct RefreshMaterial {
        uint64_t hint_id = 0;
        uint32_t select_cutoff = 0;
        // 两个半区的 parity，按选择值命名（避免与"真实/非真实"混淆）：
        //   parity_below = Σ{ r_{J,k} · sel[k] <  c }   (mod 2^128)
        //   parity_above = Σ{ r_{J,k} · sel[k] >= c }   (mod 2^128)
        // ⚠️ 决策 D38：每个分量各一份和（长度 = entry_words），逐分量相加。
        std::vector<uint128_t> parity_below;
        std::vector<uint128_t> parity_above;
        uint32_t extra_part = 0;
        uint32_t extra_offset = 0;
    };
    void Refresh(size_t hint_slot, const VooPirQuery& q,
                 const RefreshMaterial& material,
                 const std::vector<uint128_t>& reconstructed_value);

    // 由 offline server 生成的补充材料（单进程仿真用；真实部署中由服务器计算）。
    //
    // ⚠️ 必须传入本次查询的目标索引：新 hint 在分区 ℓ 上由 extra 项占据，
    // 其 PRF 偏移项不属于覆盖集合，因此计算半区 parity 时要**跳过 ℓ**。
    RefreshMaterial GenerateRefreshMaterial(const PirDatabase& db,
                                            uint64_t target_index);

    // ---- 统计与调试 ----

    // 上一次 Query 命中的槽位（用于测试与诊断）；未命中为 SIZE_MAX
    size_t LastQuerySlot() const { return last_slot_; }
    // 是否发生过"找不到含目标索引的 hint"（致命失败）
    bool LastQueryFailed() const { return last_failed_; }
    // dummy 偏移流已消耗的计数
    uint64_t dummy_counter() const { return dummy_counter_; }

    // 在 hint 集合中查找包含 index 的槽位；找不到返回 SIZE_MAX。
    // kForbidReuse 下会**跳过已被消费**的槽位（故返回 SIZE_MAX 可能是
    // "覆盖失败"也可能是"都已被消费"，用 FindHintIgnoringConsumed 区分）。
    size_t FindHint(uint64_t index) const;

    // 忽略消费标记的查找（诊断/测试用；也用于把两种失效模式分开报错）
    size_t FindHintIgnoringConsumed(uint64_t index) const {
        return FindHintIn(params_, prf_, hints_, index);
    }

    // 列出所有覆盖 index 的槽位（含已消费的）。诊断与测试用：
    // 一个索引通常被 ~λ/2 条 hint 覆盖，这个数量决定了"刷新前还能查几次"。
    std::vector<size_t> HintsContaining(uint64_t index) const;

    // 纯函数形式，便于测试与复用
    static size_t FindHintIn(const VooPirParams& params, const AesPrf& prf,
                             const std::vector<VooPirHint>& hints,
                             uint64_t index);

    // 由 (α, β) 计算分区与分区内偏移
    static std::pair<uint32_t, uint32_t> Locate(const VooPirParams& params,
                                                uint64_t index);

    // 判断分区 k 是否属于该 hint 的真实集合
    static bool IsRealPartition(const AesPrf& prf, const VooPirHint& h,
                                uint32_t k);

    // 计算分区 k 在该 hint 下的偏移，已归约到 [0, params.part_size)
    static uint32_t HintOffset(const VooPirParams& params, const AesPrf& prf,
                               const VooPirHint& h, uint32_t k);

    // 按"两个累加器"语义处理一个查询（服务器侧）
    // db_entry(i) 返回第 i 个条目的**全部分量**（`const std::vector<uint128_t>&`，
    // 长度必须 >= params.entry_words；明文或本服务器的加法共享值）。
    //
    // ⚠️ 群运算是 `Z_{2^128}` 加法（决策 D37），**逐分量**进行（决策 D38）：
    // 服务器在自己那份**加法共享**上累加。`db_entry` 必须返回加法共享（RSS）；
    // 配 XOR 共享会静默错值（D12）。
    template <typename Fn>
    static VooPirAnswer Answer(const VooPirParams& params, const VooPirQuery& q,
                               Fn&& db_entry) {
        if (q.offsets.size() != params.part_num ||
            q.groups.size() != params.part_num) {
            throw std::invalid_argument(
                "VooPirClient::Answer: 查询集的长度必须等于分区数");
        }
        VooPirAnswer a;
        a.acc0.assign(static_cast<size_t>(params.entry_words), 0);
        a.acc1.assign(static_cast<size_t>(params.entry_words), 0);
        for (uint32_t k = 0; k < params.part_num; ++k) {
            const uint64_t idx =
                static_cast<uint64_t>(k) * params.part_size + q.offsets[k];
            const std::vector<uint128_t>& v = db_entry(idx);
            if (v.size() < params.entry_words) {
                throw std::invalid_argument(
                    "VooPirClient::Answer: 条目的分量数少于 entry_words");
            }
            for (uint64_t j = 0; j < params.entry_words; ++j) {
                if (q.groups[k]) {
                    a.acc1[j] = add(a.acc1[j], v[j]);
                } else {
                    a.acc0[j] = add(a.acc0[j], v[j]);
                }
            }
        }
        return a;
    }

private:
    VooPirParams params_;
    // AesPrf 持有 unique_ptr（不可拷贝），因此按引用保存。
    // 调用方必须保证 prf 的生命周期长于本对象。
    const AesPrf& prf_;
    std::vector<VooPirHint> hints_;
    // 每个槽位是否已被 Query 消费（kForbidReuse），由 Refresh 清除
    std::vector<uint8_t> consumed_;
    HintReusePolicy policy_ = HintReusePolicy::kForbidReuse;
    uint64_t dummy_counter_ = 0;
    uint64_t next_hint_id_ = 0;
    size_t last_slot_ = std::numeric_limits<size_t>::max();
    bool last_failed_ = false;

    // 下一个 dummy 分区内偏移
    uint16_t NextDummyOffset();
};

// ---------------------------------------------------------------------------
// FindCutoff：阈值选择（S3PIR §4.1 与官方 utils.cpp 的精确规则）
// ---------------------------------------------------------------------------

// 输入 P 个 32 位选择值，返回阈值 c。
// 返回值 0 表示该 hint 无效（过滤过头，或 cutoff 在区间内重复无法均分）。
//
// 规则：
//   LowerFilter = 1/2 − 1/16, UpperFilter = 1/2 + 1/16（32 位定点）
//   若区间两侧的元素数 >= P/2 则无效
//   否则取紧凑后区间的第 (P/2 − LowerCnt) 个顺序统计量
//   若该值在区间内重复，则无效
uint32_t FindCutoff(const uint32_t* prf_values, uint32_t part_num);

// 便利重载
uint32_t FindCutoff(const std::vector<uint32_t>& prf_values);

// 由 cutoff 计算真实分区集合
std::vector<uint32_t> RealPartitions(const uint32_t* prf_values, uint32_t part_num,
                                     uint32_t cutoff, bool indicator);

}  // namespace tsb
