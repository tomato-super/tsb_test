#pragma once

// V-OO-PIR —— 可验证的 offline/online PIR（VMPQ 论文 §III）。
//
// 实现依据：doc/design/PIR_SPEC.md（由 S3PIR 官方实现交叉核对）。
// 关键规格裁决（决策 D7）：阈值规则以 S3PIR 的 `FindCutoff` 为准，**不取 median**。
//
// ⚠️ **parity 语义是 XOR**，因此参与的 entry 必须采用 XOR 共享
// （等价于 Z_2 上的加法共享）。决策 D12 已证明加法共享不保持 XOR 同态。
// 本模块的接口因此一律以"entry 的整值"为单位做 ⊕，不涉及域内加法。
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
#include "core/hash.hpp"

namespace tsb {

// 查询子集中"没有额外项"的哨兵值
constexpr uint64_t kNoExtraIndex = std::numeric_limits<uint64_t>::max();

// ---------------------------------------------------------------------------
// 参数
// ---------------------------------------------------------------------------

struct VooPirParams {
    uint64_t n = 0;        // 数据库条目数
    uint32_t part_num = 0;  // 分区数 P（2 的幂、偶数）
    uint32_t part_size = 0;  // 每分区条目数 σ（2 的幂）
    uint32_t lambda = 80;    // 安全参数，M = lambda * sqrt(n)

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
    uint128_t parity = 0;      // P_j

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
    // 填充索引：哑组中"本应属于 hint 真实集合、但被替换掉"的那一项。
    // 它同时出现在 hint parity 与应答子集中，因此在重建时抵消。
    // case A（目标是 extra 项）时为 kNoExtraIndex。
    uint64_t filler_index = kNoExtraIndex;
    uint128_t hint_parity = 0;  // P_h
    bool take_accumulator_1 = false;  // 真实组落在累加器 1（否则累加器 0）
    // 命中方式：true = case A（查询索引恰为 hint 的 extra 项）
    bool hit_via_extra = false;
};

// 服务器应答：两个累加器
struct VooPirAnswer {
    uint128_t acc0 = 0;
    uint128_t acc1 = 0;
};

// ---------------------------------------------------------------------------
// 客户端持有的 hint 集合与本地状态
// ---------------------------------------------------------------------------

class VooPirClient {
public:
    // ⚠️ 半诚实版本**不需要证明**：服务器不会篡改应答，因此不计算 hint 证明 F_j，
    // 也不需要 MAC 密钥。这是默认行为（两参数构造）。
    VooPirClient(const VooPirParams& params, const AesPrf& prf);

    // 需要证明时提供 mac_key（恶意模型 / 后续扩展）。此时才会计算 F_j。
    VooPirClient(const VooPirParams& params, const AesPrf& prf,
                 const std::vector<uint8_t>& mac_key);

    // 是否启用证明
    bool verification_enabled() const { return !mac_key_.empty(); }

    const VooPirParams& params() const { return params_; }

    // ---- 离线阶段 ----
    //
    // 客户端本地生成全部 hint。db 只需提供按索引取值的能力
    // （对测试与单机仿真即明文；真实部署中由两服务器的共享重建）。
    void HintInit(const std::vector<uint128_t>& db);

    const std::vector<VooPirHint>& hints() const { return hints_; }
    // 有效 hint 数（select_cutoff != 0）
    size_t ValidHintCount() const;

    // F_j：hint 覆盖集合的标签 XOR（纯 XOR，见决策 D13）。
    // ⚠️ 仅在 verification_enabled() 为真时可用；半诚实构建下调用会抛异常
    // （而不是返回一个无意义的零标签）。
    const MacTag& proof(size_t hint_slot) const;

    // ---- 在线阶段 ----

    // 生成查询。注意本函数会消耗一个 dummy 偏移计数器。
    VooPirQuery Query(uint64_t index);

    // 客户端重建：由两服务器应答恢复明文。
    //
    // ⚠️ **必须同时提供填充值**。由 hint 的 parity 与应答子集 XOR 得到的是
    //
    //       P_h ⊕ acc_true = DB[x] ⊕ DB[filler]
    //
    // 而不是裸的 DB[x]：填充项同时出现在 P_h 的覆盖集合与应答子集里，本应
    // 相互抵消 —— 但它只在"哑组被迫取 e_J 的槽位"时才会出现两次。为避免
    // 依赖这种偶然性，客户端显式把填充值再 XOR 一次，得到真正的 DB[x]；
    // 该填充值同时是验证等式 F ⊕ C = MAC(x,v) ⊕ MAC(fill,v_fill) 的输入。
    //
    // 注意：若查询分区 ℓ 恰为 hint 的 extra 分区，则 xor_value 已经是
    // DB[x]（填充项与目标项互相抵消），此时 filler_value 应为 0。
    struct Reconstructed {
        uint128_t value = 0;  // DB[x]
        MacTag combined_c{};  // C_0 ⊕ C_1（半诚实版本为零）
        uint128_t filler_value = 0;
    };
    Reconstructed Reconstruct(const VooPirQuery& q, const VooPirAnswer& a0,
                              const VooPirAnswer& a1);
    // 同义别名（保留以便调用方表达"尚未做验证"的语义）
    Reconstructed ReconstructRaw(const VooPirQuery& q, const VooPirAnswer& a0,
                                 const VooPirAnswer& a1) {
        return Reconstruct(q, a0, a1);
    }

    // Refresh：用 offline server 的输出替换被消耗的 hint 槽位
    struct RefreshMaterial {
        uint64_t hint_id = 0;
        uint32_t select_cutoff = 0;
        // 两个半区的 parity，按选择值命名（避免与"真实/非真实"混淆）：
        //   parity_below = ⊕{ r_{J,k} · sel[k] <  c }
        //   parity_above = ⊕{ r_{J,k} · sel[k] >= c }
        uint128_t parity_below = 0;
        uint128_t parity_above = 0;
        uint32_t extra_part = 0;
        uint32_t extra_offset = 0;
    };
    void Refresh(size_t hint_slot, const VooPirQuery& q,
                 const RefreshMaterial& material, uint128_t reconstructed_value);

    // 由 offline server 生成的补充材料（单进程仿真用；真实部署中由服务器计算）。
    //
    // ⚠️ 必须传入本次查询的目标索引：新 hint 在分区 ℓ 上由 extra 项占据，
    // 其 PRF 偏移项不属于覆盖集合，因此计算半区 parity 时要**跳过 ℓ**。
    RefreshMaterial GenerateRefreshMaterial(const std::vector<uint128_t>& db,
                                            uint64_t target_index);

    // ---- 统计与调试 ----

    // 上一次 Query 命中的槽位（用于测试与诊断）；未命中为 SIZE_MAX
    size_t LastQuerySlot() const { return last_slot_; }
    // 是否发生过"找不到含目标索引的 hint"（致命失败）
    bool LastQueryFailed() const { return last_failed_; }
    // dummy 偏移流已消耗的计数
    uint64_t dummy_counter() const { return dummy_counter_; }

    // 在 hint 集合中查找包含 index 的槽位；找不到返回 SIZE_MAX
    size_t FindHint(uint64_t index) const;

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
    // db_entry(i) 返回第 i 个条目的值（明文或共享值）
    template <typename Fn>
    static VooPirAnswer Answer(const VooPirParams& params, const VooPirQuery& q,
                               Fn&& db_entry) {
        VooPirAnswer a;
        for (uint32_t k = 0; k < params.part_num; ++k) {
            const uint64_t idx =
                static_cast<uint64_t>(k) * params.part_size + q.offsets[k];
            const uint128_t v = db_entry(idx);
            if (q.groups[k]) {
                a.acc1 = static_cast<uint128_t>(a.acc1 ^ v);
            } else {
                a.acc0 = static_cast<uint128_t>(a.acc0 ^ v);
            }
        }
        return a;
    }

private:
    VooPirParams params_;
    // AesPrf 持有 unique_ptr（不可拷贝），因此按引用保存。
    // 调用方必须保证 prf 的生命周期长于本对象。
    const AesPrf& prf_;
    std::vector<uint8_t> mac_key_;
    std::vector<VooPirHint> hints_;
    std::vector<MacTag> proofs_;
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
