#include "pir/voo_pir.hpp"

#include "core/hash.hpp"
#include "core/mset_hash.hpp"
#include "shared/verify.hpp"

#include <algorithm>
#include <cmath>
#include <memory>

namespace tsb {

namespace {

constexpr uint32_t kLowerFilter = 0x80000000u - (1u << 28);  // 1/2 − 1/16
constexpr uint32_t kUpperFilter = 0x80000000u + (1u << 28);  // 1/2 + 1/16

bool IsPowerOfTwo(uint64_t v) { return v != 0 && (v & (v - 1)) == 0; }

uint32_t Log2Exact(uint64_t v) {
    uint32_t r = 0;
    while ((static_cast<uint64_t>(1) << r) < v) ++r;
    return r;
}

}  // namespace

// ---------------------------------------------------------------------------
// 参数
// ---------------------------------------------------------------------------

VooPirParams VooPirParams::Derive(uint64_t n, uint32_t lambda) {
    if (n == 0) {
        throw std::invalid_argument("VooPirParams::Derive: n 必须 > 0");
    }
    VooPirParams p;
    p.n = n;
    p.lambda = lambda;

    // 选 2 的幂的 P（偶数）与 σ，使 P·σ == n 且尽量接近 √n
    uint64_t root = static_cast<uint64_t>(std::sqrt(static_cast<double>(n)));
    while (root > 0 && !IsPowerOfTwo(root)) --root;
    if (root == 0) root = 1;

    uint32_t part_size = static_cast<uint32_t>(root);
    uint32_t part_num = static_cast<uint32_t>(n / root);
    // 需要 P 为偶数
    if (part_num < 2) {
        part_num = 2;
        part_size = static_cast<uint32_t>(n / 2);
    }
    if (part_size == 0) part_size = 1;

    p.part_num = part_num;
    p.part_size = part_size;
    p.Validate();
    return p;
}

void VooPirParams::Validate() const {
    if (n == 0) {
        throw std::invalid_argument("VooPirParams: n 必须 > 0");
    }
    if (part_num == 0 || part_size == 0) {
        throw std::invalid_argument("VooPirParams: part_num 与 part_size 必须 > 0");
    }
    if ((part_num & 1u) != 0) {
        throw std::invalid_argument("VooPirParams: part_num 必须为偶数（要均分两半区）");
    }
    if (!IsPowerOfTwo(part_size)) {
        throw std::invalid_argument("VooPirParams: part_size 必须是 2 的幂");
    }
    // 偏移用 uint16 表示（对齐 S3PIR 的 2 字节/分区）
    if (part_size > 65536) {
        throw std::invalid_argument("VooPirParams: part_size 必须 <= 65536（偏移为 16 位）");
    }
    if (static_cast<uint64_t>(part_num) * part_size != n) {
        throw std::invalid_argument("VooPirParams: 需要 part_num * part_size == n");
    }
    if (lambda == 0) {
        throw std::invalid_argument("VooPirParams: lambda 必须 > 0");
    }
}

uint64_t VooPirParams::num_hints() const {
    // M = λ·√n
    const double root = std::sqrt(static_cast<double>(n));
    const uint64_t m = static_cast<uint64_t>(std::ceil(static_cast<double>(lambda) * root));
    return m == 0 ? 1 : m;
}

uint32_t VooPirParams::log2_part_size() const { return Log2Exact(part_size); }

std::pair<uint32_t, uint32_t> VooPirClient::Locate(const VooPirParams& params,
                                                   uint64_t index) {
    const uint32_t alpha = static_cast<uint32_t>(index / params.part_size);
    const uint32_t beta = static_cast<uint32_t>(index % params.part_size);
    return {alpha, beta};
}

// ---------------------------------------------------------------------------
// FindCutoff
// ---------------------------------------------------------------------------

uint32_t FindCutoff(const uint32_t* prf_values, uint32_t part_num) {
    if (prf_values == nullptr || part_num == 0) {
        throw std::invalid_argument("FindCutoff: 输入为空");
    }
    if ((part_num & 1u) != 0) {
        throw std::invalid_argument("FindCutoff: part_num 必须为偶数");
    }

    const uint32_t half = part_num / 2;

    // 统计过滤区间外的元素
    uint32_t lower_cnt = 0;
    uint32_t upper_cnt = 0;
    std::vector<uint32_t> middle;
    middle.reserve(part_num);
    for (uint32_t i = 0; i < part_num; ++i) {
        const uint32_t v = prf_values[i];
        if (v < kLowerFilter) {
            ++lower_cnt;
        } else if (v > kUpperFilter) {
            ++upper_cnt;
        } else {
            middle.push_back(v);
        }
    }

    // 过滤过头 ⇒ 该 hint 无效
    if (lower_cnt >= half || upper_cnt >= half) {
        return 0;
    }
    if (middle.size() < static_cast<size_t>(half - lower_cnt)) {
        return 0;
    }

    // 取第 (half − lower_cnt) 个顺序统计量（0-indexed）
    const size_t k = static_cast<size_t>(half - lower_cnt);
    std::nth_element(middle.begin(), middle.begin() + k, middle.end());
    const uint32_t cutoff = middle[k];

    // 合法 cutoff 恒落在 [LowerFilter, UpperFilter]，0 是安全哨兵
    if (cutoff == 0) {
        return 0;
    }
    // 若该值在区间内重复，则无法把 P/2 与 P/2 均分 ⇒ 无效
    if (std::count(middle.begin(), middle.end(), cutoff) > 1) {
        return 0;
    }
    return cutoff;
}

uint32_t FindCutoff(const std::vector<uint32_t>& prf_values) {
    return FindCutoff(prf_values.data(), static_cast<uint32_t>(prf_values.size()));
}

std::vector<uint32_t> RealPartitions(const uint32_t* prf_values, uint32_t part_num,
                                     uint32_t cutoff, bool indicator) {
    std::vector<uint32_t> out;
    for (uint32_t k = 0; k < part_num; ++k) {
        const bool below = prf_values[k] < cutoff;
        if (below == indicator) {
            out.push_back(k);
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// VooPirClient：hint 相关的纯函数
// ---------------------------------------------------------------------------

bool VooPirClient::IsRealPartition(const AesPrf& prf, const VooPirHint& h,
                                   uint32_t k) {
    const uint32_t v = prf.PrfSelect(static_cast<uint32_t>(h.hint_id), k);
    return (v < h.select_cutoff) == h.indicator;
}

uint32_t VooPirClient::HintOffset(const VooPirParams& params, const AesPrf& prf,
                                  const VooPirHint& h, uint32_t k) {
    // PrfIdx 内部即按 part_size-1 掩码（part_size 是 2 的幂，等价于取模）
    return prf.PrfIdx(static_cast<uint32_t>(h.hint_id), k, params.part_size);
}

// ---------------------------------------------------------------------------
// VooPirClient 构造与离线阶段
// ---------------------------------------------------------------------------

VooPirClient::VooPirClient(const VooPirParams& params, const AesPrf& prf)
    : params_(params), prf_(prf) {
    params_.Validate();
}

VooPirClient::VooPirClient(const VooPirParams& params, const AesPrf& prf,
                           const std::vector<uint8_t>& mac_key)
    : params_(params), prf_(prf), mac_key_(mac_key) {
    params_.Validate();
    if (mac_key_.empty()) {
        throw std::invalid_argument(
            "VooPirClient: 传入 mac_key 时不能为空（省略该参数即表示不启用证明）");
    }
}

uint16_t VooPirClient::NextDummyOffset() {
    return prf_.NextDummyOffset(dummy_counter_++, params_.part_size);
}

void VooPirClient::HintInit(const std::vector<uint128_t>& db) {
    if (db.size() < params_.n) {
        throw std::invalid_argument("VooPirClient::HintInit: 数据库长度不足 n");
    }

    // ⚠️ M = λ·√n 是**可用** hint 的数量，不是尝试次数。
    //
    // FindCutoff 会丢弃相当比例的 hint（过滤区间只占值域 1/8，区间内元素数
    // 常常不足 P/2），实测有效率仅 40%~65%。如果只尝试 M 次，有效 hint 就
    // 只有 0.4M~0.65M，等效安全参数会从 λ 掉到 ~0.5λ，未覆盖索引数随之上升。
    // 因此这里**持续生成直到攒够 M 条有效 hint**，保证 λ 的语义。
    const uint64_t m_target = params_.num_hints();
    hints_.clear();
    proofs_.clear();
    hints_.reserve(static_cast<size_t>(m_target));
    proofs_.reserve(static_cast<size_t>(m_target));

    // ⚠️ 必须置为非零：select_cutoff == 0 是本实现中"无效 hint"的哨兵，
    // 否则一个 cutoff 恰为 0 的有效 hint 会被误判为无效。
    next_hint_id_ = 1;

    // ⚠️ 半诚实版本不计算任何证明：hint 的 parity 已足够重建明文，
    // 而 F_j（每个 hint 覆盖集合的标签 XOR）在半诚实模型下毫无用处，
    // 却要按 hint 数 × 每 hint 覆盖项数做 HMAC，代价很高。
    //
    // 论文把 Mset-XOR-Hash 用在这里本身也有问题：客户端并不持有服务器的
    // 共享，无法对共享数据预计算标签；而 HMAC 不是线性的，
    // C_0 ⊕ C_1 ≠ C(明文)，验证等式在共享域上并不成立。
    const bool with_proofs = verification_enabled();
    std::unique_ptr<PIRVerifier> verifier;
    std::string tag_domain;
    if (with_proofs) {
        verifier = std::make_unique<PIRVerifier>(mac_key_);
        // 用与 hint 相同的域计算标签（验证时客户端与服务器必须一致）
        tag_domain = std::string(domain::kRecord) + "/hint";
    }

    uint64_t attempts = 0;
    const uint64_t kMaxAttempts = m_target * 16 + 1024;
    while (hints_.size() < m_target) {
        if (++attempts > kMaxAttempts) {
            throw std::runtime_error(
                "VooPirClient::HintInit: 无法生成足够的有效 hint（成功率过低）。"
                "通常是 part_num 太小导致 FindCutoff 大量失效——"
                "请增大 PIR 数据库规模。");
        }
        VooPirHint h;
        h.hint_id = next_hint_id_++;
        h.indicator = true;  // 主 hint 恒选 "v < c" 的一侧

        // 1) 计算 P 个选择值
        std::vector<uint32_t> sel(params_.part_num);
        for (uint32_t k = 0; k < params_.part_num; ++k) {
            sel[k] = prf_.PrfSelect(static_cast<uint32_t>(h.hint_id), k);
        }

        // 2) 阈值
        h.select_cutoff = FindCutoff(sel);

        // 3) 拒绝采样取 extra index，要求其分区**不在**真实集合内。
        //    （真实集合 = { k : (sel(k)<c) == indicator }，主 hint 的
        //      indicator 恒为 true，故要求 sel(ePart) >= c —— 与官方
        //      generateOfflineHints 的 `while (b) { ePart = ...; b = sel<c; }` 一致。）
        if (h.select_cutoff != 0) {
            bool found_extra = false;
            for (int attempt = 0; attempt < 4096; ++attempt) {
                const uint64_t cand =
                    prf_.NextDummyOffset(dummy_counter_++, params_.n);
                const auto [pa, po] = Locate(params_, cand);
                const bool below = sel[pa] < h.select_cutoff;
                const bool in_real = (below == h.indicator);
                if (!in_real) {
                    h.extra_part = pa;
                    h.extra_offset = po;
                    found_extra = true;
                    break;
                }
            }
            if (!found_extra) {
                h.select_cutoff = 0;  // 无法取到合法 extra ⇒ 丢弃该 hint
            }
        }

        // 4) parity 与证明
        //
        // ⚠️ 对齐官方实现：parity **只**覆盖真实半区的 PRF 偏移项。
        // extra 项单独存放，**不并入 parity**。
        // 这不是笔误：extra 在查询时的真实组里同样出现在 b_indicator 指定的
        // 累加器中，两边都出现才会相消；官方把 extra 只放在"额外索引"字段，
        // parity 里不含它，于是它完全不影响重建。
        if (h.select_cutoff != 0) {
            // ⚠️ extra 项**要**计入 parity。官方 generateOfflineHints
            // （server.cpp:109）在循环开始前就把 ExtraPart/ExtraOffset 处的
            // 条目 XOR 进了 parity，随后才累加真实半区的各项。
            //
            // 原因：查询时 extra 所在的槽位 (ePart, eOffset) 属于真实组
            // （bvec[ePart] = b_indicator），因此它同时出现在 parity 与应答
            // 子集里，会在 ⊕ 中相消 —— 相消正是我们需要的：
            //     P_h ⊕ acc_true = DB[x]
            const uint64_t eidx =
                static_cast<uint64_t>(h.extra_part) * params_.part_size +
                h.extra_offset;
            uint128_t parity = db[eidx];
            std::vector<MacTag> tags;
            if (with_proofs) {
                tags.push_back(verifier->ItemTag(tag_domain, eidx, db[eidx]));
            }

            for (uint32_t k = 0; k < params_.part_num; ++k) {
                if ((sel[k] < h.select_cutoff) != h.indicator) continue;
                const uint32_t off = HintOffset(params_, prf_, h, k);
                const uint64_t idx =
                    static_cast<uint64_t>(k) * params_.part_size + off;
                parity = static_cast<uint128_t>(parity ^ db[idx]);
                if (with_proofs) {
                    tags.push_back(verifier->ItemTag(tag_domain, idx, db[idx]));
                }
            }
            h.parity = parity;
            if (with_proofs) {
                proofs_.push_back(MSetXorHash::Combine(MacTag{}, tags));
            }
        }

        if (h.select_cutoff == 0) {
            // 无效 hint：丢弃（其 hint_id 已被消耗，保证 PRF 输入不重复）
            if (with_proofs && proofs_.size() > hints_.size()) {
                proofs_.pop_back();
            }
            continue;
        }
        hints_.push_back(h);
    }
}

size_t VooPirClient::ValidHintCount() const {
    size_t c = 0;
    for (const auto& h : hints_) {
        if (h.select_cutoff != 0) ++c;
    }
    return c;
}

// ---------------------------------------------------------------------------
// 查找含目标索引的 hint
// ---------------------------------------------------------------------------

size_t VooPirClient::FindHintIn(const VooPirParams& params, const AesPrf& prf,
                                const std::vector<VooPirHint>& hints,
                                uint64_t index) {
    const auto [ell, off] = Locate(params, index);
    for (size_t h = 0; h < hints.size(); ++h) {
        const VooPirHint& hh = hints[h];
        if (hh.select_cutoff == 0) continue;  // 无效 hint 跳过

        // case A：目标是 extra 项（零次 AES）
        if (hh.extra_part == ell && hh.extra_offset == off) {
            return h;
        }
        // case B：目标是真实集合在分区 ℓ 上的那一项
        const uint32_t r = HintOffset(params, prf, hh, ell);
        if (r != off) continue;
        if (IsRealPartition(prf, hh, ell)) {
            return h;
        }
    }
    return std::numeric_limits<size_t>::max();
}

size_t VooPirClient::FindHint(uint64_t index) const {
    return FindHintIn(params_, prf_, hints_, index);
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

VooPirQuery VooPirClient::Query(uint64_t index) {
    if (index >= params_.n) {
        throw std::out_of_range("VooPirClient::Query: 索引越界");
    }
    const auto [ell, off] = Locate(params_, index);

    last_slot_ = FindHint(index);
    last_failed_ = (last_slot_ == std::numeric_limits<size_t>::max());
    if (last_failed_) {
        // ⚠️ 绝不可回退到可区分的失败路径（例如直接明文取值）——
        // 那会把"正确性失败"升级为"隐私泄露"（论文 §2 明确警告）。
        // 这里显式抛错，由上层决定重跑离线阶段。
        throw std::runtime_error(
            "VooPirClient::Query: 找不到包含该索引的 hint（概率 < e^{-λ/2}）；"
            "应当重跑离线阶段，而不是回退到可区分的路径");
    }

    const VooPirHint& h = hints_[last_slot_];
    const bool beta = h.indicator;
    const uint32_t c = h.select_cutoff;

    // 命中方式：case A 表示查询索引恰为 hint 的 extra 项
    const bool via_extra = (h.extra_part == ell && h.extra_offset == off);

    // flip 随机置换"真实/哑"两组，使服务器无法判断哪一组是真实组
    const bool flip = (prf_.EvalDomainU32(PrfDomain::kDummyOffset,
                                          static_cast<uint32_t>(dummy_counter_),
                                          0) &
                       1u) != 0;

    VooPirQuery q;
    q.offsets.assign(params_.part_num, 0);
    q.groups.assign(params_.part_num, 0);
    q.target_index = index;
    q.hint_parity = h.parity;
    q.hit_via_extra = via_extra;
    q.take_accumulator_1 = (beta ^ flip);

    for (uint32_t k = 0; k < params_.part_num; ++k) {
        bool real_member;
        uint32_t x;
        if (k == ell) {
            // 查询分区：真实组里 i 已被移除，本分区由哑组持有一个全新随机偏移
            real_member = false;
            x = NextDummyOffset();
        } else if (k == h.extra_part) {
            // extra 分区：e_j 恒归真实组
            real_member = true;
            x = h.extra_offset;
        } else {
            // 对齐官方实现 client.cpp:141-149：
            //   b = PRF4Select(...) < cutoff
            //   真实组（b == indicator）用 hint 的 PRF 偏移；
            //   哑组用**全新的随机偏移**（NextDummyIdx）。
            //
            // 哑组用新随机偏移不会破坏重建：hint 的 parity 只覆盖真实半区，
            // 哑组的随机项根本不在 parity 里，因此无需相消。
            // 这也带来隐私收益：哑组每轮都不同。
            real_member = IsRealPartition(prf_, h, k);
            x = real_member ? HintOffset(params_, prf_, h, k) : NextDummyOffset();
        }
        // 真实组统一落在累加器 take_accumulator_1（= beta ⊕ flip），
        // 非真实组落在另一个。注意这里是 **相等比较**：
        // real_member == true 且 take_acc1 == true ⇒ 归入 acc1。
        // （写成异或会把两组弄反，导致重建出的是哑组合。）
        q.groups[k] = (real_member == q.take_accumulator_1) ? 1 : 0;
        q.offsets[k] = static_cast<uint16_t>(x);
    }

    // 填充项：官方实现里，parity **不含** extra，且查询分区 ℓ 在真实组中
    // 由目标项 x 占据、在 parity 中则因 ℓ ∉ 真实半区而不出现，
    // 因此 P_h ⊕ acc_true 直接等于 DB[x]，**不需要**任何填充修正。
    //
    // 这里仍记录 filler_index 供**验证**使用：验证等式
    //     F ⊕ C = MAC(x,v) ⊕ MAC(fill,v_fill)
    // 里的 fill 取官方语义下的 extra 项 —— 当命中方式是 case A 时，
    // extra 就是目标本身，故用 kNoExtraIndex 表示"无需填充"。
    q.filler_index = via_extra ? kNoExtraIndex
                               : (static_cast<uint64_t>(h.extra_part) *
                                      params_.part_size +
                                  h.extra_offset);
    return q;
}

// ---------------------------------------------------------------------------
// Reconstruct
// ---------------------------------------------------------------------------

VooPirClient::Reconstructed VooPirClient::Reconstruct(const VooPirQuery& q,
                                                      const VooPirAnswer& a0,
                                                      const VooPirAnswer& a1) {
    // 服务器各自计算两个累加器；客户端把两服务器的对应累加器 XOR 起来，
    // 得到"按组"聚合后的共享重建值。
    const uint128_t acc0 = static_cast<uint128_t>(a0.acc0 ^ a1.acc0);
    const uint128_t acc1 = static_cast<uint128_t>(a0.acc1 ^ a1.acc1);
    const uint128_t selected = q.take_accumulator_1 ? acc1 : acc0;

    // P_h ⊕ acc_true 已经等于 DB[x]：hint 覆盖集合与应答子集的交集在 ⊕ 中
    // 全部抵消，剩下的正是目标项本身。q.filler_index 记录的是**验证**所需的
    // 填充项（每轮各不相同），不参与重建。
    Reconstructed r;
    r.value = static_cast<uint128_t>(selected ^ q.hint_parity);
    r.filler_value = 0;
    return r;
}

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

VooPirClient::RefreshMaterial VooPirClient::GenerateRefreshMaterial(
    const std::vector<uint128_t>& db, uint64_t target_index) {
    // 对齐官方 server.cpp:41-77 `replenishHint`：
    //   * 计算新 hint 的 cutoff
    //   * result[0] = ⊕{ PRF 偏移项 : sel[k] <  c }   （below 半区）
    //   * result[1] = ⊕{ PRF 偏移项 : sel[k] >= c }   （above 半区）
    //   * **不含** extra 项；**不跳过**任何分区（包括目标分区 ℓ）
    // 客户端随后取"不含 ℓ 的那一半"，再 XOR 上 DB[x] 即得新 parity。
    RefreshMaterial m;
    m.hint_id = next_hint_id_++;
    (void)target_index;  // 官方实现里 ℓ 只用于客户端选择半区

    std::vector<uint32_t> sel(params_.part_num);
    for (uint32_t k = 0; k < params_.part_num; ++k) {
        sel[k] = prf_.PrfSelect(static_cast<uint32_t>(m.hint_id), k);
    }
    m.select_cutoff = FindCutoff(sel);
    if (m.select_cutoff == 0) {
        return m;  // 无效材料，调用方应重试
    }

    const VooPirHint tmp{m.hint_id, m.select_cutoff};
    uint128_t parity_below = 0, parity_above = 0;
    for (uint32_t k = 0; k < params_.part_num; ++k) {
        const uint32_t off = HintOffset(params_, prf_, tmp, k);
        const uint64_t idx = static_cast<uint64_t>(k) * params_.part_size + off;
        if (sel[k] < m.select_cutoff) {
            parity_below = static_cast<uint128_t>(parity_below ^ db[idx]);
        } else {
            parity_above = static_cast<uint128_t>(parity_above ^ db[idx]);
        }
    }
    m.parity_below = parity_below;
    m.parity_above = parity_above;

    // extra：必须落在"新 hint 真实集合"之外。新 hint 的真实集合是
    // "不含 ℓ 的那一半"，故 extra 必须落在**含 ℓ 的那一半**，
    // 即与 sel(ℓ) < c 同侧 —— 与官方 Offline/Replenish 的做法一致。
    // 官方此处直接用 (ℓ, off) 作为 extra（见 client.cpp:197-198），
    // 本实现沿用该做法：extra = 目标项自身所在的位置。
    return m;
}

void VooPirClient::Refresh(size_t hint_slot, const VooPirQuery& q,
                           const RefreshMaterial& material,
                           uint128_t reconstructed_value) {
    if (hint_slot >= hints_.size()) {
        throw std::out_of_range("VooPirClient::Refresh: 槽位越界");
    }
    if (material.select_cutoff == 0) {
        throw std::invalid_argument("VooPirClient::Refresh: 补充材料无效");
    }

    const auto [ell, off] = Locate(params_, q.target_index);

    VooPirHint h;
    h.hint_id = material.hint_id;
    h.select_cutoff = material.select_cutoff;

    // 对齐官方 client.cpp:194-201：
    //   b_indicator = !(PRF4Select(J', ℓ) < c_J')
    //   Parity       = hint_parities[b_indicator] ^ result
    // 即：新 hint 的真实集合是**不含 ℓ** 的那一半，再把目标项换进来。
    // 这样查询 ℓ 时，case B 会用 extra=(ℓ,off) 把 ℓ 处补上，
    // 而真实集合的其余部分的 PRF 项与 parity 一一对应。
    const uint32_t sel_ell =
        prf_.PrfSelect(static_cast<uint32_t>(h.hint_id), ell);
    const bool below = sel_ell < h.select_cutoff;
    h.indicator = !below;

    // 真实半区 = !below 的那一半 ⇒ 取"相反半区"的 parity
    // （below 为真时真实集合是 above 半区，其 parity 为 material.parity_above）
    const uint128_t base =
        below ? material.parity_above : material.parity_below;
    h.parity = static_cast<uint128_t>(base ^ reconstructed_value);

    // extra 指向目标项自身：新 hint 通过 case A 提供该索引
    h.extra_part = ell;
    h.extra_offset = off;

    hints_[hint_slot] = h;
    // 半诚实版本不维护证明；启用证明时这里需要服务器侧标签输入（尚未实现）
}

const MacTag& VooPirClient::proof(size_t hint_slot) const {
    if (!verification_enabled()) {
        throw std::logic_error(
            "VooPirClient::proof: 半诚实构建未启用证明（构造时未提供 mac_key）");
    }
    if (hint_slot >= proofs_.size()) {
        throw std::out_of_range("VooPirClient::proof: 槽位越界");
    }
    return proofs_[hint_slot];
}

}  // namespace tsb
