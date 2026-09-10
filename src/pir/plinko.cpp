// Plinko 实现（MPRAQ 的检索底座，任务 PIR-04）。
// 构造/接口/论文出处的完整说明见 pir/plinko.hpp 的文件头；本文件的四段结构：
//   §1 参数校验与派生（PLINKO_SPEC §1）
//   §2 客户端构造：c 个长期持有的 iPRF 求值器 + 紧凑子集（位图）
//   §3 算法 1/2：HintInit（只用 IF⁻¹）、GetHint（候选检查，勘误 ②③⑦）
//   §4 算法 3/4/5/6：QueryGen / ServerResp / ClientRecon / Verify
//
// ⚠️ 与论文的三处落地差异（详见 plinko.hpp §4 的 ⑦⑧ 与下面的注释）：
//   * 提升 hint 必须做"α ∈ E"检查、且返回 **η 折算后**的有效区块集（论文 Fig 7 两者都漏）；
//   * 哑偏移必须放在**补集**上（论文 Fig 7 的即打印文本把它放在了覆盖集上，那是错的）；
//   * 论文的随机枚举顺序改成**按下标升序**（确定性、const、可复现；选择顺序不影响正确性，
//     且服务器不可见 —— 与"随机顺序"在可观测层面等价）。

#include "pir/plinko.hpp"

#include <algorithm>
#include <numeric>
#include <string>

namespace tsb {

namespace {

// 确定性随机流的根密钥（编译期常量 ⇒ 跨进程/跨次运行可复现，铁律 D6；
// 与 core/iprf 的 kDeterministicRootKey 同做法）。
constexpr std::array<uint8_t, kAesKeyBytes> kPlinkoRootKey = {
    't', 's', 'b', ':', 'p', 'l', 'i', 'n', 'k', 'o', '/', 'd', 'e', 't', '/', 'r'};

// iPRF 定义域上界（core/iprf 的硬约束：AES 输入块的 32 位字宽）
constexpr uint64_t kMaxIprfDomain = static_cast<uint64_t>(1) << 32;

bool IsPowerOfTwo(uint64_t v) { return v != 0 && (v & (v - 1)) == 0; }

size_t BitmapWordsFor(uint64_t blocks) { return static_cast<size_t>((blocks + 63) / 64); }

const PlinkoParams& Checked(const PlinkoParams& p) {
    p.Validate();
    return p;
}

std::string Num(uint64_t v) { return std::to_string(v); }

}  // namespace

// ---------------------------------------------------------------------------
// §1 参数
// ---------------------------------------------------------------------------

void PlinkoParams::Validate() const {
    if (n < 1) {
        throw std::invalid_argument("PlinkoParams: n 必须 >= 1（实际 " + Num(n) + "）");
    }
    if (w < 1) {
        throw std::invalid_argument("PlinkoParams: w 必须 >= 1（实际 " + Num(w) + "）");
    }
    if (!IsPowerOfTwo(w)) {
        // D21：range(= 区块大小 w) 必须是 2 的幂，否则 PMNS 二叉树出现 p ≠ 1/2 的节点，
        // 论文 Fig 4 的去随机化二项采样退化为 O(count) 慢路径（core/iprf 直接拒绝）。
        throw std::invalid_argument(
            "PlinkoParams: w 必须是 2 的幂（决策 D21：w 是 iPRF 的值域，非 2 的幂会让 PMNS 退化，"
            "核心底座 core/iprf 会拒绝该输入）。实际 w = " + Num(w));
    }
    if (n % w != 0) {
        // 给出"补齐到多少"的建议：补齐由**上层**负责（D15(a)：数据库补齐到 2 的幂），
        // 本层绝不偷偷改 n。
        const uint64_t c_up = (n + w - 1) / w;
        const uint64_t c_even = (c_up + 1) & ~static_cast<uint64_t>(1);
        throw std::invalid_argument(
            "PlinkoParams: n 必须是 w 的整数倍（n = c·w，c = 区块数）。实际 n = " + Num(n) +
            "、w = " + Num(w) + "；建议由上层把条目数补齐到 " + Num(c_even * w) +
            "（补齐口径见 D15(a)）。");
    }
    const uint64_t c = n / w;
    if (c < 2) {
        throw std::invalid_argument(
            "PlinkoParams: c = n/w 必须 >= 2（实际 c = " + Num(c) +
            "）。n = w（c = 1）是退化几何：每条 hint 要选 c/2+1 个区块、补集要与其对称，"
            "c = 1 时两者不可能同时成立。");
    }
    if (c % 2 != 0) {
        // PLINKO_SPEC §5.5：|E\{α}| = c/2 必须与补集 c/2 严格相等 ⇒ c 必须是偶数
        // （否则 c/2+1 个区块的主 hint 去掉 α 后是 ⌊c/2⌋ 个，与补集不对称，两半规模不等 ⇒ 隐私破）。
        throw std::invalid_argument(
            "PlinkoParams: c = n/w 必须是**偶数**（PLINKO_SPEC §5.5：c/2+1 个区块的主 hint 去掉 α 后"
            "必须与补集同为 c/2 个）。实际 c = " + Num(c) + "；建议由上层把条目数补齐到 " +
            Num((c + 1) * w) + "。");
    }
    if (lambda == 0) {
        throw std::invalid_argument("PlinkoParams: lambda 必须 >= 1");
    }
    if (!(prp_epsilon > 0.0) || prp_epsilon >= 1.0) {
        throw std::invalid_argument("PlinkoParams: prp_epsilon 必须落在 (0,1)（实际 " +
                                    std::to_string(prp_epsilon) + "）");
    }
    if (w > kMaxIprfDomain) {
        throw std::invalid_argument("PlinkoParams: w 过大（要求 <= 2^32，见 core/iprf 的域宽约束）");
    }
    // λw 溢出与规模检查
    const uint64_t lam = lambda;
    if (lam > (kMaxIprfDomain * 4) / w) {
        throw std::invalid_argument("PlinkoParams: λw 过大/溢出（λ = " + Num(lam) + "、w = " + Num(w) +
                                    "）");
    }
    const uint64_t m = lam * w;
    if (m / 2 < 1) {
        throw std::invalid_argument("PlinkoParams: q = λw/2 必须 >= 1（需要 λw >= 2）");
    }
    const uint64_t h = m + m / 2;
    if (h > kMaxIprfDomain) {
        throw std::invalid_argument(
            "PlinkoParams: H = λw + q = " + Num(h) +
            " 超过 2^32 —— iPRF 的定义域是 [H)，受 AES 输入块的 32 位字宽限制（见 core/iprf）。"
            "请减小 λ 或 w。");
    }
}

PlinkoParams PlinkoParams::Derive(uint64_t n, uint32_t lambda, double prp_epsilon) {
    if (n < 4) {
        throw std::invalid_argument(
            "PlinkoParams::Derive: n 必须 >= 4（最小合法几何是 n = 4, w = 2, c = 2）");
    }
    // PLINKO_SPEC §1：默认 w = 2^⌈log₂√n⌉（此时 λw = λ√n，与 MPARQ.tex 的 M 一致）
    uint64_t w = 1;
    while (w < (static_cast<uint64_t>(1) << 31) && w * w < n) w *= 2;
    PlinkoParams p;
    p.n = n;
    p.w = w;
    p.lambda = lambda;
    p.prp_epsilon = prp_epsilon;
    p.Validate();  // n 不是 w 的整数倍 / c 为奇数时抛出并给出补齐建议
    return p;
}

IprfParams PlinkoParams::iprf() const {
    IprfParams ip;
    ip.domain = hint_slots();  // H = λw + q（hint 下标空间；恒不是 2 的幂）
    ip.range = w;              // 区块大小（必须是 2 的幂，见 Validate）
    ip.prp_epsilon = prp_epsilon;
    return ip;
}

// ---------------------------------------------------------------------------
// §2 构造：求值器与状态
// ---------------------------------------------------------------------------

PlinkoClient::PlinkoClient(const PlinkoParams& params, uint64_t seed)
    : PlinkoClient(params, kPlinkoRootKey, seed, /*csprng_block_keys=*/false) {}

PlinkoClient::PlinkoClient(const PlinkoParams& params,
                           const std::array<uint8_t, kAesKeyBytes>& stream_key, uint64_t nonce,
                           bool csprng_block_keys)
    : p_(Checked(params)),
      stream_key_(stream_key),
      nonce_(nonce),
      csprng_block_keys_(csprng_block_keys) {
    rng_ = std::make_unique<random::DeterministicPrng>(stream_key_, nonce_);
    owner_id_ = static_cast<uint64_t>(rng_->Next());  // 句柄归属标识（防跨客户端误用）
    subset_words_ = BitmapWordsFor(p_.block_count());
    slots_.assign(static_cast<size_t>(p_.hint_slots()), PlinkoHintSlot{});
    subsets_.assign(static_cast<size_t>(p_.hint_slots()) * subset_words_, 0);
    cache_value_.assign(static_cast<size_t>(p_.n), 0);
    cache_valid_.assign(static_cast<size_t>(p_.n), 0);
    cache_slot_.assign(static_cast<size_t>(p_.n), kPlinkoNoSlot);
    next_backup_ = static_cast<size_t>(p_.main_hints());
}

PlinkoClient PlinkoClient::Deployed(const PlinkoParams& params) {
    // 部署路径：随机流密钥与 nonce 都取自 CSPRNG（区块密钥同样走 CSPRNG）
    const std::array<uint8_t, kAesKeyBytes> key = random::AesKey();
    const uint64_t nonce = static_cast<uint64_t>(random::Uint128());
    return PlinkoClient(params, key, nonce, /*csprng_block_keys=*/true);
}

void PlinkoClient::InitializeEvaluators(const std::vector<IprfKey>& keys) {
    if (keys.size() != p_.block_count()) {
        throw std::invalid_argument(
            "PlinkoClient: 区块密钥数必须恰为 c = " + Num(p_.block_count()) + "（论文 Fig 7："
            "**每区块一把**密钥，见勘误 ①/⑤）。实际 " + Num(keys.size()) + " 把。");
    }
    const IprfParams ip = p_.iprf();
    block_iprf_.clear();
    block_iprf_.reserve(keys.size());
    for (const IprfKey& k : keys) {
        // ⚠️ 每个求值器构造期要预计算 MR14 轮常数（≈50~70 µs/把）⇒ 按区块长期持有（D22-4）
        block_iprf_.push_back(std::make_unique<Iprf>(k, ip));
    }
}

void PlinkoClient::InitializeHintTables() {
    const uint64_t h = p_.hint_slots();
    const uint64_t m = p_.main_hints();
    slots_.assign(static_cast<size_t>(h), PlinkoHintSlot{});
    subsets_.assign(static_cast<size_t>(h) * subset_words_, 0);
    // 常规 hint：均匀随机选 c/2+1 个区块；备份 hint：均匀随机选 c/2 个区块
    for (uint64_t j = 0; j < m; ++j) {
        slots_[j].kind = PlinkoSlotKind::kRegular;
        RandomSubset(static_cast<size_t>(j), p_.main_hint_blocks());
    }
    for (uint64_t j = m; j < h; ++j) {
        slots_[j].kind = PlinkoSlotKind::kBackup;
        RandomSubset(static_cast<size_t>(j), p_.backup_hint_blocks());
    }
    std::fill(cache_valid_.begin(), cache_valid_.end(), 0);  // 离线完成 ⇒ Q 清空（论文 Fig 7）
    std::fill(cache_value_.begin(), cache_value_.end(), 0);
    std::fill(cache_slot_.begin(), cache_slot_.end(), kPlinkoNoSlot);
    answered_ = 0;
    next_backup_ = static_cast<size_t>(m);
    eta0_ = 0;
    eta1_ = 0;
    query_count_ = 0;
}

void PlinkoClient::RandomSubset(size_t slot, uint64_t count) {
    const uint64_t c = p_.block_count();
    scratch_.resize(static_cast<size_t>(c));
    std::iota(scratch_.begin(), scratch_.end(), uint64_t{0});
    // 部分 Fisher–Yates：均匀随机取 count 个互不相同的区块（每条 hint 独立采样）
    for (uint64_t t = 0; t < count; ++t) {
        const uint64_t pick = t + static_cast<uint64_t>(rng_->Below(c - t));
        std::swap(scratch_[static_cast<size_t>(t)], scratch_[static_cast<size_t>(pick)]);
        bit_set(slot, scratch_[static_cast<size_t>(t)]);
    }
}

// ---- 位图 ----

bool PlinkoClient::bit_test(size_t slot, uint64_t block) const {
    const size_t base = bitmap_base(slot);
    return ((subsets_[base + static_cast<size_t>(block >> 6)] >> (block & 63)) & 1ull) != 0;
}

void PlinkoClient::bit_set(size_t slot, uint64_t block) {
    const size_t base = bitmap_base(slot);
    subsets_[base + static_cast<size_t>(block >> 6)] |= (1ull << (block & 63));
}

void PlinkoClient::bit_clear(size_t slot) {
    const size_t base = bitmap_base(slot);
    std::fill(subsets_.begin() + static_cast<std::ptrdiff_t>(base),
              subsets_.begin() + static_cast<std::ptrdiff_t>(base + subset_words_), 0ull);
}

uint64_t PlinkoClient::bit_count(size_t slot) const {
    const size_t base = bitmap_base(slot);
    uint64_t total = 0;
    for (size_t i = 0; i < subset_words_; ++i) {
        total += static_cast<uint64_t>(__builtin_popcountll(subsets_[base + i]));
    }
    return total;
}

// ---------------------------------------------------------------------------
// §3 算法 1：HintInit（离线；**只用 IF⁻¹**）
// ---------------------------------------------------------------------------

void PlinkoClient::HintInit(const std::vector<uint128_t>& db) {
    if (db.size() < p_.n) {
        throw std::invalid_argument("PlinkoClient::HintInit: 数据库长度不足 n（需要 " + Num(p_.n) +
                                    "，实际 " + Num(db.size()) + "）");
    }
    // 论文 Fig 7：K[i] ← iF.Gen，i = 1..c —— **每个区块一把**（勘误 ①/⑤）
    const std::vector<IprfKey> keys = Iprf::GenBlockKeys(
        static_cast<size_t>(p_.block_count()), csprng_block_keys_, nonce_);
    HintInitWithKeys(db, keys);
}

void PlinkoClient::HintInitWithKeys(const std::vector<uint128_t>& db,
                                    const std::vector<IprfKey>& block_keys) {
    if (db.size() < p_.n) {
        throw std::invalid_argument("PlinkoClient::HintInitWithKeys: 数据库长度不足 n（需要 " +
                                    Num(p_.n) + "，实际 " + Num(db.size()) + "）");
    }
    InitializeEvaluators(block_keys);  // c 个求值器（长期持有）
    InitializeHintTables();            // 随机子集 + parity 清零

    const uint64_t w = p_.w;
    const uint64_t m = p_.main_hints();
    std::vector<uint64_t> cand;
    // 流式扫一遍 DB：每条记录**恰好 1 次 IF⁻¹**，把该记录 XOR 进所有"在该区块取该偏移"的 hint。
    // ⚠️ 复杂度 O(λn)：候选数 ≈ H/w ≈ 1.5λ；实测瓶颈是 IF⁻¹（≈1.0 ms/次，D22-1）。
    // ⚠️ 论文说按随机顺序遍历候选，本实现按升序（core/iprf::Inverse 的输出是升序）：
    //    parity 是 XOR 累加，**与顺序无关** ⇒ 随机顺序对结果没有任何影响。
    for (uint64_t i = 0; i < p_.n; ++i) {
        const uint128_t d = db[static_cast<size_t>(i)];
        const uint64_t alpha = i / w;
        const uint64_t beta = i - alpha * w;
        block_iprf_[static_cast<size_t>(alpha)]->Inverse(beta, cand);
        for (uint64_t j : cand) {
            if (j < m) {
                // 常规 hint：只有 α ∈ P_j 才计入 parity（Fig 7 的 `If α ∈ P`）
                if (bit_test(static_cast<size_t>(j), alpha)) {
                    slots_[static_cast<size_t>(j)].parity =
                        static_cast<uint128_t>(slots_[static_cast<size_t>(j)].parity ^ d);
                }
            } else {
                // 备份 hint：α ∈ B_j ⇒ 计入 ℓ_j，否则计入 r_j（r_j 是**补集**上的 parity）
                PlinkoHintSlot& t = slots_[static_cast<size_t>(j)];
                if (bit_test(static_cast<size_t>(j), alpha)) {
                    t.backup_parity_in = static_cast<uint128_t>(t.backup_parity_in ^ d);
                } else {
                    t.backup_parity_out = static_cast<uint128_t>(t.backup_parity_out ^ d);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// §4 算法 2：GetHint（候选检查 = 勘误 ②③⑦ 的落地处）
// ---------------------------------------------------------------------------

bool PlinkoClient::slot_contains_block(size_t slot, uint64_t block) const {
    if (slot >= slots_.size() || block >= p_.block_count()) return false;
    const PlinkoHintSlot& s = slots_[slot];
    if (s.kind == PlinkoSlotKind::kEmpty) return false;
    bool in = bit_test(slot, block);
    if (s.kind == PlinkoSlotKind::kPromoted) {
        // 提升后的 hint 存的是**原始** B_j，η 说明有效集是 B_j 还是 [c]\B_j；
        // 另外 α' 块被"隐式并入"（论文 §5.2：implicitly add the block α to B_j）
        if (s.eta == 1) in = !in;
        if (block == p_.block_of(s.promoted_index)) in = true;
    }
    return in;
}

PlinkoHintSelection PlinkoClient::SelectFromSlot(size_t slot, uint64_t alpha, uint64_t beta) const {
    PlinkoHintSelection sel;
    if (slot >= slots_.size()) return sel;
    const PlinkoHintSlot& s = slots_[slot];
    if (!s.in_hint_table()) return sel;  // ⊥ 或"未提升的备份 hint"（T[j] 不在 H 中，不可被查询选中）

    const uint64_t c = p_.block_count();
    const bool promoted = (s.kind == PlinkoSlotKind::kPromoted);
    const uint64_t alpha_prime = promoted ? p_.block_of(s.promoted_index) : kPlinkoNoIndex;
    const uint64_t beta_prime = promoted ? p_.offset_of(s.promoted_index) : 0;

    // ① 廉价检查（勘误 ② 的一般化）：有效区块集 E 是否包含 α（提升 hint 按 η 折算）
    if (!slot_contains_block(slot, alpha)) return sel;
    // ② 提升 hint 的 α' 块**只覆盖被提升进来的那一条记录**（其偏移被补丁为 β'）
    if (promoted && alpha == alpha_prime && beta != beta_prime) return sel;

    // ③ 偏移向量 o_b = IF(K[b], slot)（论文 Fig 7：每个区块一个 iF 偏移）
    sel.offsets.resize(static_cast<size_t>(c));
    for (uint64_t b = 0; b < c; ++b) {
        sel.offsets[static_cast<size_t>(b)] =
            block_iprf_[static_cast<size_t>(b)]->Forward(slot);
    }
    if (promoted) sel.offsets[static_cast<size_t>(alpha_prime)] = beta_prime;  // 补丁
    // ④ **最终一致性检查**：覆盖偏移必须等于查询偏移。对常规 hint 由
    //    j ∈ IF⁻¹(K[α], β) ⇒ IF(K[α], j) = β 保证；对提升 hint 的 α' 块由上面的规则处理。
    //    这一条把"静默错值"的可能性彻底关掉（勘误 ② 的收益要落到这里才算真的落地）。
    if (sel.offsets[static_cast<size_t>(alpha)] != beta) return sel;

    sel.found = true;
    sel.slot = slot;
    sel.promoted = promoted;
    sel.parity = s.parity;
    sel.blocks.reserve(static_cast<size_t>(c));
    for (uint64_t b = 0; b < c; ++b) {
        if (slot_contains_block(slot, b)) sel.blocks.push_back(b);
    }
    return sel;
}

PlinkoHintSelection PlinkoClient::GetHint(uint64_t alpha, uint64_t beta) const {
    if (block_iprf_.empty()) {
        throw std::logic_error("PlinkoClient::GetHint: 尚未调用 HintInit（求值器未构造）");
    }
    if (alpha >= p_.block_count()) {
        throw std::out_of_range("PlinkoClient::GetHint: α 越界（要求 < c = " + Num(p_.block_count()) +
                                "，实际 " + Num(alpha) + "）");
    }
    if (beta >= p_.w) {
        throw std::out_of_range("PlinkoClient::GetHint: β 越界（要求 < w = " + Num(p_.w) +
                                "，实际 " + Num(beta) + "）");
    }
    PlinkoHintSelection sel;
    // ⚠️ **1× IF⁻¹**：一次求逆就拿到"在该区块取该偏移"的**全部** hint（论文 §5.2 的核心收益）
    std::vector<uint64_t> cand;
    block_iprf_[static_cast<size_t>(alpha)]->Inverse(beta, cand);
    sel.candidates_examined = static_cast<uint64_t>(cand.size());
    for (uint64_t j : cand) {
        // 勘误 ②：只有约一半的候选真的包含 α（其余是"该区块未被这条 hint 选中"）。
        // 漏掉这个检查会让约一半的查询拿到不覆盖目标的 hint ⇒ **静默返回错误值**。
        // 统计口径：在**任何**可见性/状态过滤之前先做位测试（§7.3 的回归用例据此测量比例）。
        if (!slot_contains_block(static_cast<size_t>(j), alpha)) continue;
        ++sel.candidates_containing;
        // 勘误 ③：跳过 ⊥ 槽位（未填充/已消费）与已被 QueryGen 预留的槽位（同一条 hint 不得复用）
        const PlinkoHintSlot& s = slots_[static_cast<size_t>(j)];
        if (!s.in_hint_table() || s.reserved) continue;
        // 计算偏移向量并做最终覆盖检查（对提升 hint 还要求 α' 块走 β' 分支）
        PlinkoHintSelection hit = SelectFromSlot(static_cast<size_t>(j), alpha, beta);
        if (!hit.found) continue;
        hit.candidates_examined = sel.candidates_examined;
        hit.candidates_containing = sel.candidates_containing;
        return hit;  // 论文按**随机**顺序取第一个可用候选；本实现按升序（确定性、可复现）
    }
    return sel;  // ⊥ ⇒ QueryGen 抛 PlinkoHintCoverageFailure（绝不回退到明文取值）
}

std::vector<uint64_t> PlinkoClient::candidates(uint64_t alpha, uint64_t beta) const {
    if (block_iprf_.empty()) {
        throw std::logic_error("PlinkoClient::candidates: 尚未调用 HintInit");
    }
    if (alpha >= p_.block_count() || beta >= p_.w) {
        throw std::out_of_range("PlinkoClient::candidates: (α, β) 越界");
    }
    std::vector<uint64_t> out;
    block_iprf_[static_cast<size_t>(alpha)]->Inverse(beta, out);
    return out;
}

bool PlinkoClient::hint_covers(size_t slot, uint64_t index) const {
    if (index >= p_.n || slot >= slots_.size()) return false;
    const PlinkoHintSlot& s = slots_[slot];
    if (!s.in_hint_table()) return false;
    const uint64_t alpha = p_.block_of(index);
    const uint64_t beta = p_.offset_of(index);
    if (!slot_contains_block(slot, alpha)) return false;
    uint64_t covered = 0;
    if (s.kind == PlinkoSlotKind::kPromoted && alpha == p_.block_of(s.promoted_index)) {
        covered = p_.offset_of(s.promoted_index);  // 提升块：只覆盖被提升进来的那一条
    } else {
        covered = block_iprf_[static_cast<size_t>(alpha)]->Forward(slot);
    }
    return covered == beta;
}

std::vector<uint64_t> PlinkoClient::covered_indices(size_t slot) const {
    if (slot >= slots_.size()) {
        throw std::out_of_range("PlinkoClient::covered_indices: 槽位越界");
    }
    std::vector<uint64_t> out;
    const PlinkoHintSlot& s = slots_[slot];
    if (!s.in_hint_table()) return out;  // ⊥ / 未提升的备份 hint：不覆盖任何记录
    const uint64_t c = p_.block_count();
    const uint64_t w = p_.w;
    for (uint64_t b = 0; b < c; ++b) {
        if (!slot_contains_block(slot, b)) continue;
        uint64_t off = block_iprf_[static_cast<size_t>(b)]->Forward(slot);
        if (s.kind == PlinkoSlotKind::kPromoted && b == p_.block_of(s.promoted_index)) {
            off = p_.offset_of(s.promoted_index);
        }
        out.push_back(b * w + off);
    }
    return out;
}

std::vector<uint8_t> PlinkoClient::coverage_mask() const {
    std::vector<uint8_t> mask(static_cast<size_t>(p_.n), 0);
    for (size_t slot = 0; slot < slots_.size(); ++slot) {
        const PlinkoHintSlot& s = slots_[slot];
        if (!s.in_hint_table() || s.reserved) continue;
        for (uint64_t idx : covered_indices(slot)) mask[static_cast<size_t>(idx)] = 1;
    }
    return mask;
}

std::vector<size_t> PlinkoClient::covering_slots(uint64_t index) const {
    if (index >= p_.n) throw std::out_of_range("PlinkoClient::covering_slots: 索引越界");
    std::vector<size_t> out;
    for (size_t slot = 0; slot < slots_.size(); ++slot) {
        if (slots_[slot].reserved) continue;
        if (hint_covers(slot, index)) out.push_back(slot);
    }
    return out;
}

// ---------------------------------------------------------------------------
// §4 算法 3：QueryGen
// ---------------------------------------------------------------------------

std::pair<PlinkoQuery, PlinkoQueryHandle> PlinkoClient::BuildQuery(const PlinkoHintSelection& sel,
                                                                  uint64_t target,
                                                                  uint64_t requested) {
    if (!sel.found || sel.slot >= slots_.size()) {
        throw std::invalid_argument("PlinkoClient::BuildQuery: hint 选择无效");
    }
    PlinkoHintSlot& s = slots_[sel.slot];
    if (s.reserved || !s.in_hint_table()) {
        throw std::invalid_argument(
            "PlinkoClient::BuildQuery: 槽位已被预留/已消费 —— 同一条 hint 不得被两条查询复用"
            "（PLINKO_SPEC §0 的 hint 生命周期）");
    }
    const uint64_t c = p_.block_count();
    const uint64_t w = p_.w;
    const uint64_t alpha = p_.block_of(target);
    const uint64_t beta = p_.offset_of(target);
    if (sel.offsets[static_cast<size_t>(alpha)] != beta) {
        throw std::logic_error("PlinkoClient::BuildQuery: 选中的 hint 不覆盖目标（内部一致性错误）");
    }

    PlinkoQuery q;
    q.blocks = c;
    q.block_size = w;
    q.offsets.assign(static_cast<size_t>(c), 0);
    q.groups.assign(static_cast<size_t>(c), 0);

    // b 随机置换两半：**服务器无法区分哪一半是 hint 的真实覆盖集**（PLINKO_SPEC §3.3）
    const uint8_t b = static_cast<uint8_t>(rng_->Below(2));
    std::vector<uint8_t> in_e(static_cast<size_t>(c), 0);
    for (uint64_t blk : sel.blocks) in_e[static_cast<size_t>(blk)] = 1;
    // ⚠️ 修正（见 plinko.hpp §4-⑧）：**侧 A = E\{α} 用 hint 的 iF 偏移**（这样 r_b = p ⊕ D[x]），
    //    **补集（含 α）用全新哑偏移**。论文 Fig 7 的即打印文本把这两侧的偏移写反了。
    //    |A| = (c/2+1) − 1 = c/2 = |补集| ⇒ 两半规模严格相等（§5.5）。
    for (uint64_t a = 0; a < c; ++a) {
        const bool side_a = (a != alpha) && (in_e[static_cast<size_t>(a)] != 0);
        if (side_a) {
            q.offsets[static_cast<size_t>(a)] = sel.offsets[static_cast<size_t>(a)];
            q.groups[static_cast<size_t>(a)] = b;
        } else {
            // 哑偏移每轮**全新随机**（PLINKO_SPEC §5.6 / D17 的教训）
            q.offsets[static_cast<size_t>(a)] = static_cast<uint64_t>(rng_->Below(w));
            q.groups[static_cast<size_t>(a)] = static_cast<uint8_t>(1 - b);
        }
    }

    PlinkoQueryHandle h;
    h.owner = owner_id_;
    h.target = target;
    h.requested = requested;
    h.b = b;
    h.hint_slot = sel.slot;
    h.hint_parity = sel.parity;
    h.cache_hit = (target != requested);
    h.candidates_examined = sel.candidates_examined;
    h.candidates_containing = sel.candidates_containing;

    // ⚠️ **立刻预留**命中的槽位：同一条 hint 不得被两条查询复用（§0 的 hint 生命周期/
    //    D17 的教训 —— 复用会让服务器从两轮查询的差集里读出两个目标区块）。
    s.reserved = true;
    ++query_count_;
    return {std::move(q), h};
}

std::pair<PlinkoQuery, PlinkoQueryHandle> PlinkoClient::QueryGen(uint64_t index) {
    if (index >= p_.n) {
        throw std::out_of_range("PlinkoClient::QueryGen: 索引越界（要求 < n = " + Num(p_.n) +
                                "，实际 " + Num(index) + "）");
    }
    if (block_iprf_.empty()) {
        throw std::logic_error("PlinkoClient::QueryGen: 尚未调用 HintInit");
    }
    // ① 备份 hint 用尽 ⇒ **在发出查询之前**显式报错（D8：不实现摊销式离线；
    //    绝不让第 q+1 次查询静默降级或算错）。
    if (next_backup_ >= slots_.size()) {
        throw PlinkoBackupsExhausted(
            "PlinkoClient::QueryGen: 备份 hint 已用尽（q = " + Num(p_.backup_hints()) +
            " 次查询的额度已用完）—— 本项目不实现摊销式离线（决策 D8），必须重跑 HintInit。");
    }
    // ② 重复查询（论文 Fig 7 的 Query）：i' ← x；只要 Q[i] 已被答复过就换一个**未答复**的索引。
    //    这样服务器看到的索引序列仍然是"全新"的，而调用方拿到的是缓存里的值。
    const uint64_t requested = index;
    uint64_t target = index;
    if (cached(target)) {
        if (answered_ >= p_.n) {
            throw std::runtime_error(
                "PlinkoClient::QueryGen: 全部 n 个索引都已答复过，无法再为重复查询选取新索引"
                "（应当重跑离线阶段）");
        }
        uint64_t guard = 0;
        const uint64_t max_attempts = 128 + 8 * p_.n;
        do {
            target = static_cast<uint64_t>(rng_->Below(p_.n));
        } while (cached(target) && ++guard < max_attempts);
        if (cached(target)) {
            throw std::runtime_error("PlinkoClient::QueryGen: 拒绝采样未能取到未答复的索引");
        }
    }
    // ③ 找覆盖 x 的 hint（1× IF⁻¹ + 候选检查）；找不到 ⇒ 致命失败，**绝不明文回退**
    const PlinkoHintSelection sel = GetHint(p_.block_of(target), p_.offset_of(target));
    if (!sel.found) {
        throw PlinkoHintCoverageFailure(
            "PlinkoClient::QueryGen: 找不到覆盖索引 " + Num(target) +
            " 的 hint（概率 2^{-λ} 量级）—— 必须重跑离线阶段，"
            "绝不可回退到明文取值等**可区分**的失败路径（PLINKO_SPEC §5.1）。");
    }
    return BuildQuery(sel, target, requested);
}

std::pair<PlinkoQuery, PlinkoQueryHandle> PlinkoClient::QueryViaSlot(size_t slot, uint64_t index) {
    if (index >= p_.n) {
        throw std::out_of_range("PlinkoClient::QueryViaSlot: 索引越界");
    }
    if (slot >= slots_.size()) {
        throw std::out_of_range("PlinkoClient::QueryViaSlot: 槽位越界");
    }
    if (block_iprf_.empty()) {
        throw std::logic_error("PlinkoClient::QueryViaSlot: 尚未调用 HintInit");
    }
    const PlinkoHintSlot& s = slots_[slot];
    if (!s.in_hint_table()) {
        throw std::invalid_argument(
            "PlinkoClient::QueryViaSlot: 该槽位是 ⊥ 或**未提升的备份 hint**（T[j] 不在 H 中，"
            "不可被查询选中）");
    }
    if (s.reserved) {
        throw std::invalid_argument("PlinkoClient::QueryViaSlot: 该槽位已被预留（同一条 hint 不得复用）");
    }
    if (next_backup_ >= slots_.size()) {
        throw PlinkoBackupsExhausted(
            "PlinkoClient::QueryViaSlot: 备份 hint 已用尽（决策 D8：需重跑离线阶段）");
    }
    const PlinkoHintSelection sel = SelectFromSlot(slot, p_.block_of(index), p_.offset_of(index));
    if (!sel.found) {
        throw std::invalid_argument("PlinkoClient::QueryViaSlot: 该槽位**不覆盖**目标索引 " +
                                    Num(index) + "（这正是「α ∈ E」检查要拦下来的情形）");
    }
    return BuildQuery(sel, index, index);
}

// ---------------------------------------------------------------------------
// §4 算法 4：ServerResp
// ---------------------------------------------------------------------------

PlinkoAnswer PlinkoClient::ServerResp(const PlinkoQuery& q, const std::vector<uint128_t>& db) {
    if (!q.well_formed()) {
        throw std::invalid_argument("PlinkoClient::ServerResp: 查询格式非法（长度/偏移越界）");
    }
    if (db.size() < q.blocks * q.block_size) {
        throw std::invalid_argument("PlinkoClient::ServerResp: 数据库长度不足 n");
    }
    PlinkoAnswer a;
    for (uint64_t i = 0; i < q.blocks; ++i) {
        const uint64_t idx = i * q.block_size + q.offsets[static_cast<size_t>(i)];
        const uint128_t v = db[static_cast<size_t>(idx)];
        if (q.groups[static_cast<size_t>(i)]) {
            a.r1 = static_cast<uint128_t>(a.r1 ^ v);
        } else {
            a.r0 = static_cast<uint128_t>(a.r0 ^ v);
        }
    }
    return a;
}

// ---------------------------------------------------------------------------
// §4 算法 5：ClientRecon
// ---------------------------------------------------------------------------

uint128_t PlinkoClient::ClientRecon(PlinkoQueryHandle& h, const PlinkoAnswer& r) {
    if (h.owner != owner_id_) {
        throw std::invalid_argument("PlinkoClient::ClientRecon: 句柄不属于本客户端");
    }
    if (h.consumed) {
        throw std::invalid_argument(
            "PlinkoClient::ClientRecon: 该查询已经重建过（重复重建会复用被消费的 hint）");
    }
    if (h.hint_slot >= slots_.size()) {
        throw std::invalid_argument("PlinkoClient::ClientRecon: 句柄的 hint 槽位非法");
    }
    PlinkoHintSlot& s = slots_[h.hint_slot];
    if (!s.reserved) {
        throw std::invalid_argument(
            "PlinkoClient::ClientRecon: 该槽位未被 QueryGen 预留（句柄非法或已被消费）");
    }
    if (h.target >= p_.n || h.requested >= p_.n) {
        throw std::invalid_argument("PlinkoClient::ClientRecon: 句柄的索引非法");
    }

    // ① 目标值：a = p ⊕ r_b（b 决定取哪个累加器；累加器 b 恰好装着侧 A = E\{α}）
    const uint128_t a = static_cast<uint128_t>(h.hint_parity ^ (h.b ? r.r1 : r.r0));

    // ② 消费被使用的 hint（H[j] ← ⊥）。主/备共用同一张下标空间：被消费的槽位不动，
    //    提升的备份 hint 落到**自己的下标** λw+k 上（论文 §5.2：keeps the same table index）。
    s.kind = PlinkoSlotKind::kEmpty;
    s.parity = 0;
    s.backup_parity_in = 0;
    s.backup_parity_out = 0;
    s.eta = 0;
    s.promoted_index = kPlinkoNoIndex;
    s.reserved = false;
    bit_clear(h.hint_slot);
    h.consumed = true;

    // ③ 提升一条备份 hint（j' = arg min_j T[j] ≠ ⊥ = λw + 已提升数；O(1) 而非线性扫描）
    if (next_backup_ >= slots_.size()) {
        throw PlinkoBackupsExhausted(
            "PlinkoClient::ClientRecon: 备份 hint 已用尽（第 q+1 次查询）—— 决策 D8："
            "本项目不实现摊销式离线，必须重跑 HintInit。");
    }
    const size_t jp = next_backup_++;
    PlinkoHintSlot& t = slots_[jp];
    if (t.kind != PlinkoSlotKind::kBackup) {
        throw std::logic_error("PlinkoClient::ClientRecon: 备份槽位状态异常（内部错误）");
    }
    const uint64_t alpha = p_.block_of(h.target);
    const bool in_b = bit_test(jp, alpha);
    // 论文 §5.2 的提升语义：B_j 恰好 c/2 个区块，"隐式并入" x 所在区块后得到 c/2+1 个，
    // 与常规 hint 同构；η 记录并入的是哪一半（0 ⇒ B∪{α}，1 ⇒ ([c]\B)∪{α}）。
    t.kind = PlinkoSlotKind::kPromoted;
    t.eta = in_b ? 1 : 0;
    t.promoted_index = h.target;
    t.parity = static_cast<uint128_t>((in_b ? t.backup_parity_out : t.backup_parity_in) ^ a);
    t.backup_parity_in = 0;
    t.backup_parity_out = 0;
    if (in_b) {
        ++eta1_;
    } else {
        ++eta0_;
    }
    h.promoted_slot = jp;
    h.promotion_eta = t.eta;

    // ④ Q[i] ← (a, j')：被提升的 hint 不会作为 x 自己的候选出现（论文 §5.2），
    //    因此已答复的索引必须留在缓存里。
    cache_value_[static_cast<size_t>(h.target)] = a;
    cache_valid_[static_cast<size_t>(h.target)] = 1;
    cache_slot_[static_cast<size_t>(h.target)] = jp;
    ++answered_;

    // ⑤ 重复查询（i' ≠ i）：本次真正查的是另一个索引，返回的是早已答复过的 i' 的值。
    //    ⚠️ 论文如此：重复查询**照样**消费 + 提升一条 hint，保持服务器视角与查询模式无关。
    if (h.requested != h.target) {
        if (cache_valid_[static_cast<size_t>(h.requested)] == 0) {
            throw std::logic_error("PlinkoClient::ClientRecon: 重复查询的目标不在缓存里（内部错误）");
        }
        return cache_value_[static_cast<size_t>(h.requested)];
    }
    return a;
}

// ---------------------------------------------------------------------------
// §4 算法 6：Verify
// ---------------------------------------------------------------------------

void PlinkoClient::Verify(const PlinkoQueryHandle&, const PlinkoQuery&, const PlinkoAnswer&) {
    // ⚠️ **Plinko 原文没有 Verify 算法**（PLINKO_SPEC §3.6）：本层不实现 HMAC 多集证明、
    //    也不实现 SPDZ MAC 校验 —— 那属于上层 MPA-07（`shared/verify`），且作用在上层的
    //    秘密共享数据上，不改变 Plinko 的 parity 结构。
    //    这里**只表达"本层不提供验证"这一语义**：永远抛异常。绝不返回一个假的"通过"
    //    （一个永远返回 true 的 Verify 会让上层误以为恶意应答已被拦住）。
    throw PlinkoVerificationUnsupported(
        "PlinkoClient::Verify: **未实现**（Plinko 原文没有 Verify 算法，PLINKO_SPEC §3.6）。"
        "MPRAQ 的验证由上层 MPA-07 用 shared/verify 的 HMAC 多集证明 + SPDZ MAC 完成；"
        "本层不提供任何验证，也不会返回\"通过\"。");
}

void Verify(const PlinkoQueryHandle& h, const PlinkoQuery& q, const PlinkoAnswer& r) {
    PlinkoClient::Verify(h, q, r);  // 永不返回
}

// ---------------------------------------------------------------------------
// 诊断
// ---------------------------------------------------------------------------

PlinkoSlotKind PlinkoClient::slot_kind(size_t slot) const {
    if (slot >= slots_.size()) {
        throw std::out_of_range("PlinkoClient::slot_kind: 槽位越界");
    }
    return slots_[slot].kind;
}

const PlinkoHintSlot& PlinkoClient::slot(size_t slot) const {
    if (slot >= slots_.size()) {
        throw std::out_of_range("PlinkoClient::slot: 槽位越界");
    }
    return slots_[slot];
}

size_t PlinkoClient::regular_hint_count() const {
    size_t n = 0;
    const size_t m = static_cast<size_t>(p_.main_hints());
    for (size_t j = 0; j < m && j < slots_.size(); ++j) {
        if (slots_[j].kind == PlinkoSlotKind::kRegular) ++n;
    }
    return n;
}

size_t PlinkoClient::promoted_hint_count() const {
    size_t n = 0;
    for (size_t j = static_cast<size_t>(p_.main_hints()); j < slots_.size(); ++j) {
        if (slots_[j].kind == PlinkoSlotKind::kPromoted) ++n;
    }
    return n;
}

size_t PlinkoClient::hints_in_table() const {
    size_t n = 0;
    for (const PlinkoHintSlot& s : slots_) {
        if (s.in_hint_table()) ++n;
    }
    return n;
}

size_t PlinkoClient::usable_hint_count() const {
    size_t n = 0;
    for (const PlinkoHintSlot& s : slots_) {
        if (s.in_hint_table() && !s.reserved) ++n;
    }
    return n;
}

uint64_t PlinkoClient::iprf_offset(uint64_t block, uint64_t hint_slot) const {
    if (block >= p_.block_count() || hint_slot >= p_.hint_slots()) {
        throw std::out_of_range("PlinkoClient::iprf_offset: 参数越界");
    }
    return block_iprf_[static_cast<size_t>(block)]->Forward(hint_slot);
}

const Iprf& PlinkoClient::block_iprf(uint64_t block) const {
    if (block >= block_iprf_.size()) {
        throw std::out_of_range("PlinkoClient::block_iprf: 区块越界");
    }
    return *block_iprf_[static_cast<size_t>(block)];
}

bool PlinkoClient::cached(uint64_t index) const {
    return index < p_.n && cache_valid_[static_cast<size_t>(index)] != 0;
}

uint128_t PlinkoClient::cached_value(uint64_t index) const {
    if (!cached(index)) {
        throw std::invalid_argument("PlinkoClient::cached_value: 该索引不在缓存里");
    }
    return cache_value_[static_cast<size_t>(index)];
}

size_t PlinkoClient::cached_slot(uint64_t index) const {
    if (!cached(index)) {
        throw std::invalid_argument("PlinkoClient::cached_slot: 该索引不在缓存里");
    }
    return static_cast<size_t>(cache_slot_[static_cast<size_t>(index)]);
}

size_t PlinkoClient::hint_state_bytes() const {
    return slots_.size() * sizeof(PlinkoHintSlot) + subsets_.size() * sizeof(uint64_t) +
           cache_value_.size() * sizeof(uint128_t) + cache_valid_.size() * sizeof(uint8_t) +
           cache_slot_.size() * sizeof(uint64_t);
}

double PlinkoClient::logical_hint_bytes() const {
    // 按 PLINKO_SPEC §2 表的口径统计"每条 hint 的开销"（不含索引/容器开销）：
    //   常规/备份 hint：parity（1 或 2 个 128 位字）+ 子集位图 ⌈c/64⌉×8 B
    //   提升后：1 个 parity + η（1 B）+ x（8 B）+ 原始 B 的位图
    const double bitmap = static_cast<double>(subset_words_) * 8.0;
    double total = 0.0;
    for (const PlinkoHintSlot& s : slots_) {
        switch (s.kind) {
            case PlinkoSlotKind::kRegular:
                total += 16.0 + bitmap;
                break;
            case PlinkoSlotKind::kBackup:
                total += 32.0 + bitmap;
                break;
            case PlinkoSlotKind::kPromoted:
                total += 16.0 + 9.0 + bitmap;
                break;
            case PlinkoSlotKind::kEmpty:
            default:
                break;
        }
    }
    return total;
}

}  // namespace tsb
