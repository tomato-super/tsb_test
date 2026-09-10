// 可逆 PRF（iPRF）实现 —— 构造、参数、论文出处的完整说明见 core/iprf.hpp 文件头。
//
// 本文件的三段结构：
//   §1 参数校验与 MR14 轮数选取（论文 §5 strategy 1 + 式 (1)）
//   §2 MR14 的 SR = SR[SN] 置换（论文 Fig 1, p.8）与轮常数预计算
//   §3 Plinko Fig 4 的 PMNS 二叉树（论文 p.16）+ iPRF 三个算法（Theorem 4.4, p.12）

#include "core/iprf.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <string>

namespace tsb {

namespace {

constexpr double kLn2 = 0.693147180559945309417232121458176568;

// MR14 轮号必须塞进 AES 输入块的 16 位域（in[1] 的低 16 位），故轮数有硬上界。
constexpr uint32_t kMaxSnRounds = 0xFFFFu;

// iPRF 的定义域/值域上界：两者都要塞进 AES 输入块的 32 位字（w0 = X̂ / 节点 low）。
constexpr uint64_t kMaxDomainOrRange = (static_cast<uint64_t>(1) << 32);

// 组装 AES 输入块：in = [w0, (domain << 16) | w1, w2, 0]（小端 uint32_t[4]）。
// ⚠️ 用 memcpy 而不是逐字节位移循环（决策 D20：PRF 是热路径，别往里塞打包开销）。
inline uint128_t MakeBlock(uint32_t w0, uint16_t domain, uint16_t w1, uint32_t w2 = 0) {
    const uint32_t words[4] = {w0, (static_cast<uint32_t>(domain) << 16) | w1, w2, 0};
    uint128_t block = 0;
    std::memcpy(&block, words, sizeof(words));
    return block;
}

inline uint64_t Low64(uint128_t v) { return static_cast<uint64_t>(v); }

bool IsPowerOfTwo(uint64_t v) { return v != 0 && (v & (v - 1)) == 0; }

// Lemire 乘法归约：64 位均匀值 → [0,bound)，偏差 ≤ bound/2^64（bound ≤ 2^32 时可忽略）。
// 比 `%` 快得多，而轮常数派生在构造期要做上千次。
inline uint64_t ReduceTo(uint64_t v, uint64_t bound) {
    return static_cast<uint64_t>((static_cast<uint128_t>(v) * bound) >> 64);
}

// 参数校验的**唯一**入口（构造 Iprf 前先过这里）。
const IprfParams& CheckedParams(const IprfParams& p) {
    p.Validate();
    return p;
}

// ---------------------------------------------------------------------------
// 去随机化二项采样：Binomial(count, 1/2; u) 的反 CDF（论文 Fig 4 的 children()）
// ---------------------------------------------------------------------------
// 论文 Fig 4 图注（p.16）："Binomial(n, p; r) is a derandomized binomial sampling function
// using r as the randomness." 本模块**只支持 range 为 2 的幂**，此时二叉树的每个节点都有
// a == b（p 恰为 1/2），因此只需要这条 p = 1/2 的路径（非 2 幂的 O(count) 慢路径被拒绝，
// 见文件头硬约束 1）。
//
// 数值口径：pmf 在众数处用一次 lgamma 求出，随后**全部**用精确递推比值
// pmf(s±1)/pmf(s) 更新；CDF 用双精度累加。走步数 O(sqrt(count))（实测均值 11~33、最大 131，
// REPORT §3.4），累积误差 ~1e-13，远小于众数附近的 CDF 台阶高度 ~1/sqrt(count)。
// ⚠️ 与往返一致性**无关**：正反两个方向在同一个节点上用完全相同的入参调用本函数，
//    得到的是同一个 s（纯确定性函数），精度只影响"与理想二项分布的统计距离"（~1e-11）。
uint64_t BinomialHalfFromUniform(uint64_t count, uint64_t u64) {
    if (count == 0) return 0;
    // 取高 53 位当 [0,1) 的均匀数（与 double 的尾数位宽一致）
    double u = static_cast<double>(u64 >> 11) * (1.0 / 9007199254740992.0);
    bool mirror = false;
    if (u >= 0.5) {  // 利用对称性 X ~ count − X，只在左半边走（走步数减半）
        u = 1.0 - u;
        mirror = true;
    }
    const uint64_t m0 = count / 2;
    const double pmf0 = std::exp(std::lgamma(static_cast<double>(count) + 1.0) -
                                 std::lgamma(static_cast<double>(m0) + 1.0) -
                                 std::lgamma(static_cast<double>(count - m0) + 1.0) -
                                 static_cast<double>(count) * kLn2);
    // 对称性直接给出众数处的 CDF：count 偶 ⇒ (1 + pmf(m0))/2；count 奇 ⇒ 恰好 1/2
    double cdf = (count % 2 == 0) ? 0.5 + 0.5 * pmf0 : 0.5;
    double pmf = pmf0;
    uint64_t s = m0;
    if (u < cdf) {
        while (s > 0) {  // 向左走：找最小的 s 使 CDF(s) > u
            const double lower = cdf - pmf;  // = CDF(s−1)
            if (lower <= u) break;
            cdf = lower;
            pmf = pmf * static_cast<double>(s) / static_cast<double>(count - s + 1);
            --s;
        }
    } else {
        while (s < count) {  // 向右走
            pmf = pmf * static_cast<double>(count - s) / static_cast<double>(s + 1);
            ++s;
            cdf += pmf;
            if (cdf > u) break;
        }
    }
    return mirror ? (count - s) : s;
}

// ---------------------------------------------------------------------------
// §1 参数校验 + MR14 轮数选取
// ---------------------------------------------------------------------------

// 论文 §5 strategy 1（p.9–10）：给定 stage 的定义域 N 与每 stage 的误差预算 ε/n，
// 取最小的 r 使 Δub_SN(N, q_N, r) ≤ 预算，其中 q_N = N − p_N = ⌈N/2⌉（被宣告"洗好了"的那一堆）。
uint32_t SelectSnRounds(uint64_t n, uint64_t q, double eps_per_stage) {
    // 在 log2 空间比较，避免 N^{3/2}（N 可达 2^32）与 0.75^{r/2} 的上下溢。
    const double log2_front = 1.0 + 1.5 * std::log2(static_cast<double>(n));  // 2·N^{3/2}
    const double log2_ratio = std::log2(static_cast<double>(q + n) / (2.0 * static_cast<double>(n)));
    const double log2_target = std::log2(eps_per_stage);
    for (uint32_t r = 1; r <= kMaxSnRounds; ++r) {
        const double log2_bound = log2_front - std::log2(static_cast<double>(r) + 2.0) +
                                  (static_cast<double>(r) / 2.0 + 1.0) * log2_ratio;
        if (log2_bound <= log2_target) return r;
    }
    throw std::invalid_argument(
        "IprfParams: prp_epsilon 太小 —— 按 MR14 式 (1) 推出的轮数超过 65535"
        "（轮号要放进 AES 输入块的 16 位域）。请把 prp_epsilon 调大。");
}

// 论文 §4（p.7）：生成的 N 值序列 G(N0) = {N0, N1, …, 1}，N_{i+1} = p(N_i) = ⌊N_i/2⌋。
// 表里只保留 N ≥ 2 的 stage（N = 1 是"一张牌已经洗好"的平凡情形，没有轮数）。
std::vector<IprfPrpStage> BuildStages(const IprfParams& p) {
    std::vector<uint64_t> generated;
    for (uint64_t n = p.domain; n > 1; n /= 2) generated.push_back(n);
    // n_stages = |G'(N0)| = G(N0) \ {1,2}（论文 §5 的计数口径：把误差均摊给非平凡 stage）
    uint64_t nontrivial = 0;
    for (uint64_t n : generated) {
        if (n >= 3) ++nontrivial;
    }
    const double eps_per_stage =
        (nontrivial == 0) ? p.prp_epsilon : p.prp_epsilon / static_cast<double>(nontrivial);

    std::vector<IprfPrpStage> stages;
    stages.reserve(generated.size());
    for (uint64_t n : generated) {
        IprfPrpStage st;
        st.n = n;
        if (n == 2) {
            // 论文 §5（p.9）："we will always select t_2 = 1, as this choice already contributes
            // zero error"（N=2 时 SN 一轮就恰好给出 S_2 上的均匀分布）。
            st.rounds = 1;
        } else {
            st.rounds = SelectSnRounds(n, n - n / 2, eps_per_stage);
        }
        stages.push_back(st);
    }
    return stages;
}

std::vector<uint32_t> BuildRoundKeyOffsets(const std::vector<IprfPrpStage>& stages) {
    std::vector<uint32_t> offsets;
    offsets.reserve(stages.size());
    uint64_t acc = 0;
    for (const IprfPrpStage& st : stages) {
        offsets.push_back(static_cast<uint32_t>(acc));
        acc += st.rounds;
    }
    return offsets;
}

// MR14 Fig 1 图注：SN 的随机性来自 K : N → N（每轮一个 K_i ∈ [N]）与 F : N × N → {0,1}。
// 二者都由 PRP 密钥派生（域分隔 kIprfDomainPrpRoundKey / kIprfDomainPrpRound），
// 且 K_i 在**构造期**一次性预计算 —— 每轮省一次 AES（热路径上这是 2× 的差别）。
std::vector<uint64_t> BuildRoundKeys(const AesPrf& prf, const std::vector<IprfPrpStage>& stages) {
    size_t total = 0;
    for (const IprfPrpStage& st : stages) total += st.rounds;
    std::vector<uint64_t> keys;
    keys.reserve(total);
    for (size_t si = 0; si < stages.size(); ++si) {
        const uint64_t n = stages[si].n;
        for (uint32_t r = 1; r <= stages[si].rounds; ++r) {
            const uint64_t v = Low64(prf.Eval(MakeBlock(static_cast<uint32_t>(si),
                                                        kIprfDomainPrpRoundKey,
                                                        static_cast<uint16_t>(r))));
            keys.push_back(ReduceTo(v, n));
        }
    }
    return keys;
}

// ---------------------------------------------------------------------------
// 确定性密钥派生（决策 D6：确定性随机源下的期望值测试）
// ---------------------------------------------------------------------------
// ⚠️ 根密钥**必须是编译期常量**：若写成 DeterministicPrng(random::AesKey(), seed)，
//    则同一 seed 在不同进程/不同次运行会得到不同密钥 —— "确定性"名不副实、
//    跨进程不可复现（Q9 原型踩过这个坑，见 REPORT §7.2）。
constexpr std::array<uint8_t, kAesKeyBytes> kDeterministicRootKey = {
    't', 's', 'b', ':', 'i', 'p', 'r', 'f', '/', 'd', 'e', 't', '/', 'r', 'o', 'o'};

// ⚠️ **底座缺陷的规避**（已在 FND-06 报告中单独记录，其它模块同样会踩）：
//    `core/random.hpp` 的 `DeterministicPrng::Next()` 是
//        EvalDomainU32(kDummyOffset, nonce >> 32, counter)
//    ⇒ nonce 的**低 32 位被静默忽略**（seed = 99 与 seed = 100 会生成完全相同的密钥流），
//    且 counter 只有 16 位（最多 65536 个 16 字节块 = 1 MiB 流）。
//    因此这里先把 64 位 seed **整体**经一次 AES-PRF（域 kIprfDomainKeyDerive）展开成 nonce，
//    保证 seed 的每一位都影响输出。编码是单射的：w0 = seed 低 32 位、w1 = bit 32..47、
//    w2 = bit 48..63。本函数只用于派生密钥（每把 32 B），远未触及计数上限。
void FillDeterministicKeyStream(uint64_t seed, uint8_t* out, size_t len) {
    const AesPrf root_prf(kDeterministicRootKey);
    const uint64_t mixed = Low64(root_prf.Eval(
        MakeBlock(static_cast<uint32_t>(seed), kIprfDomainKeyDerive,
                  static_cast<uint16_t>(seed >> 32), static_cast<uint32_t>(seed >> 48))));
    random::DeterministicPrng prng(kDeterministicRootKey, mixed);
    prng.FillBytes(out, len);
}

// 确定性流一次最多能产出 65536 个 16 字节块（counter 是 16 位）。
constexpr size_t kMaxDeterministicBytes = 65536u * 16u;

}  // namespace

// ---------------------------------------------------------------------------
// 参数校验
// ---------------------------------------------------------------------------

void IprfParams::Validate() const {
    if (domain < 1) {
        throw std::invalid_argument("IprfParams: domain 必须 >= 1（实际 " +
                                    std::to_string(domain) + "）");
    }
    if (range < 1) {
        throw std::invalid_argument("IprfParams: range 必须 >= 1（实际 " + std::to_string(range) +
                                    "）");
    }
    if (domain > kMaxDomainOrRange) {
        throw std::invalid_argument("IprfParams: domain 过大（要求 <= 2^32，实际 " +
                                    std::to_string(domain) +
                                    "）；上界来自 AES 输入块的 32 位字宽");
    }
    if (range > kMaxDomainOrRange) {
        throw std::invalid_argument("IprfParams: range 过大（要求 <= 2^32，实际 " +
                                    std::to_string(range) + "）");
    }
    if (!IsPowerOfTwo(range)) {
        // ⚠️ 决策 D21 的硬约束：range 非 2 的幂时 PMNS 二叉树的节点会出现 a ≠ b（p ≠ 1/2），
        // 论文 Fig 4 的去随机化二项采样退化成 O(count) 次 AES 的精确路径 —— 实测单次 IF
        // 从 ~2 µs 掉到 ~1.9 ms（慢约 900×，REPORT §3.3）。range 是自由设计参数，
        // 取 2 的幂没有任何代价，因此本模块**直接拒绝**而**不实现**慢路径。
        throw std::invalid_argument(
            "IprfParams: range 必须是 2 的幂（实际 " + std::to_string(range) +
            "）。原因：range 非 2 的幂会让 PMNS 树出现 p != 1/2 的节点，论文 Fig 4 的"
            "去随机化二项采样退化为 O(count) 慢路径（实测约 900 倍），本模块不实现该路径"
            "（决策 D21 / REPORT §3.3）。Plinko 的 range 是区块大小 w，取 w = 2^k 无任何代价。");
    }
    if (!(prp_epsilon > 0.0) || prp_epsilon >= 1.0) {
        throw std::invalid_argument("IprfParams: prp_epsilon 必须落在 (0,1)（实际 " +
                                    std::to_string(prp_epsilon) + "）");
    }
}

// ---------------------------------------------------------------------------
// 密钥生成
// ---------------------------------------------------------------------------

IprfKey Iprf::Gen() {
    IprfKey key;
    key.prp_key = random::AesKey();
    key.pmns_key = random::AesKey();
    return key;
}

IprfKey Iprf::GenDeterministic(uint64_t seed) {
    std::array<uint8_t, 2 * kAesKeyBytes> buf{};
    FillDeterministicKeyStream(seed, buf.data(), buf.size());
    IprfKey key;
    std::memcpy(key.prp_key.data(), buf.data(), kAesKeyBytes);
    std::memcpy(key.pmns_key.data(), buf.data() + kAesKeyBytes, kAesKeyBytes);
    return key;
}

std::vector<IprfKey> Iprf::GenBlockKeys(size_t blocks, bool use_csprng, uint64_t seed) {
    // 论文 Fig 7（p.31）：每个区块一把密钥（共 c = n/w 把），所有 hint 共用。
    std::vector<IprfKey> keys;
    keys.resize(blocks);
    if (use_csprng) {
        for (size_t i = 0; i < blocks; ++i) {
            keys[i].prp_key = random::AesKey();
            keys[i].pmns_key = random::AesKey();
        }
        return keys;
    }
    const size_t bytes = blocks * 2 * kAesKeyBytes;
    if (bytes > kMaxDeterministicBytes) {
        throw std::invalid_argument(
            "Iprf::GenBlockKeys: blocks 过大（" + std::to_string(blocks) +
            "）—— 确定性密钥流受 core/random::DeterministicPrng 的 16 位计数器限制，"
            "最多 " + std::to_string(kMaxDeterministicBytes / (2 * kAesKeyBytes)) + " 把");
    }
    // 第 i 把密钥 = 同一条流的第 i 个 32 字节块 ⇒ 与 blocks 的取值无关，可复现。
    std::vector<uint8_t> buf(bytes);
    FillDeterministicKeyStream(seed, buf.data(), bytes);
    for (size_t i = 0; i < blocks; ++i) {
        std::memcpy(keys[i].prp_key.data(), buf.data() + i * 2 * kAesKeyBytes, kAesKeyBytes);
        std::memcpy(keys[i].pmns_key.data(), buf.data() + i * 2 * kAesKeyBytes + kAesKeyBytes,
                    kAesKeyBytes);
    }
    return keys;
}

// ---------------------------------------------------------------------------
// 求值器构造
// ---------------------------------------------------------------------------

Iprf::Iprf(const IprfKey& key, const IprfParams& params)
    : params_(CheckedParams(params)),
      key_(key),
      prp_prf_(key.prp_key),
      pmns_prf_(key.pmns_key),
      stages_(BuildStages(params_)),
      round_key_offset_(BuildRoundKeyOffsets(stages_)),
      round_keys_(BuildRoundKeys(prp_prf_, stages_)) {}

// ---------------------------------------------------------------------------
// §2 MR14 的 SR = SR[SN]（论文 Fig 1, p.8）
// ---------------------------------------------------------------------------

bool Iprf::SwapOrNotBit(size_t stage_index, uint32_t round, uint64_t xhat) const {
    // F(i, X̂)：域 3；X̂ 是 {X, X'} 的规范名（max），轮号 i 与 stage 下标都进输入块，
    // 保证不同 stage / 不同轮的位相互独立（论文 Thm 4 的前提："uniformly random round keys
    // and round functions for SN"）。取输出最低位 —— MR14 的模型就是"每次调用一个随机 bit"。
    const uint64_t v =
        Low64(prp_prf_.Eval(MakeBlock(static_cast<uint32_t>(xhat), kIprfDomainPrpRound,
                                      static_cast<uint16_t>(round),
                                      static_cast<uint32_t>(stage_index))));
    return (v & 1u) != 0;
}

uint64_t Iprf::SnRounds(size_t stage_index, uint64_t x, bool inverse) const {
    const IprfPrpStage& st = stages_[stage_index];
    const uint64_t n = st.n;
    const uint32_t t = st.rounds;
    const uint32_t base = round_key_offset_[stage_index];
    if (t == 0) return x;  // 表中不存在（n >= 2 的 stage 恒有 t >= 1）；防御性
    // 单轮的三个动作（论文 Fig 1 行 21–23）：
    //     X' ← K_i − X (mod N);  X̂ ← max(X, X');  F(i, X̂) = 1 ⇒ X ← X'
    // 该映射是**对合**（{X, X'} 不变，再做一次就换回来）⇒ 解密 = 按轮号**逆序**执行同一批轮。
    if (!inverse) {
        for (uint32_t r = 1; r <= t; ++r) {
            const uint64_t k = round_keys_[base + (r - 1)];
            // K_i − X mod N：K_i, X ∈ [N) 且 N ≤ 2^32 ⇒ 用条件加法代替取模（64 位除法很贵）
            const uint64_t xp = (k >= x) ? (k - x) : (k + n - x);
            const uint64_t xhat = (x > xp) ? x : xp;
            if (SwapOrNotBit(stage_index, r, xhat)) x = xp;
        }
    } else {
        for (uint32_t r = t; r >= 1; --r) {
            const uint64_t k = round_keys_[base + (r - 1)];
            const uint64_t xp = (k >= x) ? (k - x) : (k + n - x);
            const uint64_t xhat = (x > xp) ? x : xp;
            if (SwapOrNotBit(stage_index, r, xhat)) x = xp;
            if (r == 1) break;  // 无符号下溢保护
        }
    }
    return x;
}

uint64_t Iprf::PrpForward(uint64_t x, IprfPrpTrace* trace) const {
    if (x >= params_.domain) {
        throw std::out_of_range("Iprf::PrpForward: x = " + std::to_string(x) +
                                " 越界（要求 < domain = " + std::to_string(params_.domain) + "）");
    }
    // 论文 Fig 1：while N > 1 { SN 混 t_N 轮；若 X ≥ p_N 结束，否则递归到 [p_N) }
    size_t si = 0;
    uint64_t n = params_.domain;
    while (n > 1) {
        x = SnRounds(si, x, false);
        if (trace != nullptr) {
            ++trace->stages;
            trace->rounds += stages_[si].rounds;
        }
        if (x >= n / 2) return x;  // 落入第二堆 ⇒ 这一层之后不再递归（行 31）
        n /= 2;                    // p_N = ⌊N/2⌋（规范切分），递归只洗第一堆（行 30）
        ++si;
    }
    return x;  // N == 1：一张牌已经洗好
}

uint64_t Iprf::PrpInverse(uint64_t x, IprfPrpTrace* trace) const {
    if (x >= params_.domain) {
        throw std::out_of_range("Iprf::PrpInverse: x = " + std::to_string(x) +
                                " 越界（要求 < domain = " + std::to_string(params_.domain) + "）");
    }
    // 下降：确定最深到达的 stage。子问题在 [p_N) 上的输出**必落在 [p_N)**，
    // 故"最终值 < p_N"恰好等价于"这一层发生过递归"（这是 Fig 1 行 30–31 的逆否）。
    size_t j = 0;
    uint64_t n = params_.domain;
    while (n > 1 && x < n / 2) {
        n /= 2;
        ++j;
    }
    // 升回：先反演最深的 stage（下标 j，若已走到 N=1 则从最后一个 stage 开始），再逐层回到 stage 0。
    size_t count = (j < stages_.size()) ? (j + 1) : stages_.size();
    for (size_t k = count; k-- > 0;) {
        x = SnRounds(k, x, true);
        if (trace != nullptr) {
            ++trace->stages;
            trace->rounds += stages_[k].rounds;
        }
    }
    return x;
}

uint64_t Iprf::PrpWorstCaseRounds() const {
    uint64_t total = 0;
    for (const IprfPrpStage& st : stages_) total += st.rounds;
    return total;
}

double Iprf::PrpExpectedRounds() const {
    // 每一层以 P(X < p_N) = ⌊N/2⌋/N 的概率继续递归（X 在一层的输出上近似均匀）。
    double total = 0.0;
    double reach = 1.0;
    for (const IprfPrpStage& st : stages_) {
        total += reach * static_cast<double>(st.rounds);
        reach *= static_cast<double>(st.n / 2) / static_cast<double>(st.n);
    }
    return total;
}

double Iprf::SnDistanceUpperBound(uint64_t n, uint64_t q, uint64_t rounds) {
    // MR14 式 (1)（p.5）：Δub_SN(N,q,r) = (2N^{3/2}/(r+2)) · ((q+N)/(2N))^{r/2+1}
    const double v = 2.0 * std::pow(static_cast<double>(n), 1.5) /
                     static_cast<double>(rounds + 2) *
                     std::pow(static_cast<double>(q + n) / (2.0 * static_cast<double>(n)),
                              static_cast<double>(rounds) / 2.0 + 1.0);
    return v;
}

// ---------------------------------------------------------------------------
// §3 PMNS（论文 Fig 4, p.16）+ Theorem 4.4 的 iPRF 三算法
// ---------------------------------------------------------------------------

uint64_t Iprf::SampleBinomialHalf(uint64_t count, uint32_t low, uint32_t level) const {
    if (count == 0) return 0;
    // children(k, node) 的随机源：F(k, node)，node 由 (low, level) 唯一确定
    //（同一层的不同节点 low 不同，同一条路径上不会撞车；而**正反两个方向在同一节点**
    //  用相同入参 ⇒ 必然得到同一个 s，这正是往返一致性的确定性保证）。
    const uint64_t u = Low64(pmns_prf_.Eval(MakeBlock(low, kIprfDomainPmnsNode,
                                                      static_cast<uint16_t>(level))));
    return BinomialHalfFromUniform(count, u);
}

void Iprf::PmnsWalk(uint64_t v, bool inverse, uint64_t& start, uint64_t& count,
                    uint64_t& leaf) const {
    // 论文 Fig 4：S(k, x) 与 S^-1(k, y) 走**同一棵二叉树**，每层调用一次 children(k, node)。
    start = 0;
    count = params_.domain;
    uint64_t low = 0;
    uint64_t high = params_.range - 1;
    uint32_t level = 0;
    while (low < high) {
        const uint64_t mid = low + (high - low) / 2;
        const uint64_t a = mid - low + 1;
        const uint64_t b = high - mid;
        // range = 2^k ⇒ 每层区间长度都是 2 的幂 ⇒ a == b（p 恰为 1/2）。
        // Validate() 已强制该前提，这里是防御性检查（不可达）。
        if (a != b) {
            throw std::logic_error(
                "Iprf: PMNS 二叉树出现 a != b 的节点（range 必须是 2 的幂；若你是从"
                "反序列化/内部状态改的 range，请重新构造 IprfParams 并校验）");
        }
        const uint64_t s = SampleBinomialHalf(count, static_cast<uint32_t>(low), level);
        if (!inverse) {
            // S(k, x)：x < start + s 走左子，否则走右子（论文 Fig 4 的左列）
            if (v < start + s) {
                count = s;
                high = mid;
            } else {
                start += s;
                count -= s;
                low = mid + 1;
            }
        } else {
            // S^-1(k, y)：y ≤ mid 走左子（论文 Fig 4 的右列）
            if (v <= mid) {
                count = s;
                high = mid;
            } else {
                start += s;
                count -= s;
                low = mid + 1;
            }
        }
        ++level;
    }
    leaf = low;  // 叶子编号 = 值域元素 ∈ [range)
}

uint64_t Iprf::Forward(uint64_t x) const {
    if (x >= params_.domain) {
        throw std::out_of_range("Iprf::Forward: x = " + std::to_string(x) +
                                " 越界（要求 < domain = " + std::to_string(params_.domain) + "）");
    }
    // Theorem 4.4：iF.F((k1,k2), x) = S(k2, P(k1, x))
    const uint64_t px = PrpForward(x, nullptr);
    uint64_t start = 0, count = 0, leaf = 0;
    PmnsWalk(px, false, start, count, leaf);
    return leaf;
}

uint64_t Iprf::InverseSize(uint64_t y) const {
    if (y >= params_.range) {
        throw std::out_of_range("Iprf::InverseSize: y = " + std::to_string(y) +
                                " 越界（要求 < range = " + std::to_string(params_.range) + "）");
    }
    uint64_t start = 0, count = 0, leaf = 0;
    PmnsWalk(y, true, start, count, leaf);
    return count;
}

void Iprf::Inverse(uint64_t y, std::vector<uint64_t>& out) const {
    if (y >= params_.range) {
        throw std::out_of_range("Iprf::Inverse: y = " + std::to_string(y) +
                                " 越界（要求 < range = " + std::to_string(params_.range) + "）");
    }
    uint64_t start = 0, count = 0, leaf = 0;
    PmnsWalk(y, true, start, count, leaf);
    out.resize(static_cast<size_t>(count));
    // Theorem 4.4：iF.F^-1((k1,k2), y) = { P^-1(k1, t) : t ∈ S^-1(k2, y) }
    // S^-1 是**连续区间** ⇒ 成本 = |原像| 次 PRP 逆（这是 iPRF 相对普通 PRF 的关键优势）。
    for (uint64_t i = 0; i < count; ++i) {
        out[static_cast<size_t>(i)] = PrpInverse(start + i, nullptr);
    }
    // 论文只要求集合语义；本实现统一输出升序，便于比对与去重检查。
    std::sort(out.begin(), out.end());
}

void Iprf::InverseInto(uint64_t y, uint64_t* out, size_t cap, size_t& n) const {
    if (y >= params_.range) {
        throw std::out_of_range("Iprf::InverseInto: y = " + std::to_string(y) +
                                " 越界（要求 < range = " + std::to_string(params_.range) + "）");
    }
    uint64_t start = 0, count = 0, leaf = 0;
    PmnsWalk(y, true, start, count, leaf);
    if (cap < static_cast<size_t>(count)) {
        throw std::length_error("Iprf::InverseInto: 缓冲区容量不足（需要 " +
                                std::to_string(count) + "，给出 " + std::to_string(cap) + "）");
    }
    if (out == nullptr && count > 0) {
        throw std::invalid_argument("Iprf::InverseInto: out 为空指针但原像非空");
    }
    if (count == 0) {  // 空 bin：不碰 out（也避免对空指针做 std::sort）
        n = 0;
        return;
    }
    for (uint64_t i = 0; i < count; ++i) {
        out[static_cast<size_t>(i)] = PrpInverse(start + i, nullptr);
    }
    std::sort(out, out + count);
    n = static_cast<size_t>(count);
}

void Iprf::PmnsPreimage(uint64_t y, uint64_t& start, uint64_t& count) const {
    if (y >= params_.range) {
        throw std::out_of_range("Iprf::PmnsPreimage: y = " + std::to_string(y) +
                                " 越界（要求 < range = " + std::to_string(params_.range) + "）");
    }
    uint64_t leaf = 0;
    PmnsWalk(y, true, start, count, leaf);
}

}  // namespace tsb
