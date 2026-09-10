#pragma once

// 可逆伪随机函数（iPRF，invertible PRF）—— Plinko 检索层的密码学底座（任务 FND-06）。
//
// ============================ 1. 定义与构造 ============================
//
// 定义（Plinko 论文 Def 4.1，p.10）：iPRF 是三元组 (Gen, F, F^-1)，
//   Gen : {0,1}* → K 是**随机化**密钥生成；
//   F   : K × D → R 是确定性函数；
//   F^-1: K × R → 2^D 返回**原像集合**（不是"逆函数"——PRP 的逆才是单点对单点）。
// 正确性要求：Pr_{k←Gen}[ F^-1_k(y) ≠ { x ∈ D | F_k(x) = y } ] ≤ negl(λ)。
//
// 本模块实现 Plinko **Theorem 4.4**（p.12）的构造 iF = PMNS ∘ PRP：
//     Gen()            = (P.Gen, S.Gen)                        ← 两把 AES-128 密钥
//     F((k1,k2), x)    = S(k2, P(k1, x))
//     F^-1((k1,k2), y) = { P^-1(k1, t) : t ∈ S^-1(k2, y) }
// 其中 P 是 [H) 上的 PRP，S 是 PMNS（伪随机多项分布采样器，Def 4.2/4.3、Fig 4, p.16）。
//
// Plinko 的实例化口径（Fig 7 图注，p.31 底部，逐字）：
//     "The client uses an iPRF iF from [λw + q] to [w]."
//   ⇒ **定义域 [H) → 值域 [w)**，其中 H := λw + q 是 hint 下标空间、w 是**区块大小**
//     （区块内偏移的取值范围），c := n/w 是区块数。**不是** [n]→[m]、也不是 [n]→[r]×[n/r]。
//   ⇒ 定义域**大于**值域（H = 1.5λw ≫ w），且 PMNS 的反像是**连续区间**
//     （Fig 4 的 S^-1 返回 {start, …, start+count−1}），
//     故 F^-1 的成本 = |原像| 次 PRP 逆，F 的成本 = log₂w 次节点采样 + 1 次 PRP。
//
// ============================ 2. 三条硬约束（决策 D21）============================
//
//  ⚠️ 1. **range 必须是 2 的幂**。range 非 2 的幂时 PMNS 二叉树里会出现 a ≠ b 的节点
//        （p = a/(a+b) ≠ 1/2），论文 Fig 4 的去随机化二项采样就退化成"count 次伯努利求和"
//        的精确路径，单次 F 从 ~2 µs 掉到 ~1.9 ms（实测**慢约 900×**，REPORT §3.3）。
//        本模块**直接拒绝**该输入（构造时抛 std::invalid_argument 并说明原因），
//        **不实现慢路径**：range(=区块大小 w) 是自由设计参数，取 2 的幂没有任何代价
//        （与 D15(a)"PIR 数据库补齐到 2 的幂"同一口径）。
//
//  ⚠️ 2. **绝不**为了让"每个 bin 的原像个数相等"而做排序/重定位/贪心匹配等平衡化后处理。
//        Plinko §4.2（p.12）逐字把 truncated PRP 的"等长原像"列为**安全缺陷**：
//        "The core issue with truncated PRPs is that each output has the same pre-image size …
//         This is fundamentally different than a random function from [n] to [m], which will have
//         pre-image sizes that are distributed as though one threw n balls into m bins."
//        ⇒ 原像规模必须服从**多项分布 MN(H,w)**（PMNS 的定义性要求）。本构造**直接**按
//        多项分布采样，"保证平衡"这个需求根本不存在。任何"顺手优化成平衡"的改动都会把构造
//        退化回 truncated PRP，**降低**安全性（tests/test_iprf.cpp 里有防回归用例固化该性质）。
//
//  ⚠️ 3. 求值器（Iprf 对象）**必须长期持有**。构造函数会预计算 MR14 每一轮的轮常数 K_i
//        （约 lg H 个 stage、合计数百~数千次 AES 调用），因此"每次求值新建一个 Iprf"
//        会让热路径慢一个数量级。Plinko 侧按论文 Fig 7 "每个区块一把密钥"持有 c 个求值器
//        （c = n/w），全程复用。这与决策 D20（PRF 是热路径，别往里塞打包开销）同一精神。
//
// ============================ 3. PRP 的实例化：MR14 ============================
//
// 依据：`doc/paper/Sometimes-Recurse Shuffle.pdf`（Morris & Rogaway, "Sometimes-Recurse
// Shuffle: Almost-Random Permutations in Logarithmic Expected Time"），本文件逐条给出页号/算法号。
//
// 为什么必须用 MR14（决策 D21 的风险 R1、TASK_PLAN §7.8 L6）：
//   iPRF 的 PRP 作用在**小定义域** [H) 上（Plinko 里 H ≈ 1.5λw，λ=80、w=256 时 H = 3×10⁴，
//   只有 15~16 bit）。小定义域 Feistel 的信息论安全性只到 ~2^{b/2} 次查询
//   （MR14 §1, p.1：「But information-theoretic security will vanish by the time the adversary
//   asks √N queries, which is a problem on small-sized domains」），H = 3×10⁴ 时约 256 次查询，
//   而 Plinko 要求 "a secure PRP over [n]"。MR14 的 SR 洗牌用 Θ(lg N − lg ε) 期望轮数达到
//   **full security**：敌手可以查询**整个定义域**，区分优势仍 ≤ ε（Thm 4, p.9）。
//   ⇒ 不允许用"把 Feistel 轮数提到 10~12"糊过去。
//
// SR = SR[SN]（论文 Fig 1, p.8，逐行对应）：
//     E_K^N(X):                                  // 不变式：X ∈ [N)
//       if N == 1 then return X                  // 单张牌已经洗好
//       for i ← 1 to t_N do                      // ① 用 SN 混 t_N 轮（行 20–23）
//          X'  ← K_i − X (mod N)                 //    X' 是 X 的"伙伴"
//          X̂  ← max(X, X')                       //    {X, X'} 的规范名
//          if F(i, X̂) = 1 then X ← X'            //    可能对换
//       if X < p_N then return E_K^{p_N}(X)      // ② 只递归洗**第一堆**（行 30–31）
//       if X ≥ p_N then return X                 //    第二堆已经好了
//   规范切分 p_N = ⌊N/2⌋（Fig 1 图注、§5 p.10："the canonical choice for the split p_N is p_N = ⌊N/2⌋"）。
//   随机性来源：轮常数 K : N → N（即每个轮号一个 K_i ∈ [N]）与 F : N × N → {0,1}（Fig 1 图注）。
//   每一轮 X ↦ K_i − X 是**对合**（伙伴关系不变），故**解密 = 按轮号逆序执行同样的轮**（不需要 F 的逆）。
//
//   轮数 t_N 的选取（论文 §5 "Parameter Optimization / Round counts", p.9–10，**strategy 1**：
//   "Split the error equally"）：设 n = |G'(N0)| = 生成 N 值中 ≥ 3 的个数 ≈ lg N0，
//     t_N = min { r ≥ 1 : Δub_SN(N, q_N, r) ≤ ε/n }，其中 q_N = N − p_N = ⌈N/2⌉，
//     Δub_SN(N, q, r) = (2·N^{3/2}/(r+2)) · ((q+N)/(2N))^{r/2+1}      ← 论文式 (1)（p.5）
//   另有 t_2 = 1（论文 §5：「we will always select t_2 = 1, as this choice already contributes
//   zero error」）与 t_1 = 0。渐近下界见式 (2)（p.5）：r ≥ 7.23 lg N − 4.82 lg ε。
//
//   安全性（论文 Thm 3, p.7 与 Thm 4, p.9）：
//     * Thm 3：SR_p[SH] 是 δ-good，δ = Σ_{N ∈ G(N0)} ε_N（本实现按 strategy 1 均摊 ⇒ δ ≤ ε）；
//     * Thm 4：任何 N ≥ 1、ε ∈ (0,1)，SR 的期望轮数 Θ(lg N − lg ε)、最坏 Θ(lg²N − lg N lg ε)，
//       **没有**敌手能以超过 ε 的优势把它与 [N) 上的均匀随机置换区分开
//       （前提：轮常数与轮函数均匀随机、轮数 t_N 合适、规范切分）。
//   数值对照：论文 Fig 2（p.10）给出 ε ≤ 10⁻¹⁰ 时 d 位十进制定义域的 min/mean/max 轮数
//   （d=5 即 N0=10⁵：386 / 758 / 8885）。
//
//   ⚠️ 论文的 SR 对**任意** N 成立（§4"The SR transformation", p.7）
//      ⇒ 本模块**不需要 cycle-walking**（Q9 原型的 Feistel 需要，且它是唯一重试点）。
//      构造完全确定性：无拒绝采样、无回溯、无 eviction、无匹配。
//      cycle-walking 的消失是本模块相对 Q9 原型的一个额外好处（Q9 报告 §4.3 R4 曾担心它是变时的）。
//
// ============================ 4. 域分隔与输入块 ============================
//
// core/aes_prf 的 PrfDomain 已占用 0/1/2（V-OO-PIR），本模块用：
//     kIprfDomainPrpRound    = 3   MR14 SN 的 swap-or-not 比特 F(i, X̂)（1 bit / 轮）
//     kIprfDomainPmnsNode    = 4   PMNS 树节点二项采样种子（1 次 / 节点）
//     kIprfDomainPrpRoundKey = 6   MR14 轮常数 K_i 的派生流（仅构造期用）
//     kIprfDomainKeyDerive   = 7   确定性密钥派生（Iprf::GenDeterministic，仅构造期用）
//   （REPORT §2 曾把 5 留给"range 非 2 的幂时的伯努利位流"；本模块拒绝该路径 ⇒ **5 保留不用**，
//     绝不复用它的语义。6/7 是本模块新增的编号。）
//
// AES 输入块布局沿用 core/aes_prf 的约定（`in[0]=w0, in[1]=(domain<<16)|w1, in[2]=w2, in[3]=0`，
// 小端 uint32_t[4]），只用 memcpy 组装，不做逐字节位移循环（决策 D20）。

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

#include "core/aes_prf.hpp"
#include "core/random.hpp"

namespace tsb {

// ---------------------------------------------------------------------------
// 域分隔常量
// ---------------------------------------------------------------------------
constexpr uint16_t kIprfDomainPrpRound = 3;     // MR14 SN 轮函数 F(i, X̂) → 1 bit
constexpr uint16_t kIprfDomainPmnsNode = 4;     // PMNS 树节点二项采样种子
constexpr uint16_t kIprfDomainPrpRoundKey = 6;  // MR14 轮常数 K_i 派生流
constexpr uint16_t kIprfDomainKeyDerive = 7;    // 确定性密钥派生（GenDeterministic）

// ---------------------------------------------------------------------------
// 参数
// ---------------------------------------------------------------------------

// iPRF: [domain) → [range)
//   Plinko 用法：domain = λw + q（hint 下标空间，**恒不是** 2 的幂），range = w（区块大小）。
struct IprfParams {
    uint64_t domain = 0;  // H = |D| ≥ 1；上界 2³²（受 AES 输入块的 32 位字宽限制）
    uint64_t range = 0;   // w = |R| ≥ 1；**必须是 2 的幂**（见文件头硬约束 1）

    // MR14 的目标总变差距离 ε（Thm 4：任何敌手的区分优势 ≤ ε）。默认取论文 §5 数值例子的
    // ε = 10⁻¹⁰（Fig 2, p.10），这样实测轮数可以直接与该表的 d=4/d=5 行对照。
    // 调大 ε ⇒ 轮数变少、PRP 更弱；调小 ε ⇒ 轮数变多。**策略参数，由调用方给定**。
    double prp_epsilon = 1e-10;

    // 校验：domain/range ≥ 1、range 为 2 的幂、domain 与 range ≤ 2³²、ε ∈ (0,1)，
    // 且按 ε 推出的轮数不超过 65535。违反时抛 std::invalid_argument（消息里给出原因）。
    void Validate() const;

    // 平均原像大小 = domain / range（**只是均值**，实际服从多项分布，绝不是"每个 bin 都这么多"）。
    double average_preimage() const {
        return static_cast<double>(domain) / static_cast<double>(range);
    }
};

// 一把 iPRF 密钥 = 两把 AES-128 密钥（Plinko Theorem 4.4：iF.Gen = (P.Gen, S.Gen)）。
// ⚠️ Plinko 是**每个区块一把**（论文 Fig 7：`For i = 1,…,n/w: K[i] ← iF.Gen(1^λ)`，
//    共 c = n/w 把，所有 hint 共用同一批区块密钥），见 Iprf::GenBlockKeys。
struct IprfKey {
    std::array<uint8_t, kAesKeyBytes> prp_key{};   // P: [domain) 上的 MR14 PRP
    std::array<uint8_t, kAesKeyBytes> pmns_key{};  // S: PMNS
};

// MR14 的一个 stage（生成的 N 值）+ 该 stage 的 SN 轮数（供诊断/单测/bench 使用）。
struct IprfPrpStage {
    uint64_t n = 0;       // 该 stage 的定义域大小 N_j（N_0 = domain，N_{j+1} = ⌊N_j/2⌋）
    uint32_t rounds = 0;  // t_N：论文 §5 strategy 1 选出的 SN 轮数
};

// PRP 求值的结构轨迹（不含 AES；用来验证"无重试/轮数符合论文"）。
struct IprfPrpTrace {
    uint64_t stages = 0;  // 实际执行了多少个 stage（≤ 表长）
    uint64_t rounds = 0;  // 实际执行了多少轮 SN
};

// ---------------------------------------------------------------------------
// 求值器
// ---------------------------------------------------------------------------

// ⚠️ 一个 Iprf 对象 = **一把** iPRF 密钥的求值器，构造时预计算 MR14 的轮常数（见文件头约束 3）。
//    不可拷贝（内部持有 Crypto++ AES 上下文）；需要放容器时用 std::unique_ptr<Iprf>。
class Iprf {
public:
    Iprf(const IprfKey& key, const IprfParams& params);

    Iprf(const Iprf&) = delete;
    Iprf& operator=(const Iprf&) = delete;

    // ---- 密钥生成 ----

    // CSPRNG 生成（部署路径）。
    static IprfKey Gen();

    // **显式种子**生成：同一 seed 在**任何进程/任何次运行**都给出逐位相同的密钥
    // （决策 D6：确定性随机源下的期望值测试）。内部用编译期常量根密钥喂
    // random::DeterministicPrng —— 若根密钥取自 CSPRNG，"确定性"就是假的（Q9 原型踩过的坑）。
    static IprfKey GenDeterministic(uint64_t seed);

    // 批量生成区块密钥（Plinko Fig 7：每区块一把，共 c = n/w 把）。
    // use_csprng=false 时第 i 把密钥 = 同一条确定性流的第 i 个 32 字节块（与 blocks 的取值无关，
    // 可复现）；第 0 把与 GenDeterministic(seed) 完全相同。
    // blocks 上限 32768（受 core/random 的确定性 PRNG 计数器位宽限制，超出抛 std::invalid_argument）。
    static std::vector<IprfKey> GenBlockKeys(size_t blocks, bool use_csprng = true,
                                             uint64_t seed = 0);

    // ---- iPRF 三个算法（Plinko Def 4.1）----

    // IF(k, x)：x ∈ [domain) → y ∈ [range)。x ≥ domain 抛 std::out_of_range。
    uint64_t Forward(uint64_t x) const;

    // IF^-1(k, y)：y ∈ [range) → 原像集合，**升序**输出（论文只要求集合语义，升序便于比对）。
    // 成本 = |原像| 次 PRP 逆。y ≥ range 抛 std::out_of_range。
    void Inverse(uint64_t y, std::vector<uint64_t>& out) const;

    // 零分配版本：写入调用方缓冲，语义与 Inverse 相同（同样升序）。
    // 原像个数 > cap 时抛 std::length_error（不静默截断）；out == nullptr 且原像非空抛
    // std::invalid_argument。成功时 n 为写入个数。
    void InverseInto(uint64_t y, uint64_t* out, size_t cap, size_t& n) const;

    // 只要 |IF^-1(y)|（不产生元素）：HintInit/GetHint 里判断候选规模时用。
    uint64_t InverseSize(uint64_t y) const;

    // ---- 诊断（与实现同源，供单测与 bench 使用）----

    const IprfParams& params() const { return params_; }
    const IprfKey& key() const { return key_; }

    // MR14 的 PRP（P / P^-1），x ∈ [domain)；越界抛 std::out_of_range。
    uint64_t PrpForward(uint64_t x, IprfPrpTrace* trace = nullptr) const;
    uint64_t PrpInverse(uint64_t x, IprfPrpTrace* trace = nullptr) const;

    // PMNS 的反像区间：S^-1(y) = [start, start+count)。
    void PmnsPreimage(uint64_t y, uint64_t& start, uint64_t& count) const;

    // MR14 参数：每个 stage 的 N_j 与轮数 t_N。
    const std::vector<IprfPrpStage>& prp_stages() const { return stages_; }
    // 最坏情况总轮数 = Σ_j t_j（必递归到底）；期望轮数按"每个 stage 以 p_N/N 概率递归"算。
    uint64_t PrpWorstCaseRounds() const;
    double PrpExpectedRounds() const;
    // 构造函数预计算的轮常数个数（= Σ_j t_j）。
    size_t PrpPrecomputedRoundKeys() const { return round_keys_.size(); }

    // 论文式 (1)（p.5）的 Δub_SN(N,q,r) —— 暴露出来供单测**独立重算**轮数选择是否合规。
    static double SnDistanceUpperBound(uint64_t n, uint64_t q, uint64_t rounds);

private:
    // MR14 SN 的 t_N 轮（inverse=true 时按轮号逆序，见文件头"对合 ⇒ 解密"）。
    uint64_t SnRounds(size_t stage_index, uint64_t x, bool inverse) const;
    // 论文 Fig 4 的二叉树下降：forward 返回叶子编号，inverse 返回连续区间 [start,start+count)。
    void PmnsWalk(uint64_t v, bool inverse, uint64_t& start, uint64_t& count,
                  uint64_t& leaf) const;
    // 去随机化二项采样 Binomial(count, 1/2; F(k,node))（论文 Fig 4 的 children()，p=1/2 路径）。
    uint64_t SampleBinomialHalf(uint64_t count, uint32_t low, uint32_t level) const;
    // MR14 SN 的 swap-or-not 比特 F(i, X̂)。
    bool SwapOrNotBit(size_t stage_index, uint32_t round, uint64_t xhat) const;

    IprfParams params_;
    IprfKey key_;
    AesPrf prp_prf_;   // 密钥 k1：MR14 PRP（轮函数与轮常数派生）
    AesPrf pmns_prf_;  // 密钥 k2：PMNS 树节点

    std::vector<IprfPrpStage> stages_;      // N_0 … N_last（N ≥ 2；N=1 不需要 stage）
    std::vector<uint32_t> round_key_offset_;  // 每个 stage 的轮常数在 round_keys_ 中的起始下标
    std::vector<uint64_t> round_keys_;      // K_i ∈ [N_j]，按 stage 连续存放（构造期预计算）
};

}  // namespace tsb
