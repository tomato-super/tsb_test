// FND-06：core/iprf（可逆 PRF）测试。
//
// 规格来源：`doc/design/q9_iprf/REPORT.md` §6 的测试清单 + `TASK_PLAN.md` §9.2 S1 的验收标准。
// 口径（决策 D21 / §10 第 11 条）：IF = PMNS ∘ PRP、定义域 [λw+q] → 值域 [w]、w 必须是 2 的幂、
// 原像规模必须服从**多项分布**（**禁止**断言"严格平衡"——论文 §4.2 把等长原像列为安全缺陷）。
// 小定义域 PRP 按 MR14（`doc/paper/Sometimes-Recurse Shuffle.pdf`）实例化，见 core/iprf.hpp 文件头。
//
// 全部用例都用**确定性随机源**（Iprf::GenDeterministic）⇒ 结果可复现、无 flaky（决策 D6）。

#include "core/iprf.hpp"
#include "core/random.hpp"
#include "test_framework.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace tsb;

namespace {

using Clock = std::chrono::steady_clock;

double MicrosBetween(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::micro>(b - a).count();
}

IprfParams Params(uint64_t domain, uint64_t range, double eps = 1e-10) {
    IprfParams p;
    p.domain = domain;
    p.range = range;
    p.prp_epsilon = eps;
    return p;
}

uint64_t RandBelow(random::DeterministicPrng& prng, uint64_t bound) {
    if (bound == 0) return 0;
    return static_cast<uint64_t>(prng.Below(bound));
}

// 用 IF 前向**按定义**建原像表（独立于 IF⁻¹ 的实现路径）。
// ⚠️ REPORT §7.2 的教训：原型靠这条独立路径抓出过"备份 hint 补集 parity 未更新"的真 bug，
//    因此交叉验证必须保留 —— 正反两向不一致会表现为**静默**的错误结果。
std::vector<std::vector<uint64_t>> PreimagesByDefinition(const Iprf& ip, uint64_t domain) {
    std::vector<std::vector<uint64_t>> by_def(static_cast<size_t>(ip.params().range));
    for (uint64_t x = 0; x < domain; ++x) {
        by_def[static_cast<size_t>(ip.Forward(x))].push_back(x);
    }
    return by_def;
}

std::string VectorToString(const std::vector<uint64_t>& v) {
    std::string s = "{";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i != 0) s += ",";
        s += std::to_string(v[i]);
        if (i > 24) { s += ",…(共 " + std::to_string(v.size()) + ")"; break; }
    }
    return s + "}";
}

// Plinko 的部署参数派生：w = 2^⌈log2√n⌉、M = λw（常规 hint）、q = M/2（备份 hint）、H = M+q。
// （参数派生本身属于 PIR-04；这里只是为了取"与 REPORT §3.3 同口径"的 benchmark 参数。）
struct PlinkoLike {
    uint64_t n;
    uint64_t w;
    uint64_t c;
    uint64_t H;
};

PlinkoLike DerivePlinkoLike(uint32_t lambda, uint64_t n) {
    PlinkoLike r{};
    r.n = n;
    uint64_t w = 1;
    while (w * w < n) w *= 2;
    r.w = w;
    r.c = n / w;
    const uint64_t M = static_cast<uint64_t>(lambda) * w;
    r.H = M + M / 2;
    return r;
}

}  // namespace

// ---------------------------------------------------------------------------
// 1. 参数校验
// ---------------------------------------------------------------------------

TEST(Iprf, ParamsValidateRejectsNonPowerOfTwoRangeAndDegenerateValues) {
    // 合法参数：range = 1 = 2^0 也算 2 的幂。
    EXPECT_NO_THROW(Params(1, 1).Validate());
    EXPECT_NO_THROW(Params(16, 4).Validate());
    EXPECT_NO_THROW(Params(30720, 256).Validate());
    EXPECT_NO_THROW(Params(1ull << 20, 1ull << 20).Validate());

    // 退化值
    EXPECT_THROW(Params(0, 4).Validate(), std::invalid_argument);
    EXPECT_THROW(Params(16, 0).Validate(), std::invalid_argument);
    EXPECT_THROW(Params(16, 4, 0.0).Validate(), std::invalid_argument);
    EXPECT_THROW(Params(16, 4, 1.0).Validate(), std::invalid_argument);
    EXPECT_THROW(Params(16, 4, -1e-10).Validate(), std::invalid_argument);
    // 超出 AES 输入块字宽的参数
    EXPECT_THROW(Params((1ull << 32) + 1, 4).Validate(), std::invalid_argument);
    EXPECT_THROW(Params(16, (1ull << 32) + 2).Validate(), std::invalid_argument);

    // ⚠️ 决策 D21 / REPORT §3.3 的硬约束：range 非 2 的幂必须被**直接拒绝**
    //（论文 Fig 4 的二项采样会退化成 O(count) 慢路径，实测慢约 900×；本模块不实现该路径）。
    for (uint64_t w : {3ull, 7ull, 100ull, 181ull, 251ull, 257ull, 1000ull, 2043ull}) {
        EXPECT_THROW(Params(4096, w).Validate(), std::invalid_argument);
    }
    // 同一个非法 range 在构造求值器时也必须抛（校验入口唯一，不留绕过路径）
    EXPECT_THROW(Iprf(Iprf::GenDeterministic(1), Params(4096, 251)), std::invalid_argument);

    // 消息里必须说明原因（"为什么拒绝 w != 2^k"是给未来维护者的关键信息）
    bool explained = false;
    try {
        Params(4096, 251).Validate();
    } catch (const std::invalid_argument& e) {
        const std::string msg = e.what();
        explained = msg.find("2 的幂") != std::string::npos &&
                    msg.find("900") != std::string::npos;
    }
    EXPECT_TRUE(explained);
}

// ---------------------------------------------------------------------------
// 2. 确定性与可复现（决策 D6 / REPORT §6 用例 1）
// ---------------------------------------------------------------------------

TEST(Iprf, GenDeterministicIsReproducibleAcrossInstances) {
    const IprfKey a = Iprf::GenDeterministic(20260910);
    const IprfKey b = Iprf::GenDeterministic(20260910);
    EXPECT_EQ(a.prp_key, b.prp_key);
    EXPECT_EQ(a.pmns_key, b.pmns_key);

    const IprfKey c = Iprf::GenDeterministic(20260911);
    EXPECT_NE(a.prp_key, c.prp_key);
    EXPECT_NE(a.pmns_key, c.pmns_key);

    // ⚠️ seed 的**每一位**都必须影响密钥。这条断言来自一个真实的底座缺陷：
    //    `random::DeterministicPrng::Next()` 只把 nonce 的高 32 位放进 AES 输入块
    //    （`EvalDomainU32(..., nonce >> 32, counter)`），低 32 位被静默忽略 ⇒
    //    若把 seed 直接当 nonce，seed=99 与 seed=100 会生成**完全相同**的密钥流
    //    （本模块在 GenDeterministic 里先做一次 AES-PRF 展开规避，见 iprf.cpp）。
    EXPECT_NE(Iprf::GenDeterministic(99).prp_key, Iprf::GenDeterministic(100).prp_key);
    EXPECT_NE(Iprf::GenDeterministic(99).prp_key,
              Iprf::GenDeterministic(99 + (1ull << 32)).prp_key);
    EXPECT_NE(Iprf::GenDeterministic(100).prp_key,
              Iprf::GenDeterministic(100 + (1ull << 32)).prp_key);
    EXPECT_NE(Iprf::GenDeterministic(0).pmns_key, Iprf::GenDeterministic(1ull << 40).pmns_key);

    // 两个独立构造的求值器必须给出逐位相同的结果（密钥 + 预计算轮常数都确定）
    const IprfParams p = Params(1024, 32);
    const Iprf ip1(a, p);
    const Iprf ip2(b, p);
    for (uint64_t x = 0; x < 64; ++x) EXPECT_EQ(ip1.Forward(x), ip2.Forward(x));
    for (uint64_t y = 0; y < 32; ++y) {
        std::vector<uint64_t> o1, o2;
        ip1.Inverse(y, o1);
        ip2.Inverse(y, o2);
        EXPECT_EQ(VectorToString(o1), VectorToString(o2));
    }

    // CSPRNG 生成的密钥不应与确定性密钥相同（否则说明 Gen 根本没走随机源）
    const IprfKey r = Iprf::Gen();
    EXPECT_NE(r.prp_key, a.prp_key);
}

TEST(Iprf, GenBlockKeysIsDeterministicAndPrefixStable) {
    // Plinko Fig 7：每区块一把密钥。批量生成必须可复现，且第 i 把与 blocks 的取值无关
    //（否则 HintInit 的参数一改所有区块偏移全变）。
    const std::vector<IprfKey> four = Iprf::GenBlockKeys(4, false, 99);
    const std::vector<IprfKey> two = Iprf::GenBlockKeys(2, false, 99);
    ASSERT_EQ(four.size(), size_t{4});
    ASSERT_EQ(two.size(), size_t{2});
    EXPECT_EQ(four[0].prp_key, two[0].prp_key);
    EXPECT_EQ(four[1].pmns_key, two[1].pmns_key);
    // 不同区块的密钥必须不同
    EXPECT_NE(four[0].prp_key, four[1].prp_key);
    EXPECT_NE(four[2].pmns_key, four[3].pmns_key);
    // 不同种子 ⇒ 不同密钥
    const std::vector<IprfKey> other = Iprf::GenBlockKeys(4, false, 100);
    EXPECT_NE(four[0].prp_key, other[0].prp_key);
}

// ---------------------------------------------------------------------------
// 3. 黄金向量（REPORT §6 用例 2/3：防"构造漂移"的回归基线）
// ---------------------------------------------------------------------------

// 黄金向量用的**显式固定密钥**（原本由 `GenDeterministic(0)` 派生）。
//
// ⚠️ 为什么改成显式写死：这些向量要固化的是 **PRP/PMNS 构造**（轮函数输入布局、域分隔
// 编号、二项采样、树下降）。若密钥经由 `GenDeterministic` ⇒ `DeterministicPrng` 派生，
// 那么**修 PRNG 本身**（例如修掉"nonce 低 32 位被忽略"的底座缺陷）也会让向量失效，
// 把两件不相干的事绑在一起。构造的确定性/可复现性由 `GenDeterministic` 的专门用例覆盖。
IprfKey PinnedGoldenKey() {
    IprfKey k;
    k.prp_key = {0x8f, 0x8a, 0x6f, 0xa2, 0x0d, 0xb4, 0x0e, 0x3f,
                 0x8a, 0xaa, 0x21, 0x48, 0x91, 0x6e, 0xed, 0x92};
    k.pmns_key = {0xac, 0x85, 0x5e, 0x40, 0x79, 0xf7, 0x12, 0x4a,
                  0x39, 0xa6, 0xd6, 0x73, 0x33, 0xdb, 0x0d, 0x5d};
    return k;
}

TEST(Iprf, GoldenVectorsPinConstruction) {
    // 期望值在 2026-09-10 的首次实现上用上面这把固定密钥生成并**冻结**。
    // 改动 PRP/PMNS 的构造（轮函数输入布局、域分隔编号、二项采样、树下降）都会让它们变化
    // —— 这正是本用例的目的：任何构造漂移都必须被显式确认，而不是静默通过。
    {
        const Iprf ip(PinnedGoldenKey(), Params(16, 4));
        const uint64_t expected_fwd[16] = {3, 3, 1, 3, 1, 2, 3, 2, 1, 2, 3, 3, 3, 2, 0, 2};
        for (uint64_t x = 0; x < 16; ++x) EXPECT_EQ(ip.Forward(x), expected_fwd[x]);
        // 注意 load 分别为 1/3/5/7 —— 与"严格平衡"（每个 bin 恰好 4）截然不同，
        // 这正是多项分布的正常表现（论文 §4.2）。
        const std::vector<std::vector<uint64_t>> expected_inv = {
            {14}, {2, 4, 8}, {5, 7, 9, 13, 15}, {0, 1, 3, 6, 10, 11, 12}};
        for (uint64_t y = 0; y < 4; ++y) {
            std::vector<uint64_t> out;
            ip.Inverse(y, out);
            EXPECT_EQ(VectorToString(out), VectorToString(expected_inv[y]));
        }
    }
    {
        const Iprf ip(PinnedGoldenKey(), Params(1024, 32));
        const uint64_t expected_small[8] = {28, 3, 29, 25, 7, 7, 18, 20};
        for (uint64_t x = 0; x < 8; ++x) EXPECT_EQ(ip.Forward(x), expected_small[x]);
        const uint64_t expected_1k[4] = {4, 14, 11, 0};
        for (uint64_t i = 0; i < 4; ++i) EXPECT_EQ(ip.Forward(1000 + i), expected_1k[i]);
        EXPECT_EQ(ip.PrpForward(0), uint64_t{917});
        EXPECT_EQ(ip.PrpInverse(0), uint64_t{90});
        std::vector<uint64_t> out;
        ip.Inverse(31, out);
        EXPECT_EQ(out.size(), size_t{28});
        EXPECT_EQ(out.front(), uint64_t{224});
        EXPECT_EQ(out.back(), uint64_t{1022});
    }
}

// ---------------------------------------------------------------------------
// 4. 往返一致性（两个方向）—— REPORT §6 用例 4/5，验收要求"样本量 >= 10^5、失败数 0"
// ---------------------------------------------------------------------------

TEST(Iprf, RoundTripForwardThenInverseLargeSample) {
    // IF⁻¹(IF(x)) ∋ x。每个样本 1 次 IF + 1 次 IF⁻¹，并按 |IF⁻¹| 做 x 级断言：
    //   Σ|IF⁻¹(IF(x))| = 3×10^4 + 6.4×10^4 + 3.6×10^4 = 1.3×10^5 >= 10^5（验收口径）。
    // 前若干个样本另外对**原像里的每一个元素**回代验证（O(|原像|) 次 IF，故只做有限个）。
    struct Case { uint64_t H, w, samples, full_verify; };
    const Case cases[] = {{16, 4, 30000, 3000}, {1024, 32, 2000, 50}, {30720, 256, 300, 20}};
    uint64_t total_samples = 0, total_x_checks = 0, total_failures = 0;
    for (const Case& c : cases) {
        const Iprf ip(Iprf::GenDeterministic(0x51D + c.H), Params(c.H, c.w));
        random::DeterministicPrng prng(Iprf::GenDeterministic(c.H).prp_key, c.H);
        std::vector<uint64_t> preimage;
        uint64_t failures = 0, checks = 0;
        for (uint64_t i = 0; i < c.samples; ++i) {
            const uint64_t x = RandBelow(prng, c.H);
            const uint64_t y = ip.Forward(x);
            ip.Inverse(y, preimage);
            if (!std::binary_search(preimage.begin(), preimage.end(), x)) ++failures;
            checks += preimage.size();
            if (i < c.full_verify) {
                for (uint64_t v : preimage) {
                    if (ip.Forward(v) != y) ++failures;
                    ++checks;
                }
            }
        }
        EXPECT_EQ(failures, uint64_t{0});
        total_samples += c.samples;
        total_x_checks += checks;
        total_failures += failures;
        std::printf("  [往返 正→逆] H=%-6llu w=%-4llu 样本=%-6llu x级断言=%-7llu 失败=%llu\n",
                    static_cast<unsigned long long>(c.H),
                    static_cast<unsigned long long>(c.w),
                    static_cast<unsigned long long>(c.samples),
                    static_cast<unsigned long long>(checks),
                    static_cast<unsigned long long>(failures));
    }
    EXPECT_TRUE(total_samples >= 20000);
    EXPECT_TRUE(total_x_checks >= 100000);
    EXPECT_EQ(total_failures, uint64_t{0});
}

TEST(Iprf, RoundTripInverseThenForwardLargeSample) {
    // 对随机 y 取 IF⁻¹(y)，对其中**每一个** x 回代验证 IF(x) == y。
    // 校验的 x 总数（= Σ|IF⁻¹(y)|）= 4×10^4 + 4.8×10^4 + 4.8×10^4 = 1.36×10^5，
    // 满足"两个方向都要 >= 10^5 样本"的验收口径。
    struct Case { uint64_t H, w, samples; };
    const Case cases[] = {{16, 4, 10000}, {1024, 32, 1500}, {30720, 256, 400}};
    uint64_t total_x_checked = 0, total_failures = 0, total_ys = 0;
    for (const Case& c : cases) {
        const Iprf ip(Iprf::GenDeterministic(0x7A2 + c.H), Params(c.H, c.w));
        random::DeterministicPrng prng(Iprf::GenDeterministic(c.H + 5).prp_key, c.H + 5);
        std::vector<uint64_t> preimage;
        uint64_t failures = 0, checked = 0;
        for (uint64_t i = 0; i < c.samples; ++i) {
            const uint64_t y = RandBelow(prng, c.w);
            ip.Inverse(y, preimage);
            // 集合必须是升序且无重复（Inverse 的契约）
            if (!std::is_sorted(preimage.begin(), preimage.end())) ++failures;
            if (std::adjacent_find(preimage.begin(), preimage.end()) != preimage.end()) ++failures;
            for (uint64_t x : preimage) {
                if (ip.Forward(x) != y) ++failures;
                ++checked;
            }
            if (preimage.size() != ip.InverseSize(y)) ++failures;
        }
        EXPECT_EQ(failures, uint64_t{0});
        total_x_checked += checked;
        total_failures += failures;
        total_ys += c.samples;
        std::printf("  [往返 逆→正] H=%-6llu w=%-4llu y样本=%-5llu 回代x=%-7llu 失败=%llu\n",
                    static_cast<unsigned long long>(c.H),
                    static_cast<unsigned long long>(c.w),
                    static_cast<unsigned long long>(c.samples),
                    static_cast<unsigned long long>(checked),
                    static_cast<unsigned long long>(failures));
    }
    EXPECT_TRUE(total_ys > 0);
    EXPECT_TRUE(total_x_checked >= 100000);
    EXPECT_EQ(total_failures, uint64_t{0});
}

// ---------------------------------------------------------------------------
// 5. 小规模穷举：IF⁻¹ 与"按定义的前像表"完全相等（TASK_PLAN §9.2 S1 的最硬确定性用例）
// ---------------------------------------------------------------------------

TEST(Iprf, ExhaustiveSmallParamsInverseEqualsForwardDefinition) {
    // ⚠️ 口径更正：**不能**断言 IF 是 [H) 到 [w) 的"满射"。IF 是随机函数 [H)→[w)，
    //    当 H 只是略大于 w（尤其 H == w）时，按随机函数模型期望有 w·e^{-H/w} 个**空 bin**
    //    （H = w = 4 时约 1.27 个）。正确的性质是：{IF⁻¹(y)} 构成 [H) 的**一个划分**
    //    （两两不交、并集 = [H)、每个集合 = {x : IF(x) = y}），空 bin 的 IF⁻¹ 为空集。
    //    只有负载足够大（H >= 8w）时才断言"无空 bin"。
    struct Case { uint64_t H, w; bool expect_no_empty_bin; };
    const Case cases[] = {
        // expect_no_empty_bin 只在负载足够大（H >= 8w）时断言：按随机函数模型，
        // 空 bin 的期望个数是 w·e^{-H/w}，H = 4w 时仍有约 7% 的 bin 可能是空的。
        {4, 2, false}, {4, 4, false}, {8, 4, false}, {16, 4, false}, {16, 2, true},
        {16, 8, false}, {8, 8, false}, {7, 4, false}, {32, 4, true}, {64, 8, true},
        {100, 16, false},
    };
    for (const Case& c : cases) {
        const Iprf ip(Iprf::GenDeterministic(0xBEEF), Params(c.H, c.w));
        const auto by_def = PreimagesByDefinition(ip, c.H);
        std::set<uint64_t> seen;
        size_t empty_bins = 0;
        uint64_t total = 0;
        for (uint64_t y = 0; y < c.w; ++y) {
            std::vector<uint64_t> got;
            ip.Inverse(y, got);
            // ① 与按定义的前像表**完全相等**
            EXPECT_EQ(VectorToString(got), VectorToString(by_def[static_cast<size_t>(y)]));
            EXPECT_EQ(got.size(), by_def[static_cast<size_t>(y)].size());
            // ② 两两不交（并集 = [H) 的检查见下）
            for (uint64_t x : got) {
                EXPECT_TRUE(seen.insert(x).second);
                total += 1;
            }
            if (got.empty()) ++empty_bins;
        }
        // ③ 并集 = [H)
        EXPECT_EQ(seen.size(), size_t{c.H});
        EXPECT_EQ(total, c.H);
        if (c.expect_no_empty_bin) {
            EXPECT_EQ(empty_bins, size_t{0});
        }
        // ④ 每个 bin 的原像个数之和由 IF 前向独立确认
        uint64_t forward_total = 0;
        for (uint64_t x = 0; x < c.H; ++x) forward_total += (ip.Forward(x) < c.w) ? 1 : 0;
        EXPECT_EQ(forward_total, c.H);
    }
}

TEST(Iprf, ExhaustiveMediumParamsCrossCheckTwoIndependentPaths) {
    // 用 IF 前向**按定义**建表，与 IF⁻¹ 逐 y 比对（含 H 非 2 的幂、H < w 的情形）。
    // 这是 REPORT §7.2 强调的交叉验证：正反向不一致会表现为静默的 parity 错误。
    struct Case { uint64_t H, w; };
    const Case cases[] = {{1024, 32}, {4097, 1024}, {3000, 256}, {100, 128}, {1, 1}, {1, 4096}};
    for (const Case& c : cases) {
        const Iprf ip(Iprf::GenDeterministic(0xC0FFEE), Params(c.H, c.w));
        const auto by_def = PreimagesByDefinition(ip, c.H);
        uint64_t sum = 0;
        size_t mismatches = 0;
        for (uint64_t y = 0; y < c.w; ++y) {
            std::vector<uint64_t> got;
            ip.Inverse(y, got);
            if (got != by_def[static_cast<size_t>(y)]) ++mismatches;
            sum += got.size();
        }
        EXPECT_EQ(mismatches, size_t{0});
        EXPECT_EQ(sum, c.H);  // Σ_y |IF⁻¹(y)| == H（划分性质）
    }
}

// ---------------------------------------------------------------------------
// 6. 原像分布：多项分布（**不是**严格平衡）—— REPORT §6 用例 7/8/14
// ---------------------------------------------------------------------------

TEST(Iprf, PreimageSizesFollowMultinomialDistribution) {
    // 负载由**前向全枚举**统计（独立于 IF⁻¹ 路径），确认每个 bin 的精确原像个数。
    // 阈值口径：所有用例都跑在**固定密钥**上 ⇒ 结果完全确定，阈值不是"flaky 旋钮"，
    // 而是"构造是否被改坏"的判据。REPORT §3.2 在 5 组规模上实测 |z| <= 1.14，
    // 这里放宽到 |z| <= 4（若构造漂移，z 会立刻爆掉）。
    struct Case { uint64_t H, w; };
    const Case cases[] = {{15360, 128}, {30720, 256}, {4096, 1024}};
    for (const Case& c : cases) {
        const Iprf ip(Iprf::GenDeterministic(0x1234), Params(c.H, c.w));
        std::vector<uint64_t> load(static_cast<size_t>(c.w), 0);
        for (uint64_t x = 0; x < c.H; ++x) load[static_cast<size_t>(ip.Forward(x))] += 1;

        const double mean = static_cast<double>(c.H) / static_cast<double>(c.w);
        double sum = 0.0;
        for (uint64_t v : load) sum += static_cast<double>(v);
        const double measured_mean = sum / static_cast<double>(c.w);
        double var = 0.0;
        for (uint64_t v : load) var += (static_cast<double>(v) - measured_mean) *
                                       (static_cast<double>(v) - measured_mean);
        var /= static_cast<double>(c.w);

        // ① 均值**精确**等于 H/w（整数口径：Σ load == H）
        EXPECT_EQ(static_cast<uint64_t>(sum), c.H);
        EXPECT_TRUE(std::fabs(measured_mean - mean) < 1e-9);

        // ② 与 Binomial(H, 1/w) 的方差同量级
        const double theo_var = static_cast<double>(c.H) * (1.0 / static_cast<double>(c.w)) *
                                (1.0 - 1.0 / static_cast<double>(c.w));
        EXPECT_TRUE(var > 0.3 * theo_var);
        EXPECT_TRUE(var < 3.0 * theo_var);

        // ③ Pearson χ²（多项分布零假设，E = H/w，dof = w−1）
        double chi2 = 0.0;
        for (uint64_t v : load) {
            const double d = static_cast<double>(v) - mean;
            chi2 += d * d / mean;
        }
        const double dof = static_cast<double>(c.w) - 1.0;
        const double z = (chi2 - dof) / std::sqrt(2.0 * dof);
        EXPECT_TRUE(std::fabs(z) <= 4.0);

        // ④ 高负载时不应出现空 bin；max load 与 Chernoff 一致（<= 均值 + 6σ）
        const uint64_t mn = *std::min_element(load.begin(), load.end());
        const uint64_t mx = *std::max_element(load.begin(), load.end());
        if (c.H >= 8 * c.w) EXPECT_TRUE(mn > 0);
        EXPECT_TRUE(static_cast<double>(mx) <= mean + 6.0 * std::sqrt(theo_var));

        std::printf("  [分布] H=%-6llu w=%-5llu mean=%.4f var=%.2f(理论 %.2f) min=%llu max=%llu "
                    "χ²=%.1f dof=%.0f z=%.2f\n",
                    static_cast<unsigned long long>(c.H), static_cast<unsigned long long>(c.w),
                    measured_mean, var, theo_var, static_cast<unsigned long long>(mn),
                    static_cast<unsigned long long>(mx), chi2, dof, z);
    }
}

TEST(Iprf, PreimageSizesAreNotStrictlyBalancedAntiRegression) {
    // ⚠️ **防回归的核心用例**（论文 §4.2）：如果有人"顺手优化"成
    // "每个 bin 恰好 H/w 个原像"，这些断言会立刻失败。
    // 严格平衡 = truncated PRP 的特征 = 论文点名的**安全缺陷**（敌手可区分），
    // 正确要求是原像规模服从多项分布 MN(H,w)。
    const Iprf ip(Iprf::GenDeterministic(0x5EED), Params(30720, 256));
    std::vector<uint64_t> load(256, 0);
    for (uint64_t x = 0; x < 30720; ++x) load[static_cast<size_t>(ip.Forward(x))] += 1;

    const std::set<uint64_t> distinct(load.begin(), load.end());
    uint64_t outside = 0;
    for (uint64_t v : load) {
        if (v != 30720 / 256 && v != 30720 / 256 + 1) ++outside;
    }
    // ① 负载取值必须多样（严格平衡只有 1 种取值）
    EXPECT_TRUE(distinct.size() >= 5);
    // ② 绝大多数 bin 的负载**不在** {⌊H/w⌋,⌈H/w⌉} 内（REPORT §3.2：512 个 bin 里 497 个在外）
    EXPECT_TRUE(outside * 2 >= 256);
    // ③ 方差必须显著非零
    double mean = 0.0;
    for (uint64_t v : load) mean += static_cast<double>(v);
    mean /= 256.0;
    double var = 0.0;
    for (uint64_t v : load) var += (static_cast<double>(v) - mean) * (static_cast<double>(v) - mean);
    var /= 256.0;
    EXPECT_TRUE(var > 10.0);
    std::printf("  [非平衡防回归] H=30720 w=256: 不同 load 取值=%zu 落在 {120,121} 之外=%llu/256 "
                "方差=%.1f\n",
                distinct.size(), static_cast<unsigned long long>(outside), var);
}

// ---------------------------------------------------------------------------
// 7. 边界（REPORT §3.5 的 9 组，按"w 必须是 2 的幂"调整后）
// ---------------------------------------------------------------------------

TEST(Iprf, BoundaryCasesIncludingNonPowerOfTwoDomain) {
    // REPORT §3.5 的 9 组边界：w 非 2 的幂的那几组（w = 3/100/181/2043）
    // 在本模块下**必须抛异常**（决策 D21），其余保持可工作。
    struct Case { uint64_t H, w; };
    const Case work[] = {
        {1, 1},      // 双退化
        {1, 4096},   // domain < range（H 远小于 w）
        {7, 16},     // domain < range
        {100, 128},  // domain < range
        {3000, 256}, // 常规
        {4095, 1024},
        {4097, 1024},// domain 非 2 的幂（原报告用它验证 cycle-walking；MR14 无 cycle-walking）
        {2048, 2048},// domain == range
        {16, 1},     // range == 1（w = 2^0）
    };
    for (const Case& c : work) {
        const Iprf ip(Iprf::GenDeterministic(0xABCD + c.H), Params(c.H, c.w));
        uint64_t sum = 0;
        for (uint64_t y = 0; y < c.w; ++y) {
            std::vector<uint64_t> out;
            ip.Inverse(y, out);
            sum += out.size();
            // 区间语义：prp 逆必须落在 [H)
            for (uint64_t x : out) EXPECT_TRUE(x < c.H);
        }
        EXPECT_EQ(sum, c.H);  // Σ_y |IF⁻¹(y)| == H，永远成立
        // 对小的 case 再做一次逐 x 往返
        if (c.H <= 4097) {
            for (uint64_t x = 0; x < c.H; ++x) {
                const uint64_t y = ip.Forward(x);
                EXPECT_TRUE(y < c.w);
                std::vector<uint64_t> out;
                ip.Inverse(y, out);
                EXPECT_TRUE(std::binary_search(out.begin(), out.end(), x));
            }
        }
    }
    // w 非 2 的幂的几组 → 抛异常
    for (const Case& c : {Case{100, 100}, Case{3000, 181}, Case{2048, 2043}}) {
        EXPECT_THROW(Iprf(Iprf::GenDeterministic(1), Params(c.H, c.w)), std::invalid_argument);
    }
}

TEST(Iprf, OutOfRangeInputsAndBufferContract) {
    const IprfParams p = Params(1024, 32);
    const Iprf ip(Iprf::GenDeterministic(7), p);

    // x >= domain
    EXPECT_THROW(ip.Forward(1024), std::out_of_range);
    EXPECT_THROW(ip.Forward(1ull << 40), std::out_of_range);
    EXPECT_THROW(ip.PrpForward(1024), std::out_of_range);
    EXPECT_THROW(ip.PrpInverse(4096), std::out_of_range);
    // y >= range
    EXPECT_THROW(ip.InverseSize(32), std::out_of_range);
    std::vector<uint64_t> out;
    EXPECT_THROW(ip.Inverse(32, out), std::out_of_range);
    uint64_t pmns_start = 0, pmns_count = 0;
    EXPECT_THROW(ip.PmnsPreimage(32, pmns_start, pmns_count), std::out_of_range);
    EXPECT_NO_THROW(ip.PmnsPreimage(31, pmns_start, pmns_count));
    // 边界内的最大取值必须可用
    EXPECT_NO_THROW(ip.Forward(1023));
    EXPECT_NO_THROW(ip.InverseSize(31));

    // 零分配版本：容量不足抛 std::length_error（不静默截断），容量足够时与 Inverse 一致
    const uint64_t y = 7;
    const uint64_t need = ip.InverseSize(y);
    std::vector<uint64_t> big(need, 0);
    size_t n = 0;
    ip.InverseInto(y, big.data(), big.size(), n);
    EXPECT_EQ(n, static_cast<size_t>(need));
    std::vector<uint64_t> ref;
    ip.Inverse(y, ref);
    EXPECT_EQ(VectorToString(std::vector<uint64_t>(big.begin(), big.begin() + n)),
              VectorToString(ref));
    std::vector<uint64_t> small(need - 1, 0);
    EXPECT_THROW(ip.InverseInto(y, small.data(), small.size(), n), std::length_error);
    EXPECT_THROW(ip.InverseInto(y, nullptr, 0, n), std::length_error);
}

// ---------------------------------------------------------------------------
// 8. MR14（SmallReCurse Shuffle）的实例化正确性
// ---------------------------------------------------------------------------

TEST(Iprf, Mr14PrpIsABijection) {
    // 小定义域全枚举（含大量非 2 的幂）：无重复 + 逆成立。
    for (uint64_t H : {1ull, 2ull, 3ull, 5ull, 16ull, 63ull, 64ull, 255ull, 256ull, 1000ull,
                       1023ull, 1024ull, 4096ull}) {
        const Iprf ip(Iprf::GenDeterministic(H), Params(H, 4));
        std::set<uint64_t> image;
        for (uint64_t x = 0; x < H; ++x) {
            const uint64_t y = ip.PrpForward(x);
            EXPECT_TRUE(y < H);
            EXPECT_TRUE(image.insert(y).second);
            EXPECT_EQ(ip.PrpInverse(y), x);
        }
        EXPECT_EQ(image.size(), size_t{H});
    }
}

TEST(Iprf, Mr14StageTableAndRoundSelectionFollowPaperRule) {
    // 论文 §5 strategy 1（p.9–10）：n = |G'(N0)|（生成 N 值 \ {1,2}），
    // t_N = min{ r : Δub_SN(N, ⌈N/2⌉, r) ≤ ε/n }；t_2 = 1、t_1 = 0。
    struct Case { uint64_t H, w; };
    for (const Case& c : {Case{30720, 256}, Case{4097, 1024}, Case{1024, 32}, Case{100, 16}}) {
        const IprfParams p = Params(c.H, c.w);
        const Iprf ip(Iprf::GenDeterministic(3), p);
        const std::vector<IprfPrpStage>& stages = ip.prp_stages();

        // ① 生成的 N 值序列：N_0 = domain，N_{j+1} = ⌊N_j/2⌋，到 1 结束（只保留 N >= 2 的 stage）
        std::vector<uint64_t> expect;
        for (uint64_t n = c.H; n > 1; n /= 2) expect.push_back(n);
        ASSERT_EQ(stages.size(), expect.size());
        for (size_t i = 0; i < stages.size(); ++i) EXPECT_EQ(stages[i].n, expect[i]);

        // ② 非平凡 stage 数 = |G'(N0)|（排除 N=1 与 N=2），每 stage 的误差预算 = ε/n
        uint64_t nontrivial = 0;
        for (const IprfPrpStage& st : stages) {
            if (st.n >= 3) ++nontrivial;
        }
        const double budget = p.prp_epsilon / static_cast<double>(nontrivial);

        // ③ 每个 stage 的轮数满足论文式 (1) 的界，且**取最小**
        for (const IprfPrpStage& st : stages) {
            const uint64_t q = st.n - st.n / 2;  // q_N = N − p_N = ⌈N/2⌉
            if (st.n == 2) {
                EXPECT_EQ(st.rounds, uint32_t{1});  // 论文 §5：t_2 = 1（误差为 0）
                continue;
            }
            EXPECT_TRUE(Iprf::SnDistanceUpperBound(st.n, q, st.rounds) <= budget);
            if (st.rounds > 1) {  // r=1 时"r-1"是论文允许的平凡下界，不做最小性断言
                EXPECT_TRUE(Iprf::SnDistanceUpperBound(st.n, q, st.rounds - 1) > budget);
            }
        }

        // ④ 每个 stage 的轮数 >= 1，且总轮数 = 各 stage 轮数之和。
        //    ⚠️ **不能**断言"轮数随 N 递减"：论文式 (1) 里 q_N = ⌈N/2⌉ 使比值
        //    (q+N)/(2N) 对**奇数 N** 偏大（N=3 时是 5/6 = 0.833，偶数时恒为 0.75），
        //    因此小奇数 stage（3/5/7）可能反而需要更多轮。轮数的单调性不是论文的性质。
        uint64_t sum = 0;
        for (size_t i = 0; i < stages.size(); ++i) {
            sum += stages[i].rounds;
            EXPECT_TRUE(stages[i].rounds >= 1);
        }
        EXPECT_EQ(ip.PrpWorstCaseRounds(), sum);
        EXPECT_EQ(ip.PrpPrecomputedRoundKeys(), sum);

        // ⑤ 与论文的渐近下界式 (2)（p.5：r >= 7.23 lg N − 4.82 lg ε）量级一致：
        //    常数取论文 Fig 2 的 ε = 10^-10 数值例子（d=4/5 的 mean-1 分别 660/758）。
        std::printf("  [MR14] H=%-6llu w=%-5llu stage 数=%-3zu 首 stage 轮数=%-4u 总轮数=%-5llu "
                    "期望轮数=%.1f\n",
                    static_cast<unsigned long long>(c.H), static_cast<unsigned long long>(c.w),
                    stages.size(), stages.empty() ? 0u : stages[0].rounds,
                    static_cast<unsigned long long>(sum), ip.PrpExpectedRounds());
    }
}

TEST(Iprf, Mr14RoundCountsMatchExactRecursionStructure) {
    // 一个**精确**（不是统计）的性质：SN 是 [N) 上的**置换** ⇒ 每个 stage 之后恰好
    // ⌊N/2⌋ 张牌落在第一堆 ⇒ 恰好 N_j 个 x 会到达 stage j。
    // 因此 Σ_x rounds(x) == Σ_j t_j · N_j（整数恒等式），且到达各 stage 的 x 个数 == N_j。
    struct Case { uint64_t H, w; };
    for (const Case& c : {Case{1024, 32}, Case{4097, 1024}, Case{256, 8}}) {
        const Iprf ip(Iprf::GenDeterministic(0x9E), Params(c.H, c.w));
        uint64_t sum_rounds = 0, max_rounds = 0;
        std::map<uint64_t, uint64_t> stage_hits;  // stage 数 → x 的个数
        for (uint64_t x = 0; x < c.H; ++x) {
            IprfPrpTrace tr;
            ip.PrpForward(x, &tr);
            sum_rounds += tr.rounds;
            max_rounds = std::max(max_rounds, tr.rounds);
            stage_hits[tr.stages] += 1;
        }
        uint64_t expected_sum = 0;
        const std::vector<IprfPrpStage>& stages = ip.prp_stages();
        for (const IprfPrpStage& st : stages) expected_sum += st.rounds * st.n;
        EXPECT_EQ(sum_rounds, expected_sum);
        EXPECT_TRUE(max_rounds <= ip.PrpWorstCaseRounds());
        // 到达 stage j（0-based）的 x 个数**恰好**是 N_j：
        //   #{x : stages(x) >= j+1} == N_j（SN 是置换 ⇒ 每层恰好 ⌊N/2⌋ 张牌进第一堆）
        for (size_t j = 0; j < stages.size(); ++j) {
            uint64_t reached = 0;
            for (const auto& kv : stage_hits) {
                if (kv.first > j) reached += kv.second;
            }
            EXPECT_EQ(reached, stages[j].n);
        }
        EXPECT_TRUE(stage_hits.size() <= stages.size());
        // 期望轮数（解析值）与全枚举均值一致
        EXPECT_TRUE(std::fabs(ip.PrpExpectedRounds() * static_cast<double>(c.H) -
                              static_cast<double>(sum_rounds)) < 1e-6);
    }
}

// ---------------------------------------------------------------------------
// 9. 计时基准（与 REPORT §3.3 对照；只打印不断言）
// ---------------------------------------------------------------------------

TEST(Iprf, TimingBenchmarkForPlinkoScaleParameters) {
    // λ = 80、n = 2^12 / 2^14 / 2^16，w = 2^⌈log2√n⌉（= 64/128/256），H = 1.5λw。
    // ⚠️ 与 REPORT §3.3 的原型（Feistel + cycle-walking）**不可直接比较**：
    //    本模块的 PRP 换成 MR14 的 full-security 构造（敌手可查询整个定义域），
    //    单次 PRP 求值 ≈ 数百次 AES 调用（Feistel 是 8 轮 × cycle-walking 因子）。
    // ⚠️ 采样必须**均匀**：IF⁻¹ 的成本 ∝ 该 y 的递归深度（y 越小越深），
    //    用 y = 0,1,2,… 这种小值采样会把 IF⁻¹ 高估 2 倍以上（本模块开发时踩过）。
    std::printf("  [bench] lambda=80, prp_epsilon=1e-10（MR14 strategy 1）\n");
    std::printf("  %-8s %-6s %-6s %-9s %-10s %-12s %-12s %-9s %-11s\n", "n", "w", "H", "Gen(us)",
                "ctor(us)", "IF(us)", "IF^-1(us)", "均原像", "每原像(us)");
    for (uint64_t n : {1ull << 12, 1ull << 14, 1ull << 16}) {
        const PlinkoLike pl = DerivePlinkoLike(80, n);
        const IprfParams p = Params(pl.H, pl.w);

        auto t0 = Clock::now();
        const IprfKey key = Iprf::GenDeterministic(0xF00D);
        auto t1 = Clock::now();
        const Iprf ip(key, p);
        auto t2 = Clock::now();

        random::DeterministicPrng prng(Iprf::GenDeterministic(0xF00D).pmns_key, 1);
        const int fwd_iters = 2000;
        uint64_t acc = 0;
        auto t3 = Clock::now();
        for (int i = 0; i < fwd_iters; ++i) acc += ip.Forward(RandBelow(prng, pl.H));
        auto t4 = Clock::now();

        std::vector<uint64_t> out;
        const int inv_iters = 150;
        uint64_t preimage_sum = 0;
        auto t5 = Clock::now();
        for (int i = 0; i < inv_iters; ++i) {
            ip.Inverse(RandBelow(prng, pl.w), out);
            preimage_sum += out.size();
        }
        auto t6 = Clock::now();

        const double inv_us = MicrosBetween(t5, t6) / inv_iters;
        std::printf("  %-8llu %-6llu %-6llu %-9.1f %-10.1f %-12.2f %-12.1f %-9.2f %-11.2f\n",
                    static_cast<unsigned long long>(n), static_cast<unsigned long long>(pl.w),
                    static_cast<unsigned long long>(pl.H), MicrosBetween(t0, t1),
                    MicrosBetween(t1, t2), MicrosBetween(t3, t4) / fwd_iters, inv_us,
                    static_cast<double>(preimage_sum) / inv_iters,
                    inv_us * inv_iters / static_cast<double>(preimage_sum));
        EXPECT_TRUE(acc > 0);
    }
    // 说明：HintInit 的成本 ≈ n 次 IF⁻¹（论文 Fig 7 的流式扫描一遍 DB），
    // 由上面的 IF^-1 列 × n 直接可估；PIR-04 会用真实实现复测。
}
