// FND-15：恶意行为注入测试集。
//
// 目标不是"再写几个篡改用例"，而是**系统性地**回答一个问题：
// 当服务器可以任意偏离协议时，客户端是否**必然**检出，而不会接受被污染的结果？
//
// 覆盖三类攻击（对应 TASK_PLAN §6 第 2 层的验收标准）：
//   A. 篡改应答 —— 逐比特翻转、逐字节篡改、整体替换、越界值
//      → 必须在验证阶段被检出（abort），不得产生"看似合法"的结果
//   B. 重放 —— 用旧的合法应答冒充新应答
//      → 由于验证把索引与值都绑进标签，必须被检出
//   C. 替换共享 —— 改动某一台服务器持有的共享
//      → 在 SPDZ MAC 下必须被检出
//
// 判定原则（论文 §2 明确警告）：**不允许存在可区分的失败路径**。
// 客户端要么接受正确结果，要么 abort；绝不能"悄悄用一个降级的近似值"。
//
// 本文件的测试使用确定性随机源，保证可复现。

#include "core/random.hpp"
#include "shared/verify.hpp"
#include "test_framework.hpp"
#include "test_cluster.hpp"

#include <vector>

using namespace tsb;

namespace {

const uint128_t kQ = (static_cast<uint128_t>(1) << 127) - 1;
const std::string kDomain = domain::kRecord;

std::vector<uint8_t> TestKey() { return std::vector<uint8_t>(16, 0xA7); }

// 一个典型的 V-OO-PIR 诚实场景（模型见 TASK_PLAN 决策 D13）
struct PirScenario {
    PIRVerifier verifier;
    HintProof proof;
    VerifyValue honest_c;

    uint64_t target_index = 10;
    uint128_t target_value = 1000;
    uint64_t filler_index = 99;
    uint128_t filler_value = 9900;

    explicit PirScenario(const std::vector<uint8_t>& key) : verifier(key) {
        const std::vector<std::pair<uint64_t, uint128_t>> covered = {
            {20, 2000}, {30, 3000}, {40, 4000}};
        proof = verifier.ComputeHintProof(kDomain, covered);
        auto subset = covered;
        subset.emplace_back(target_index, target_value);
        subset.emplace_back(filler_index, filler_value);
        honest_c = verifier.ComputeSubsetValue(kDomain, subset);
    }

    bool AcceptsHonest() const {
        return verifier.VerifyResponse(kDomain, proof, honest_c, target_index,
                                       target_value, filler_index, filler_value);
    }

    // 给定（可能被污染的）服务器验证值与重建值，客户端是否接受
    bool Accepts(const VerifyValue& c, uint128_t v) const {
        return verifier.VerifyResponse(kDomain, proof, c, target_index, v,
                                       filler_index, filler_value);
    }

    bool AcceptsFull(const VerifyValue& c, uint64_t x, uint128_t v, uint64_t fill,
                     uint128_t v_fill) const {
        return verifier.VerifyResponse(kDomain, proof, c, x, v, fill, v_fill);
    }
};

}  // namespace

// ===========================================================================
// 基线：先确认诚实路径确实被接受，否则后面的"检出"没有意义
// ===========================================================================

TEST(Adversary, HonestBaselineIsAccepted) {
    const PirScenario s(TestKey());
    EXPECT_TRUE(s.AcceptsHonest());
}

// ===========================================================================
// A. 篡改应答
// ===========================================================================

TEST(Adversary, DetectsEverySingleBitFlipInServerResponse) {
    // 128 位标签的每一位被翻转都必须被检出——漏掉任何一位都是安全漏洞
    const PirScenario s(TestKey());
    int detected = 0;
    const int total = static_cast<int>(kMacTagBytes * 8);
    for (size_t byte = 0; byte < kMacTagBytes; ++byte) {
        for (int bit = 0; bit < 8; ++bit) {
            VerifyValue evil = s.honest_c;
            evil[byte] ^= static_cast<uint8_t>(1u << bit);
            if (!s.Accepts(evil, s.target_value)) ++detected;
        }
    }
    EXPECT_EQ(detected, total);
}

TEST(Adversary, DetectsEveryByteReplacementInServerResponse) {
    const PirScenario s(TestKey());
    int detected = 0;
    for (size_t byte = 0; byte < kMacTagBytes; ++byte) {
        for (uint8_t mask : {static_cast<uint8_t>(0x00), static_cast<uint8_t>(0xFF),
                             static_cast<uint8_t>(0x5A)}) {
            VerifyValue evil = s.honest_c;
            evil[byte] = mask;
            if (!s.Accepts(evil, s.target_value)) ++detected;
        }
    }
    EXPECT_EQ(detected, static_cast<int>(kMacTagBytes * 3));
}

TEST(Adversary, DetectsFullyReplacedOrZeroedResponse) {
    const PirScenario s(TestKey());
    // 值被改
    EXPECT_FALSE(s.Accepts(s.honest_c, s.target_value + 1));
    // 应答被清零
    VerifyValue zeroed{};
    EXPECT_FALSE(s.Accepts(zeroed, s.target_value));
    // 应答被随机替换：多轮均不得通过
    const auto key = AesPrf::GenerateKey();
    random::DeterministicPrng prng(key, 1234);
    for (int round = 0; round < 64; ++round) {
        VerifyValue evil{};
        prng.FillBytes(evil.data(), evil.size());
        EXPECT_FALSE(s.Accepts(evil, s.target_value));
    }
}

TEST(Adversary, DetectsTamperedTargetFillerAndIndices) {
    const PirScenario s(TestKey());
    // 目标值被改
    EXPECT_FALSE(s.AcceptsFull(s.honest_c, s.target_index, s.target_value + 1,
                               s.filler_index, s.filler_value));
    // 填充值被改
    EXPECT_FALSE(s.AcceptsFull(s.honest_c, s.target_index, s.target_value,
                               s.filler_index, s.filler_value + 1));
    // 目标索引被改
    EXPECT_FALSE(s.AcceptsFull(s.honest_c, s.target_index + 1, s.target_value,
                               s.filler_index, s.filler_value));
    // 填充索引被改
    EXPECT_FALSE(s.AcceptsFull(s.honest_c, s.target_index, s.target_value,
                               s.filler_index + 1, s.filler_value));
}

TEST(Adversary, DetectsServerDroppingOrDuplicatingSubsetItems) {
    // 服务器在计算 C 时漏算、重算某个数据项
    const PirScenario s(TestKey());
    const MacTag target_tag = s.verifier.ItemTag(kDomain, s.target_index, s.target_value);
    const MacTag filler_tag = s.verifier.ItemTag(kDomain, s.filler_index, s.filler_value);

    // 漏掉填充项
    const std::vector<std::pair<uint64_t, uint128_t>> missing_filler = {
        {20, 2000}, {30, 3000}, {40, 4000}, {s.target_index, s.target_value}};
    EXPECT_FALSE(PIRVerifier::VerifyRelation(
        s.proof, s.verifier.ComputeSubsetValue(kDomain, missing_filler), target_tag,
        filler_tag));

    // 漏掉目标项
    const std::vector<std::pair<uint64_t, uint128_t>> missing_target = {
        {20, 2000}, {30, 3000}, {40, 4000}, {s.filler_index, s.filler_value}};
    EXPECT_FALSE(PIRVerifier::VerifyRelation(
        s.proof, s.verifier.ComputeSubsetValue(kDomain, missing_target), target_tag,
        filler_tag));

    // 重复计算某一项（该项在 XOR 中被抵消）
    auto dup = missing_target;
    dup.push_back({20, 2000});
    dup.push_back({20, 2000});
    EXPECT_FALSE(PIRVerifier::VerifyRelation(
        s.proof, s.verifier.ComputeSubsetValue(kDomain, dup), target_tag, filler_tag));
}

TEST(Adversary, SingleServerAloneCannotForgeAResponse) {
    // 没有 MAC 密钥的服务器无法构造出能通过验证的 C
    const PirScenario s(TestKey());
    const MacVerifier attacker(std::vector<uint8_t>(16, 0x00));
    const VerifyValue forged =
        attacker.Compute(kDomain, s.target_index, s.target_value);
    EXPECT_FALSE(s.Accepts(forged, s.target_value));
}

TEST(Adversary, ForgerySucceedsOnlyWithTheRightKey) {
    // 对照实验：只有拿到正确密钥才能造出合法标签。
    // 这确认"检出"来自密钥保密性，而不是验证逻辑本身太弱。
    const PirScenario s(TestKey());
    const MacVerifier with_key(TestKey());
    // 用正确密钥重算整个子集 —— 这就是诚实应答，必然通过
    const std::vector<std::pair<uint64_t, uint128_t>> subset = {
        {20, 2000}, {30, 3000}, {40, 4000}, {10, 1000}, {99, 9900}};
    VerifyValue c{};
    bool first = true;
    for (const auto& [i, v] : subset) {
        const MacTag t = with_key.Compute(kDomain, i, v);
        c = first ? t : XorTags(c, t);
        first = false;
    }
    EXPECT_TRUE(s.Accepts(c, s.target_value));
}

// ===========================================================================
// B. 重放
// ===========================================================================

TEST(Adversary, DetectsReplayOfPreviousResponse) {
    // 服务器把**另一次查询的合法应答**拿来冒充这一次
    const PirScenario s(TestKey());
    const std::vector<std::pair<uint64_t, uint128_t>> other_subset = {
        {20, 2000}, {30, 3000}, {40, 4000}, {11, 1111}, {98, 9898}};
    const VerifyValue other_c = s.verifier.ComputeSubsetValue(kDomain, other_subset);
    EXPECT_FALSE(s.Accepts(other_c, s.target_value));
}

TEST(Adversary, DetectsSwappedTargetAndFillerValues) {
    // 交换目标与填充的值（两个值本身都是合法的数据库内容）
    const PirScenario s(TestKey());
    EXPECT_FALSE(s.AcceptsFull(s.honest_c, s.target_index, s.filler_value,
                               s.filler_index, s.filler_value));
    EXPECT_FALSE(s.AcceptsFull(s.honest_c, s.target_index, s.target_value,
                               s.filler_index, s.target_value));
    // 互换索引
    EXPECT_FALSE(s.AcceptsFull(s.honest_c, s.filler_index, s.target_value,
                               s.target_index, s.filler_value));
}

TEST(Adversary, DetectsCrossDomainReplay) {
    // 把别处（不同域）的合法标签拿来冒充本域标签
    const MacVerifier v(TestKey());
    const MacTag feature_tag = v.Compute(domain::kFeature, 10, 1000);
    EXPECT_FALSE(v.Verify(kDomain, 10, 1000, feature_tag));
    const MacTag attribute_tag = v.Compute(domain::kAttribute, 10, 1000);
    EXPECT_FALSE(v.Verify(kDomain, 10, 1000, attribute_tag));
}

TEST(Adversary, DetectsCrossRecordTagReuse) {
    // 用同一批数据里另一条记录的合法标签冒充本条
    const MacVerifier v(TestKey());
    const MacTag tag_of_other = v.Compute(kDomain, 20, 2000);
    EXPECT_FALSE(v.Verify(kDomain, 10, 1000, tag_of_other));
}

// ===========================================================================
// C. 替换共享（SPDZ MAC）
// ===========================================================================

TEST(Adversary, DetectsAnySingleBitFlipInValueShare) {
    const MacKeyShares ks = GenerateMacKey(2, kQ);
    auto [s0, s1] = ShareAuthenticated(424242, ks, kQ);
    EXPECT_TRUE(VerifyAuthenticatedShares(s0, s1, ks.alpha, kQ));

    int detected = 0;
    const int total = 128 * 2;  // 两份共享各 128 位
    for (int which = 0; which < 2; ++which) {
        for (int bit = 0; bit < 128; ++bit) {
            AuthenticatedShare evil = (which == 0) ? s0 : s1;
            evil.value.value ^= (static_cast<uint128_t>(1) << bit);
            const bool ok = (which == 0)
                                ? VerifyAuthenticatedShares(evil, s1, ks.alpha, kQ)
                                : VerifyAuthenticatedShares(s0, evil, ks.alpha, kQ);
            if (!ok) ++detected;
        }
    }
    EXPECT_EQ(detected, total);
}

TEST(Adversary, DetectsAnySingleBitFlipInMacShare) {
    const MacKeyShares ks = GenerateMacKey(2, kQ);
    auto [s0, s1] = ShareAuthenticated(777, ks, kQ);

    int detected = 0;
    const int total = 128 * 2;
    for (int which = 0; which < 2; ++which) {
        for (int bit = 0; bit < 128; ++bit) {
            AuthenticatedShare evil = (which == 0) ? s0 : s1;
            evil.mac.value ^= (static_cast<uint128_t>(1) << bit);
            const bool ok = (which == 0)
                                ? VerifyAuthenticatedShares(evil, s1, ks.alpha, kQ)
                                : VerifyAuthenticatedShares(s0, evil, ks.alpha, kQ);
            if (!ok) ++detected;
        }
    }
    EXPECT_EQ(detected, total);
}

TEST(Adversary, DetectsMismatchedValueAndMacShares) {
    // 真实攻击：把**另一个已认证值**的 MAC 拿过来与本值的共享配对。
    // 此时 z 与 mac 各自都能重建，但二者之间不再满足 mac = α·z。
    const MacKeyShares ks = GenerateMacKey(2, kQ);
    auto [a0, a1] = ShareAuthenticated(1234, ks, kQ);
    auto [b0, b1] = ShareAuthenticated(5678, ks, kQ);

    // 值的共享取自 a，MAC 的共享取自 b
    AuthenticatedShare crossed{a0.value, b0.mac};
    EXPECT_FALSE(VerifyAuthenticatedShares(crossed, a1, ks.alpha, kQ));
    EXPECT_FALSE(VerifyAuthenticatedShares(a0, AuthenticatedShare{a1.value, b1.mac},
                                           ks.alpha, kQ));

    // 反向确认：a 与 a 配对、b 与 b 配对时都通过（说明失败源于错配，而非构造有误）
    EXPECT_TRUE(VerifyAuthenticatedShares(a0, a1, ks.alpha, kQ));
    EXPECT_TRUE(VerifyAuthenticatedShares(b0, b1, ks.alpha, kQ));
}

TEST(Adversary, SwappingTheTwoServersSharesIsAValidRelabeling) {
    // 记录一个容易误解的点：把两台服务器的共享整体互换**不是攻击**。
    // 重建是加法，可交换，因此 (s1, s0) 仍然还原出同一个值、同一条 MAC。
    // 真正会破坏校验的是"值共享与 MAC 共享来自不同的认证值"（见上一个用例）。
    const MacKeyShares ks = GenerateMacKey(2, kQ);
    auto [s0, s1] = ShareAuthenticated(1234, ks, kQ);
    EXPECT_TRUE(VerifyAuthenticatedShares(s1, s0, ks.alpha, kQ));
    EXPECT_EQ(ReconstructAuthenticated(s1, s0, kQ),
              ReconstructAuthenticated(s0, s1, kQ));
}

TEST(Adversary, DetectsWrongAlpha) {
    const MacKeyShares ks = GenerateMacKey(2, kQ);
    auto [s0, s1] = ShareAuthenticated(555, ks, kQ);
    // 用一个错误的 α 去校验（模拟密钥被换）
    EXPECT_FALSE(VerifyAuthenticatedShares(s0, s1, addMod(ks.alpha, 1, kQ), kQ));
    EXPECT_FALSE(VerifyAuthenticatedShares(s0, s1, mulMod(ks.alpha, 2, kQ), kQ));
}

TEST(Adversary, RejectsDegenerateAlphaZero) {
    // α = 0 会让任何 mac = 0 通过校验，必须被显式拒绝而不是静默接受
    EXPECT_THROW(VerifyMac(1234, 0, 0, kQ), std::invalid_argument);
}

TEST(Adversary, HonestAuthenticatedSharesAlwaysVerifyAcrossManyRounds) {
    // 反向确认：诚实路径在大量随机取值的多轮测试中**零误报**
    const MacKeyShares ks = GenerateMacKey(2, kQ);
    const auto key = AesPrf::GenerateKey();
    random::DeterministicPrng prng(key, 99);

    for (int round = 0; round < 256; ++round) {
        const uint128_t v = prng.Below(kQ);
        auto [s0, s1] = ShareAuthenticated(v, ks, kQ);
        EXPECT_TRUE(VerifyAuthenticatedShares(s0, s1, ks.alpha, kQ));
        EXPECT_EQ(ReconstructAuthenticated(s0, s1, kQ), v);
    }
}

// ===========================================================================
// D. 传输层：可用性与完整性
// ===========================================================================

TEST(Adversary, UnresponsiveServerIsReportedNotSilentlyIgnored) {
    // 服务器拒答必须变成显式错误，而不是被当作"值为 0"继续算下去
    TestCluster c;
    c.SetDbHandler(0, [](const ServerDatabase&, const Payload&) {
        return Payload{1, 2, 3, 4};
    });
    c.SetDbHandler(1, [](const ServerDatabase&, const Payload&) {
        return Payload{1, 2, 3, 4};
    });

    c.MakeUnresponsive(1);
    c.Submit(0, Payload{0});
    c.Submit(1, Payload{0});
    const auto rs = c.Collect();
    EXPECT_TRUE(rs[0].ok);
    EXPECT_FALSE(rs[1].ok);   // 必须显式失败
    EXPECT_TRUE(!rs[1].error.empty());
}

TEST(Adversary, ServerExceptionBecomesExplicitError) {
    TestCluster c;
    c.SetHandler(0, [](const Payload&) -> Payload {
        throw std::runtime_error("服务器内部故障");
    });
    const auto r = c.RoundTrip(0, Payload{0});
    EXPECT_FALSE(r.ok);
    EXPECT_TRUE(r.error.find("服务器内部故障") != std::string::npos);
}

TEST(Adversary, TamperedTransportResponseIsCaughtByVerification) {
    // 端到端：传输层篡改 → 应用层验证检出。
    // 这是"两层防护"的联合验证：传输层不负责保证完整性，验证层负责。
    PirScenario s(TestKey());
    TestCluster c;

    // 服务器计算 C 并返回
    const VerifyValue honest = s.honest_c;
    c.SetDbHandler(0, [honest](const ServerDatabase&, const Payload&) {
        return Payload(honest.begin(), honest.end());
    });
    c.SetDbHandler(1, [honest](const ServerDatabase&, const Payload&) {
        return Payload(honest.begin(), honest.end());
    });

    // 从载荷还原标签
    const auto to_tag = [](const Payload& p) {
        VerifyValue t{};
        const size_t n = p.size() < kMacTagBytes ? p.size() : kMacTagBytes;
        for (size_t i = 0; i < n; ++i) t[i] = p[i];
        return t;
    };

    // 诚实路径：取回后验证通过
    auto r = c.RoundTrip(0, Payload{0});
    EXPECT_TRUE(s.Accepts(to_tag(r.payload), s.target_value));

    // 让服务器 0 开始篡改
    c.MakeMalicious(0);
    r = c.RoundTrip(0, Payload{0});
    EXPECT_FALSE(s.Accepts(to_tag(r.payload), s.target_value));
}
