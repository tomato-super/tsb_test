#include "shared/verify.hpp"
#include "test_framework.hpp"

#include <stdexcept>
#include <vector>

using namespace tsb;

namespace {

const uint128_t kQ = (static_cast<uint128_t>(1) << 127) - 1;  // 梅森素数
const std::string kDomain = domain::kRecord;

std::vector<uint8_t> TestKey() { return std::vector<uint8_t>(16, 0x5A); }

}  // namespace

// ===========================================================================
// 1. V-OO-PIR 多集证明
// ===========================================================================

TEST(PIRVerifier, HintProofIsPureXorOfItemTags) {
    // ⚠️ F 必须是各元素标签的**纯 XOR**，不掺基准值——否则验证等式两侧
    // 无法抵消（见 verify.hpp 的注释）。
    const PIRVerifier v(TestKey());
    const std::vector<std::pair<uint64_t, uint128_t>> items = {
        {1, 111}, {2, 222}, {3, 333}};

    const MacTag proof = v.ComputeHintProof(kDomain, items);

    MacTag expect{};
    bool first = true;
    for (const auto& [i, val] : items) {
        const MacTag t = v.ItemTag(kDomain, i, val);
        expect = first ? t : XorTags(expect, t);
        first = false;
    }
    EXPECT_TRUE(ConstantTimeEquals(proof, expect));

    // 掺入 BaseTag 的写法必须与之不同（防回归）
    MacTag with_base = v.BaseTag();
    for (const auto& [i, val] : items) {
        with_base = XorTags(with_base, v.ItemTag(kDomain, i, val));
    }
    EXPECT_FALSE(ConstantTimeEquals(proof, with_base));
}

TEST(PIRVerifier, HintProofAndSubsetValueAgreeOnSameSet) {
    const PIRVerifier v(TestKey());
    const std::vector<std::pair<uint64_t, uint128_t>> items = {{1, 11}, {2, 22}};
    // 同一个集合：F 与 C 的定义完全相同（都是标签的纯 XOR）
    EXPECT_TRUE(ConstantTimeEquals(v.ComputeHintProof(kDomain, items),
                                   v.ComputeSubsetValue(kDomain, items)));
}

TEST(PIRVerifier, SymmetricDifferenceProperty) {
    // 验证等式的代数核心：对任意两个集合 X（hint 覆盖）与 S（查询子集），
    //     F(X) ⊕ C(S) = ⊕_{i ∈ X \u25b3 S} tag(i)      （对称差）
    // 这条性质正是"交集抵消"的来源，也是验证能成立的根本原因。
    const PIRVerifier v(TestKey());
    const std::vector<std::pair<uint64_t, uint128_t>> X = {
        {1, 10}, {2, 20}, {3, 30}, {4, 40}};
    const std::vector<std::pair<uint64_t, uint128_t>> S = {
        {3, 30}, {4, 40}, {5, 50}};
    // 交集是 {3,4}；对称差是 {1,2,5}

    const MacTag F = v.ComputeHintProof(kDomain, X);
    const MacTag C = v.ComputeSubsetValue(kDomain, S);
    const MacTag lhs = XorTags(F, C);

    MacTag expect = XorTags(v.ItemTag(kDomain, 1, 10), v.ItemTag(kDomain, 2, 20));
    expect = XorTags(expect, v.ItemTag(kDomain, 5, 50));
    EXPECT_TRUE(ConstantTimeEquals(lhs, expect));

    // 完全相同的集合 -> 对称差为空 -> 抵消为全零
    EXPECT_TRUE(ConstantTimeEquals(XorTags(v.ComputeHintProof(kDomain, X),
                                           v.ComputeSubsetValue(kDomain, X)),
                                   MacTag{}));
}

TEST(PIRVerifier, EmptySubsetValueIsZero) {
    const PIRVerifier v(TestKey());
    const MacTag c = v.ComputeSubsetValue(kDomain, {});
    const MacTag zero{};
    EXPECT_TRUE(ConstantTimeEquals(c, zero));
}

// 本组测试采用的 V-OO-PIR 模型（与 PIR_SPEC §2.2/§3.5 一致）：
//
//   客户端预存：F = ⊕ tag(hint 覆盖集合 X)
//   查询子集  S = X ∪ {目标项 x, 填充项 fill}
//   服务器返回：C = ⊕ tag(S)
//   ⇒ F ⊕ C = tag(x) ⊕ tag(fill)
//     （X 完全相同，在 XOR 中完全抵消，只剩两项"额外"的）
//
//   注意：x 与 fill **不属于** hint 的覆盖集合 X——它们正是查询时额外引入的
//   两项。目标项用于取出 DB[x]，填充项负责让两组子集结构对称、掩护目标。
namespace {
const std::vector<std::pair<uint64_t, uint128_t>> kHintCovered = {
    {20, 2000}, {30, 3000}, {40, 4000}};

// 查询子集 = hint 覆盖集合 + 目标项 + 填充项
std::vector<std::pair<uint64_t, uint128_t>> QuerySubset(uint64_t x, uint128_t v,
                                                        uint64_t fill,
                                                        uint128_t v_fill) {
    auto s = kHintCovered;
    s.emplace_back(x, v);
    s.emplace_back(fill, v_fill);
    return s;
}
}

TEST(PIRVerifier, VerifyRelationHoldsForHonestResponse) {
    const PIRVerifier v(TestKey());
    const MacTag proof = v.ComputeHintProof(kDomain, kHintCovered);
    const auto subset = QuerySubset(10, 1000, 99, 9900);
    const MacTag c = v.ComputeSubsetValue(kDomain, subset);

    EXPECT_TRUE(v.VerifyResponse(kDomain, proof, c, 10, 1000, 99, 9900));
    EXPECT_TRUE(PIRVerifier::VerifyRelation(proof, c,
                                            v.ItemTag(kDomain, 10, 1000),
                                            v.ItemTag(kDomain, 99, 9900)));
}

TEST(PIRVerifier, VerifyRejectsTamperedResponseValue) {
    const PIRVerifier v(TestKey());
    const MacTag proof = v.ComputeHintProof(kDomain, kHintCovered);
    const MacTag c = v.ComputeSubsetValue(kDomain, QuerySubset(10, 1000, 99, 9900));

    // 诚实情况通过
    EXPECT_TRUE(v.VerifyResponse(kDomain, proof, c, 10, 1000, 99, 9900));
    // 篡改重建出的明文值 -> 必须失败
    EXPECT_FALSE(v.VerifyResponse(kDomain, proof, c, 10, 1001, 99, 9900));
    // 篡改目标索引 -> 必须失败
    EXPECT_FALSE(v.VerifyResponse(kDomain, proof, c, 11, 1000, 99, 9900));
    // 篡改填充值 -> 必须失败
    EXPECT_FALSE(v.VerifyResponse(kDomain, proof, c, 10, 1000, 99, 9901));
    // 篡改填充索引 -> 必须失败
    EXPECT_FALSE(v.VerifyResponse(kDomain, proof, c, 10, 1000, 98, 9900));
}

TEST(PIRVerifier, VerifyRejectsTamperedSubsetItems) {
    // 服务器若在计算 C 时漏掉/替换/重复了某个数据项，C 就会与真实子集不符
    const PIRVerifier v(TestKey());
    const MacTag proof = v.ComputeHintProof(kDomain, kHintCovered);
    const auto honest = QuerySubset(10, 1000, 99, 9900);
    const MacTag c = v.ComputeSubsetValue(kDomain, honest);
    const MacTag target = v.ItemTag(kDomain, 10, 1000);
    const MacTag filler = v.ItemTag(kDomain, 99, 9900);
    EXPECT_TRUE(PIRVerifier::VerifyRelation(proof, c, target, filler));

    // 漏了一项
    auto missing = honest;
    missing.pop_back();
    EXPECT_FALSE(PIRVerifier::VerifyRelation(
        proof, v.ComputeSubsetValue(kDomain, missing), target, filler));

    // 替换了某项取值
    auto wrong = honest;
    wrong[0].second = 9999;
    EXPECT_FALSE(PIRVerifier::VerifyRelation(
        proof, v.ComputeSubsetValue(kDomain, wrong), target, filler));

    // 重复计数（多 XOR 了一次同一项 -> 该项被抵消）
    auto dup = honest;
    dup.push_back(honest[0]);
    EXPECT_FALSE(PIRVerifier::VerifyRelation(
        proof, v.ComputeSubsetValue(kDomain, dup), target, filler));
}

TEST(PIRVerifier, VerifyRejectsCorruptedProofOrC) {
    const PIRVerifier v(TestKey());
    const MacTag proof = v.ComputeHintProof(kDomain, kHintCovered);
    const MacTag c = v.ComputeSubsetValue(kDomain, QuerySubset(10, 1000, 99, 9900));
    const MacTag target = v.ItemTag(kDomain, 10, 1000);
    const MacTag filler = v.ItemTag(kDomain, 99, 9900);

    EXPECT_TRUE(PIRVerifier::VerifyRelation(proof, c, target, filler));

    // 篡改服务器返回的 C（模拟恶意服务器）
    MacTag bad_c = c;
    bad_c[0] ^= 0x01;
    EXPECT_FALSE(PIRVerifier::VerifyRelation(proof, bad_c, target, filler));

    // 篡改客户端预存的 F
    MacTag bad_proof = proof;
    bad_proof[15] ^= 0x80;
    EXPECT_FALSE(PIRVerifier::VerifyRelation(bad_proof, c, target, filler));
}

TEST(PIRVerifier, DifferentKeysGiveDifferentProofs) {
    const PIRVerifier a(std::vector<uint8_t>(16, 0x01));
    const PIRVerifier b(std::vector<uint8_t>(16, 0x02));
    const std::vector<std::pair<uint64_t, uint128_t>> items = {{1, 100}};
    EXPECT_FALSE(ConstantTimeEquals(a.ComputeHintProof(kDomain, items),
                                    b.ComputeHintProof(kDomain, items)));
}

TEST(PIRVerifier, DifferentDomainsGiveDifferentTags) {
    const PIRVerifier v(TestKey());
    EXPECT_FALSE(ConstantTimeEquals(v.ItemTag(domain::kRecord, 1, 5),
                                    v.ItemTag(domain::kFeature, 1, 5)));
    EXPECT_FALSE(ConstantTimeEquals(v.ItemTag(domain::kFeature, 1, 5),
                                    v.ItemTag(domain::kAttribute, 1, 5)));
}

TEST(PIRVerifier, RejectsEmptyKey) {
    EXPECT_THROW(PIRVerifier(std::vector<uint8_t>()), std::invalid_argument);
}

// ===========================================================================
// 2. 单条记录 HMAC 校验
// ===========================================================================

TEST(MacVerifier, HonestTagVerifies) {
    const MacVerifier v(TestKey());
    const MacTag tag = v.Compute(kDomain, 42, 12345);
    EXPECT_TRUE(v.Verify(kDomain, 42, 12345, tag));
}

TEST(MacVerifier, RejectsMismatchedValueIndexOrDomain) {
    const MacVerifier v(TestKey());
    const MacTag tag = v.Compute(kDomain, 42, 12345);
    EXPECT_FALSE(v.Verify(kDomain, 42, 12346, tag));  // 值被改
    EXPECT_FALSE(v.Verify(kDomain, 43, 12345, tag));  // 索引被改
    EXPECT_FALSE(v.Verify(domain::kFeature, 42, 12345, tag));  // 域不同
}

TEST(MacVerifier, RejectsForgedTagWithoutKey) {
    // 没有密钥的攻击者无法伪造标签
    const MacVerifier honest(TestKey());
    const MacVerifier attacker(std::vector<uint8_t>(16, 0xFF));
    const MacTag forged = attacker.Compute(kDomain, 42, 12345);
    EXPECT_FALSE(honest.Verify(kDomain, 42, 12345, forged));
}

TEST(MacVerifier, BatchVerification) {
    const MacVerifier v(TestKey());
    std::vector<MacVerifier::Item> items;
    for (uint64_t i = 0; i < 10; ++i) {
        items.push_back({i, static_cast<uint128_t>(i * 100), v.Compute(kDomain, i, i * 100)});
    }
    EXPECT_TRUE(v.VerifyBatch(kDomain, items));

    // 篡改其中一条 -> 整体失败
    items[4].value += 1;
    EXPECT_FALSE(v.VerifyBatch(kDomain, items));

    // 空列表视为通过
    EXPECT_TRUE(v.VerifyBatch(kDomain, {}));
}

TEST(MacVerifier, AggregateIsOrderIndependentXor) {
    const MacVerifier v(TestKey());
    std::vector<MacTag> tags = {v.Compute(kDomain, 1, 1), v.Compute(kDomain, 2, 2),
                                v.Compute(kDomain, 3, 3)};
    const MacTag a = MacVerifier::Aggregate(tags);
    std::reverse(tags.begin(), tags.end());
    const MacTag b = MacVerifier::Aggregate(tags);
    EXPECT_TRUE(ConstantTimeEquals(a, b));
}

TEST(MacVerifier, RejectsEmptyKey) {
    EXPECT_THROW(MacVerifier(std::vector<uint8_t>()), std::invalid_argument);
}

// ===========================================================================
// 3. SPDZ MAC
// ===========================================================================

TEST(SpdzMac, GeneratedKeyIsNonZeroAndSharesReconstruct) {
    const MacKeyShares ks = GenerateMacKey(2, kQ);
    EXPECT_NE(ks.alpha, static_cast<uint128_t>(0));
    EXPECT_EQ(ks.alpha_shares.size(), static_cast<size_t>(2));
    // 两份分享相加应还原 α
    EXPECT_EQ(addMod(ks.alpha_shares[0], ks.alpha_shares[1], kQ), ks.alpha);
    // α 必须是可逆元（避免 α = 0 让校验恒成立）
    EXPECT_EQ(mulMod(ks.alpha, modInverse(ks.alpha, kQ), kQ), static_cast<uint128_t>(1));
}

TEST(SpdzMac, SharesAreFresh) {
    const MacKeyShares a = GenerateMacKey(2, kQ);
    const MacKeyShares b = GenerateMacKey(2, kQ);
    EXPECT_NE(a.alpha, b.alpha);
    EXPECT_NE(a.alpha_shares[0], b.alpha_shares[0]);
}

TEST(SpdzMac, HonestSharesVerify) {
    const MacKeyShares ks = GenerateMacKey(2, kQ);
    for (uint128_t v : {static_cast<uint128_t>(0), static_cast<uint128_t>(1),
                        static_cast<uint128_t>(42), kQ - 1}) {
        auto [s0, s1] = ShareAuthenticated(v, ks, kQ);
        EXPECT_EQ(ReconstructAuthenticated(s0, s1, kQ), v);
        EXPECT_TRUE(VerifyAuthenticatedShares(s0, s1, ks.alpha, kQ));
    }
}

TEST(SpdzMac, TamperedValueShareIsDetected) {
    const MacKeyShares ks = GenerateMacKey(2, kQ);
    auto [s0, s1] = ShareAuthenticated(1000, ks, kQ);
    EXPECT_TRUE(VerifyAuthenticatedShares(s0, s1, ks.alpha, kQ));

    // 服务器 0 篡改自己的值共享 -> 重建出的 z 变了，但 mac 没变
    AuthenticatedShare evil = s0;
    evil.value.value = addMod(evil.value.value, 1, kQ);
    EXPECT_FALSE(VerifyAuthenticatedShares(evil, s1, ks.alpha, kQ));
}

TEST(SpdzMac, TamperedMacShareIsDetected) {
    const MacKeyShares ks = GenerateMacKey(2, kQ);
    auto [s0, s1] = ShareAuthenticated(1000, ks, kQ);

    // 服务器 1 篡改自己的 MAC 共享
    AuthenticatedShare evil = s1;
    evil.mac.value = addMod(evil.mac.value, 7, kQ);
    EXPECT_FALSE(VerifyAuthenticatedShares(s0, evil, ks.alpha, kQ));
}

TEST(SpdzMac, BothServersColludingCanForgeSoSharesMustStaySeparate) {
    // 记录一个已知边界：若两服务器把共享拼起来，它们就能算出 α = mac/z，
    // 从而伪造任意值。这正是不共谋假设的必要性。
    const MacKeyShares ks = GenerateMacKey(2, kQ);
    auto [s0, s1] = ShareAuthenticated(12345, ks, kQ);
    const uint128_t z = ReconstructAuthenticated(s0, s1, kQ);
    const uint128_t mac = addMod(s0.mac.value, s1.mac.value, kQ);
    // 拥有两半即可反推 α
    const uint128_t recovered = mulMod(mac, modInverse(z, kQ), kQ);
    EXPECT_EQ(recovered, ks.alpha);
}

TEST(SpdzMac, DetailedResultReportsExpectedMac) {
    const MacKeyShares ks = GenerateMacKey(2, kQ);
    auto [s0, s1] = ShareAuthenticated(777, ks, kQ);
    const MacVerificationResult r = VerifyAuthenticatedDetailed(s0, s1, ks.alpha, kQ);
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.z, static_cast<uint128_t>(777));
    EXPECT_EQ(r.mac, mulMod(ks.alpha, static_cast<uint128_t>(777), kQ));
    EXPECT_EQ(r.expected_mac, r.mac);

    // 用错误的 α 校验必须失败，且 expected_mac 会随之改变
    const MacVerificationResult bad =
        VerifyAuthenticatedDetailed(s0, s1, addMod(ks.alpha, 1, kQ), kQ);
    EXPECT_FALSE(bad.ok);
    EXPECT_NE(bad.expected_mac, bad.mac);
}

TEST(SpdzMac, BatchSharesAllVerify) {
    const MacKeyShares ks = GenerateMacKey(2, kQ);
    std::vector<uint128_t> values;
    for (uint64_t i = 0; i < 32; ++i) {
        values.push_back(static_cast<uint128_t>(i) * 999983_k % kQ);
    }
    auto [a, b] = ShareAuthenticatedBatch(values, ks, kQ);
    EXPECT_EQ(a.size(), values.size());
    for (size_t i = 0; i < values.size(); ++i) {
        EXPECT_EQ(ReconstructAuthenticated(a[i], b[i], kQ), values[i]);
        EXPECT_TRUE(VerifyAuthenticatedShares(a[i], b[i], ks.alpha, kQ));
    }
    // 篡改其中一个
    a[5].value.value = addMod(a[5].value.value, 3, kQ);
    EXPECT_FALSE(VerifyAuthenticatedShares(a[5], b[5], ks.alpha, kQ));
}

TEST(SpdzMac, VerifyMacRejectsWrongAlpha) {
    const MacKeyShares ks = GenerateMacKey(2, kQ);
    const uint128_t z = 555;
    const uint128_t mac = mulMod(ks.alpha, z, kQ);
    EXPECT_TRUE(VerifyMac(z, mac, ks.alpha, kQ));
    EXPECT_FALSE(VerifyMac(z, mac, addMod(ks.alpha, 1, kQ), kQ));
    EXPECT_FALSE(VerifyMac(addMod(z, 1, kQ), mac, ks.alpha, kQ));
}

TEST(SpdzMac, RejectsZeroAlpha) {
    // α = 0 是退化参数：此时 mac = 0 会让任何值都"通过"校验。
    // 因此 VerifyMac 直接拒绝 α = 0，而不是静默返回 true。
    EXPECT_THROW(VerifyMac(12345, 0, 0, kQ), std::invalid_argument);
    // GenerateMacKey 保证不返回 0
    for (int i = 0; i < 8; ++i) {
        EXPECT_NE(GenerateMacKey(2, kQ).alpha, static_cast<uint128_t>(0));
    }
}

TEST(SpdzMac, RejectsBadParameters) {
    EXPECT_THROW(GenerateMacKey(0, kQ), std::invalid_argument);
    EXPECT_THROW(GenerateMacKey(2, 0), std::invalid_argument);
    EXPECT_THROW(GenerateMacKey(2, 1), std::invalid_argument);

    const MacKeyShares ks = GenerateMacKey(2, kQ);
    MacKeyShares wrong = ks;
    wrong.alpha_shares.resize(3);
    EXPECT_THROW(ShareAuthenticated(1, wrong, kQ), std::invalid_argument);
}

TEST(SpdzMac, WorksWithSmallPrimeModulus) {
    // 用小素数验证通用性（SecureMul 的 2^{-1} 在奇模数下存在）
    const uint128_t q = 1000003;
    const MacKeyShares ks = GenerateMacKey(2, q);
    auto [s0, s1] = ShareAuthenticated(12345, ks, q);
    EXPECT_TRUE(VerifyAuthenticatedShares(s0, s1, ks.alpha, q));
    EXPECT_EQ(ReconstructAuthenticated(s0, s1, q), reduce(12345, q));
}
