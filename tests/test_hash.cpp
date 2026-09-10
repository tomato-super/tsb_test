#include "core/hash.hpp"
#include "core/mset_hash.hpp"
#include "test_framework.hpp"

#include <cstring>
#include <string>
#include <vector>

using namespace tsb;

namespace {

std::string Hex(const Digest& d) { return ToHexString(d.data(), d.size()); }
std::string Hex(const MacTag& t) { return ToHexString(t.data(), t.size()); }

std::vector<uint8_t> Repeat(uint8_t b, size_t n) {
    return std::vector<uint8_t>(n, b);
}

std::vector<uint8_t> FromString(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

}  // namespace

// ---------------------------------------------------------------------------
// SHA-256：FIPS 180-2 已知向量
// ---------------------------------------------------------------------------

TEST(Hash, Sha256MatchesFips180Vectors) {
    EXPECT_EQ(Hex(Sha256(std::string("abc"))),
              std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    EXPECT_EQ(Hex(Sha256(std::string(""))),
              std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

TEST(Hash, Sha256IsDeterministicAndSensitive) {
    EXPECT_EQ(Sha256(std::string("hello")), Sha256(std::string("hello")));
    EXPECT_NE(Sha256(std::string("hello")), Sha256(std::string("hellp")));
    // 输入长度不同但前缀相同，不应碰撞
    EXPECT_NE(Sha256(std::string("ab")), Sha256(std::string("abc")));
}

// ---------------------------------------------------------------------------
// HMAC-SHA256：RFC 4231 测试向量
// ---------------------------------------------------------------------------

TEST(Hash, HmacMatchesRfc4231TestCase1) {
    // key = 20 字节 0x0b, data = "Hi There"
    const auto key = Repeat(0x0b, 20);
    const std::string msg = "Hi There";
    const Digest d = HmacSha256(key.data(), key.size(),
                                reinterpret_cast<const uint8_t*>(msg.data()),
                                msg.size());
    EXPECT_EQ(Hex(d),
              std::string("b0344c61d8db38535ca8afceaf0bf12b"
                          "881dc200c9833da726e9376c2e32cff7"));
}

TEST(Hash, HmacMatchesRfc4231TestCase2) {
    // key = 20 字节 0xaa, data = "Hi There"
    const auto key = Repeat(0xaa, 20);
    const std::string msg = "Hi There";
    const Digest d = HmacSha256(key.data(), key.size(),
                                reinterpret_cast<const uint8_t*>(msg.data()),
                                msg.size());
    EXPECT_EQ(Hex(d),
              std::string("8d2b67f5ef2861123b44abac34456ce0"
                          "9ff60d4ced892ee7891c7477f70e206a"));
}

TEST(Hash, HmacDiffersByKeyAndByMessage) {
    const auto k1 = Repeat(0x0b, 20);
    const auto k2 = Repeat(0x0c, 20);
    const std::string m = "Hi There";
    const auto p = reinterpret_cast<const uint8_t*>(m.data());
    EXPECT_NE(HmacSha256(k1.data(), k1.size(), p, m.size()),
              HmacSha256(k2.data(), k2.size(), p, m.size()));
    const std::string m2 = "Hi Therf";
    EXPECT_NE(HmacSha256(k1.data(), k1.size(), p, m.size()),
              HmacSha256(k1.data(), k1.size(),
                         reinterpret_cast<const uint8_t*>(m2.data()), m2.size()));
}

TEST(Hash, HmacTagIsTruncationOfFullDigest) {
    const auto key = Repeat(0x11, 16);
    const std::string msg = "truncation check";
    const auto p = reinterpret_cast<const uint8_t*>(msg.data());
    const Digest full = HmacSha256(key.data(), key.size(), p, msg.size());
    const MacTag tag = HmacTag(key.data(), key.size(), p, msg.size());
    EXPECT_EQ(tag.size(), kMacTagBytes);
    for (size_t i = 0; i < kMacTagBytes; ++i) {
        EXPECT_EQ(tag[i], full[i]);
    }
}

// ---------------------------------------------------------------------------
// MAC_k(i, v) = HMAC_k(domain || i || v)
// ---------------------------------------------------------------------------

TEST(Hash, MacIsBoundToIndex) {
    const auto key = Repeat(0x22, 16);
    // 同值不同索引必须得到不同 MAC（防止记录位置迁移伪造）
    EXPECT_NE(ComputeMac(key.data(), key.size(), domain::kRecord, 1, 42),
              ComputeMac(key.data(), key.size(), domain::kRecord, 2, 42));
}

TEST(Hash, MacIsBoundToDomain) {
    const auto key = Repeat(0x22, 16);
    // 同索引同值、不同域必须得到不同 MAC（防跨上下文伪造）
    EXPECT_NE(ComputeMac(key.data(), key.size(), domain::kRecord, 7, 99),
              ComputeMac(key.data(), key.size(), domain::kFeature, 7, 99));
    EXPECT_NE(ComputeMac(key.data(), key.size(), domain::kFeature, 7, 99),
              ComputeMac(key.data(), key.size(), domain::kAttribute, 7, 99));
}

TEST(Hash, MacIsBoundToValueAndKey) {
    const auto key = Repeat(0x22, 16);
    EXPECT_NE(ComputeMac(key.data(), key.size(), domain::kRecord, 7, 99),
              ComputeMac(key.data(), key.size(), domain::kRecord, 7, 100));
    const auto key2 = Repeat(0x23, 16);
    EXPECT_NE(ComputeMac(key.data(), key.size(), domain::kRecord, 7, 99),
              ComputeMac(key2.data(), key2.size(), domain::kRecord, 7, 99));
}

TEST(Hash, MacEncodingLayoutIsCanonical) {
    // domain || index(8B LE) || value(16B LE)
    const auto msg = EncodeMacMessage("AB", 0x0102030405060708ull, 0x11);
    EXPECT_EQ(msg.size(), static_cast<size_t>(2 + 8 + 16));
    EXPECT_EQ(msg[0], static_cast<uint8_t>('A'));
    EXPECT_EQ(msg[1], static_cast<uint8_t>('B'));
    EXPECT_EQ(msg[2], static_cast<uint8_t>(0x08));  // index 最低字节
    EXPECT_EQ(msg[9], static_cast<uint8_t>(0x01));  // index 最高字节
    EXPECT_EQ(msg[10], static_cast<uint8_t>(0x11)); // value 最低字节
    EXPECT_EQ(msg[25], static_cast<uint8_t>(0x00)); // value 最高字节
}

TEST(Hash, MacWithEmptyDomainStillWorks) {
    const auto key = Repeat(0x22, 16);
    const MacTag a = ComputeMac(key.data(), key.size(), "", 1, 1);
    const MacTag b = ComputeMac(key.data(), key.size(), "", 1, 2);
    EXPECT_NE(a, b);
}

// ---------------------------------------------------------------------------
// 常量时间比较
// ---------------------------------------------------------------------------

TEST(Hash, ConstantTimeEqualsBehaviour) {
    const MacTag a = ComputeMac(Repeat(0x22, 16).data(), 16, domain::kRecord, 1, 1);
    MacTag b = a;
    EXPECT_TRUE(ConstantTimeEquals(a, b));
    b[0] ^= 0x01;
    EXPECT_FALSE(ConstantTimeEquals(a, b));
    b = a;
    b[kMacTagBytes - 1] ^= 0x80;
    EXPECT_FALSE(ConstantTimeEquals(a, b));
}

// ---------------------------------------------------------------------------
// MSet-XOR-Hash
// ---------------------------------------------------------------------------

TEST(MSetXorHash, OrderIndependent) {
    const MSetXorHash h = MSetXorHash::WithRandomKey();
    const MacTag a = h.ElementTag(domain::kRecord, 1, 100);
    const MacTag b = h.ElementTag(domain::kRecord, 2, 200);
    const MacTag c = h.ElementTag(domain::kRecord, 3, 300);
    const MacTag base = h.BaseTag();

    const MacTag order1 = MSetXorHash::Combine(base, {a, b, c});
    const MacTag order2 = MSetXorHash::Combine(base, {c, a, b});
    const MacTag order3 = MSetXorHash::Combine(base, {b, c, a});
    EXPECT_EQ(order1, order2);
    EXPECT_EQ(order1, order3);
}

TEST(MSetXorHash, IncrementalAddEqualsBatch) {
    // 增量维护（逐项 XOR）必须等于一次性汇总——这是 hint 证明 F_j 可增量累积的依据
    const MSetXorHash h = MSetXorHash::WithRandomKey();
    std::vector<std::pair<uint64_t, uint128_t>> items;
    for (uint64_t i = 0; i < 50; ++i) {
        items.emplace_back(i, static_cast<uint128_t>(i) * 7919);
    }

    MacTag incremental = h.BaseTag();
    for (const auto& [idx, val] : items) {
        incremental = MSetXorHash::XorTag(incremental, h.ElementTag(domain::kRecord, idx, val));
    }
    EXPECT_EQ(incremental, h.HashDataSet(domain::kRecord, items));
}

TEST(MSetXorHash, RemoveUndoesAdd) {
    // XOR 是自逆的：把元素"移除"就是再 XOR 一次
    const MSetXorHash h = MSetXorHash::WithRandomKey();
    const MacTag base = h.BaseTag();
    const MacTag t1 = h.ElementTag(domain::kRecord, 1, 11);
    const MacTag t2 = h.ElementTag(domain::kRecord, 2, 22);

    const MacTag both = MSetXorHash::XorTag(MSetXorHash::XorTag(base, t1), t2);
    const MacTag onlyOne = MSetXorHash::XorTag(both, t1);  // 移除 t1
    EXPECT_EQ(onlyOne, MSetXorHash::XorTag(base, t2));
}

TEST(MSetXorHash, EmptySetEqualsBase) {
    const MSetXorHash h = MSetXorHash::WithRandomKey();
    EXPECT_EQ(MSetXorHash::Combine(h.BaseTag(), {}), h.BaseTag());
    EXPECT_EQ(h.HashDataSet(domain::kRecord, {}), h.BaseTag());
}

TEST(MSetXorHash, DifferentSetsGiveDifferentHashes) {
    const MSetXorHash h = MSetXorHash::WithRandomKey();
    const MacTag s1 = h.HashDataSet(domain::kRecord, {{1, 10}, {2, 20}});
    const MacTag s2 = h.HashDataSet(domain::kRecord, {{1, 10}, {2, 21}});
    const MacTag s3 = h.HashDataSet(domain::kRecord, {{1, 10}});
    EXPECT_NE(s1, s2);
    EXPECT_NE(s1, s3);
}

TEST(MSetXorHash, DifferentKeysGiveDifferentHashes) {
    const std::vector<uint8_t> k1(16, 0x01);
    const std::vector<uint8_t> k2(16, 0x02);
    const MSetXorHash h1(k1), h2(k2);
    EXPECT_NE(h1.HashDataSet(domain::kRecord, {{1, 10}}),
              h2.HashDataSet(domain::kRecord, {{1, 10}}));
}

TEST(MSetXorHash, DuplicateElementsCancel) {
    // 多集语义：同一元素出现两次会互相抵消——这正是"多集"而非"集合"的特征，
    // 在 V-OO-PIR 中意味着重复项会被消去，实现时必须保证每个数据项只被加一次。
    const MSetXorHash h = MSetXorHash::WithRandomKey();
    const MacTag once = h.HashDataSet(domain::kRecord, {{5, 55}});
    const MacTag twice = h.HashDataSet(domain::kRecord, {{5, 55}, {5, 55}});
    EXPECT_EQ(twice, h.BaseTag());
    EXPECT_NE(once, twice);
}

TEST(MSetXorHash, RejectsEmptyKey) {
    EXPECT_THROW(MSetXorHash(std::vector<uint8_t>()), std::invalid_argument);
}

TEST(MSetXorHash, WithRandomKeyProducesDistinctHashes) {
    const MSetXorHash a = MSetXorHash::WithRandomKey();
    const MSetXorHash b = MSetXorHash::WithRandomKey();
    EXPECT_NE(a.key(), b.key());
    EXPECT_NE(a.HashDataSet(domain::kRecord, {{1, 10}}),
              b.HashDataSet(domain::kRecord, {{1, 10}}));
}
