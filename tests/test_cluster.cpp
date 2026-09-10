#include "test_cluster.hpp"
#include "test_framework.hpp"

#include <string>
#include <vector>

using namespace tsb;

namespace {

Payload MakePayload(const std::string& s) {
    return Payload(s.begin(), s.end());
}
std::string PayloadToString(const Payload& p) {
    return std::string(p.begin(), p.end());
}

}  // namespace

// ---------------------------------------------------------------------------
// 数据分发与重建（milestone M1 的核心）
// ---------------------------------------------------------------------------

TEST(TestCluster, SharedDataReconstructsToOriginal) {
    TestCluster c;
    const std::vector<uint128_t> plain = {0, 1, 42, 999999_k, ~static_cast<uint128_t>(0)};
    c.DistributeVarList("v", plain);

    // 两台服务器各持一份共享，缺一不可重建
    EXPECT_EQ(c.server_db(0).var_list.size(), plain.size());
    EXPECT_EQ(c.server_db(1).var_list.size(), plain.size());
    EXPECT_TRUE(c.VarListMatches("v", plain));

    const auto reconstructed = c.ReconstructVarList("v");
    for (size_t i = 0; i < plain.size(); ++i) {
        EXPECT_EQ(reconstructed[i], plain[i]);
    }
}

TEST(TestCluster, SingleServerShareIsNotThePlaintext) {
    TestCluster c;
    const std::vector<uint128_t> plain = {12345_k, 67890_k};
    c.DistributeVarList("v", plain);
    // 任一单方共享都不应等于明文（否则数据隐私不成立）
    EXPECT_NE(c.server_db(0).var_list[0].value, plain[0]);
    EXPECT_NE(c.server_db(1).var_list[0].value, plain[0]);
    EXPECT_NE(c.server_db(0).var_list[1].value, plain[1]);
    EXPECT_NE(c.server_db(1).var_list[1].value, plain[1]);
}

TEST(TestCluster, OneHotTableDistributesFlat) {
    TestCluster c;
    const uint32_t num_bucket = 4;
    // 两行 one-hot：值为 1 和 3
    const std::vector<uint128_t> rows = {0, 1, 0, 0,   // row0 -> col1
                                         0, 0, 0, 1};  // row1 -> col3
    c.DistributeOneHotTable("t", num_bucket, rows);

    // 通过 shared/database 的表抽象访问
    const ShareTable& t0 = c.server_db(0).tables.Table("t");
    const ShareTable& t1 = c.server_db(1).tables.Table("t");
    EXPECT_EQ(t0.num_columns(), static_cast<size_t>(num_bucket));
    EXPECT_EQ(t0.num_rows(), static_cast<size_t>(2));
    EXPECT_EQ(t0.num_elements(), rows.size());
    EXPECT_FALSE(c.server_db(0).tables.HasTable("nope"));

    // 重建回明文（加法共享 -> 相加重建）
    const PlainTable back = ReconstructTable(t0, t1);
    for (size_t r = 0; r < 2; ++r) {
        for (uint32_t col = 0; col < num_bucket; ++col) {
            EXPECT_EQ(back.At(r, col), rows[r * num_bucket + col]);
        }
    }
}

TEST(TestCluster, OneHotTableRejectsBadInput) {
    TestCluster c;
    EXPECT_THROW(c.DistributeOneHotTable("t", 0, {1, 2}), std::invalid_argument);
    EXPECT_THROW(c.DistributeOneHotTable("t", 4, {1, 2, 3}), std::invalid_argument);
}

TEST(TestCluster, VarListMatchesDetectsMismatch) {
    TestCluster c;
    const std::vector<uint128_t> plain = {1, 2, 3};
    c.DistributeVarList("v", plain);
    EXPECT_TRUE(c.VarListMatches("v", plain));
    EXPECT_FALSE(c.VarListMatches("v", {1, 2, 4}));
    EXPECT_FALSE(c.VarListMatches("v", {1, 2}));  // 长度不同
}

TEST(TestCluster, RejectsInvalidServerId) {
    TestCluster c;
    EXPECT_THROW(c.server_db(2), std::out_of_range);
    EXPECT_THROW(c.server_db(-1), std::out_of_range);
}

// ---------------------------------------------------------------------------
// 传输往返
// ---------------------------------------------------------------------------

TEST(TestCluster, HandlerSeesItsOwnDatabase) {
    TestCluster c;
    const std::vector<uint128_t> plain = {7, 8, 9};
    c.DistributeVarList("v", plain);

    // 两个服务器用同一段代码处理请求，但各自看到的是自己的共享
    c.SetDbHandler(0, [](const ServerDatabase& db, const Payload&) {
        // 返回第一个共享的字节
        const uint128_t v = db.var_list[0].value;
        Payload out(16);
        for (size_t i = 0; i < 16; ++i) {
            out[i] = static_cast<uint8_t>(v >> (8 * i));
        }
        return out;
    });
    c.SetDbHandler(1, [](const ServerDatabase& db, const Payload&) {
        const uint128_t v = db.var_list[0].value;
        Payload out(16);
        for (size_t i = 0; i < 16; ++i) {
            out[i] = static_cast<uint8_t>(v >> (8 * i));
        }
        return out;
    });

    c.Submit(0, MakePayload("q"));
    c.Submit(1, MakePayload("q"));
    const auto rs = c.Collect();
    EXPECT_EQ(rs.size(), static_cast<size_t>(2));
    EXPECT_TRUE(rs[0].ok);
    EXPECT_TRUE(rs[1].ok);

    // 客户端 XOR/相加两个应答即可得到明文共享的重建
    uint128_t s0 = 0, s1 = 0;
    for (size_t i = 0; i < 16; ++i) {
        s0 |= static_cast<uint128_t>(rs[0].payload[i]) << (8 * i);
        s1 |= static_cast<uint128_t>(rs[1].payload[i]) << (8 * i);
    }
    EXPECT_EQ(ReconstructRing(RingShare{s0}, RingShare{s1}), plain[0]);
}

TEST(TestCluster, EndToEndShareTransportReconstruct) {
    // M1 验收：共享 → 传输 → 重建 完整往返
    TestCluster c;
    std::vector<uint128_t> plain;
    for (uint64_t i = 0; i < 64; ++i) {
        plain.push_back(static_cast<uint128_t>(i) * 0x9E3779B97F4A7C15_k);
    }
    c.DistributeVarList("v", plain);

    // 服务器把整份共享按请求中指定的下标返回
    c.SetDbHandler(0, [](const ServerDatabase& db, const Payload& req) {
        Payload out;
        for (uint8_t idx : req) {
            const uint128_t v = db.var_list[idx].value;
            for (size_t i = 0; i < 16; ++i) {
                out.push_back(static_cast<uint8_t>(v >> (8 * i)));
            }
        }
        return out;
    });
    c.SetDbHandler(1, [](const ServerDatabase& db, const Payload& req) {
        Payload out;
        for (uint8_t idx : req) {
            const uint128_t v = db.var_list[idx].value;
            for (size_t i = 0; i < 16; ++i) {
                out.push_back(static_cast<uint8_t>(v >> (8 * i)));
            }
        }
        return out;
    });

    const Payload query = {3, 17, 63};
    c.Submit(0, query);
    c.Submit(1, query);
    const auto rs = c.Collect();

    for (size_t k = 0; k < query.size(); ++k) {
        uint128_t s0 = 0, s1 = 0;
        for (size_t i = 0; i < 16; ++i) {
            s0 |= static_cast<uint128_t>(rs[0].payload[16 * k + i]) << (8 * i);
            s1 |= static_cast<uint128_t>(rs[1].payload[16 * k + i]) << (8 * i);
        }
        EXPECT_EQ(ReconstructRing(RingShare{s0}, RingShare{s1}), plain[query[k]]);
    }
}

// ---------------------------------------------------------------------------
// 恶意行为注入
// ---------------------------------------------------------------------------

TEST(TestCluster, MakeMaliciousCorruptsOneServer) {
    TestCluster c;
    c.SetDbHandler(0, [](const ServerDatabase&, const Payload&) {
        return Payload{1, 2, 3, 4};
    });
    c.SetDbHandler(1, [](const ServerDatabase&, const Payload&) {
        return Payload{1, 2, 3, 4};
    });

    c.Submit(0, MakePayload("q"));
    c.Submit(1, MakePayload("q"));
    auto honest = c.Collect();
    EXPECT_EQ(honest[0].payload, honest[1].payload);  // 诚实阶段两边一致

    c.MakeMalicious(1);
    c.Submit(0, MakePayload("q"));
    c.Submit(1, MakePayload("q"));
    auto tampered = c.Collect();
    EXPECT_EQ(tampered[0].payload.size(), static_cast<size_t>(4));
    EXPECT_NE(tampered[0].payload, tampered[1].payload);  // 服务器 1 被篡改

    c.RestoreAll();
    c.Submit(0, MakePayload("q"));
    c.Submit(1, MakePayload("q"));
    auto restored = c.Collect();
    EXPECT_EQ(restored[0].payload, restored[1].payload);  // 恢复后一致
}

TEST(TestCluster, MakeUnresponsiveDropsOneServer) {
    TestCluster c;
    c.SetDbHandler(0, [](const ServerDatabase&, const Payload&) {
        return Payload{9};
    });
    c.SetDbHandler(1, [](const ServerDatabase&, const Payload&) {
        return Payload{9};
    });

    c.MakeUnresponsive(1);
    c.Submit(0, MakePayload("q"));
    c.Submit(1, MakePayload("q"));
    const auto rs = c.Collect();
    EXPECT_TRUE(rs[0].ok);
    EXPECT_FALSE(rs[1].ok);  // 服务器 1 不可达

    c.RestoreAll();
    c.Submit(1, MakePayload("q"));
    EXPECT_TRUE(c.Collect()[0].ok);
}

TEST(TestCluster, RequestCountsAreTracked) {
    TestCluster c;
    c.SetDbHandler(0, [](const ServerDatabase&, const Payload&) { return Payload{}; });
    c.SetDbHandler(1, [](const ServerDatabase&, const Payload&) { return Payload{}; });
    for (int i = 0; i < 5; ++i) c.RoundTrip(0, MakePayload("q"));
    for (int i = 0; i < 3; ++i) c.RoundTrip(1, MakePayload("q"));
    EXPECT_EQ(c.transport().RequestCount(0), static_cast<uint64_t>(5));
    EXPECT_EQ(c.transport().RequestCount(1), static_cast<uint64_t>(3));
}
