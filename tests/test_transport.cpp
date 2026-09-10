#include "net/transport.hpp"
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

// 一个把请求内容回显（加前缀）的服务器
ServerHandler EchoHandler(const std::string& prefix) {
    return [prefix](const Payload& req) {
        Payload out = MakePayload(prefix);
        out.insert(out.end(), req.begin(), req.end());
        return out;
    };
}

}  // namespace

// ---------------------------------------------------------------------------
// 基本收发
// ---------------------------------------------------------------------------

TEST(LocalTransport, RoundTripEchoes) {
    LocalTransport t(2);
    t.SetHandler(0, EchoHandler("S0:"));
    t.SetHandler(1, EchoHandler("S1:"));

    const Response r0 = t.RoundTrip(0, MakePayload("hello"));
    EXPECT_TRUE(r0.ok);
    EXPECT_EQ(PayloadToString(r0.payload), std::string("S0:hello"));

    const Response r1 = t.RoundTrip(1, MakePayload("world"));
    EXPECT_TRUE(r1.ok);
    EXPECT_EQ(PayloadToString(r1.payload), std::string("S1:world"));
}

TEST(LocalTransport, SubmitCollectPreservesOrder) {
    LocalTransport t(2);
    t.SetHandler(0, EchoHandler("A"));
    t.SetHandler(1, EchoHandler("B"));

    // 先提交两个，再一起收取（PIR 的典型用法）
    t.Submit(0, MakePayload("x"));
    t.Submit(1, MakePayload("y"));
    EXPECT_EQ(t.PendingCount(), static_cast<size_t>(2));

    const auto responses = t.Collect();
    EXPECT_EQ(responses.size(), static_cast<size_t>(2));
    EXPECT_EQ(PayloadToString(responses[0].payload), std::string("Ax"));
    EXPECT_EQ(PayloadToString(responses[1].payload), std::string("By"));
    EXPECT_EQ(t.PendingCount(), static_cast<size_t>(0));
}

TEST(LocalTransport, SupportsMultiPhaseRelay) {
    // 模拟 VMPQ Multiply：先问两个服务器，再把中间值转给对方
    LocalTransport t(2);
    t.SetHandler(0, [](const Payload& req) {
        // 第一阶段返回 <e>_0，第二阶段返回 z_0
        if (PayloadToString(req) == "phase1") return MakePayload("e0");
        return MakePayload("z0");
    });
    t.SetHandler(1, [](const Payload& req) {
        if (PayloadToString(req) == "phase1") return MakePayload("e1");
        return MakePayload("z1");
    });

    // 阶段一
    t.Submit(0, MakePayload("phase1"));
    t.Submit(1, MakePayload("phase1"));
    auto r1 = t.Collect();
    EXPECT_EQ(r1.size(), static_cast<size_t>(2));
    EXPECT_EQ(PayloadToString(r1[0].payload), std::string("e0"));
    EXPECT_EQ(PayloadToString(r1[1].payload), std::string("e1"));

    // 客户端中转：把 e0 给 server1、e1 给 server0
    t.Submit(0, MakePayload("e1"));
    t.Submit(1, MakePayload("e0"));
    auto r2 = t.Collect();
    EXPECT_EQ(PayloadToString(r2[0].payload), std::string("z0"));
    EXPECT_EQ(PayloadToString(r2[1].payload), std::string("z1"));
}

TEST(LocalTransport, EmptyPayloadWorks) {
    LocalTransport t(1);
    t.SetHandler(0, [](const Payload&) { return Payload{}; });
    const Response r = t.RoundTrip(0, Payload{});
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.payload.size(), static_cast<size_t>(0));
}

// ---------------------------------------------------------------------------
// 错误处理
// ---------------------------------------------------------------------------

TEST(LocalTransport, MissingHandlerReportsError) {
    LocalTransport t(2);
    // 只注册 server 0
    t.SetHandler(0, EchoHandler("ok"));
    const Response r = t.RoundTrip(1, MakePayload("x"));
    EXPECT_FALSE(r.ok);
}

TEST(LocalTransport, HandlerExceptionBecomesError) {
    LocalTransport t(1);
    t.SetHandler(0, [](const Payload&) -> Payload {
        throw std::runtime_error("内部错误");
    });
    const Response r = t.RoundTrip(0, MakePayload("x"));
    EXPECT_FALSE(r.ok);
    // 错误信息应保留原因，便于定位
    EXPECT_TRUE(r.error.find("内部错误") != std::string::npos);
}

TEST(LocalTransport, RejectsInvalidServerId) {
    LocalTransport t(2);
    t.SetHandler(0, EchoHandler("ok"));
    EXPECT_THROW(t.Submit(2, MakePayload("x")), std::out_of_range);
    EXPECT_THROW(t.Submit(-1, MakePayload("x")), std::out_of_range);
    EXPECT_THROW(t.SetHandler(5, EchoHandler("ok")), std::out_of_range);
}

TEST(LocalTransport, RejectsInvalidConstruction) {
    EXPECT_THROW(LocalTransport(0), std::invalid_argument);
    EXPECT_THROW(LocalTransport(-1), std::invalid_argument);
    LocalTransport t(1);
    EXPECT_THROW(t.SetHandler(0, nullptr), std::invalid_argument);
}

TEST(LocalTransport, AbortDiscardsPending) {
    LocalTransport t(1);
    t.SetHandler(0, EchoHandler("ok"));
    t.Submit(0, MakePayload("a"));
    t.Submit(0, MakePayload("b"));
    EXPECT_EQ(t.PendingCount(), static_cast<size_t>(2));
    t.Abort();
    EXPECT_EQ(t.PendingCount(), static_cast<size_t>(0));
    EXPECT_EQ(t.Collect().size(), static_cast<size_t>(0));
}

// ---------------------------------------------------------------------------
// 恶意行为注入（FND-15 的基础设施）
// ---------------------------------------------------------------------------

TEST(LocalTransport, TamperHookModifiesResponse) {
    LocalTransport t(1);
    t.SetHandler(0, EchoHandler("ok:"));
    t.options().tamper_hook = [](int, Payload& resp) {
        for (auto& b : resp) b ^= 0xFF;  // 翻转所有比特
    };
    const Response r = t.RoundTrip(0, MakePayload("x"));
    EXPECT_TRUE(r.ok);
    EXPECT_NE(PayloadToString(r.payload), std::string("ok:x"));
}

TEST(LocalTransport, TamperHookCanTargetOneServerOnly) {
    LocalTransport t(2);
    t.SetHandler(0, EchoHandler("A"));
    t.SetHandler(1, EchoHandler("B"));
    // 只篡改 server 1 的应答（模拟单台恶意服务器）
    t.options().tamper_hook = [](int sid, Payload& resp) {
        if (sid == 1) resp.push_back(0x00);
    };
    t.Submit(0, MakePayload("x"));
    t.Submit(1, MakePayload("y"));
    const auto rs = t.Collect();
    EXPECT_EQ(PayloadToString(rs[0].payload), std::string("Ax"));
    // server 1 的应答被追加了一个 0x00 字节，因此长度与内容都变了
    EXPECT_EQ(rs[1].payload.size(), static_cast<size_t>(3));
    EXPECT_EQ(rs[1].payload[0], static_cast<uint8_t>('B'));
    EXPECT_EQ(rs[1].payload[1], static_cast<uint8_t>('y'));
    EXPECT_EQ(rs[1].payload[2], static_cast<uint8_t>(0x00));
    EXPECT_NE(rs[1].payload, rs[0].payload);
}

TEST(LocalTransport, DropHookProducesError) {
    LocalTransport t(2);
    t.SetHandler(0, EchoHandler("A"));
    t.SetHandler(1, EchoHandler("B"));
    t.options().drop_hook = [](int sid) { return sid == 1; };

    t.Submit(0, MakePayload("x"));
    t.Submit(1, MakePayload("y"));
    const auto rs = t.Collect();
    EXPECT_TRUE(rs[0].ok);
    EXPECT_FALSE(rs[1].ok);
}

TEST(LocalTransport, HooksCanBeSwitchedAtRuntime) {
    // 先诚实、后恶意：同一个连接上模拟"某个时刻开始作恶"
    LocalTransport t(1);
    t.SetHandler(0, EchoHandler("v:"));
    const Response honest = t.RoundTrip(0, MakePayload("1"));
    EXPECT_EQ(PayloadToString(honest.payload), std::string("v:1"));

    t.options().tamper_hook = [](int, Payload& resp) {
        resp.assign({'b', 'a', 'd'});
    };
    const Response evil = t.RoundTrip(0, MakePayload("1"));
    EXPECT_EQ(PayloadToString(evil.payload), std::string("bad"));
}

// ---------------------------------------------------------------------------
// 统计与隐私性检查基础设施（PIR-03 用）
// ---------------------------------------------------------------------------

TEST(LocalTransport, RecordsRequestLog) {
    LocalTransport t(2);
    t.SetHandler(0, EchoHandler("A"));
    t.SetHandler(1, EchoHandler("B"));
    t.RoundTrip(0, MakePayload("q1"));
    t.RoundTrip(0, MakePayload("q2"));
    t.RoundTrip(1, MakePayload("q3"));

    EXPECT_EQ(t.RequestCount(0), static_cast<uint64_t>(2));
    EXPECT_EQ(t.RequestCount(1), static_cast<uint64_t>(1));
    EXPECT_EQ(t.RequestLog(0).size(), static_cast<size_t>(2));
    EXPECT_EQ(PayloadToString(t.RequestLog(0)[0]), std::string("q1"));
    EXPECT_EQ(PayloadToString(t.RequestLog(0)[1]), std::string("q2"));

    t.ResetStats();
    EXPECT_EQ(t.RequestCount(0), static_cast<uint64_t>(0));
}

TEST(LocalTransport, LatencyOptionIsApplied) {
    LocalTransport t(1);
    t.SetHandler(0, EchoHandler("ok"));
    t.options().latency = std::chrono::microseconds(1000);  // 1ms
    const auto start = std::chrono::steady_clock::now();
    const Response r = t.RoundTrip(0, MakePayload("x"));
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_TRUE(r.ok);
    // 两个方向各 1ms
    EXPECT_TRUE(elapsed >= std::chrono::microseconds(1900));
}
