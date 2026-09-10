// VMP-08：真实 gRPC 双服务器端到端测试。
//
// 本文件在同一进程内起两台**真实的 gRPC 服务器**（不同端口），
// 客户端通过 `GrpcChannel` 与它们通信，跑通完整链路：
//   InitTable（分配存储）→ UploadEntries（上传 XOR 共享）→ PirQuery（在线检索）
//
// 与 `test_vmpq.cpp` 的区别：那里的服务器是进程内对象（LocalChannel，无序列化、
// 无网络）；这里走的是真正的 protobuf 序列化 + TCP 回环 + gRPC 运行时。
//
// 重点验证：
//   1. 端到端结果与明文基准一致（协议在网络往返后仍然正确）
//   2. **Q5 口径**：一次 Count 查询只发**一次** PirQuery RPC，
//      请求里包含全部谓词的全部查询集（而非逐谓词往返）
//   3. 服务器只拿到自己的共享，单方无法还原明文

#include "net/grpc_vmpq.hpp"
#include "core/random.hpp"
#include "test_framework.hpp"
#include "vmpq/vmpq.hpp"

#include <algorithm>
#include <cstdio>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

using namespace tsb;

namespace {

// ⚠️ 早期版本用固定端口（53001 起）：只要**并发**再跑一次测试套件
// （例如另一个 agent / 另一个 build 目录同时在跑 ctest），或开发机上恰好有
// 进程占用该端口，`InProcessNode` 就会绑定失败，表现为
// `started() == false` + "No address added out of total 1 resolved"。
// 现在一律用**临时端口**（内核分配 `:0`），再从 `bound_port()` 读回实际端口。
constexpr char kEphemeralAddr[] = "127.0.0.1:0";

// 已启动服务器对应的客户端地址
std::string LocalAddress(const InProcessNode& node) {
    return "127.0.0.1:" + node.bound_port();
}

VmpqParams MakeParams(uint32_t window) {
    VmpqParams p;
    p.window_size = window;
    p.attr_sizes = {64, 32};
    p.lambda = 24;
    return p;
}

AesPrf MakePrf(uint64_t seed = 1) {
    std::vector<uint8_t> key(16);
    for (size_t i = 0; i < 16; ++i) key[i] = static_cast<uint8_t>(seed + i);
    return AesPrf(key);
}

std::vector<std::vector<uint64_t>> MakeRecords(uint32_t n, uint64_t seed) {
    const auto key = AesPrf::GenerateKey();
    random::DeterministicPrng prng(key, seed);
    std::vector<std::vector<uint64_t>> recs(n, std::vector<uint64_t>(2));
    for (auto& r : recs) {
        r[0] = prng.Below(64);
        r[1] = prng.Below(32);
    }
    return recs;
}

uint64_t PlainCount(const std::vector<std::vector<uint64_t>>& recs, uint32_t attr,
                    uint64_t value) {
    uint64_t c = 0;
    for (const auto& r : recs) {
        if (r[attr] == value) ++c;
    }
    return c;
}

}  // namespace

// ===========================================================================
// 基础：两台服务器能起来、能连接
// ===========================================================================

TEST(GrpcVmpq, ServersStartAndAcceptConnections) {
    InProcessNode s0(kEphemeralAddr);
    InProcessNode s1(kEphemeralAddr);
    EXPECT_TRUE(s0.started());
    EXPECT_TRUE(s1.started());
    EXPECT_NE(s0.bound_port(), s1.bound_port());

    GrpcChannel c0(LocalAddress(s0));
    GrpcChannel c1(LocalAddress(s1));
    EXPECT_TRUE(c0.WaitForConnection(5000));
    EXPECT_TRUE(c1.WaitForConnection(5000));
}

TEST(GrpcVmpq, HandlesRpcErrorsGracefully) {
    InProcessNode s0(kEphemeralAddr);
    GrpcChannel c0(LocalAddress(s0));
    EXPECT_TRUE(c0.WaitForConnection(5000));

    // 未 InitTable 就查询：服务器应返回错误而不是崩溃
    EXPECT_THROW(c0.PirQuery({}), std::runtime_error);

    // 参数非法：InitTable 应被拒绝
    VmpqParams bad;
    bad.window_size = 128;
    bad.attr_sizes = {8, 3};  // 3 不是 2 的幂
    EXPECT_THROW(c0.InitTable(bad.window_size, bad.attr_sizes), std::runtime_error);
}

// ===========================================================================
// 端到端正确性（真实网络往返）
// ===========================================================================

TEST(GrpcVmpq, EndToEndCountMatchesPlaintext) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 501);

    InProcessNode s0(kEphemeralAddr);
    InProcessNode s1(kEphemeralAddr);
    ASSERT_TRUE(s0.started());
    ASSERT_TRUE(s1.started());

    GrpcChannel c0(LocalAddress(s0));
    GrpcChannel c1(LocalAddress(s1));
    ASSERT_TRUE(c0.WaitForConnection(5000));
    ASSERT_TRUE(c1.WaitForConnection(5000));

    // 远程模式：客户端通过通道与两台服务器交互
    c0.InitTable(p.window_size, p.attr_sizes);
    c1.InitTable(p.window_size, p.attr_sizes);

    const AesPrf prf = MakePrf(3);
    VmpqClient client(p, prf, c0, c1);
    client.Init(recs);

    // 服务器确实拿到了共享
    EXPECT_EQ(s0.node().num_entries(), p.PaddedEntries());
    EXPECT_EQ(s1.node().num_entries(), p.PaddedEntries());

    // 逐取值对照明文
    for (uint32_t v = 0; v < p.attr_sizes[0]; ++v) {
        EXPECT_EQ(client.CountSinglePredicate(0, v), PlainCount(recs, 0, v));
    }
    for (uint32_t v = 0; v < p.attr_sizes[1]; ++v) {
        EXPECT_EQ(client.CountSinglePredicate(1, v), PlainCount(recs, 1, v));
    }
}

TEST(GrpcVmpq, EndToEndMultiPredicateAndSum) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 502);

    InProcessNode s0(kEphemeralAddr);
    InProcessNode s1(kEphemeralAddr);
    ASSERT_TRUE(s0.started());
    ASSERT_TRUE(s1.started());

    GrpcChannel c0(LocalAddress(s0));
    GrpcChannel c1(LocalAddress(s1));
    ASSERT_TRUE(c0.WaitForConnection(5000));
    ASSERT_TRUE(c1.WaitForConnection(5000));

    c0.InitTable(p.window_size, p.attr_sizes);
    c1.InitTable(p.window_size, p.attr_sizes);

    const AesPrf prf = MakePrf(5);
    VmpqClient client(p, prf, c0, c1);
    client.Init(recs);

    // 多谓词
    uint64_t expect_both = 0;
    for (const auto& r : recs) {
        if (r[0] == 7 && r[1] == 3) ++expect_both;
    }
    EXPECT_EQ(client.CountMultiPredicate({{0, 7}, {1, 3}}), expect_both);

    // SUM：对属性 1 求和（filter: 属性 0 == 5）
    uint64_t expect_sum = 0;
    for (const auto& r : recs) {
        if (r[0] == 5) expect_sum += r[1];
    }
    EXPECT_EQ(client.SumWithFilter({{0, 5}}, 1), expect_sum);
}

// ===========================================================================
// Q5 口径：一次查询只发一次 PirQuery RPC
// ===========================================================================

TEST(GrpcVmpq, SinglePredicateQueryUsesOneRpc) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 503);

    InProcessNode s0(kEphemeralAddr);
    InProcessNode s1(kEphemeralAddr);
    GrpcChannel c0(LocalAddress(s0));
    GrpcChannel c1(LocalAddress(s1));
    ASSERT_TRUE(c0.WaitForConnection(5000));
    ASSERT_TRUE(c1.WaitForConnection(5000));
    c0.InitTable(p.window_size, p.attr_sizes);
    c1.InitTable(p.window_size, p.attr_sizes);

    const AesPrf prf = MakePrf(7);
    VmpqClient client(p, prf, c0, c1);
    client.Init(recs);

    const uint64_t before0 = c0.rpc_count();
    const uint64_t before1 = c1.rpc_count();
    (void)client.CountSinglePredicate(0, 3);
    const uint64_t after0 = c0.rpc_count();
    const uint64_t after1 = c1.rpc_count();

    // ⚠️ 关键断言：单谓词查询**只发一次** PirQuery RPC。
    // 该 RPC 内部携带该列全部 ⌈N/128⌉ 个 word 的查询集。
    EXPECT_EQ(after0 - before0, static_cast<uint64_t>(1));
    EXPECT_EQ(after1 - before1, static_cast<uint64_t>(1));

    // 服务器侧统计的查询集数量应等于 word 数
    const uint64_t words = p.words_per_column();
    EXPECT_TRUE(s0.queries_served() >= words);
}

TEST(GrpcVmpq, MultiPredicateSendsAllQueriesInOneRpc) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 504);

    InProcessNode s0(kEphemeralAddr);
    InProcessNode s1(kEphemeralAddr);
    GrpcChannel c0(LocalAddress(s0));
    GrpcChannel c1(LocalAddress(s1));
    ASSERT_TRUE(c0.WaitForConnection(5000));
    ASSERT_TRUE(c1.WaitForConnection(5000));
    c0.InitTable(p.window_size, p.attr_sizes);
    c1.InitTable(p.window_size, p.attr_sizes);

    const AesPrf prf = MakePrf(9);
    VmpqClient client(p, prf, c0, c1);
    client.Init(recs);

    const uint64_t served_before = s0.queries_served();
    const uint64_t rpc_before = c0.rpc_count();

    (void)client.CountMultiPredicate({{0, 1}, {1, 2}});

    // 决策 Q5：**所有谓词的全部查询集一次发过去**。
    // 两个谓词 ⇒ 2×⌈N/128⌉ 个查询集，但**只有 1 次 RPC**。
    const uint64_t words = p.words_per_column();
    EXPECT_EQ(c0.rpc_count() - rpc_before, static_cast<uint64_t>(1));
    EXPECT_EQ(s0.queries_served() - served_before, words * 2);
}

// ===========================================================================
// 诊断：单机 gRPC 回环下"每次 RPC"的固定开销
//
// ⚠️ 这条用例**只做诊断与量级看护**，不断言精确耗时（会随机器波动）。
// 存在的理由：§7.11 的 demo 里在线延迟被 RPC 往返主导，而 §7.10 的 bench
// 是进程内的、不含这部分 —— 两者不可混为一谈，必须把这块成本量出来。
// ===========================================================================

TEST(GrpcVmpq, PerRpcOverheadIsSmallButDominantInLoopback) {
    const VmpqParams p = MakeParams(1024);
    InProcessNode s0(kEphemeralAddr);
    ASSERT_TRUE(s0.started());
    GrpcChannel c0(LocalAddress(s0));
    ASSERT_TRUE(c0.WaitForConnection(5000));
    c0.InitTable(p.window_size, p.attr_sizes);

    const VooPirParams pp = p.DerivePirParams();
    PirQuerySetData q;
    q.offsets.assign(pp.part_num, 1);
    q.groups.assign(pp.part_num, 0);
    // 一次单谓词查询 = ⌈N/128⌉ 个查询集
    const uint32_t words = p.words_per_column();
    std::vector<PirQuerySetData> sets(words, q);

    // 热身（首次 RPC 含通道握手/HTTP2 建连）
    for (int i = 0; i < 5; ++i) (void)c0.PirQuery(sets);

    constexpr int kRounds = 20;
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kRounds; ++i) (void)c0.PirQuery(sets);
    const double per_rpc_ms =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0)
            .count() / kRounds;

    std::printf("  [诊断] 单机 gRPC 回环：%u 个查询集/次 ⇒ %.3f ms/RPC\n",
                words, per_rpc_ms);
    // 进程内同一操作约 0.3 ms（§7.10 N=1024 的 Cnt1）：回环 RPC 至少不慢到离谱。
    // 放宽到 50 ms 只为拦住病态回归（例如每次调用重建通道/加 sleep）。
    EXPECT_TRUE(per_rpc_ms < 50.0);
}

// ===========================================================================
// 隐私性：服务器只拿到自己的共享
// ===========================================================================

TEST(GrpcVmpq, NeitherServerAloneHoldsPlaintextBits) {
    const VmpqParams p = MakeParams(1024);
    const auto recs = MakeRecords(p.window_size, 505);

    InProcessNode s0(kEphemeralAddr);
    InProcessNode s1(kEphemeralAddr);
    GrpcChannel c0(LocalAddress(s0));
    GrpcChannel c1(LocalAddress(s1));
    ASSERT_TRUE(c0.WaitForConnection(5000));
    ASSERT_TRUE(c1.WaitForConnection(5000));
    c0.InitTable(p.window_size, p.attr_sizes);
    c1.InitTable(p.window_size, p.attr_sizes);

    const AesPrf prf = MakePrf(11);
    VmpqClient client(p, prf, c0, c1);
    client.Init(recs);

    // 单方共享与"两方 XOR 后的明文"必须不同——且不同的比例应当很高
    //（随机掩码，逐位独立，期望约一半的位不同）
    uint64_t differing_bits = 0;
    uint64_t total_bits = 0;
    for (uint64_t i = 0; i < p.PaddedEntries(); ++i) {
        const uint128_t a = s0.node().Entry(i);
        const uint128_t b = s1.node().Entry(i);
        const uint128_t plain = static_cast<uint128_t>(a ^ b);
        if (a == plain) continue;  // 该 word 掩码恰好无影响
        for (uint32_t bit = 0; bit < 128; ++bit) {
            const bool pa = ((a >> bit) & 1u) != 0;
            const bool pp = ((plain >> bit) & 1u) != 0;
            if (pa != pp) ++differing_bits;
            ++total_bits;
        }
    }
    EXPECT_TRUE(total_bits > 0);
    // 若掩码有效，差异比例应显著偏离 0
    EXPECT_TRUE(differing_bits * 10 > total_bits);
}
