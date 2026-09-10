// MPRAQ 端到端测试（任务 `MPA-08`）：**真实 gRPC**、客户端 + 两台服务器（各自的
// gRPC 服务实例与各自的 `MpraqNode`）、`Count` / `Sum` / `Avg` 与明文基准逐值一致。
//
// ===========================================================================
// 0. 这个文件测什么（以及与"两个进程"的关系）
// ===========================================================================
//   * 链路上的一切都是**真的**：两台独立的 `grpc::Server`（各自**临时端口**、
//     各自的 `MpraqDemoService` 实例、各自的节点存储），客户端通过
//     `GrpcMpraqChannel`（4 条数据 RPC）与 `GrpcTransportClient`（通用 `Relay`）
//     走**回环 socket** 通信。
//   * 与"两个操作系统进程"的唯一差别是内存不隔离（同一地址空间）；协议字节、
//     RPC 次数、往返数、失败路径**完全一样** ⇒ 本文件用 `--rows` 覆盖不到的
//     "两进程"演示由 `src/apps/mpraq_server.cpp` / `mpraq_client.cpp` 承担
//     （`MPA-08` 的交付物①）。
//   * 每条断言都有**确定性期望值**（铁律 D6）：数据集用显式公式
//     （attr0 = i%5、attr1 = (i/2)%3），明文基准来自 `mpraq_baseline`（独立暴力实现），
//     账目数字全部由 `N`/`⌈N/128⌉`/`c`/`λ`/`w` 推导，**不写死常数**。
//
// ===========================================================================
// 1. 覆盖的验收点（对应任务书的 ①–⑤）
// ===========================================================================
//   ① 结果 = 明文基准：`Count` / `filter` / `Sum` / `Avg` 四路对照；
//   ② 每台 PIR RPC 次数 = **Count 次数**（不是查询集个数）—— 一次 `RunBatch` 恒 1 次；
//   ③ `Sum` 的往返数 = 2（`rounds`），且线上消息 = 2N/4N、每台帧数 = 2；
//   ④ 账目数字与公式一致：服务器存储（实测 vs §1 公式，双报含/不含补齐）、
//      查询集数、word 读取量、Relay 安装/相位帧数；
//   ⑤ 异常路径：未 Init 就查询、越界上传、几何不符、Relay 收到非法帧、
//      应答被篡改 —— 全部**拒绝/中止**（fail-loudly，绝不静默给错值）。
//
// ⚠️ 本文件不写 main（用 tests/support 的共享 `test_main.cpp`）。

#include "test_framework.hpp"

#include "mpraq_baseline.hpp"

#include "net/mpraq_remote_securemul.hpp"

#include "core/field.hpp"
#include "core/random.hpp"
#include "mpraq/aggquery.hpp"
#include "mpraq/aggvalue.hpp"
#include "mpraq/init.hpp"
#include "mpraq/node.hpp"
#include "mpraq/predicate.hpp"
#include "net/grpc_mpraq.hpp"
#include "net/grpc_transport.hpp"

#include <grpcpp/grpcpp.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace tsb;
using namespace tsb::mpraq;

namespace {

using Clock = std::chrono::steady_clock;

double MsSince(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

std::string Num(uint64_t v) { return std::to_string(v); }

// ---------------------------------------------------------------------------
// 数据集 / schema（**显式公式** ⇒ 期望值可独立手算）
// ---------------------------------------------------------------------------
//   属性 0：R = [0,5]、m = 6、domain = [0,4]；取值 = i % 5
//   属性 1：R = [0,3]、m = 4、domain = [0,2]；取值 = (i / 2) % 3
constexpr uint32_t kAttr0M = 6;
constexpr uint32_t kAttr1M = 4;
constexpr int64_t kAttr0DomainMax = 4;
constexpr int64_t kAttr1DomainMax = 2;
constexpr size_t kRealColumns = kAttr0M + kAttr1M;  // M = 10

AttributeSchema MakeAttr(uint32_t id, uint32_t m, int64_t dmin, int64_t dmax, size_t n) {
    AttributeSchema a;
    a.name = "attr" + std::to_string(id);
    a.id = id;
    a.lcte.window_size = static_cast<uint32_t>(n);
    a.lcte.range_min = dmin;
    a.lcte.range_size = m;
    a.domain_min = dmin;
    a.domain_max = dmax;
    return a;
}

Schema MakeSchema(size_t n) {
    Schema s;
    s.AddAttribute(MakeAttr(0, kAttr0M, 0, kAttr0DomainMax, n));
    s.AddAttribute(MakeAttr(1, kAttr1M, 0, kAttr1DomainMax, n));
    return s;
}

std::vector<MpraqRecord> MakeRecords(size_t n) {
    std::vector<MpraqRecord> recs(n);
    for (size_t i = 0; i < n; ++i) {
        recs[i].attributes = {static_cast<int64_t>(i % 5),
                              static_cast<int64_t>((i / 2) % 3)};
        recs[i].feature = static_cast<int64_t>(i);
    }
    return recs;
}

mpraq_baseline::Dataset MakeBaseline(const std::vector<MpraqRecord>& recs) {
    mpraq_baseline::Dataset d;
    d.num_attributes = 2;
    d.domain_min = {0, 0};
    d.domain_max = {kAttr0DomainMax, kAttr1DomainMax};
    d.records.reserve(recs.size());
    for (const MpraqRecord& r : recs) d.records.push_back(r.attributes);
    return d;
}

Predicate P(uint32_t attr, mpraq::PredicateOp op, int64_t v) {
    Predicate p;
    p.by_id = true;
    p.attribute_id = attr;
    p.op = op;
    p.value = v;
    return p;
}
Predicate R(uint32_t attr, int64_t lo, int64_t hi) {
    Predicate p;
    p.by_id = true;
    p.attribute_id = attr;
    p.op = mpraq::PredicateOp::kRange;
    p.lower = lo;
    p.upper = hi;
    return p;
}
mpraq_baseline::Pred BR(uint32_t attr, int64_t lo, int64_t hi) {
    return mpraq_baseline::Pred{attr, mpraq_baseline::Op::kRange, 0, lo, hi};
}

// 独立手算的期望值（python3 暴力脚本：逐记录判谓词后计数/累加；**不用**本项目的
// 任何代码，也不从 `mpraq_baseline` 抄）：
//   N=1024、Φ1 = attr0 ∈ [1,4)                ⇒ count 615、Σ attr1 = 614、Avg 0
//   N=1024、Φ2 = attr0 ∈ [2,5) ∧ attr1 ≥ 1    ⇒ count 410、Σ attr1 = 614、Avg 1
//   N=300 、Φ3 = attr0 ∈ [1,4) ∧ attr1 ≥ 1    ⇒ count 120、Σ attr1 = 180、Avg 1
//（覆盖 2 的幂与非 128 倍数的 N；`mpraq_baseline` 是**第二个**独立 oracle）
constexpr uint64_t kCaseACount1024 = 615, kCaseASum1024 = 614;
constexpr uint64_t kCaseBCount1024 = 410, kCaseBSum1024 = 614;
constexpr uint64_t kCaseCCount300 = 120, kCaseCSum300 = 180;
constexpr size_t kCaseAN = 1024;
constexpr size_t kCaseBN = 300;

// ---------------------------------------------------------------------------
// 两台**真实的** gRPC 服务器（临时端口；各自独立的节点与服务实例）
// ---------------------------------------------------------------------------
class TwoServers {
public:
    TwoServers() : node0_(), node1_(), service0_(node0_), service1_(node1_) {
        start(0, node0_, service0_, &server0_, &port0_);
        start(1, node1_, service1_, &server1_, &port1_);
    }

    bool started() const { return server0_ != nullptr && server1_ != nullptr; }
    std::string address(int i) const {
        return "127.0.0.1:" + (i == 0 ? port0_ : port1_);
    }
    MpraqNode& node(int i) { return i == 0 ? node0_ : node1_; }
    MpraqDemoService& service(int i) { return i == 0 ? service0_ : service1_; }
    ServerStats stats(int i) const { return i == 0 ? service0_.Stats() : service1_.Stats(); }

private:
    static void start(int id, MpraqNode& node, MpraqDemoService& service,
                      std::unique_ptr<grpc::Server>* out, std::string* port) {
        (void)id;
        (void)node;
        grpc::ServerBuilder builder;
        int bound = 0;
        builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &bound);
        builder.RegisterService(&service);
        builder.SetMaxReceiveMessageSize(256 * 1024 * 1024);
        builder.SetMaxSendMessageSize(256 * 1024 * 1024);
        std::unique_ptr<grpc::Server> s = builder.BuildAndStart();
        if (!s || bound == 0) {
            throw std::runtime_error("两节点夹具：无法在临时端口上起 gRPC 服务器");
        }
        *out = std::move(s);
        *port = std::to_string(bound);
    }

    MpraqNode node0_;
    MpraqNode node1_;
    MpraqDemoService service0_;
    MpraqDemoService service1_;
    std::unique_ptr<grpc::Server> server0_;
    std::unique_ptr<grpc::Server> server1_;
    std::string port0_;
    std::string port1_;
};

// ---------------------------------------------------------------------------
// 端到端夹具：两台服务器进程内 + 两条 MPRAQ 通道 + 一条 Relay 通道
// ---------------------------------------------------------------------------
class E2e {
public:
    explicit E2e(size_t n, uint32_t lambda = 16) : n_(n), servers_() {
        if (!servers_.started()) {
            throw std::runtime_error("E2e: 服务器未启动");
        }
        channel0_ = std::make_unique<GrpcMpraqChannel>(servers_.address(0));
        channel1_ = std::make_unique<GrpcMpraqChannel>(servers_.address(1));
        channel0_->Connect();
        channel1_->Connect();
        transport_ = std::make_unique<GrpcTransportClient>(
            std::vector<std::string>{servers_.address(0), servers_.address(1)});
        transport_->Connect(5000);

        schema_ = MakeSchema(n_);
        records_ = MakeRecords(n_);
        baseline_ = MakeBaseline(records_);
        MpraqInitParams p;
        p.lambda = lambda;
        p.prp_epsilon = 1e-4;  // 测试取值（默认 1e-10 太慢；口径不变）
        p.seed = 7;
        client_ = MpraqClient::InitWithChannels(schema_, records_, p, *channel0_,
                                                *channel1_);
        mac_ = std::make_unique<SecureMulClientState>(client_->mac_key_shares(),
                                                      client_->modulus());
        prng_ = std::make_unique<random::DeterministicPrng>(
            MakeAesSeed(std::vector<uint8_t>{'m', 'p', 'a', '0', '8', 'e', '2', 'e'}),
            /*nonce=*/11);
        ep0_ = std::make_unique<RemoteSecureMulBatchEndpoint>(*transport_, kServer0);
        ep1_ = std::make_unique<RemoteSecureMulBatchEndpoint>(*transport_, kServer1);
    }

    size_t n() const { return n_; }
    const Schema& schema() const { return schema_; }
    const mpraq_baseline::Dataset& baseline() const { return baseline_; }
    const std::vector<MpraqRecord>& records() const { return records_; }
    MpraqClient& client() { return *client_; }
    SecureMulClientState& mac() { return *mac_; }
    random::DeterministicPrng& prng() { return *prng_; }
    GrpcMpraqChannel& channel(int i) { return i == 0 ? *channel0_ : *channel1_; }
    GrpcTransportClient& transport() { return *transport_; }
    TwoServers& servers() { return servers_; }
    ISecureMulBatchEndpoint& endpoint(int i) { return i == 0 ? *ep0_ : *ep1_; }
    size_t words_per_column() const { return client_->store_params().words_per_column; }
    uint64_t block_count() const { return client_->plinko_params().block_count(); }
    uint64_t backup_hints() const { return client_->plinko_params().backup_hints(); }

    // 一次 Count + Sum/Avg（服务器在**另一个进程/另一个服务实例**里）
    struct Outcome {
        CountResult c;
        SumResult s;
        uint128_t avg = 0;
        uint64_t pir_rpc[2] = {0, 0};
        uint64_t sm_rpc[2] = {0, 0};
    };

    Outcome RunCase(const std::vector<Predicate>& preds, uint32_t sum_attr,
                    uint64_t salt) {
        Outcome o;
        const uint64_t r0 = channel(0).rpc_count();
        const uint64_t r1 = channel(1).rpc_count();
        const uint64_t t0 = transport().RequestCount(0);
        const uint64_t t1 = transport().RequestCount(1);
        o.c = CountPredicates(client(), schema(), preds);
        o.pir_rpc[0] = channel(0).rpc_count() - r0;
        o.pir_rpc[1] = channel(1).rpc_count() - r1;
        o.s = SumOverFilter(o.c, schema(), sum_attr, client(), transport(), endpoint(0),
                            endpoint(1), mac(), prng(), salt);
        o.avg = AvgOverFilter(o.s);
        o.sm_rpc[0] = transport().RequestCount(0) - t0;
        o.sm_rpc[1] = transport().RequestCount(1) - t1;
        return o;
    }

    // 账目：客户端侧的查询集数 = Σ 列数 × ⌈N/128⌉
    uint64_t ExpectedQuerySets(size_t columns) const {
        return static_cast<uint64_t>(columns) * words_per_column();
    }

private:
    size_t n_;
    TwoServers servers_;
    std::unique_ptr<GrpcMpraqChannel> channel0_;
    std::unique_ptr<GrpcMpraqChannel> channel1_;
    std::unique_ptr<GrpcTransportClient> transport_;
    Schema schema_;
    std::vector<MpraqRecord> records_;
    mpraq_baseline::Dataset baseline_;
    std::unique_ptr<MpraqClient> client_;
    std::unique_ptr<SecureMulClientState> mac_;
    std::unique_ptr<random::DeterministicPrng> prng_;
    std::unique_ptr<RemoteSecureMulBatchEndpoint> ep0_;
    std::unique_ptr<RemoteSecureMulBatchEndpoint> ep1_;
};

}  // namespace

// ===========================================================================
// 1. 临时端口 + 远程 Init：几何、上传字节、服务器实测存储 = §1 公式
// ===========================================================================
TEST(MpraqE2e, EphemeralPortsInitAndStorageFormula) {
    // ⚠️ 夹具 `E2e` **自己**起两台服务器并完成 Init ⇒ 断言一律打在 `e.servers()` 上
    //    （另起一个 `TwoServers` 会得到"从未服务过任何请求"的空服务器对象）。
    const auto t0 = Clock::now();
    E2e e(kCaseAN);
    const double init_ms = MsSince(t0);
    TwoServers& servers = e.servers();
    ASSERT_TRUE(servers.started());
    // 两个内核分配的临时端口必须不同（同端口 = 后起的静默抢了前一个的地址）
    EXPECT_NE(servers.address(0), servers.address(1));

    const StoreParams& sp = e.client().store_params();
    // 几何：n = m·⌈N/128⌉、w 是 2 的幂、c = n/w 为偶数
    EXPECT_EQ(sp.num_records, kCaseAN);
    EXPECT_EQ(sp.words_per_column, (kCaseAN + 127) / 128);
    EXPECT_EQ(sp.real_column_count, kRealColumns);
    EXPECT_EQ(sp.entry_count(),
              static_cast<uint64_t>(sp.column_count * sp.words_per_column));
    // 几何合法性：先让库自己校验（不合法会抛），再复核 w 是 2 的幂、c 为偶数
    e.client().plinko_params().Validate();
    const uint64_t w = e.client().plinko_params().w;
    EXPECT_TRUE(w >= 1 && (w & (w - 1)) == 0);
    EXPECT_EQ(e.block_count(), e.client().plinko_params().n / w);
    EXPECT_EQ(e.block_count() % 2, uint64_t{0});
    EXPECT_EQ(e.client().plinko_params().n, sp.entry_count());

    // 上传字节 = 2 台 × (16n + 16N·|attrs|)
    const uint64_t expect_upload =
        2ull * (16ull * sp.entry_count() + 16ull * sp.num_records * sp.num_attributes());
    EXPECT_EQ(e.client().upload_bytes(), expect_upload);

    // Init 的 RPC 次数（每台）：InitTable 1 + 分块上传 ⌈n/chunk⌉ + 属性共享 |attrs|
    const uint64_t expect_init_rpc =
        1 + static_cast<uint64_t>(e.client().timings().chunk_count) +
        sp.num_attributes();
    EXPECT_EQ(e.channel(0).rpc_count(), expect_init_rpc);
    EXPECT_EQ(e.channel(1).rpc_count(), expect_init_rpc);
    EXPECT_EQ(servers.service(0).data().rpc_count(), expect_init_rpc);
    EXPECT_EQ(servers.service(1).data().rpc_count(), expect_init_rpc);
    EXPECT_EQ(e.channel(0).server_resp_calls(), uint64_t{0});        // 查询尚未发生
    EXPECT_EQ(e.channel(0).server_resp_batch_calls(), uint64_t{0});

    // 服务器存储：**实测** vs §1 公式（含补齐 / 不含补齐双报）
    const uint64_t feature_padded = 16ull * sp.column_count * sp.words_per_column;
    const uint64_t feature_unpadded = 16ull * sp.real_column_count * sp.words_per_column;
    const uint64_t attrs = 16ull * sp.num_records * sp.num_attributes();
    for (int i = 0; i < 2; ++i) {
        const ServerStats st = servers.stats(i);
        EXPECT_TRUE(st.initialized);
        EXPECT_EQ(st.storage_bytes, feature_padded + attrs);
        EXPECT_EQ(st.feature_storage_bytes, feature_padded);
        EXPECT_EQ(st.attribute_storage_bytes, attrs);
        EXPECT_EQ(servers.node(i).StorageBytes(), feature_padded + attrs);
    }
    std::printf("[mpa08] N=%zu：Init 走 gRPC = %.1f ms；m=%zu（真实 M=%zu，补齐 %zu 列）、"
                "n=%llu、w=%llu、c=%llu\n",
                kCaseAN, init_ms, sp.column_count, sp.real_column_count,
                sp.padding_columns(), static_cast<unsigned long long>(sp.entry_count()),
                static_cast<unsigned long long>(e.client().plinko_params().w),
                static_cast<unsigned long long>(e.block_count()));
    std::printf("[mpa08] 存储/台：含补齐=%llu B（= 16·m·⌈N/128⌉ + 16·N·|attrs|）、"
                "不含补齐=%llu B、差=%llu B（补齐列 %zu）\n",
                static_cast<unsigned long long>(feature_padded + attrs),
                static_cast<unsigned long long>(feature_unpadded + attrs),
                static_cast<unsigned long long>(feature_padded - feature_unpadded),
                sp.padding_columns());
}

// ===========================================================================
// 2. 范围查询：Count / filter 与**明文基准**逐位一致；一次 RunBatch 恒 1 次 RPC/台
// ===========================================================================
TEST(MpraqE2e, RangeQueryCountMatchesPlaintextAndOneRpcPerBatch) {
    E2e e(kCaseAN);
    const std::vector<Predicate> preds = {R(0, 1, 4)};
    const std::vector<mpraq_baseline::Pred> bpreds = {BR(0, 1, 4)};

    const ServerStats before0 = e.servers().stats(0);
    const ServerStats before1 = e.servers().stats(1);

    E2e::Outcome o = e.RunCase(preds, /*sum_attr=*/1, /*salt=*/0xA801);

    // ---- ① 与明文基准逐值一致 ----
    const std::vector<uint8_t> bf = mpraq_baseline::Filter(e.baseline(), bpreds);
    const uint64_t bcount = mpraq_baseline::Count(e.baseline(), bpreds);
    EXPECT_EQ(bcount, kCaseACount1024);
    EXPECT_EQ(o.c.count, kCaseACount1024);
    EXPECT_EQ(mpraq_baseline::FilterShape(o.c.filter), mpraq_baseline::FilterShape(bf));

    // 范围谓词 = 2 个 LCTE 列（[x<4] 与 [x<1] 的差），每列 ⌈N/128⌉ 个 word
    EXPECT_EQ(o.c.columns.size(), size_t{2});
    EXPECT_EQ(o.c.queries_issued, e.ExpectedQuerySets(2));
    EXPECT_EQ(o.c.queries_issued, 2 * e.words_per_column());

    // ---- ② 每台 PIR RPC 次数 = **Count 次数**（1），不是查询集个数 ----
    EXPECT_EQ(o.pir_rpc[0], uint64_t{1});
    EXPECT_EQ(o.pir_rpc[1], uint64_t{1});
    EXPECT_EQ(e.channel(0).server_resp_batch_calls(), uint64_t{1});
    EXPECT_EQ(e.channel(0).server_resp_calls(), uint64_t{0});  // 标量路径未被用到
    // 查询集个数与 RPC 次数**不同轴**：一次 RPC 承载 16 个查询集
    EXPECT_NE(o.c.queries_issued, o.pir_rpc[0]);

    // ---- ④ 服务器侧实测计数（增量）与公式一致 ----
    for (int i = 0; i < 2; ++i) {
        const ServerStats a = e.servers().stats(i);
        const ServerStats& b = (i == 0 ? before0 : before1);
        EXPECT_EQ(a.rpc_count - b.rpc_count, uint64_t{1});  // 数据 RPC 增量
        EXPECT_EQ(a.queries_served - b.queries_served, e.ExpectedQuerySets(2));
        // 每个查询集读 c 个区块 ⇒ word 读取量 = 查询集数 × c
        EXPECT_EQ(a.words_read - b.words_read, e.ExpectedQuerySets(2) * e.block_count());
    }
    // hint 预算：L14 的①口——每个 word 查询消费 1 条备份 hint
    EXPECT_EQ(e.client().query_count(), e.ExpectedQuerySets(2));
    EXPECT_EQ(e.client().backup_remaining(),
              e.backup_hints() - e.ExpectedQuerySets(2));

    std::printf("[mpa08] 范围查询：count=%llu（基准 %llu）、查询集=%llu、RPC/台=%llu、"
                "retrieve=%.1f ms\n",
                static_cast<unsigned long long>(o.c.count),
                static_cast<unsigned long long>(bcount),
                static_cast<unsigned long long>(o.c.queries_issued),
                static_cast<unsigned long long>(o.pir_rpc[0]), o.c.retrieve_ms);
}

// ===========================================================================
// 3. 多谓词（2 属性）合取：列去重 + 结果与基准逐位一致
// ===========================================================================
TEST(MpraqE2e, MultiPredicateConjunctionMatchesPlaintext) {
    E2e e(kCaseBN);  // N = 300：**非 128 的倍数**（尾部填充位必须被忽略）
    const std::vector<Predicate> preds = {R(0, 1, 4), P(1, mpraq::PredicateOp::kGe, 1)};
    const std::vector<mpraq_baseline::Pred> bpreds = {
        BR(0, 1, 4), mpraq_baseline::Pred{1, mpraq_baseline::Op::kGe, 1, 0, 0}};

    E2e::Outcome o = e.RunCase(preds, /*sum_attr=*/1, /*salt=*/0xA802);

    const uint64_t bcount = mpraq_baseline::Count(e.baseline(), bpreds);
    EXPECT_EQ(bcount, kCaseCCount300);
    EXPECT_EQ(o.c.count, kCaseCCount300);
    EXPECT_EQ(mpraq_baseline::FilterShape(o.c.filter),
              mpraq_baseline::FilterShape(mpraq_baseline::Filter(e.baseline(), bpreds)));
    // 3 个不同的 LCTE 列（attr0 的 4 与 1、attr1 的 1）⇒ 去重升序、无重复
    EXPECT_EQ(o.c.columns.size(), size_t{3});
    for (size_t i = 1; i < o.c.columns.size(); ++i) {
        const bool sorted = o.c.columns[i - 1] < o.c.columns[i];
        EXPECT_TRUE(sorted);
    }
    EXPECT_EQ(o.c.queries_issued, e.ExpectedQuerySets(3));
    EXPECT_EQ(o.pir_rpc[0], uint64_t{1});
    EXPECT_EQ(o.pir_rpc[1], uint64_t{1});

    // Sum/Avg 在这个（非 128 倍数、且 filter 稀疏）的用例上也必须与基准一致
    const mpraq_baseline::Moments bm =
        mpraq_baseline::Aggregate(e.baseline(), bpreds, /*sum_attr=*/1);
    EXPECT_EQ(o.s.sum, static_cast<uint128_t>(bm.sum));
    EXPECT_EQ(o.s.count, bm.count);
    EXPECT_EQ(o.avg, static_cast<uint128_t>(bm.sum / bm.count));
    EXPECT_EQ(o.s.sum, static_cast<uint128_t>(kCaseCSum300));

    std::printf("[mpa08] 合取（N=%zu，非 128 倍数）：count=%llu、列=%zu、查询集=%llu、"
                "Sum=%s、Avg=%s\n",
                kCaseBN, static_cast<unsigned long long>(o.c.count), o.c.columns.size(),
                static_cast<unsigned long long>(o.c.queries_issued),
                toString(o.s.sum).c_str(), toString(o.avg).c_str());
}

// ===========================================================================
// 4. Sum/Avg 账目：往返恒 2、消息 2N/4N、每台 2 帧、安装帧 2、不剪枝
// ===========================================================================
TEST(MpraqE2e, RemoteSumAccountsMatchFormulas) {
    E2e e(kCaseAN);
    const std::vector<mpraq_baseline::Pred> bpreds = {BR(0, 2, 5),
                                                      {1, mpraq_baseline::Op::kGe, 1, 0, 0}};
    const ServerStats before0 = e.servers().stats(0);
    const ServerStats before1 = e.servers().stats(1);

    E2e::Outcome o = e.RunCase({R(0, 2, 5), P(1, mpraq::PredicateOp::kGe, 1)},
                               /*sum_attr=*/1, /*salt=*/0xA803);

    const mpraq_baseline::Moments bm =
        mpraq_baseline::Aggregate(e.baseline(), bpreds, /*sum_attr=*/1);
    EXPECT_EQ(bm.count, kCaseBCount1024);
    EXPECT_EQ(o.s.sum, static_cast<uint128_t>(kCaseBSum1024));
    EXPECT_EQ(o.s.count, kCaseBCount1024);
    EXPECT_EQ(o.avg, static_cast<uint128_t>(kCaseBSum1024 / kCaseBCount1024));

    const SecureMulBatchStats& s = o.s.securemul;
    // ③ 往返恒 2；每轮 1 次 Collect
    EXPECT_EQ(s.rounds, uint64_t{2});
    EXPECT_EQ(s.collect_calls_phase1, uint64_t{1});
    EXPECT_EQ(s.collect_calls_phase2, uint64_t{1});
    // 消息口径：单台 2N、线上 4N；帧长 6+34N / 6+58N
    EXPECT_EQ(s.records, kCaseAN);
    EXPECT_EQ(s.messages, 2 * kCaseAN);
    EXPECT_EQ(s.wire_messages, 4 * kCaseAN);
    EXPECT_EQ(s.phase1_messages, kCaseAN);
    EXPECT_EQ(s.phase2_messages, kCaseAN);
    EXPECT_EQ(s.frame_bytes_phase1, 6 + 34 * kCaseAN);
    EXPECT_EQ(s.frame_bytes_phase2, 6 + 58 * kCaseAN);
    // 不剪枝：每台每轮都处理 N 条（与 filter 命中数无关）
    EXPECT_EQ(s.server_records_processed[0], kCaseAN);
    EXPECT_EQ(s.server_records_processed[1], kCaseAN);
    EXPECT_EQ(s.server_records_processed_phase2[0], kCaseAN);
    EXPECT_EQ(s.server_records_processed_phase2[1], kCaseAN);
    // 每台 2 个批量帧（两轮各一帧）
    EXPECT_EQ(s.server_frames[0], uint64_t{2});
    EXPECT_EQ(s.server_frames[1], uint64_t{2});
    // 服务器侧常驻材料 = N × (7×16 + 16)
    EXPECT_EQ(s.server_state_peak_bytes, kCaseAN * (7 * 16 + 16));
    // 安装阶段（**两进程特有**）：每台 1 帧、共 2 帧，字节 = 2×(13 + 152N)
    EXPECT_EQ(s.install_frames, uint64_t{2});
    EXPECT_EQ(s.install_rounds, uint64_t{2});
    EXPECT_EQ(s.install_bytes, 2ull * (13 + 152 * kCaseAN));

    // ④ 服务器进程侧实测：Relay 安装/相位帧数、处理记录数、以及 SecureMul 的 RPC 总数
    for (int i = 0; i < 2; ++i) {
        const ServerStats a = e.servers().stats(i);
        const ServerStats& b = (i == 0 ? before0 : before1);
        EXPECT_EQ(a.relay_install_frames - b.relay_install_frames, uint64_t{1});
        EXPECT_EQ(a.relay_phase_frames - b.relay_phase_frames, uint64_t{2});
        EXPECT_EQ(a.relay_records_processed - b.relay_records_processed, 2 * kCaseAN);
    }
    // SecureMul 在真实链路上的往返：每台 2（在线）+ 1（安装）= 3 次 Relay
    EXPECT_EQ(o.sm_rpc[0], uint64_t{3});
    EXPECT_EQ(o.sm_rpc[1], uint64_t{3});

    std::printf("[mpa08] 远程 Sum：sum=%s、count=%llu、Avg=%s；rounds=%llu、"
                "messages=%llu、wire=%llu、install_bytes=%llu、online=%.1f ms\n",
                toString(o.s.sum).c_str(), static_cast<unsigned long long>(o.s.count),
                toString(o.avg).c_str(), static_cast<unsigned long long>(s.rounds),
                static_cast<unsigned long long>(s.messages),
                static_cast<unsigned long long>(s.wire_messages),
                static_cast<unsigned long long>(s.install_bytes), s.online_ms);
}

// ===========================================================================
// 5. 两条链路**逐位等价**：gRPC 两进程路径 == 进程内 `LocalTransport` 路径
//    （同一份输入 + 同一个 PRNG 种子 ⇒ z 向量逐元素相等）
// ===========================================================================
TEST(MpraqE2e, RemotePathIsBitwiseEqualToLocalTransport) {
    E2e e(kCaseAN);
    const std::vector<Predicate> preds = {R(0, 1, 4)};
    const CountResult c = CountPredicates(e.client(), e.schema(), preds);

    const std::vector<ModShare> e0 = e.client().AttributeShares(1, kServer0);
    const std::vector<ModShare> e1 = e.client().AttributeShares(1, kServer1);

    // ---- 进程内 `LocalTransport` 路径（改动前的口径）----
    SecureMulClientState mac_local(e.client().mac_key_shares(), e.client().modulus());
    random::DeterministicPrng prng_local(
        MakeAesSeed(std::vector<uint8_t>{'e', 'q', 'u', 'i', 'v'}), /*nonce=*/7);
    LocalTransport net(2);
    const SecureMulBatchOutcome local =
        RunSecureMulBatch(c.filter, e0, e1, net, mac_local, prng_local, 0xA805);
    EXPECT_TRUE(local.all_ok());

    // ---- 真实 gRPC、服务端在**另一个服务实例/进程**里的路径 ----
    SecureMulClientState mac_remote(e.client().mac_key_shares(), e.client().modulus());
    random::DeterministicPrng prng_remote(
        MakeAesSeed(std::vector<uint8_t>{'e', 'q', 'u', 'i', 'v'}), /*nonce=*/7);
    const SecureMulBatchOutcome remote =
        RunSecureMulBatch(c.filter, e0, e1, e.transport(), e.endpoint(0), e.endpoint(1),
                          mac_remote, prng_remote, 0xA805);
    EXPECT_TRUE(remote.all_ok());

    // 逐记录 z 完全一致（**逐位等价**，不只是"和相等"）
    EXPECT_EQ(remote.z.size(), local.z.size());
    size_t mismatches = 0;
    for (size_t i = 0; i < local.z.size(); ++i) {
        if (remote.z[i] != local.z[i]) ++mismatches;
    }
    EXPECT_EQ(mismatches, size_t{0});
    EXPECT_EQ(remote.SumOrThrow(mac_remote.modulus()),
              local.SumOrThrow(mac_local.modulus()));
    // 账目口径差异**只在**安装阶段（本地 0；远程 2 帧）
    EXPECT_EQ(local.stats.install_frames, uint64_t{0});
    EXPECT_EQ(local.stats.install_bytes, uint64_t{0});
    EXPECT_EQ(remote.stats.install_frames, uint64_t{2});
    EXPECT_EQ(remote.stats.rounds, local.stats.rounds);
    EXPECT_EQ(remote.stats.wire_messages, local.stats.wire_messages);
    EXPECT_EQ(remote.stats.server_frames[0], local.stats.server_frames[0]);
    EXPECT_EQ(remote.stats.server_records_processed[0],
              local.stats.server_records_processed[0]);

    std::printf("[mpa08] 等价性：z 向量 %zu 条全部逐位相等（local vs 真实 gRPC 两进程）；"
                "Sum=%s\n",
                local.z.size(), toString(local.SumOrThrow(mac_local.modulus())).c_str());
}

// ===========================================================================
// 6. 确定性：同种子两次运行逐位一致（线上字节口径）
// ===========================================================================
TEST(MpraqE2e, SameSeedIsBitwiseReproducible) {
    E2e a(kCaseAN);
    E2e b(kCaseAN);
    const std::vector<Predicate> preds = {R(0, 1, 4)};
    const CountResult ca = CountPredicates(a.client(), a.schema(), preds);
    const CountResult cb = CountPredicates(b.client(), b.schema(), preds);
    EXPECT_EQ(mpraq_baseline::FilterShape(ca.filter),
              mpraq_baseline::FilterShape(cb.filter));
    EXPECT_EQ(ca.count, cb.count);

    // 同一 (种子, salt) ⇒ z 向量逐位一致（triple 与挑战都由确定性源派生）
    const SecureMulBatchOutcome ra = RunSecureMulBatch(
        ca.filter, a.client().AttributeShares(1, kServer0),
        a.client().AttributeShares(1, kServer1), a.transport(), a.endpoint(0),
        a.endpoint(1), a.mac(), a.prng(), 0xD00D);
    const SecureMulBatchOutcome rb = RunSecureMulBatch(
        cb.filter, b.client().AttributeShares(1, kServer0),
        b.client().AttributeShares(1, kServer1), b.transport(), b.endpoint(0),
        b.endpoint(1), b.mac(), b.prng(), 0xD00D);
    EXPECT_TRUE(ra.all_ok());
    EXPECT_TRUE(rb.all_ok());
    size_t diff = 0;
    for (size_t i = 0; i < ra.z.size(); ++i) {
        if (ra.z[i] != rb.z[i]) ++diff;
    }
    EXPECT_EQ(diff, size_t{0});
    EXPECT_EQ(ra.SumOrThrow(a.mac().modulus()), rb.SumOrThrow(b.mac().modulus()));
}

// ===========================================================================
// 7. 异常路径：未 Init 就查询 / 越界上传 / 几何不符 —— 一律拒绝
// ===========================================================================
TEST(MpraqE2e, FailLoudlyOnUninitializedAndMalformedRequests) {
    TwoServers servers;
    ASSERT_TRUE(servers.started());
    GrpcMpraqChannel ch(servers.address(0));
    ASSERT_TRUE(ch.WaitForConnection(5000));

    // ① 未 InitTable 就 ServerResp ⇒ 服务器拒绝（`MpraqNode` 显式抛），通道抛异常
    PlinkoQuery q;
    q.blocks = 2;
    q.block_size = 4;
    q.offsets = {0, 1};
    q.groups = {0, 1};
    EXPECT_THROW(ch.ServerResp(q), std::runtime_error);
    EXPECT_EQ(servers.service(0).data().rpc_count(), uint64_t{0});  // 失败不计入

    // ② 未 InitTable 就上传 ⇒ 同样被拒绝
    EXPECT_THROW(ch.UploadFeatureWords(0, std::vector<uint128_t>{1, 2}, 2), std::runtime_error);
    EXPECT_THROW(ch.SetAttributeShares(0, std::vector<ModShare>{ModShare{1}}),
                 std::runtime_error);

    // ③ 正常 Init 之后：越界上传 / 长度不符一律拒绝（绝不静默截断或扩容）
    E2e e(kCaseAN);
    const uint64_t n = e.client().store_params().entry_count();
    GrpcMpraqChannel& c0 = e.channel(0);
    EXPECT_THROW(c0.UploadFeatureWords(n, std::vector<uint128_t>{1}, 1), std::runtime_error);
    EXPECT_THROW(c0.UploadFeatureWords(0, std::vector<uint128_t>{1, 2}, /*count=*/1),
                 std::invalid_argument);  // count 与 words 长度不符（客户端侧就拦住）
    // 属性共享长度必须恰好 N
    EXPECT_THROW(c0.SetAttributeShares(0, std::vector<ModShare>{ModShare{1}}),
                 std::runtime_error);
    EXPECT_THROW(c0.SetAttributeShares(99, std::vector<ModShare>(kCaseAN, ModShare{1})),
                 std::runtime_error);

    // ④ 几何不符的查询（block_size 写错 ⇒ 静默错 128 倍的那类）必须被拒绝
    MpraqQueryBatch batch = e.client().CreateColumnQuery(0, 1);
    PlinkoQuery bad = batch.at(0).query();
    bad.block_size = e.client().plinko_params().w * 2;  // 故意的错几何
    EXPECT_THROW(c0.ServerResp(bad), std::runtime_error);

    // ⑤ 越界的 `attr_id`（本地就抛，不是发出去让别人拒）
    EXPECT_THROW(CountPredicates(e.client(), e.schema(), {P(7, mpraq::PredicateOp::kEq, 1)}),
                 std::out_of_range);
}

// ===========================================================================
// 8. Relay 层：非法帧必须被拒绝；应答被篡改 ⇒ Sum **中止**（不给错值）
// ===========================================================================
TEST(MpraqE2e, RelayRejectsGarbageAndTamperedAckAbortsSum) {
    E2e e(kCaseAN);

    // ① 垃圾字节（魔数不符）⇒ 服务器拒绝，客户端拿到 ok=false（绝不冒充成功）
    const Response garbage =
        e.transport().RoundTrip(0, Payload{0x00, 0x01, 0x02, 0x03, 0x04});
    EXPECT_FALSE(garbage.ok);
    EXPECT_TRUE(!garbage.error.empty());

    // ② 魔数正确但类型未知 ⇒ 同样拒绝
    Payload unknown = EncodeRelayFrame(RelayFrameKind::kPhase1Batch, 0, Payload{});
    unknown[4] = 0x7F;  // 篡改 kind 字节
    const Response bad_kind = e.transport().RoundTrip(0, unknown);
    EXPECT_FALSE(bad_kind.ok);

    // ③ 长度自相矛盾（payload_len 与实际不符）⇒ 拒绝
    Payload short_frame = EncodeRelayFrame(RelayFrameKind::kInstallSetups, 0, Payload{});
    short_frame.pop_back();
    const Response bad_len = e.transport().RoundTrip(0, short_frame);
    EXPECT_FALSE(bad_len.ok);

    // ④ 应答被篡改（翻掉封套里的一个字节）⇒ 客户端**结构化地**判定失败，
    //    `SumOverFilter` 抛 `SecureMulBatchAbort`（**绝不**返回部分和/错值）
    const CountResult c =
        CountPredicates(e.client(), e.schema(), {R(0, 1, 4)});
    const uint64_t baseline_sum = mpraq_baseline::Sum(
        e.baseline(), {BR(0, 1, 4)}, /*sum_attr=*/1);
    // 只篡改**服务器 0** 第 1 轮应答里第 0 条记录的 `e_computed` 最低字节。
    // 偏移推导（三处布局都是本项目已固化的）：
    //   封套头 13 B（magic4+kind1+count4+payload_len4）
    //   + 内层批量帧头 6 B（version1+type1+count4）
    //   + Phase1Response 内 `e_computed` 在偏移 10（version1+type1+session8）
    //   ⇒ 13 + 6 + 10 = 29（`test_mpraq_grpc.cpp` 已用同一偏移 10 钉住 v3 布局）
    constexpr size_t kPhase1AckEByte = kRelayHeaderBytes + kBatchFrameHeaderBytes + 10;
    e.transport().set_tamper_hook([](int server_id, Payload& resp) {
        if (server_id != 0) return;
        if (resp.size() <= kPhase1AckEByte) return;
        if (resp[4] != static_cast<uint8_t>(RelayFrameKind::kPhase1Ack)) return;
        resp[kPhase1AckEByte] ^= 0x01;
    });
    bool aborted = false;
    bool produced_wrong_value = false;
    try {
        const SumResult s = SumOverFilter(c, e.schema(), 1, e.client(), e.transport(),
                                          e.endpoint(0), e.endpoint(1), e.mac(), e.prng(),
                                          0xA808);
        produced_wrong_value = (s.sum != static_cast<uint128_t>(baseline_sum));
    } catch (const SecureMulBatchAbort&) {
        aborted = true;
    } catch (const std::exception&) {
        aborted = true;  // 传输层错误也算"中止"（结构化失败）
    }
    e.transport().clear_tamper_hook();
    EXPECT_TRUE(aborted);
    EXPECT_FALSE(produced_wrong_value);

    // ⑤ 篡改之后**不重跑离线**再查一次：诚实路径仍然给出正确结果
    //   （把会话重来一遍 ⇒ 服务端 state 被新的安装帧覆盖）
    const SumResult ok = SumOverFilter(c, e.schema(), 1, e.client(), e.transport(),
                                       e.endpoint(0), e.endpoint(1), e.mac(), e.prng(),
                                       0xA809);
    EXPECT_EQ(ok.sum, static_cast<uint128_t>(baseline_sum));
}

// ===========================================================================
// 9. `SecureMulTransport` 接口重载本身也要有覆盖：
//    在**进程内真实 gRPC 回环**（`GrpcTransportServer` 两条端点 + 组合视图）上跑
//    批量路径 / 逐记录路径 / `SumOverFilter`，并与 `LocalTransport` 路径**逐位对照**。
//    （`MPA-08` 的授权改动就是这三个重载；没有用例的话"源兼容 + 行为不变"只是声明。）
// ===========================================================================
TEST(MpraqE2e, SecureMulTransportInterfaceLoopbackMatchesLocal) {
    // 两条**真实** gRPC 端点（临时端口）+ 组合视图：server_id 0/1 分别落到两个端点
    GrpcTransportServer server_view(
        std::vector<std::string>{"127.0.0.1:0", "127.0.0.1:0"});
    ASSERT_TRUE(server_view.started());  // started() 在未启动时为 false
    EXPECT_EQ(server_view.bound_ports().size(), size_t{2});
    EXPECT_NE(server_view.bound_ports()[0], server_view.bound_ports()[1]);

    class Composite : public ITransportServer {
    public:
        explicit Composite(GrpcTransportServer& inner) : inner_(inner) {}
        void SetHandler(int server_id, ServerHandler handler) override {
            inner_.SetHandler(server_id, std::move(handler));
        }
        int NumServers() const override { return inner_.NumServers(); }

    private:
        GrpcTransportServer& inner_;
    };
    Composite composite(server_view);
    GrpcTransportClient client(std::vector<std::string>{
        "127.0.0.1:" + server_view.bound_ports()[0],
        "127.0.0.1:" + server_view.bound_ports()[1]});
    client.Connect(5000);
    SecureMulTransport view{client, composite};

    E2e e(kCaseAN);
    const CountResult c = CountPredicates(e.client(), e.schema(), {R(0, 1, 4)});
    const std::vector<ModShare> a0 = e.client().AttributeShares(1, kServer0);
    const std::vector<ModShare> a1 = e.client().AttributeShares(1, kServer1);
    const uint128_t expect = mpraq_baseline::Sum(e.baseline(), {BR(0, 1, 4)}, 1);
    EXPECT_EQ(expect, static_cast<uint128_t>(kCaseASum1024));

    // ---- ① 批量路径（`SecureMulTransport` 重载）----
    SecureMulClientState mac_iface(e.client().mac_key_shares(), e.client().modulus());
    random::DeterministicPrng prng_iface(MakeAesSeed(std::vector<uint8_t>{'i', 'f', 'a', 'c', 'e'}),
                                         3);
    const SecureMulBatchOutcome via_iface =
        RunSecureMulBatch(c.filter, a0, a1, view, mac_iface, prng_iface, 0xC001);
    EXPECT_TRUE(via_iface.all_ok());
    EXPECT_EQ(via_iface.SumOrThrow(mac_iface.modulus()), expect);
    EXPECT_EQ(via_iface.stats.rounds, uint64_t{2});
    EXPECT_EQ(via_iface.stats.install_frames, uint64_t{0});  // 同进程 ⇒ 无需下发
    EXPECT_EQ(client.RequestCount(0), 2);  // 两轮 = 2 次 Relay/台
    EXPECT_EQ(client.RequestCount(1), 2);

    // ---- ② 与 `LocalTransport` 路径**逐位一致**（同一份输入 + 同一个种子）----
    SecureMulClientState mac_local(e.client().mac_key_shares(), e.client().modulus());
    random::DeterministicPrng prng_local(MakeAesSeed(std::vector<uint8_t>{'i', 'f', 'a', 'c', 'e'}),
                                         3);
    LocalTransport local(2);
    const SecureMulBatchOutcome via_local =
        RunSecureMulBatch(c.filter, a0, a1, local, mac_local, prng_local, 0xC001);
    size_t diff = 0;
    for (size_t i = 0; i < via_local.z.size(); ++i) {
        if (via_local.z[i] != via_iface.z[i]) ++diff;
    }
    EXPECT_EQ(diff, size_t{0});
    EXPECT_EQ(via_iface.stats.wire_messages, via_local.stats.wire_messages);
    EXPECT_EQ(via_iface.stats.server_frames[0], via_local.stats.server_frames[0]);

    // ---- ③ `SumOverFilter` 的接口重载 ----
    SumResult sum;
    EXPECT_NO_THROW(sum = SumOverFilter(c, e.schema(), 1, e.client(), view, mac_iface,
                                        prng_iface, 0xC002));
    EXPECT_EQ(sum.sum, expect);
    EXPECT_EQ(AvgOverFilter(sum), static_cast<uint128_t>(expect / c.count));

    // ---- ④ 逐记录路径的接口重载（小规模子集：130 条 ⇒ 260 个往返）----
    constexpr size_t kSubset = 130;
    std::vector<uint8_t> f_sub(c.filter.begin(), c.filter.begin() + kSubset);
    std::vector<ModShare> a0_sub(a0.begin(), a0.begin() + kSubset);
    std::vector<ModShare> a1_sub(a1.begin(), a1.begin() + kSubset);
    SecureMulClientState mac_rec(e.client().mac_key_shares(), e.client().modulus());
    random::DeterministicPrng prng_rec(MakeAesSeed(std::vector<uint8_t>{'r', 'e', 'c'}), 5);
    const SecureMulBatchOutcome per_record = RunSecureMulPerRecord(
        f_sub, a0_sub, a1_sub, view, mac_rec, prng_rec, 0xC003);
    EXPECT_TRUE(per_record.all_ok());
    EXPECT_EQ(per_record.stats.rounds, 2 * kSubset);      // 逐记录 = 每条 2 个往返
    EXPECT_EQ(per_record.stats.messages, 2 * kSubset);
    EXPECT_EQ(per_record.stats.server_state_peak_bytes, 7 * 16 + 16);  // 一次只装 1 条
    // 与批量路径在**同一批记录**上逐位一致
    SecureMulClientState mac_rec2(e.client().mac_key_shares(), e.client().modulus());
    random::DeterministicPrng prng_rec2(MakeAesSeed(std::vector<uint8_t>{'r', 'e', 'c'}), 5);
    LocalTransport local_rec(2);
    const SecureMulBatchOutcome per_record_local = RunSecureMulPerRecord(
        f_sub, a0_sub, a1_sub, local_rec, mac_rec2, prng_rec2, 0xC003);
    size_t diff2 = 0;
    for (size_t i = 0; i < f_sub.size(); ++i) {
        if (per_record.z[i] != per_record_local.z[i]) ++diff2;
    }
    EXPECT_EQ(diff2, size_t{0});

    std::printf("[mpa08] 接口重载：批量 rounds=%llu（Relay/台=2）、SumOverFilter Sum=%s、"
                "逐记录 rounds=%llu（130 条）——与 LocalTransport 逐位一致\n",
                static_cast<unsigned long long>(via_iface.stats.rounds),
                toString(sum.sum).c_str(),
                static_cast<unsigned long long>(per_record.stats.rounds));
}

// ===========================================================================
// 10. 预算（L14）：两次 Count 的查询集总数不得超过 min(q, n)，且实测消耗一致
// ===========================================================================
TEST(MpraqE2e, QueryBudgetFollowsL14AndMatchesHintConsumption) {
    E2e e(kCaseAN);
    const uint64_t q = e.backup_hints();          // λw/2
    const uint64_t pool = e.client().store_params().entry_count();  // n = m·⌈N/128⌉

    // 两次查询用的列**互不重复** ⇒ 只消耗 `列数 × ⌈N/128⌉` 个新鲜索引
    E2e::Outcome a = e.RunCase({R(0, 1, 4)}, 1, 0xB901);
    E2e::Outcome b = e.RunCase({R(0, 2, 5), P(1, mpraq::PredicateOp::kGe, 1)}, 1, 0xB902);

    const uint64_t total = a.c.queries_issued + b.c.queries_issued;
    EXPECT_EQ(a.c.queries_issued, 2 * e.words_per_column());
    EXPECT_EQ(b.c.queries_issued, 3 * e.words_per_column());
    EXPECT_TRUE(total <= q);      // ① 备份 hint 预算
    EXPECT_TRUE(total <= pool);   // ② 新鲜索引池预算
    EXPECT_EQ(e.client().query_count(), total);                       // 实测消耗 = 算出来的
    EXPECT_EQ(e.client().backup_remaining(), q - total);
    // 客户端侧发出的查询集与服务器侧受理的查询集必须一致（同一批、无重发）
    const ServerStats st = e.servers().stats(0);
    EXPECT_EQ(st.queries_served, total);

    std::printf("[mpa08] L14 预算：两次 Count 共 %llu 个 word 查询 ≤ min(q=%llu, n=%llu)；"
                "备份 hint 剩余 %llu\n",
                static_cast<unsigned long long>(total),
                static_cast<unsigned long long>(q),
                static_cast<unsigned long long>(pool),
                static_cast<unsigned long long>(e.client().backup_remaining()));
}
