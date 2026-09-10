// MPRAQ 的**传输层**测试（`TASK_PLAN.md` §9.2 S5 的前置件；`MPA-08` 的直接前置）。
//
// 被验证的东西只有一件：**把已经落地的 `MPA-03`（`IMpraqChannel`）与
// `MPA-05`（`ITransportClient/ITransportServer`）接到真实 gRPC 上之后，
// 语义与进程内实现完全一致**。因此本文件里的每一条断言都有一份"本地对照"：
//   * 通道侧：同一份数据、同一份 `MpraqInitParams`（同种子 ⇒ 逐位可复现），
//     本地通道与 gRPC 通道的**整列重建结果必须逐位相同**；
//   * 传输侧：`MPA-05` 的 SecureMul 四条腿原样跑在 `Relay` 上，
//     `z == f·E` / `mac == α·z` 与 `test_mpraq_securemul.cpp` 的本地结论一致。
//
// ⚠️ **临时端口**：全部用例一律 `127.0.0.1:0` + `bound_port()`。固定端口会让
//    **并发**跑第二份测试套件（另一个 build 目录 / 另一个 agent）时绑定失败
//    ——`TASK_PLAN.md` §3.4 的已知坑，`test_grpc_e2e.cpp` 踩过一次。
//    最后一个用例（`ConcurrentNodePairsDoNotCollide`）就是这条纪律的**回归测试**。
//
// ⚠️ **性能**：`HintInit ≈ n × IF⁻¹`（D22-1），因此规模一律压到 n ≤ 64：
//    N = 128（⌈N/128⌉ = 1，一个整列 = 1 个 word = 1 次 RPC）或 N = 100（含补齐列）。
//    ε 取 1e-4（合法但比默认 1e-10 快得多）。
//
// ⚠️ 本任务**不做验证层**（D16 / §7.13 待裁决）⇒ 本文件没有任何"证明/验证值"断言。
// ⚠️ 本文件不写 main（用 tests/support 的 TEST/EXPECT_* 宏 + 共享 test_main.cpp）。

#include "core/field.hpp"
#include "mpraq/init.hpp"
#include "mpraq/node.hpp"
#include "mpraq/predicate.hpp"
#include "mpraq/secure_mul_flow.hpp"
#include "net/grpc_mpraq.hpp"
#include "net/grpc_transport.hpp"
#include "net/transport.hpp"
#include "shared/secret_sharing.hpp"
#include "test_framework.hpp"
#include "mpraq_baseline.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

using namespace tsb;
using namespace tsb::mpraq;

namespace {

using Clock = std::chrono::steady_clock;

// 临时端口端点（§3.4 的纪律：**绝不**用固定端口）
constexpr char kEphemeralAddr[] = "127.0.0.1:0";

double MsSince(const Clock::time_point& t) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t).count();
}

// ---------------------------------------------------------------------------
// 数据集 / schema（与 `test_mpraq_init.cpp` 同一构造口径）
// ---------------------------------------------------------------------------

AttributeSchema MakeAttr(uint32_t id, uint32_t m, int64_t dmin, int64_t dmax,
                         size_t window_size) {
    AttributeSchema a;
    a.name = "attr" + std::to_string(id);
    a.id = id;
    a.lcte.window_size = static_cast<uint32_t>(window_size);
    a.lcte.range_size = m;
    a.lcte.range_min = dmin;
    a.domain_min = dmin;
    a.domain_max = dmax;
    return a;
}

// 两个属性：attr0 取值恒 0（R = [0,0]，m = 2 列，**只有列 0 有 1**）、
// attr1 取值 0/1（R = [0,1]，m = 3 列，三列都有 1）⇒ 真实列数 M = 5。
// ⚠️ m ≥ 跨度 + 2 是 D19-5 的硬约束（R 必须比闭取值域多覆盖一个点），
//    因此 attr0/attr1 的 m 分别是 2 / 3，不能都取 2。
// 各列的比特模式刻意不同（全 1 / 全 0 / 交替）⇒ "取回整列"必须逐位列位正确，
// 不可能靠"某列恰好全 1"蒙对。
Schema MakeSchema(size_t N) {
    Schema s;
    s.AddAttribute(MakeAttr(0, 2, 0, 0, N));
    s.AddAttribute(MakeAttr(1, 3, 0, 1, N));
    return s;
}

// 各属性的 LCTE 列数（= StoreAttribute::lcte.range_size），与 schema 保持同步
constexpr uint32_t kAttrColumns[2] = {2, 3};
constexpr uint32_t kAttrCount = 2;

// 真实列数 M = Σ_a m_a（未补齐）；补齐列数 = column_count − M
size_t RealColumnCount() {
    size_t m = 0;
    for (uint32_t a = 0; a < kAttrCount; ++a) m += kAttrColumns[a];
    return m;
}

// 遍历全部**真实**列（attr, column）的回调式辅助，避免各处写死 0..1
template <typename F>
void ForEachRealColumn(F&& f) {
    for (uint32_t a = 0; a < kAttrCount; ++a) {
        for (uint32_t col = 0; col < kAttrColumns[a]; ++col) {
            f(a, col);
        }
    }
}

// 确定性记录（铁律 D6）：feature = 7i+3；attr0 ≡ 0；attr1 = i mod 2。
std::vector<MpraqRecord> MakeRecords(size_t N) {
    std::vector<MpraqRecord> recs(N);
    for (size_t i = 0; i < N; ++i) {
        recs[i].feature = static_cast<int64_t>(i * 7 + 3);
        recs[i].attributes = {
            0, static_cast<int64_t>(i % 2)  // attr0 ∈ [0,0]，attr1 ∈ [0,1]
        };
    }
    return recs;
}

// 快参数：λ = 16、ε = 1e-4（D22-1 的加速口径）。
// ⚠️ λ 不能太小：备份 hint 数 = λw/2，而一次"取回整列"要消费
//    `⌈N/128⌉` 条（每轮 PIR 消费 1 条常规 hint + 提升 1 条备份 hint，决策 D8）。
//    N = 128 ⇒ ⌈N/128⌉ = 1 ⇒ 一次整列 = 1 条；本文件的用例最多连查
//    (M 个真实列 + 补齐列) = column_count 次 ⇒ λw/2 ≥ column_count 才能跑完。
//    N = 128 时 column_count = 8 ⇒ λ = 16（λw/2 = 8）刚好够，且 hint 表
//    H = 3λw/2 = 48 槽，`HintInit` 的预算（≈ n × IF⁻¹）仍然很小。
MpraqInitParams FastParams(uint64_t seed = 7, uint32_t lambda = 16) {
    MpraqInitParams p;
    p.lambda = lambda;
    p.prp_epsilon = 1e-4;
    p.seed = seed;
    return p;
}

// ---------------------------------------------------------------------------
// 一对"进程内真实 gRPC 服务器"（临时端口）+ 两条 gRPC 通道
// ---------------------------------------------------------------------------

class GrpcPair {
public:
    GrpcPair() : node0_(kEphemeralAddr), node1_(kEphemeralAddr) {
        if (node0_.started()) {
            channel0_ = std::make_unique<GrpcMpraqChannel>(node0_.local_address());
        }
        if (node1_.started()) {
            channel1_ = std::make_unique<GrpcMpraqChannel>(node1_.local_address());
        }
    }

    bool started() const { return node0_.started() && node1_.started(); }
    InProcessMpraqNode& node(int i) { return i == 0 ? node0_ : node1_; }
    GrpcMpraqChannel& channel(int i) { return i == 0 ? *channel0_ : *channel1_; }

    bool wait_for_connection(int timeout_ms) {
        return channel0_ && channel1_ && channel0_->WaitForConnection(timeout_ms) &&
               channel1_->WaitForConnection(timeout_ms);
    }

private:
    InProcessMpraqNode node0_;
    InProcessMpraqNode node1_;
    std::unique_ptr<GrpcMpraqChannel> channel0_;
    std::unique_ptr<GrpcMpraqChannel> channel1_;
};

// 两条通道都要在**同一端口**上（用于"未 InitTable 就查"等错误路径）
class SingleNode {
public:
    SingleNode() : node_(kEphemeralAddr) {
        if (node_.started()) {
            channel_ = std::make_unique<GrpcMpraqChannel>(node_.local_address());
        }
    }
    bool started() const { return node_.started(); }
    InProcessMpraqNode& node() { return node_; }
    GrpcMpraqChannel& channel() { return *channel_; }
    bool wait_for_connection(int timeout_ms) {
        return channel_ && channel_->WaitForConnection(timeout_ms);
    }

private:
    InProcessMpraqNode node_;
    std::unique_ptr<GrpcMpraqChannel> channel_;
};

// ---------------------------------------------------------------------------
// 逐位对照辅件
// ---------------------------------------------------------------------------

// 把一批重建出的 word 还原成"取回整列"的比特向量（word 第 j 位 = 第 j 条记录）
std::vector<uint8_t> BitsFromWords(const std::vector<uint128_t>& words, size_t N) {
    std::vector<uint8_t> bits(N, 0);
    for (size_t j = 0; j < N; ++j) {
        bits[j] = static_cast<uint8_t>((words[j / 128] >> (j % 128)) & 1u);
    }
    return bits;
}

std::string BitString(const std::vector<uint8_t>& bits) {
    std::string s;
    s.reserve(bits.size());
    for (uint8_t b : bits) s.push_back(b ? '1' : '0');
    return s;
}

// ---------------------------------------------------------------------------
// 通用 gRPC transport 的"服务器对 + 客户端"
// ---------------------------------------------------------------------------

class TransportPair {
public:
    TransportPair()
        : server0_(kEphemeralAddr), server1_(kEphemeralAddr),
          client_({server0_.local_address(), server1_.local_address()}) {}

    bool started() const { return server0_.started() && server1_.started(); }

    // 两台服务器在**线路上**是两个独立端点（各自的端口），但 `MPA-05` 的
    // `RegisterSecureMulServers` 需要一个 `ITransportServer`；因此这里把它们
    // 合成一个 view（server_id 0 → 第一个端点、1 → 第二个端点）。
    // ⚠️ 这只是**测试进程**里的视图：两台 gRPC 服务器本身仍然互不相识。
    ITransportServer& net() { return composite_; }
    // ⚠️ 返回**具体类型**：`RequestCount` / `set_tamper_hook` 是 gRPC 实现特有的
    //    诊断与注入入口（`ITransportClient` 的接口里没有这两样）。
    GrpcTransportClient& client() { return client_; }
    void wait_for_connection() { client_.Connect(5000); }

    // 诊断：两台服务器各自收到的 Relay 请求数（一次 SecureMul = 2 次/台）
    uint64_t relay_count(int i) const {
        return i == 0 ? server0_.relay_count() : server1_.relay_count();
    }
    uint64_t error_count(int i) const {
        return i == 0 ? server0_.error_count() : server1_.error_count();
    }

private:
    // 把两台**各自独立**的进程内 gRPC 服务器合成一个 `ITransportServer`
    // （server_id 0 / 1 分别落在两台真实服务器进程上）。
    class Composite : public ITransportServer {
    public:
        Composite(InProcessTransportServer& a, InProcessTransportServer& b)
            : a_(a), b_(b) {}
        void SetHandler(int server_id, ServerHandler handler) override {
            if (server_id == 0) {
                a_.server().SetHandler(0, std::move(handler));
            } else if (server_id == 1) {
                b_.server().SetHandler(0, std::move(handler));
            } else {
                throw std::out_of_range("TransportPair: server_id 只能是 0/1");
            }
        }
        int NumServers() const override { return 2; }

    private:
        InProcessTransportServer& a_;
        InProcessTransportServer& b_;
    };

    InProcessTransportServer server0_;
    InProcessTransportServer server1_;
    Composite composite_{server0_, server1_};
    GrpcTransportClient client_;
};

// ---------------------------------------------------------------------------
// 结构性断言：一次 `InitWithChannels` 在**每台服务器**上恰好发生这些 RPC
// ---------------------------------------------------------------------------
// 口径直接由 `MpraqClient::DistributeUpload()` 与 `StoreParams` 的几何推导得出，
// 不写死常数（几何一改，断言跟着变）：
//   InitTable          × 1
//   UploadFeatureWords × ⌈n / upload_chunk_words⌉ = 1（小规模下 n ≤ 4096）
//   SetAttributeShares × |attrs|
// ⇒ 这里也顺带验证"上传真的走的是通道，而不是悄悄落回本地节点"。
// 一次 `InitWithChannels` 在**每台服务器**上恰好发生这些 RPC（口径由
// `MpraqClient::DistributeUpload()` 与 `StoreParams` 的几何推导，不写死常数）：
//   InitTable          × 1
//   UploadFeatureWords × ⌈n / upload_chunk_words⌉ = 1（小规模下 n ≤ 4096）
//   SetAttributeShares × |attrs|
// ⇒ 这里也顺带验证"上传真的走的是通道，而不是悄悄落回本地节点"。
void ExpectInitRpcs(const MpraqClient& c, const GrpcMpraqChannel& ch0,
                    const GrpcMpraqChannel& ch1, const InProcessMpraqNode& node0,
                    const InProcessMpraqNode& node1) {
    const uint64_t n = c.store_params().entry_count();
    const uint64_t chunk = c.timings().chunk_count;  // ⌈n / upload_chunk_words⌉
    const uint64_t mine = 1 + chunk + c.store_params().num_attributes();
    EXPECT_EQ(ch0.rpc_count(), mine);
    EXPECT_EQ(ch1.rpc_count(), mine);
    // 服务器侧 RPC 总数 = 同一个算式（同一份共享被上传、同一张表被查询）
    EXPECT_EQ(node0.rpc_count(), mine);
    EXPECT_EQ(node1.rpc_count(), mine);
    EXPECT_EQ(ch0.server_resp_calls(), uint64_t{0});        // 初始化阶段没有查询
    EXPECT_EQ(ch0.server_resp_batch_calls(), uint64_t{0});
    // 上传的字节数：2 台 × (特征 word 16n + 属性值 16·N·|attrs|)
    const uint64_t expect_bytes =
        2ull * (16ull * n + 16ull * c.store_params().num_records *
                                c.store_params().num_attributes());
    EXPECT_EQ(c.upload_bytes(), expect_bytes);
}

// 一次 `RunBatch` 的 RPC 统计：**每台服务器恰好一次往返**（Q5 口径）。
// 返回两张表的合计 RPC 差值，便于调用方继续断言。
//
// ⚠️ 与调用粒度的关系：`IMpraqChannel` 现在的批量接口是 `ServerRespBatch`
//    （一次 `RunBatch` = 一次调用 = 一次 RPC）。这里**不**断言"必定是批量"，
//    而是断言 `rpc_calls()` 与 `server_resp_batch_calls + server_resp_single_calls`
//    自洽，并要求**通道侧的 rpc_count 增量 == 本地侧统计的 rpc_calls 增量**
//    —— 这才是"两条通道等价"的可检验口径，与具体粒度无关。
struct BatchRpcDelta {
    uint64_t channel0 = 0;
    uint64_t channel1 = 0;
    uint64_t local0 = 0;
    uint64_t local1 = 0;
    uint64_t queries0 = 0;
    uint64_t queries1 = 0;
};

BatchRpcDelta MeasureRunBatch(const MpraqClient& c, MpraqQueryBatch& batch,
                              const GrpcMpraqChannel& ch0, const GrpcMpraqChannel& ch1,
                              std::vector<uint128_t>* out) {
    const uint64_t ch0_before = ch0.rpc_count();
    const uint64_t ch1_before = ch1.rpc_count();
    const MpraqRpcStats s0_before = c.channel_rpc_stats(0);
    const MpraqRpcStats s1_before = c.channel_rpc_stats(1);
    std::vector<uint128_t> words = const_cast<MpraqClient&>(c).RunBatch(batch);
    const uint64_t ch0_after = ch0.rpc_count();
    const uint64_t ch1_after = ch1.rpc_count();
    const MpraqRpcStats s0_after = c.channel_rpc_stats(0);
    const MpraqRpcStats s1_after = c.channel_rpc_stats(1);
    if (out != nullptr) *out = std::move(words);

    BatchRpcDelta d;
    d.channel0 = ch0_after - ch0_before;
    d.channel1 = ch1_after - ch1_before;
    d.local0 = s0_after.rpc_calls() - s0_before.rpc_calls();
    d.local1 = s1_after.rpc_calls() - s1_before.rpc_calls();
    d.queries0 = s0_after.queries - s0_before.queries;
    d.queries1 = s1_after.queries - s1_before.queries;
    // 两条通道的 RPC 次数必须逐次相等（等价性的核心断言）
    EXPECT_EQ(d.channel0, d.local0);
    EXPECT_EQ(d.channel1, d.local1);
    // 一次 `RunBatch` 只可能是"整批一次"或"每查询集一次"，不可能是别的数
    EXPECT_TRUE(d.channel0 == 1 ||
                d.channel0 == static_cast<uint64_t>(batch.size()));
    EXPECT_EQ(d.channel0, d.channel1);
    // 服务器侧统计的"查询集个数" = 批次大小（与往返粒度无关）
    EXPECT_EQ(d.queries0, static_cast<uint64_t>(batch.size()));
    EXPECT_EQ(d.queries1, static_cast<uint64_t>(batch.size()));
    return d;
}

// ---------------------------------------------------------------------------
// SecureMul（MPA-05）在真实 gRPC 上的安装 + 一条记录
// ---------------------------------------------------------------------------

struct SecureMulOverGrpc {
    SecureMulClientState client{SecureMulClientState::GenerateMacKey(kSecureMulModulus)};
    SecureMulTripleMaterial material{};
    SecureMulSetupBundle bundle{};
    uint64_t challenge = 0;
    uint128_t e_value = 0;
    SecureMulServerState s0{0, TripleShare{}, kSecureMulModulus};
    SecureMulServerState s1{1, TripleShare{}, kSecureMulModulus};

    // 安装一条记录的服务器状态（Init 阶段的动作：triple 共享 + ⟨E⟩ + challenge）。
    // ⚠️ `material` 的**客户端本地**部分（a、b、c）只留在客户端，绝不下发。
    void Install(ITransportServer& net, uint64_t record_index, uint128_t e,
                 tsb::random::DeterministicPrng& prng) {
        e_value = e;
        material = GenerateBeaverTriple(client.keys(), kSecureMulModulus, prng);
        challenge = MakeChallenge(record_index, {0x5A, 0x17});
        bundle = MakeSetupsAndContext(record_index, material,
                                      ShareMod(e, kSecureMulModulus), challenge);
        s0 = MakeServerState(bundle.server0, kSecureMulModulus);
        s1 = MakeServerState(bundle.server1, kSecureMulModulus);
        RegisterSecureMulServers(net, s0, s1);
    }
};

// 篡改点：第 1 轮应答里 `e_computed` 的最低字节（wire 偏移 10，v3 布局）。
// ⇒ 该台服务器第 2 轮的 `e_check` 一致性检查必然失败（§4.5）。
constexpr size_t kPhase1ResponseEByte = 10;

// ---------------------------------------------------------------------------
// **编译期证据**：`IMpraqChannel::ServerRespBatch` 是纯虚（`MPA-08` 裁决 2）
// ---------------------------------------------------------------------------
// 下面这个类实现了除 `ServerRespBatch` 之外的**全部**纯虚方法，**故意**不覆写它：
//   * 若 `ServerRespBatch` 仍是纯虚 ⇒ 该类是抽象类（`std::is_abstract` 为真）✔
//   * 若将来有人把"逐条退化"的默认实现加回来 ⇒ 该类变成可实例化，
//     `static_assert` **当场编译失败** —— 这就是"忘记覆写必须是编译期错误"的钉子。
// （不是运行期断言：它在 `ctest` 之前、编译这一关就生效。）
class ChannelWithoutBatch final : public IMpraqChannel {
public:
    void InitTable(const StoreParams&) override {}
    void UploadFeatureWords(uint64_t, const std::vector<uint128_t>&, size_t) override {}
    void SetAttributeShares(uint32_t, const std::vector<ModShare>&) override {}
    PlinkoAnswer ServerResp(const PlinkoQuery&) override { return PlinkoAnswer{}; }
    // ⚠️ 这里**故意**不写 `ServerRespBatch`（要的就是"忘记覆写 ⇒ 编译不过"）
};
static_assert(std::is_abstract<ChannelWithoutBatch>::value,
              "IMpraqChannel::ServerRespBatch 必须是**纯虚**：忘记覆写要在编译期暴露"
              "（若这条断言失败，说明有人又把退化的默认实现加回来了）");

}  // namespace

// ===========================================================================
// 1. 两节点能起、能连（临时端口）
// ===========================================================================

TEST(MpraqGrpc, NodesStartOnEphemeralPortsAndAcceptConnections) {
    GrpcPair pair;
    ASSERT_TRUE(pair.started());
    // ⚠️ 内核分配的两个临时端口必须不同（同端口 = 后起的那个静默抢了前一个的地址）
    EXPECT_NE(pair.node(0).bound_port(), pair.node(1).bound_port());
    EXPECT_TRUE(pair.wait_for_connection(5000));
    EXPECT_EQ(pair.channel(0).target(), "127.0.0.1:" + pair.node(0).bound_port());
    EXPECT_EQ(pair.channel(1).target(), "127.0.0.1:" + pair.node(1).bound_port());

    // 还没 InitTable 时，两台服务器的节点都是"未初始化"的
    EXPECT_FALSE(pair.node(0).node().initialized());
    EXPECT_FALSE(pair.node(1).node().initialized());
    EXPECT_EQ(pair.node(0).rpc_count(), uint64_t{0});
    EXPECT_EQ(pair.channel(0).rpc_count(), uint64_t{0});
}

// ===========================================================================
// 2. 远程 Init 端到端：真实 gRPC 上的 PIR 链路，逐位与明文基准一致
// ===========================================================================

TEST(MpraqGrpc, RemoteInitAndColumnQueryMatchPlaintext) {
    constexpr size_t kN = 128;  // ⌈N/128⌉ = 1 ⇒ 一个整列 = 1 个 word = 1 次 RPC
    GrpcPair pair;
    ASSERT_TRUE(pair.started());
    ASSERT_TRUE(pair.wait_for_connection(5000));

    const auto t_init = Clock::now();
    auto c = MpraqClient::InitWithChannels(MakeSchema(kN), MakeRecords(kN), FastParams(),
                                           pair.channel(0), pair.channel(1));
    const double init_ms = MsSince(t_init);
    std::printf("[mpraq_grpc] N=%zu：Init 走 gRPC = %.1f ms（n=%llu, w=%llu, c=%llu）\n",
                kN, init_ms,
                static_cast<unsigned long long>(c->store_params().entry_count()),
                static_cast<unsigned long long>(c->plinko_params().w),
                static_cast<unsigned long long>(c->plinko_params().block_count()));
    EXPECT_EQ(c->store_params().words_per_column, size_t{1});
    ExpectInitRpcs(*c, pair.channel(0), pair.channel(1), pair.node(0), pair.node(1));

    // 两台服务器上真的有了共享（而不是"客户端自己算完就完了"）
    // ⚠️ 远程模式下 `MpraqClient::node(i)` 会抛 `std::logic_error`
    //    （"远程模式下没有本地节点"）—— 服务器侧的观测必须走真实节点对象，
    //    这也顺带证明"共享确实落到了远端"，而不是留在客户端进程里。
    EXPECT_EQ(pair.node(0).node().num_entries(), c->store_params().entry_count());
    EXPECT_EQ(pair.node(1).node().num_entries(), c->store_params().entry_count());

    const uint64_t m = c->column_count();
    uint64_t batches = 0;   // 本用例总共发了几个 RunBatch
    uint64_t words_seen = 0;

    // 逐位核对"取回一整列"与 `PlainColumnBits`（明文基准，独立于协议实现），
    // 并逐批核对 RPC 次数（每台服务器每批恰好一次往返，Q5 口径）。
    ForEachRealColumn([&](uint32_t attr, uint32_t col) {
        auto batch = c->CreateColumnQuery(attr, col);
        ASSERT_EQ(batch.size(), size_t{1});
        std::vector<uint128_t> words;
        MeasureRunBatch(*c, batch, pair.channel(0), pair.channel(1), &words);
        ASSERT_EQ(words.size(), size_t{1});
        const std::vector<uint8_t> want = c->PlainColumnBits(attr, col);
        EXPECT_EQ(BitString(BitsFromWords(words, kN)), BitString(want));
        EXPECT_EQ(words[0], c->PlainFeatureWord(c->ColumnWordIndex(attr, col, 0)));
        ++batches;
        words_seen += static_cast<uint64_t>(batch.size());
    });

    // 补齐列在真实链路上同样可检索（明文恒 0）
    for (size_t gc = c->real_column_count(); gc < m; ++gc) {
        auto batch = c->CreateQueriesForIndices({c->GlobalColumnWordIndex(gc, 0)});
        std::vector<uint128_t> words;
        MeasureRunBatch(*c, batch, pair.channel(0), pair.channel(1), &words);
        ASSERT_EQ(words.size(), size_t{1});
        EXPECT_EQ(words[0], uint128_t{0});
        ++batches;
        words_seen += static_cast<uint64_t>(batch.size());
    }

    // 通道与本地统计自洽：批次数 = ServerRespBatch 次数（每台），
    // 查询集个数 = 检索过的 word 数（与往返粒度无关）。
    EXPECT_EQ(pair.channel(0).server_resp_batch_calls(), batches);
    EXPECT_EQ(pair.channel(1).server_resp_batch_calls(), batches);
    EXPECT_EQ(c->channel_rpc_stats(0).server_resp_batch_calls, batches);
    EXPECT_EQ(c->channel_rpc_stats(1).server_resp_batch_calls, batches);
    EXPECT_EQ(c->channel_rpc_stats(0).queries, words_seen);
    EXPECT_EQ(c->channel_rpc_stats(1).queries, words_seen);
    EXPECT_EQ(pair.channel(0).queries_served(), words_seen);
    EXPECT_EQ(pair.channel(1).queries_served(), words_seen);
    // 服务器侧确实受理了这么多次查询（`queries_served` 数的是查询集/word 数，
    // 与往返粒度无关）
    EXPECT_EQ(pair.node(0).queries_served(), words_seen);
    EXPECT_EQ(pair.node(1).queries_served(), words_seen);
    // 每台服务器的 RPC 总数 = 初始化 RPC + 批次数（没有任何"多出来的"RPC）
    EXPECT_EQ(pair.node(0).rpc_count(), pair.channel(0).rpc_count());
    EXPECT_EQ(pair.node(1).rpc_count(), pair.channel(1).rpc_count());
}

TEST(MpraqGrpc, RemoteInitWithPaddingMatchesPlaintext) {
    // N = 100 ⇒ ⌈N/128⌉ = 1，真实列数 M = 4 ⇒ 补齐到 4 列（M 已是 2 的幂），
    // 但**记录数不是 128 的倍数**，因此这条用例专门覆盖"尾部填充位"：
    // word 的第 100..127 位两台共享必须一致（否则 XOR 重建会出错值）。
    constexpr size_t kN = 100;
    GrpcPair pair;
    ASSERT_TRUE(pair.started());
    ASSERT_TRUE(pair.wait_for_connection(5000));

    auto c = MpraqClient::InitWithChannels(MakeSchema(kN), MakeRecords(kN), FastParams(),
                                           pair.channel(0), pair.channel(1));
    EXPECT_EQ(c->store_params().num_records, kN);
    EXPECT_EQ(c->store_params().words_per_column, size_t{1});

    auto batch = c->CreateColumnQuery(1, 0);
    const std::vector<uint128_t> words = c->RunBatch(batch);
    ASSERT_EQ(words.size(), size_t{1});
    const std::vector<uint8_t> want = c->PlainColumnBits(1, 0);
    EXPECT_EQ(BitString(BitsFromWords(words, kN)), BitString(want));
    // 尾部填充位（第 N 位起）明文为 0
    for (size_t j = kN; j < 128; ++j) {
        EXPECT_EQ(static_cast<uint8_t>((words[0] >> j) & 1u), uint8_t{0});
    }
}

// ===========================================================================
// 3. 通道等价性：本地通道 vs gRPC 通道
// ===========================================================================

TEST(MpraqGrpc, GrpcChannelIsEquivalentToLocalChannel) {
    constexpr size_t kN = 128;
    const MpraqInitParams params = FastParams(/*seed=*/20260910);

    // ---- 路径 A：进程内本地通道 ----
    auto local = MpraqClient::Init(MakeSchema(kN), MakeRecords(kN), params);

    // ---- 路径 B：真实 gRPC 通道 ----
    GrpcPair pair;
    ASSERT_TRUE(pair.started());
    ASSERT_TRUE(pair.wait_for_connection(5000));
    auto remote = MpraqClient::InitWithChannels(MakeSchema(kN), MakeRecords(kN), params,
                                                pair.channel(0), pair.channel(1));

    // ---- ① 几何与账目必须完全一致 ----
    EXPECT_EQ(local->store_params().entry_count(), remote->store_params().entry_count());
    EXPECT_EQ(local->store_params().column_count, remote->store_params().column_count);
    EXPECT_EQ(local->store_params().words_per_column,
              remote->store_params().words_per_column);
    // ⚠️ `MpraqClient::storage_bytes(i)` 内部走 `node(i)` ⇒ 远程模式下会抛。
    //    因此远程侧直接问节点对象（两边都是 `MpraqNode::StorageBytes()` 同一实现）。
    EXPECT_EQ(local->storage_bytes(0), pair.node(0).node().StorageBytes());
    EXPECT_EQ(local->storage_bytes(1), pair.node(1).node().StorageBytes());
    EXPECT_EQ(local->upload_bytes(), remote->upload_bytes());

    // ---- ② 服务器侧的**共享本身**逐位一致（同种子 ⇒ 掩码流逐位一致）----
    //    这比"重建结果一致"更强：它证明**线路上搬运的 16 字节没有被动过**
    //    （端序写错 / 长度截断 / 补齐列丢失都会在这里被抓到）。
    const uint64_t n = local->store_params().entry_count();
    size_t word_mismatch = 0;
    for (uint64_t i = 0; i < n; ++i) {
        if (local->node(0).FeatureWord(i) != pair.node(0).node().FeatureWord(i)) {
            ++word_mismatch;
        }
        if (local->node(1).FeatureWord(i) != pair.node(1).node().FeatureWord(i)) {
            ++word_mismatch;
        }
    }
    EXPECT_EQ(word_mismatch, size_t{0});
    size_t attr_mismatch = 0;
    for (uint32_t a = 0; a < local->schema().num_attributes(); ++a) {
        for (int s = 0; s < 2; ++s) {
            // ⚠️ 远程侧不能用 `remote->AttributeShares(a, s)`（内部走 `node()`，
            //    远程模式抛异常）⇒ 逐记录从**真实节点**读并逐位比对。
            const std::vector<ModShare> sl = local->AttributeShares(a, s);
            for (size_t r = 0; r < sl.size(); ++r) {
                if (sl[r].value != pair.node(s).node().AttributeShare(a, r).value) {
                    ++attr_mismatch;
                }
            }
        }
    }
    EXPECT_EQ(attr_mismatch, size_t{0});

    // ---- ③ 两条路径各自重建整列，结果逐位一致 ----
    ForEachRealColumn([&](uint32_t attr, uint32_t col) {
        auto bl = local->CreateColumnQuery(attr, col);
        auto br = remote->CreateColumnQuery(attr, col);
        const std::vector<uint128_t> wl = local->RunBatch(bl);
        const std::vector<uint128_t> wr = remote->RunBatch(br);
        ASSERT_EQ(wl.size(), wr.size());
        EXPECT_EQ(BitString(BitsFromWords(wl, kN)), BitString(BitsFromWords(wr, kN)));
        EXPECT_EQ(BitString(BitsFromWords(wl, kN)),
                  BitString(local->PlainColumnBits(attr, col)));
    });
}

// ===========================================================================
// 4. RPC 次数：一次 RunBatch（多列多 word）= 每台服务器**恰好 1 次往返**
// ===========================================================================

TEST(MpraqGrpc, OneBatchIsOneRoundTripPerServer) {
    // N = 256 ⇒ ⌈N/128⌉ = 2 ⇒ **一个整列 = 2 个 word**（多 word 情形）；
    // λ = 12 ⇒ 备份 hint = λw/2 = 12 条（w = 2），一批 2 列 = 4 个 word。
    constexpr size_t kN = 256;
    GrpcPair pair;
    ASSERT_TRUE(pair.started());
    ASSERT_TRUE(pair.wait_for_connection(5000));

    const auto t_init = Clock::now();
    auto c = MpraqClient::InitWithChannels(MakeSchema(kN), MakeRecords(kN),
                                           FastParams(/*seed=*/11, /*lambda=*/12),
                                           pair.channel(0), pair.channel(1));
    const double init_ms = MsSince(t_init);
    ASSERT_EQ(c->store_params().words_per_column, size_t{2});
    std::printf("[mpraq_grpc] N=%zu：Init 走 gRPC = %.1f ms（n=%llu, w=%llu, c=%llu）\n",
                kN, init_ms,
                static_cast<unsigned long long>(c->store_params().entry_count()),
                static_cast<unsigned long long>(c->plinko_params().w),
                static_cast<unsigned long long>(c->plinko_params().block_count()));

    const uint64_t init_rpc0 = pair.channel(0).rpc_count();
    const uint64_t init_rpc1 = pair.channel(1).rpc_count();
    const uint64_t init_node0 = pair.node(0).rpc_count();
    const uint64_t init_node1 = pair.node(1).rpc_count();
    ExpectInitRpcs(*c, pair.channel(0), pair.channel(1), pair.node(0), pair.node(1));

    // ① 一批 2 个 word（一整个列）
    auto batch0 = c->CreateColumnQuery(0, 1);
    ASSERT_EQ(batch0.size(), size_t{2});
    std::vector<uint128_t> w0;
    const auto t_batch = Clock::now();
    const BatchRpcDelta d0 =
        MeasureRunBatch(*c, batch0, pair.channel(0), pair.channel(1), &w0);
    const double one_batch_ms = MsSince(t_batch);

    // ② 再一批 2 个 word（另一个属性的另一列）
    auto batch1 = c->CreateColumnQuery(1, 0);
    ASSERT_EQ(batch1.size(), size_t{2});
    std::vector<uint128_t> w1;
    const BatchRpcDelta d1 =
        MeasureRunBatch(*c, batch1, pair.channel(0), pair.channel(1), &w1);

    std::printf("[mpraq_grpc] N=%zu：一次 RunBatch（1 列 × 2 word）= %.1f ms，"
                "每台通道 RPC 增量 = %llu / %llu（服务器侧 %llu / %llu）\n",
                kN, one_batch_ms,
                static_cast<unsigned long long>(d0.channel0),
                static_cast<unsigned long long>(d0.channel1),
                static_cast<unsigned long long>(d0.local0),
                static_cast<unsigned long long>(d0.local1));
    ASSERT_EQ(w0.size(), size_t{2});
    ASSERT_EQ(w1.size(), size_t{2});

    // ✅ **Q5 口径**：一次 `RunBatch`（任意列数 × 每列任意 word 数）= 每台 **1 次** RPC
    EXPECT_EQ(d0.channel0, uint64_t{1});
    EXPECT_EQ(d0.channel1, uint64_t{1});
    EXPECT_EQ(d1.channel0, uint64_t{1});
    EXPECT_EQ(d1.channel1, uint64_t{1});
    // 两次批量调用 ⇒ 通道与本地统计都是 2 次批量、每台 4 个查询集
    EXPECT_EQ(pair.channel(0).server_resp_batch_calls(), uint64_t{2});
    EXPECT_EQ(pair.channel(1).server_resp_batch_calls(), uint64_t{2});
    EXPECT_EQ(c->channel_rpc_stats(0).server_resp_batch_calls, uint64_t{2});
    EXPECT_EQ(c->channel_rpc_stats(1).server_resp_batch_calls, uint64_t{2});
    EXPECT_EQ(c->channel_rpc_stats(0).queries, uint64_t{4});
    EXPECT_EQ(c->channel_rpc_stats(1).queries, uint64_t{4});
    // 标量 ServerResp 一次都没用到（批量路径全权覆盖）
    EXPECT_EQ(pair.channel(0).server_resp_calls(), uint64_t{0});
    EXPECT_EQ(c->channel_server_resp_calls(0), uint64_t{0});
    // 通道 RPC 总增量 = 2 批（InitTable/Upload 没有被重复发）
    EXPECT_EQ(pair.channel(0).rpc_count() - init_rpc0, uint64_t{2});
    EXPECT_EQ(pair.channel(1).rpc_count() - init_rpc1, uint64_t{2});
    // 服务器侧：同样只多了 2 次 RPC，但受理了 4 个查询集
    // ⚠️ 口径（`MPA-08` 裁决 1，2026-09-10）：`InProcessMpraqNode::rpc_count()` =
    //    **服务侧**受理的数据 RPC 次数（每 RPC +1，与一次 RPC 里装了 k 个查询集无关）；
    //    查询集个数走 `queries_served()`。两个轴分开数。
    EXPECT_EQ(pair.node(0).rpc_count() - init_node0, uint64_t{2});
    EXPECT_EQ(pair.node(1).rpc_count() - init_node1, uint64_t{2});
    EXPECT_EQ(pair.node(0).queries_served(), uint64_t{4});
    EXPECT_EQ(pair.node(1).queries_served(), uint64_t{4});
    // **服务侧批量入口**：每 RPC 恰好一次 ⇒ 2 次 RPC = 2 次批量调用（不再是 0）
    EXPECT_EQ(pair.node(0).batch_rpc_count(), uint64_t{2});
    EXPECT_EQ(pair.node(1).batch_rpc_count(), uint64_t{2});
    // node 层：批量入口被调 2 次、**标量**入口一次都没被服务侧调过（恒 0）
    EXPECT_EQ(pair.node(0).node().batch_rpc_count(), uint64_t{2});
    EXPECT_EQ(pair.node(1).node().batch_rpc_count(), uint64_t{2});
    EXPECT_EQ(pair.node(0).node().rpc_count(), uint64_t{0});
    EXPECT_EQ(pair.node(1).node().rpc_count(), uint64_t{0});
    // node 层的查询集/读取量口径不变（D31）
    EXPECT_EQ(pair.node(0).node().queries_served(), uint64_t{4});
    EXPECT_EQ(pair.node(0).node().words_read(), uint64_t{4} * c->plinko_params().block_count());

    // 取回的位与明文一致（真实链路上的多 word 列）
    EXPECT_EQ(BitString(BitsFromWords(w0, kN)), BitString(c->PlainColumnBits(0, 1)));
    EXPECT_EQ(BitString(BitsFromWords(w1, kN)), BitString(c->PlainColumnBits(1, 0)));
}

// ===========================================================================
// 5. 错误路径：客户端必须收到异常，绝不崩溃、绝不静默错值
// ===========================================================================

TEST(MpraqGrpc, ServerRespWithoutInitTableIsRejected) {
    SingleNode single;
    ASSERT_TRUE(single.started());
    ASSERT_TRUE(single.wait_for_connection(5000));

    // 一个"格式合法"的查询（offets/groups 长度正确、分组比特 0/1）
    PlinkoQuery q;
    q.blocks = 4;
    q.block_size = 1;
    q.offsets.assign(4, 0);
    q.groups.assign(4, 0);
    EXPECT_TRUE(q.well_formed());
    EXPECT_THROW(single.channel().ServerResp(q), std::runtime_error);
    // 被拒绝的请求不计入服务器的成功计数
    EXPECT_EQ(single.node().rpc_count(), uint64_t{0});
}

TEST(MpraqGrpc, UploadOutOfRangeIsRejected) {
    GrpcPair pair;
    ASSERT_TRUE(pair.started());
    ASSERT_TRUE(pair.wait_for_connection(5000));
    auto c = MpraqClient::InitWithChannels(MakeSchema(128), MakeRecords(128), FastParams(),
                                           pair.channel(0), pair.channel(1));

    const uint64_t n = c->store_params().entry_count();
    // 记下"被拒绝的上传之前"的共享值，事后要求它**逐位不变**
    // （否则一次被拒的越界写会静默污染后续 PIR）
    const uint128_t before0 = pair.node(0).node().FeatureWord(0);
    const uint128_t before_last = pair.node(0).node().FeatureWord(n - 1);
    // ① 越界上传：base_index + count > n
    EXPECT_THROW(pair.channel(0).UploadFeatureWords(n, {uint128_t{1}}, 1),
                 std::runtime_error);
    EXPECT_THROW(pair.channel(0).UploadFeatureWords(n + 4096, {uint128_t{1}}, 1),
                 std::runtime_error);
    // ② 分块长度自相矛盾：count != words.size()（发请求**之前**就该被拒绝）
    EXPECT_THROW(pair.channel(0).UploadFeatureWords(0, {uint128_t{1}, uint128_t{2}}, 1),
                 std::invalid_argument);
    EXPECT_EQ(pair.node(0).node().FeatureWord(0), before0);
    EXPECT_EQ(pair.node(0).node().FeatureWord(n - 1), before_last);
    // 服务器侧 RPC 计数 = 通道侧发出的非 PIR RPC，其中**2 次越界上传**（base_index = n
    // 与 n+4096）已经发出去了但被服务器拒绝 ⇒ 服务器不计入成功计数；第 3 次
    // （count != words.size()）在**客户端**就被拦下，两边都不计。
    // ⚠️ 曾经写成 `channel.rpc_count() - channel.server_resp_calls()`：D28 之后批量
    //    PIR 走 `server_resp_batch_calls()`，只减标量会让这条恒等式失真（且本用例
    //    根本没发 PIR 查询，这里顺带把"没发"也断言掉）。
    EXPECT_EQ(pair.channel(0).server_resp_calls(), uint64_t{0});
    EXPECT_EQ(pair.channel(0).server_resp_batch_calls(), uint64_t{0});
    EXPECT_EQ(pair.node(0).rpc_count(), pair.channel(0).rpc_count() - 2);

    // ③ 属性共享：长度必须恰好等于 N
    EXPECT_THROW(pair.channel(0).SetAttributeShares(0, std::vector<ModShare>(127)),
                 std::runtime_error);
    // ④ 属性号越界
    EXPECT_THROW(pair.channel(0).SetAttributeShares(9, std::vector<ModShare>(128)),
                 std::runtime_error);
}

TEST(MpraqGrpc, ServerRespGeometryMismatchIsRejected) {
    GrpcPair pair;
    ASSERT_TRUE(pair.started());
    ASSERT_TRUE(pair.wait_for_connection(5000));
    auto c = MpraqClient::InitWithChannels(MakeSchema(128), MakeRecords(128), FastParams(),
                                           pair.channel(0), pair.channel(1));
    const PlinkoParams& p = c->plinko_params();

    // ① 合法几何 ⇒ 正常应答（先确认"拒绝"不是因为别的原因）
    PlinkoQuery good;
    good.blocks = p.block_count();
    good.block_size = p.w;
    good.offsets.assign(static_cast<size_t>(p.block_count()), 0);
    good.groups.assign(static_cast<size_t>(p.block_count()), 0);
    EXPECT_NO_THROW(pair.channel(0).ServerResp(good));

    // ② 把"每区块 word 数"（block_size）写错 —— D24④ 的静默错 128 倍陷阱
    PlinkoQuery bad_w = good;
    bad_w.block_size = p.w * 128;
    EXPECT_THROW(pair.channel(0).ServerResp(bad_w), std::runtime_error);

    // ③ 把区块数 c 写错
    PlinkoQuery bad_c = good;
    bad_c.blocks = p.block_count() + 1;
    bad_c.offsets.push_back(0);
    bad_c.groups.push_back(0);
    EXPECT_TRUE(bad_c.well_formed());  // 自洽但**与数据库不符**
    EXPECT_THROW(pair.channel(0).ServerResp(bad_c), std::runtime_error);

    // ④ offsets 长度与 c 不一致
    PlinkoQuery bad_len = good;
    bad_len.offsets.pop_back();
    EXPECT_THROW(pair.channel(0).ServerResp(bad_len), std::runtime_error);

    // ⑤ 分组比特不是 0/1
    PlinkoQuery bad_group = good;
    bad_group.groups[0] = 2;
    EXPECT_THROW(pair.channel(0).ServerResp(bad_group), std::runtime_error);

    // ⑥ 偏移 ≥ w
    PlinkoQuery bad_off = good;
    bad_off.offsets[0] = p.w;
    EXPECT_THROW(pair.channel(0).ServerResp(bad_off), std::runtime_error);
}

// ===========================================================================
// 6. 通用 relay 上的 SecureMul（MPA-05 的四条腿走真实 gRPC）
// ===========================================================================

TEST(MpraqGrpc, SecureMulOverGrpcRelayMatchesAlgebra) {
    TransportPair pair;
    ASSERT_TRUE(pair.started());
    pair.wait_for_connection();

    SecureMulOverGrpc flow;
    random::DeterministicPrng prng(MakeAesSeed({'m', 'p', 'a', '0', '5', 'g'}), 0);
    flow.Install(pair.net(), /*record_index=*/3, /*e=*/5, prng);

    const uint128_t f = 1;

    const auto t_flow = Clock::now();
    // 第 1 轮：两台服务器各一条 Relay（Phase1Request → Phase1Response）
    const SecureMulPhase1Out p1 =
        ClientRunPhase1(/*session=*/1001, flow.challenge, f, flow.material.client_triple,
                        pair.client(), kSecureMulModulus);
    // 第 2 轮：两台服务器各一条 Relay（Phase2Request → Phase2Response）
    const auto p2 = ClientRunPhase2(1001, p1, pair.client(), kSecureMulModulus);
    const double flow_ms = MsSince(t_flow);

    const SecureMulFlowResult r = VerifyAndReconstruct(
        1001, p2, flow.client, &flow.bundle.ctx, f, p1.e_sent,
        &flow.material.client_triple, p1.e_check_sent0, p1.e_check_sent1);

    std::printf("[mpraq_grpc] SecureMul 一条记录走 gRPC：2 往返 = %.1f ms"
                "（Relay 次数 %llu / %llu）\n",
                flow_ms,
                static_cast<unsigned long long>(pair.relay_count(0)),
                static_cast<unsigned long long>(pair.relay_count(1)));

    EXPECT_TRUE(r.ok);
    EXPECT_EQ(static_cast<int>(r.failure), static_cast<int>(SecureMulFailure::kNone));
    // z = f·E、mac = α·z（与 `test_mpraq_securemul.cpp` 的本地结论同一口径）
    EXPECT_EQ(r.z, mulMod(f, flow.e_value, kSecureMulModulus));
    EXPECT_EQ(r.mac, mulMod(flow.client.alpha(), r.z, kSecureMulModulus));
    EXPECT_EQ(r.mac, r.expected_mac);
    EXPECT_TRUE(VerifyMac(r.z, r.mac, flow.client.alpha(), kSecureMulModulus));

    // 每条腿走**一台**服务器：一次 SecureMul = 2 条消息/台（零服务器间通信）
    EXPECT_EQ(pair.relay_count(0), uint64_t{2});
    EXPECT_EQ(pair.relay_count(1), uint64_t{2});
    EXPECT_EQ(pair.client().RequestCount(0), uint64_t{2});
    EXPECT_EQ(pair.client().RequestCount(1), uint64_t{2});
    EXPECT_EQ(pair.error_count(0), uint64_t{0});
    EXPECT_EQ(pair.error_count(1), uint64_t{0});
    // 两台服务器的一次性语义都用掉了（state consumed）
    EXPECT_TRUE(flow.s0.consumed());
    EXPECT_TRUE(flow.s1.consumed());
}

TEST(MpraqGrpc, TamperedRelayByteIsRejected) {
    TransportPair pair;
    ASSERT_TRUE(pair.started());
    pair.wait_for_connection();

    SecureMulOverGrpc flow;
    random::DeterministicPrng prng(MakeAesSeed({'t', 'a', 'm', 'p', 'e', 'r'}), 0);
    flow.Install(pair.net(), /*record_index=*/4, /*e=*/9, prng);

    // 篡改**服务器 0** 第 1 轮应答里 `e_computed` 的最低字节
    // （wire 偏移 10；其它历史应答 `Phase2Response` 的同一偏移是 z_share 的低字节，
    //  因此必须只对第 1 条应答动手 —— 用第 1 轮的 PendingCount 做闸门）。
    pair.client().set_tamper_hook([&pair](int server_id, Payload& resp) {
        if (server_id != 0) return;
        if (resp.size() != 27) return;  // 只改 27 字节的 Phase1Response（v3 布局）
        if (resp.size() <= kPhase1ResponseEByte) return;
        resp[kPhase1ResponseEByte] ^= 0x01;
    });

    const uint128_t f = 1;
    // 第 1 轮照常完成（线格式没有完整性保护 ⇒ 解码层放过，见 MPA-05 §4.5 末段）
    const SecureMulPhase1Out p1 =
        ClientRunPhase1(1002, flow.challenge, f, flow.material.client_triple,
                        pair.client(), kSecureMulModulus);
    const auto p2 = ClientRunPhase2(1002, p1, pair.client(), kSecureMulModulus);
    pair.client().clear_tamper_hook();

    const SecureMulFlowResult r = VerifyAndReconstruct(
        1002, p2, flow.client, &flow.bundle.ctx, f, p1.e_sent,
        &flow.material.client_triple, p1.e_check_sent0, p1.e_check_sent1);

    // ⚠️ 按 MPA-05 的现有语义：被篡改的那台在第 2 轮做 `e_check` 一致性检查时
    //    **拒绝继续**（status ≠ kOk，z/mac 保持 0），客户端**结构化地**报告
    //    `kServerReported` 且 `ok == false` —— 错值绝不被采信。
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(static_cast<int>(r.failure),
              static_cast<int>(SecureMulFailure::kServerReported));
    EXPECT_NE(r.z, mulMod(f, flow.e_value, kSecureMulModulus));
    EXPECT_FALSE(r.error.empty());
    // 两台都收到了 2 条消息，且只有一台报错（诚实的那台照常工作）
    EXPECT_EQ(pair.relay_count(0), uint64_t{2});
    EXPECT_EQ(pair.relay_count(1), uint64_t{2});
}

// ===========================================================================
// 7. 并发安全：并行起两份"两节点 + 两条通道"，临时端口互不干扰
//     （§3.4 的固定端口坑的**回归测试**）
// ===========================================================================

TEST(MpraqGrpc, ConcurrentNodePairsDoNotCollide) {
    constexpr size_t kN = 128;
    std::mutex mu;
    std::vector<std::string> failures;
    auto worker = [&](int id) {
        try {
            GrpcPair pair;
            if (!pair.started()) {
                throw std::runtime_error("节点未启动（端口冲突？）");
            }
            if (!pair.wait_for_connection(5000)) {
                throw std::runtime_error("通道未能连接");
            }
            auto c = MpraqClient::InitWithChannels(MakeSchema(kN), MakeRecords(kN),
                                                   FastParams(/*seed=*/100 + id),
                                                   pair.channel(0), pair.channel(1));
            uint64_t rpcs = 0;
            for (uint32_t attr = 0; attr < kAttrCount; ++attr) {
                for (uint32_t col = 0; col < kAttrColumns[attr]; ++col) {
                    auto batch = c->CreateColumnQuery(attr, col);
                    const std::vector<uint128_t> words = c->RunBatch(batch);
                    if (words.size() != 1) {
                        throw std::runtime_error("重建的 word 数不对");
                    }
                    const std::vector<uint8_t> want = c->PlainColumnBits(attr, col);
                    if (BitString(BitsFromWords(words, kN)) != BitString(want)) {
                        throw std::runtime_error("并发路径上重建结果与明文不一致");
                    }
                    ++rpcs;
                }
            }
            // ⚠️ 每次 `RunBatch`（哪怕批里只有 1 个查询集）都走 `ServerRespBatch` ⇒
            //    计入 `server_resp_batch_calls()`；标量计数必须保持 0（口径由入口决定）。
            if (pair.channel(0).server_resp_batch_calls() != rpcs ||
                pair.channel(1).server_resp_batch_calls() != rpcs) {
                throw std::runtime_error("并发路径上的 ServerRespBatch 次数不对");
            }
            if (pair.channel(0).server_resp_calls() != 0 ||
                pair.channel(1).server_resp_calls() != 0) {
                throw std::runtime_error("并发批量路径上出现了标量 ServerResp 调用");
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(mu);
            failures.push_back("worker " + std::to_string(id) + ": " + e.what());
        }
    };

    const auto t_conc = Clock::now();
    std::thread a(worker, 0);
    std::thread b(worker, 1);
    a.join();
    b.join();
    std::printf("[mpraq_grpc] 并发两份两节点用例：%.1f ms\n", MsSince(t_conc));

    for (const std::string& msg : failures) {
        TSB_FAIL_(msg);
    }
    EXPECT_EQ(failures.size(), size_t{0});
}

// ===========================================================================
// 8. `MPA-08` 裁决 1：**一次 RPC 恰好一次批量入口调用**（服务侧可断言），
//    且批量入口与逐条标量路径的应答**逐位相同**（k = 1 与 k = 4 各一次）
// ===========================================================================

TEST(MpraqGrpc, OneRpcIsExactlyOneBatchCallOnServerSide) {
    // N = 256 ⇒ ⌈N/128⌉ = 2（一个整列 = 2 个 word）；λ = 12 ⇒ 备份 hint 足够
    constexpr size_t kN = 256;
    GrpcPair pair;
    ASSERT_TRUE(pair.started());
    ASSERT_TRUE(pair.wait_for_connection(5000));

    auto c = MpraqClient::InitWithChannels(MakeSchema(kN), MakeRecords(kN),
                                           FastParams(/*seed=*/11, /*lambda=*/12),
                                           pair.channel(0), pair.channel(1));
    ASSERT_EQ(c->store_params().words_per_column, size_t{2});

    // Init 阶段的基线（Init 的 4 类 RPC 不计入批量入口）
    const uint64_t s_rpc0 = pair.node(0).rpc_count();
    const uint64_t s_batch0 = pair.node(0).batch_rpc_count();
    const uint64_t s_queries0 = pair.node(0).queries_served();
    EXPECT_EQ(s_batch0, uint64_t{0});  // Init 不发查询 ⇒ 批量入口一次都没调

    // ---- 造 k 个**合法**查询集（k = 1 与 k = 4），每个都来自真实的 QueryGen；
    //      只取查询集本身（`PlinkoQuery`），不走 `RunBatch`（本用例只看链路口径）。
    std::vector<PlinkoQuery> qs;
    {
        auto batch = c->CreateQueries({ColumnWord{0, 0, 0}, ColumnWord{0, 0, 1},
                                       ColumnWord{1, 0, 0}, ColumnWord{1, 1, 0}});
        ASSERT_EQ(batch.size(), size_t{4});
        qs.reserve(batch.size());
        for (size_t i = 0; i < batch.size(); ++i) {
            qs.push_back(batch.at(i).query());  // 拷贝：查询集 = 服务器可见的全部信息
        }
    }

    // ---- ① k = 1：一次 `ServerRespBatch` 调用 = 1 次 RPC = 服务侧 1 次批量入口 ----
    {
        std::vector<PlinkoQuery> one{qs[0]};
        const uint64_t rpc_before0 = pair.channel(0).rpc_count();
        const std::vector<PlinkoAnswer> answers = pair.channel(0).ServerRespBatch(one);
        ASSERT_EQ(answers.size(), size_t{1});
        EXPECT_EQ(pair.channel(0).rpc_count() - rpc_before0, uint64_t{1});
        EXPECT_EQ(pair.node(0).rpc_count() - s_rpc0, uint64_t{1});
        EXPECT_EQ(pair.node(0).batch_rpc_count() - s_batch0, uint64_t{1});   // ★ 关键
        EXPECT_EQ(pair.node(0).node().batch_rpc_count(), uint64_t{1});       // ★ node 层
        EXPECT_EQ(pair.node(0).node().rpc_count(), uint64_t{0});             // 标量恒 0
        EXPECT_EQ(pair.node(0).queries_served() - s_queries0, uint64_t{1});
    }

    // ---- ② k = 4：仍然是**一次** RPC、**一次**批量调用（不是 4 次）----
    const uint64_t rpc_before = pair.channel(0).rpc_count();
    const uint64_t s_rpc_before = pair.node(0).rpc_count();
    const uint64_t s_batch_before = pair.node(0).batch_rpc_count();
    const uint64_t s_queries_before = pair.node(0).queries_served();
    const uint64_t words_before = pair.node(0).node().words_read();
    const std::vector<PlinkoAnswer> batch4 = pair.channel(0).ServerRespBatch(qs);
    ASSERT_EQ(batch4.size(), size_t{4});
    EXPECT_EQ(pair.channel(0).rpc_count() - rpc_before, uint64_t{1});       // 1 次 RPC
    EXPECT_EQ(pair.node(0).rpc_count() - s_rpc_before, uint64_t{1});
    EXPECT_EQ(pair.node(0).batch_rpc_count() - s_batch_before, uint64_t{1}); // ★ 1 次批量
    // 查询集个数与读取量的口径不变（D31：k 个查询集、每查询集读 c 个区块）
    EXPECT_EQ(pair.node(0).queries_served() - s_queries_before, uint64_t{4});
    EXPECT_EQ(pair.node(0).node().words_read() - words_before,
              uint64_t{4} * c->plinko_params().block_count());
    // 服务侧两个计数器同步增长 ⇒ "每 RPC +1"（不变量的直接形式）。
    // ⚠️ `rpc_count()` 里还含 Init 的 4 次 RPC（InitTable/上传/属性共享）⇒
    //    不变量必须写成**增量**形式（`s_rpc0` = Init 之后的基线）：
    //        批量入口次数 − 0 == 数据 RPC 次数 − Init 的 RPC 次数
    EXPECT_EQ(pair.node(0).batch_rpc_count() - s_batch0,
              pair.node(0).rpc_count() - s_rpc0);
    EXPECT_EQ(pair.node(0).batch_rpc_count() - s_batch0, uint64_t{2});  // k=1 那次 + k=4 那次

    // ---- ③ 与**逐条标量**路径逐位对照（同一批查询集，4 次独立 RPC）----
    for (size_t i = 0; i < qs.size(); ++i) {
        const PlinkoAnswer scalar = pair.channel(0).ServerResp(qs[i]);
        EXPECT_EQ(scalar.r0, batch4[i].r0);
        EXPECT_EQ(scalar.r1, batch4[i].r1);
    }
    // 标量路径确实被**客户端**用到了（4 次标量 RPC），但服务侧走的仍是批量入口
    // ⇒ gRPC 部署下 node 层标量计数恒 0 是**正确的**（它数的是"标量接口被直接调用"）。
    EXPECT_EQ(pair.channel(0).server_resp_calls(), uint64_t{4});

    std::printf("[mpraq_grpc] 裁决 1（服务侧**增量**）：k=1 ⇒ 批量入口=1、数据 RPC=1；"
                "k=4 ⇒ 批量入口=1、数据 RPC=1（**一次 RPC 恒一次批量调用**，不是 k 次）；"
                "node 层标量=%llu（gRPC 部署下恒 0）\n",
                static_cast<unsigned long long>(pair.node(0).node().rpc_count()));
}

// ===========================================================================
// 9. `MPA-08` 裁决 2：`ServerRespBatch` 是纯虚 —— 占位通道必须**大声抛异常**
//    （编译期证据是同文件顶部的 `static_assert`）
// ===========================================================================

TEST(MpraqGrpc, ServerRespBatchIsPureVirtualAndPlaceholderRefusesToDegrade) {
    // ① 占位远程通道：`ServerRespBatch` 抛 `RemoteMpraqChannelNotImplemented`
    //    （**绝不**静默逐条退化，也绝不偷偷成本地调用）
    PlaceholderRemoteMpraqChannel placeholder("127.0.0.1:1");
    PlinkoQuery q;
    q.blocks = 2;
    q.block_size = 1;
    q.offsets = {0, 0};
    q.groups = {0, 1};
    EXPECT_THROW(placeholder.ServerRespBatch({q, q}), RemoteMpraqChannelNotImplemented);
    EXPECT_THROW(placeholder.ServerRespBatch({q}), RemoteMpraqChannelNotImplemented);
    // 其它方法同一纪律（回归：别让某个方法变成"能用的假实现"）
    EXPECT_THROW(placeholder.Connect(), RemoteMpraqChannelNotImplemented);
    EXPECT_THROW(placeholder.ServerResp(q), RemoteMpraqChannelNotImplemented);
    // 错误信息必须说明"远程通道必须覆写 ServerRespBatch"这一类可执行的指引
    std::string what;
    try {
        placeholder.ServerRespBatch({q});
    } catch (const std::exception& e) {
        what = e.what();
    }
    EXPECT_TRUE(what.find("ServerRespBatch") != std::string::npos);
    EXPECT_TRUE(what.find("PlaceholderRemoteMpraqChannel") != std::string::npos);

    // ② 编译期证据（运行期再确认一次，便于在测试输出里看到这条性质）
    EXPECT_TRUE(std::is_abstract<ChannelWithoutBatch>::value);
    EXPECT_FALSE(std::is_abstract<LocalMpraqChannel>::value);      // 实现方都不是抽象
    EXPECT_FALSE(std::is_abstract<GrpcMpraqChannel>::value);
    EXPECT_FALSE(std::is_abstract<PlaceholderRemoteMpraqChannel>::value);
}

// ===========================================================================
// 10. `MPA-08` 裁决 1 的边界：**空批**必须被拒绝（绝不"静默成功、0 条应答"）
// ===========================================================================

TEST(MpraqGrpc, EmptyBatchRequestIsRejectedNotSilentlyAccepted) {
    constexpr size_t kN = 128;
    GrpcPair pair;
    ASSERT_TRUE(pair.started());
    ASSERT_TRUE(pair.wait_for_connection(5000));
    auto c = MpraqClient::InitWithChannels(MakeSchema(kN), MakeRecords(kN), FastParams(),
                                           pair.channel(0), pair.channel(1));
    (void)c;

    // 绕过客户端侧的"空批拒绝"，直接用 proto stub 发一个 `queries` 为空的请求
    // （合法客户端构造不出它 —— `GrpcMpraqChannel::ServerRespBatch` 在本地就拦了）
    auto stub = ::mpraqwire::MpraqService::NewStub(grpc::CreateChannel(
        pair.node(0).local_address(), grpc::InsecureChannelCredentials()));
    ::mpraqwire::PirQueryRequest req;
    req.set_blocks(c->plinko_params().block_count());
    req.set_block_size(c->plinko_params().w);
    // queries 故意留空
    ::mpraqwire::PirQueryResponse resp;
    grpc::ClientContext ctx;
    const uint64_t rpc_before = pair.node(0).rpc_count();
    const uint64_t queries_before = pair.node(0).queries_served();
    const grpc::Status st = stub->ServerResp(&ctx, req, &resp);
    EXPECT_FALSE(st.ok());  // 非 OK 的 gRPC status（协议违例绝不当成成功）
    // ⚠️ 可读原因在 **status message** 里，而**不是** `resp.error()`：
    //    gRPC 在非 OK 状态下**不发送**响应消息体（C++ 实现的行为）⇒ 服务侧写的
    //    `resp.error()` 到不了客户端。这一点 `net/grpc_mpraq.hpp` 的旧注释表述不准
    //    （已在该处补注）；本用例钉住"原因必须能从 status message 读到"。
    EXPECT_FALSE(st.error_message().empty());
    EXPECT_TRUE(st.error_message().find("queries") != std::string::npos);
    EXPECT_EQ(resp.answers_size(), 0);
    EXPECT_TRUE(resp.error().empty());  // 非 OK ⇒ 响应体不达 ⇒ 这里必然为空
    // 被拒绝的请求不计入任何计数（与既有纪律一致）
    EXPECT_EQ(pair.node(0).rpc_count(), rpc_before);
    EXPECT_EQ(pair.node(0).queries_served(), queries_before);
    EXPECT_EQ(pair.node(0).node().batch_rpc_count(), uint64_t{0});
    EXPECT_EQ(pair.node(0).node().rpc_count(), uint64_t{0});

    std::printf("[mpraq_grpc] 空批被拒绝：status 非 OK、status message=\"%s\"\n",
                st.error_message().c_str());
}
