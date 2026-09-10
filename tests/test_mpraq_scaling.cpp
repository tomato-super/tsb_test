// `MPA-09` 参数与复杂度验证的**确定性测试**（铁律 D6：只用结构/账目/公式类不变量，
// **不含任何计时断言** —— 计时类数字由 `bench/bench_mpraq.cpp` 产出，本文件不碰）。
//
// ===========================================================================
// 0. 这个文件断言什么（每条都有**确定性期望值**，不是"跑通即通过"）
// ===========================================================================
//   ① 查询集数 = **列数 × ⌈N/128⌉**（多个 N，含**非 128 倍数**与边界 N=130）；
//   ② 每台服务器 RPC 次数 = **查询（Count）次数**（一次 `RunBatch` 恒 1 次；标量恒 0），
//      并核对服务器侧 `words_read = 查询集数 × c`（D31 的两个正交口径）；
//   ③ `Sum` 的 `rounds == 2` / `messages == 2N` / `wire == 4N` / 帧长 `6+34N`、`6+58N`
//      （进程内 `LocalTransport` 口径，`install_*` 必须为 0）；
//   ④ **两进程口径**（真实 gRPC、两台服务器服务实例）的 `install_bytes == 2×(13+152N)`、
//      `install_rounds == 2`、`install_frames == 2`（**D34**），且 `install_*` **不并入**
//      `wire_messages`（仍恒 4N）；
//   ⑤ 服务器存储 = §1 公式（**双报**含/不含补齐）+ `MpraqNode::StorageBytes()` 与公式一致；
//   ⑥ **L14 预算**：给定参数的 word 查询总数 ≤ `min(q, n)`；并用**超预算的参数**构造反例，
//      驱动 `bench_mpraq` 断言它**拒绝运行**（退出码 3 + 可读原因），
//      **不**跑到一半抛 `PlinkoBackupsExhausted`；
//   ⑦ 备份 hint 用尽 ⇒ `PlinkoBackupsExhausted`（D8：本项目不做摊销式离线，用尽必须**显式**报错）；
//   ⑧ `bench_mpraq --json` 的输出**可解析**（极简解析器）且字段齐全、内部自洽。
//
// ⚠️ 口径（每个数字都要能回答"这是进程内还是两进程？区块访问还是 word 查询还是 RPC？"）：
//    * 进程内 = `LocalTransport` + 进程内 `MpraqNode`（用例 ①②③⑤⑦）；
//    * 两进程 = 真实 gRPC、两台 `grpc::Server` + `MpraqDemoService`（用例 ④，链路与
//      `src/apps/mpraq_server.cpp` 逐字相同，只差内存隔离）；
//    * `queries_issued` = **word 查询数** = 查询集数（**不是** RPC 次数，也不是区块访问量）；
//    * 区块访问量 = `queries_issued × c`（`c = n/w`）—— 论文 `Õ(n/r)` 的实数化口径，
//      **不把 `c` 与 `n/r` 等同**（Q9 报告 D6）。

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

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

using namespace tsb;
using namespace tsb::mpraq;

namespace {

std::string Num(uint64_t v) { return std::to_string(v); }

// ---------------------------------------------------------------------------
// 数据集 / schema（显式公式 ⇒ 期望值可独立手算）
//   属性 0：R = [0,5]、m = 6、domain = [0,4]；取值 = i % 5
//   属性 1：R = [0,3]、m = 4、domain = [0,2]；取值 = (i / 2) % 3   ← Sum/Avg 的属性
// ---------------------------------------------------------------------------
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

Predicate Range(uint32_t attr, int64_t lo, int64_t hi) {
    Predicate p;
    p.by_id = true;
    p.attribute_id = attr;
    p.op = mpraq::PredicateOp::kRange;
    p.lower = lo;
    p.upper = hi;
    return p;
}

Predicate P(uint32_t attr, mpraq::PredicateOp op, int64_t v) {
    Predicate p;
    p.by_id = true;
    p.attribute_id = attr;
    p.op = op;
    p.value = v;
    return p;
}

const std::vector<mpraq_baseline::Pred> kRangePreds = {
    mpraq_baseline::Pred{0, mpraq_baseline::Op::kRange, 0, 1, 4}};
const std::vector<mpraq_baseline::Pred> kConjPreds = {
    mpraq_baseline::Pred{0, mpraq_baseline::Op::kRange, 0, 2, 5},
    mpraq_baseline::Pred{1, mpraq_baseline::Op::kGe, 1, 0, 0}};

struct Fixture {
    size_t N = 0;
    Schema schema;
    std::vector<MpraqRecord> records;
    mpraq_baseline::Dataset baseline;
    std::unique_ptr<MpraqClient> client;
};

// λ 用小值（测试惯例：正确性不依赖 λ，只有失败概率依赖；见 D22-1②）
constexpr uint32_t kTestLambda = 16;
constexpr double kTestEps = 1e-4;

std::unique_ptr<Fixture> MakeFixture(size_t n, uint32_t lambda = kTestLambda,
                                     double eps = kTestEps, uint64_t w = 0) {
    auto f = std::make_unique<Fixture>();
    f->N = n;
    f->schema = MakeSchema(n);
    f->records = MakeRecords(n);
    f->baseline = MakeBaseline(f->records);
    MpraqInitParams p;
    p.lambda = lambda;
    p.prp_epsilon = eps;
    p.seed = 7;
    p.has_explicit_w = (w != 0);
    p.w = w;
    f->client = MpraqClient::Init(f->schema, f->records, p);
    return f;
}

// ---------------------------------------------------------------------------
// 两台**真实的** gRPC 服务器（临时端口；各自独立的节点与服务实例）—— 链路与
// `src/apps/mpraq_server.cpp` 逐字相同（`MpraqDemoService` = 4 条数据 RPC + Relay）
// ---------------------------------------------------------------------------
class TwoServers {
public:
    TwoServers() : node0_(), node1_(), service0_(node0_), service1_(node1_) {
        start(node0_, service0_, &server0_, &port0_);
        start(node1_, service1_, &server1_, &port1_);
    }

    bool started() const { return server0_ != nullptr && server1_ != nullptr; }
    std::string address(int i) const {
        return "127.0.0.1:" + (i == 0 ? port0_ : port1_);
    }
    MpraqDemoService& service(int i) { return i == 0 ? service0_ : service1_; }
    ServerStats stats(int i) const { return i == 0 ? service0_.Stats() : service1_.Stats(); }

private:
    static void start(MpraqNode& node, MpraqDemoService& service,
                      std::unique_ptr<grpc::Server>* out, std::string* port) {
        (void)node;
        grpc::ServerBuilder builder;
        int bound = 0;
        builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &bound);
        builder.RegisterService(&service);
        builder.SetMaxReceiveMessageSize(256 * 1024 * 1024);
        builder.SetMaxSendMessageSize(256 * 1024 * 1024);
        std::unique_ptr<grpc::Server> s = builder.BuildAndStart();
        if (!s || bound == 0) {
            throw std::runtime_error("MPA-09 夹具：无法在临时端口上起 gRPC 服务器");
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

// 两进程口径的装置（服务器在**另一个服务实例**里，走真实 gRPC）
struct RemoteFixture {
    TwoServers servers;
    std::unique_ptr<GrpcMpraqChannel> ch0, ch1;
    std::unique_ptr<GrpcTransportClient> transport;
    std::unique_ptr<RemoteSecureMulBatchEndpoint> ep0, ep1;
    Schema schema;
    std::vector<MpraqRecord> records;
    std::unique_ptr<MpraqClient> client;

    explicit RemoteFixture(size_t n, uint32_t lambda = kTestLambda) {
        if (!servers.started()) throw std::runtime_error("RemoteFixture: 服务器未启动");
        ch0 = std::make_unique<GrpcMpraqChannel>(servers.address(0));
        ch1 = std::make_unique<GrpcMpraqChannel>(servers.address(1));
        ch0->Connect();
        ch1->Connect();
        transport = std::make_unique<GrpcTransportClient>(
            std::vector<std::string>{servers.address(0), servers.address(1)});
        transport->Connect(10000);
        schema = MakeSchema(n);
        records = MakeRecords(n);
        MpraqInitParams p;
        p.lambda = lambda;
        p.prp_epsilon = kTestEps;
        p.seed = 7;
        client = MpraqClient::InitWithChannels(schema, records, p, *ch0, *ch1);
        ep0 = std::make_unique<RemoteSecureMulBatchEndpoint>(*transport, kServer0);
        ep1 = std::make_unique<RemoteSecureMulBatchEndpoint>(*transport, kServer1);
    }
    size_t words_per_column() const {
        return client->store_params().words_per_column;
    }
    uint64_t blocks() const { return client->plinko_params().block_count(); }
};

// ---------------------------------------------------------------------------
// 极简 JSON 读取器（`--json` 的输出自检；**不是**通用解析器，够用即可）
// ---------------------------------------------------------------------------
std::string TopLevelObject(const std::string& doc, const std::string& key) {
    const std::string pat = "\"" + key + "\":";
    const size_t at = doc.find(pat);
    if (at == std::string::npos) return {};
    size_t i = at + pat.size();
    if (i >= doc.size() || doc[i] != '{') return {};
    int depth = 0;
    bool in_str = false;
    for (size_t j = i; j < doc.size(); ++j) {
        const char c = doc[j];
        if (in_str) {
            if (c == '\\') {
                ++j;
            } else if (c == '"') {
                in_str = false;
            }
            continue;
        }
        if (c == '"') {
            in_str = true;
        } else if (c == '{') {
            ++depth;
        } else if (c == '}') {
            if (--depth == 0) return doc.substr(i, j - i + 1);
        }
    }
    return {};
}

// 在给定对象文本里找 `"key":` 的**值**（原样文本：数字/字符串/对象）
std::string FindValue(const std::string& obj, const std::string& key) {
    const std::string pat = "\"" + key + "\":";
    const size_t at = obj.find(pat);
    if (at == std::string::npos) return {};
    size_t i = at + pat.size();
    if (i >= obj.size()) return {};
    if (obj[i] == '{') {
        // 嵌套对象：配平
        int depth = 0;
        bool in_str = false;
        for (size_t j = i; j < obj.size(); ++j) {
            const char c = obj[j];
            if (in_str) {
                if (c == '\\') {
                    ++j;
                } else if (c == '"') {
                    in_str = false;
                }
                continue;
            }
            if (c == '"') {
                in_str = true;
            } else if (c == '{') {
                ++depth;
            } else if (c == '}') {
                if (--depth == 0) return obj.substr(i, j - i + 1);
            }
        }
        return {};
    }
    if (obj[i] == '"') {
        size_t j = i + 1;
        while (j < obj.size() && obj[j] != '"') {
            if (obj[j] == '\\') ++j;
            ++j;
        }
        return obj.substr(i, j - i + 1);
    }
    size_t j = i;
    while (j < obj.size() && obj[j] != ',' && obj[j] != '}') ++j;
    return obj.substr(i, j - i);
}

bool HasKey(const std::string& obj, const std::string& key) {
    return !FindValue(obj, key).empty();
}

uint64_t ValueU64(const std::string& obj, const std::string& key) {
    const std::string v = FindValue(obj, key);
    if (v.empty()) throw std::runtime_error("JSON 缺少字段: " + key);
    return std::stoull(v);
}

std::string ValueStr(const std::string& obj, const std::string& key) {
    const std::string v = FindValue(obj, key);
    if (v.size() < 2 || v.front() != '"') {
        throw std::runtime_error("JSON 字段不是字符串: " + key);
    }
    return v.substr(1, v.size() - 2);
}

// 花括号/方括号/引号配平（`--json` 每行一条 JSON，用它校验"整行是一个完整对象"）
bool Balanced(const std::string& s) {
    int depth = 0;
    bool in_str = false;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (in_str) {
            if (c == '\\') {
                ++i;
            } else if (c == '"') {
                in_str = false;
            }
            continue;
        }
        if (c == '"') {
            in_str = true;
        } else if (c == '{' || c == '[') {
            ++depth;
        } else if (c == '}' || c == ']') {
            if (--depth < 0) return false;
        }
    }
    return depth == 0 && !in_str;
}

// ---------------------------------------------------------------------------
// 驱动 `bench_mpraq` 二进制（用于 L14 拒绝路径 + `--json` 可解析性）
//   ⚠️ 这两条**只能**用真实进程来断言："拒绝运行"是**程序**的行为，"可解析"是
//      **输出契约**；在进程内调库函数证明不了其中任何一条。
// ---------------------------------------------------------------------------
constexpr int kExitBudgetRejected = 3;

struct BenchRun {
    int exit_code = -1;
    std::string out;
    std::string err;
};

BenchRun RunBench(const std::string& args) {
#ifdef MPRAQ_BENCH_BIN
    const std::string bin = MPRAQ_BENCH_BIN;
#else
    const std::string bin = "";
#endif
    BenchRun r;
    if (bin.empty()) {
        throw std::runtime_error("未定义 MPRAQ_BENCH_BIN（CMake 未注入 bench 路径）");
    }
    const std::string err_file =
        "/tmp/mpa09_bench_stderr_" + std::to_string(::getpid()) + ".txt";
    // stdout 走管道（下面读），stderr 落文件（两者都要检查）
    const std::string cmd = bin + " " + args + " 2>" + err_file;
    FILE* f = ::popen(cmd.c_str(), "r");
    if (f == nullptr) throw std::runtime_error("popen 失败：无法运行 bench_mpraq");
    char buf[4096];
    size_t got = 0;
    while ((got = std::fread(buf, 1, sizeof(buf), f)) > 0) {
        r.out.append(buf, got);
    }
    const int status = ::pclose(f);
    r.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    std::ifstream in(err_file);
    if (in) {
        std::ostringstream oss;
        oss << in.rdbuf();
        r.err = oss.str();
    }
    ::unlink(err_file.c_str());
    return r;
}

std::vector<std::string> SplitLines(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream iss(s);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

bool Contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

}  // namespace

// ===========================================================================
// ① 查询集数 = 列数 × ⌈N/128⌉（多个 N，含**非 128 倍数**）
// ===========================================================================
TEST(MpraqScaling, QueriesIssuedIsColumnsTimesWordsPerColumn) {
    // ⚠️ N 覆盖：130（非 128 倍数、⌈N/128⌉=2）、300、1000、1024（2 的幂）、4096
    const std::vector<size_t> ns = {130, 300, 1000, 1024, 4096};
    for (size_t n : ns) {
        auto f = MakeFixture(n);
        const StoreParams& sp = f->client->store_params();
        const PlinkoParams& pp = f->client->plinko_params();
        const uint64_t L = sp.words_per_column;
        // ⌈N/128⌉ 与几何自洽（n = m·⌈N/128⌉、c = n/w 为偶、w 是 2 的幂）
        EXPECT_EQ(L, (n + 127) / 128);
        EXPECT_EQ(sp.entry_count(), static_cast<uint64_t>(sp.column_count) * L);
        EXPECT_EQ(pp.n, sp.entry_count());
        EXPECT_EQ(pp.block_count() % 2, uint64_t{0});
        EXPECT_TRUE(pp.w >= 1 && (pp.w & (pp.w - 1)) == 0);

        const uint64_t q = pp.backup_hints();
        const uint64_t budget = std::min<uint64_t>(q, sp.entry_count());

        struct Case {
            std::vector<Predicate> preds;
            std::vector<mpraq_baseline::Pred> bpreds;
        };
        const std::vector<Case> cases = {
            {{Range(0, 1, 4)}, kRangePreds},
            {{Range(0, 2, 5), P(1, mpraq::PredicateOp::kGe, 1)}, kConjPreds},
        };
        uint64_t consumed_total = 0;
        for (const Case& c : cases) {
            const CountResult r = CountPredicates(*f->client, f->schema, c.preds);
            // ---- 核心恒等式：查询集数 = 列数 × ⌈N/128⌉ ----
            EXPECT_EQ(r.queries_issued,
                      static_cast<uint64_t>(r.columns.size()) * L);
            EXPECT_EQ(r.server_resp_calls[0], uint64_t{1});   // 一次 RunBatch = 1 次 RPC
            EXPECT_EQ(r.server_resp_calls[1], uint64_t{1});
            EXPECT_EQ(r.server_resp_single_calls[0], uint64_t{0});
            EXPECT_EQ(r.server_resp_batch_calls[0], uint64_t{1});
            // 列去重升序（同一列绝不重复检索）
            for (size_t i = 1; i < r.columns.size(); ++i) {
                const bool asc = (r.columns[i - 1].first < r.columns[i].first) ||
                                 (r.columns[i - 1].first == r.columns[i].first &&
                                  r.columns[i - 1].second < r.columns[i].second);
                EXPECT_TRUE(asc);
            }
            EXPECT_TRUE(r.columns.size() >= 1);
            // 结果与明文基准一致（D6：确定性 oracle）
            const std::vector<uint8_t> bf =
                mpraq_baseline::Filter(f->baseline, c.bpreds);
            uint64_t bc = 0;
            for (uint8_t b : bf) bc += b ? 1 : 0;
            EXPECT_EQ(r.count, bc);
            EXPECT_EQ(mpraq_baseline::FilterShape(r.filter),
                      mpraq_baseline::FilterShape(bf));
            consumed_total = f->client->query_count();
        }
        // hint 生命周期：每次 word 查询恰好消费 1 条常规 hint 并提升 1 条备份
        EXPECT_EQ(f->client->query_count(), consumed_total);
        EXPECT_EQ(f->client->backup_remaining(),
                  static_cast<uint64_t>(q - consumed_total));
        // 总消耗必须在 L14 预算内（**实测**复核，不只是事前计划）
        EXPECT_TRUE(consumed_total <= budget);

        std::printf("[mpa09] N=%zu：⌈N/128⌉=%llu、m=%zu、n=%llu、w=%llu、c=%llu、"
                    "两次 Count 共 %llu 个 word 查询（≤ min(q=%llu, n=%llu) = %llu）✓\n",
                    n, static_cast<unsigned long long>(L), sp.column_count,
                    static_cast<unsigned long long>(sp.entry_count()),
                    static_cast<unsigned long long>(pp.w),
                    static_cast<unsigned long long>(pp.block_count()),
                    static_cast<unsigned long long>(consumed_total),
                    static_cast<unsigned long long>(q),
                    static_cast<unsigned long long>(sp.entry_count()),
                    static_cast<unsigned long long>(budget));
    }
}

// ===========================================================================
// ② 每台 RPC 次数 == 查询次数（批量恒 1 次/批，与批大小无关）；word 读取 = 查询集×c
// ===========================================================================
TEST(MpraqScaling, OneRpcPerCountAndWordsReadEqualsQueriesTimesC) {
    auto f = MakeFixture(1024);
    const uint64_t c = f->client->plinko_params().block_count();
    const uint64_t L = f->client->store_params().words_per_column;

    struct Round {
        int id;
        uint64_t expect_queries;
    };
    // 三次查询：2 列（range）、3 列（conj）、**1 个查询集**（边界：批里只有 1 条 —— D32）
    const uint64_t queries_range = 2 * L;
    const uint64_t queries_conj = 3 * L;
    const std::vector<Round> plan = {
        {0, queries_range}, {1, queries_conj}, {2, 1}};

    uint64_t rpc_before[2] = {f->client->channel_rpc_stats(0).server_resp_batch_calls,
                              f->client->channel_rpc_stats(1).server_resp_batch_calls};
    uint64_t node_batch_before[2] = {f->client->node(0).batch_rpc_count(),
                                     f->client->node(1).batch_rpc_count()};
    uint64_t node_scalar_before[2] = {f->client->node(0).rpc_count(),
                                      f->client->node(1).rpc_count()};
    uint64_t words_before[2] = {f->client->node(0).words_read(),
                                f->client->node(1).words_read()};

    for (const Round& r : plan) {
        CountResult res;
        if (r.id == 0) {
            res = CountPredicates(*f->client, f->schema, {Range(0, 1, 4)});
        } else if (r.id == 1) {
            res = CountPredicates(*f->client, f->schema,
                                  {Range(0, 2, 5), P(1, mpraq::PredicateOp::kGe, 1)});
        } else {
            // 单查询集（batch.size() == 1）：D32 的边界形态（计数由**入口**决定）
            MpraqQueryBatch batch =
                f->client->CreateQueries({ColumnWord{0, 0, 0}});
            EXPECT_EQ(batch.size(), size_t{1});
            const std::vector<uint128_t> words = f->client->RunBatch(batch);
            EXPECT_EQ(words.size(), size_t{1});
            // 与**明文副本**逐位对照（确定性 oracle：同一次 Init 的明文表）
            EXPECT_EQ(words[0], f->client->PlainFeatureWord(0));
            res.queries_issued = 1;
            res.server_resp_batch_calls[0] = 1;
            res.server_resp_batch_calls[1] = 1;
            res.server_resp_single_calls[0] = 0;
            res.server_resp_single_calls[1] = 0;
        }
        EXPECT_EQ(res.queries_issued, r.expect_queries);
        EXPECT_EQ(res.server_resp_batch_calls[0], uint64_t{1});
        EXPECT_EQ(res.server_resp_batch_calls[1], uint64_t{1});
        EXPECT_EQ(res.server_resp_single_calls[0], uint64_t{0});
        EXPECT_EQ(res.server_resp_single_calls[1], uint64_t{0});
    }
    // 每台 RPC 次数 == 查询次数（= 一次 RunBatch 恒 1 次）
    for (int i = 0; i < 2; ++i) {
        const uint64_t rpc_delta =
            f->client->channel_rpc_stats(i).server_resp_batch_calls -
            rpc_before[static_cast<size_t>(i)];
        EXPECT_EQ(rpc_delta, static_cast<uint64_t>(plan.size()));
        EXPECT_EQ(f->client->node(i).batch_rpc_count() - node_batch_before[i],
                  static_cast<uint64_t>(plan.size()));
        // 标量路径恒 0（批量路径不走标量接口）
        EXPECT_EQ(f->client->node(i).rpc_count() - node_scalar_before[i], uint64_t{0});
        // 服务器侧工作量口径（D31）：words_read = 查询集数 × c
        const uint64_t expected_words =
            (queries_range + queries_conj + 1) * c;
        EXPECT_EQ(f->client->node(i).words_read() - words_before[i], expected_words);
        EXPECT_EQ(f->client->node(i).queries_served(),
                  queries_range + queries_conj + 1);
    }
    std::printf("[mpa09] 3 次 Count（2 列 / 3 列 / **1 个查询集**）：每台 RPC = 3 = 查询次数、"
                "标量 = 0、words_read = %llu × c=%llu ✓\n",
                static_cast<unsigned long long>(queries_range + queries_conj + 1),
                static_cast<unsigned long long>(c));
}

// ===========================================================================
// ③ Sum 的进程内账目：rounds=2 / messages=2N / wire=4N / 帧长 / install_*=0
// ===========================================================================
TEST(MpraqScaling, SumLocalAccountsMatchFormulas) {
    auto f = MakeFixture(1024);
    const CountResult cr =
        CountPredicates(*f->client, f->schema, {Range(0, 1, 4)});
    // 独立手算的期望值（python3 暴力：逐记录判谓词后计数/累加；**不用**本项目任何代码）
    EXPECT_EQ(cr.count, uint64_t{615});

    SecureMulClientState mac(f->client->mac_key_shares(), f->client->modulus());
    random::DeterministicPrng prng(
        MakeAesSeed(std::vector<uint8_t>{'m', 'p', 'a', '9', 's', 'u', 'm'}), 11);
    LocalTransport net(2);
    const SumResult s = SumOverFilter(cr, f->schema, /*attr_id=*/1, *f->client, net, mac,
                                      prng, /*salt=*/0x9A01);
    EXPECT_EQ(s.sum, static_cast<uint128_t>(614));   // 独立手算
    EXPECT_EQ(s.count, uint64_t{615});
    EXPECT_EQ(AvgOverFilter(s), static_cast<uint128_t>(0));

    const SecureMulBatchStats& st = s.securemul;
    EXPECT_EQ(st.rounds, uint64_t{2});
    EXPECT_EQ(st.collect_calls_phase1, uint64_t{1});
    EXPECT_EQ(st.collect_calls_phase2, uint64_t{1});
    EXPECT_EQ(st.records, uint64_t{1024});
    EXPECT_EQ(st.messages, uint64_t{2 * 1024});
    EXPECT_EQ(st.wire_messages, uint64_t{4 * 1024});
    EXPECT_EQ(st.phase1_messages, uint64_t{1024});
    EXPECT_EQ(st.phase2_messages, uint64_t{1024});
    EXPECT_EQ(st.frame_bytes_phase1, static_cast<uint64_t>(6 + 34 * 1024));
    EXPECT_EQ(st.frame_bytes_phase2, static_cast<uint64_t>(6 + 58 * 1024));
    EXPECT_EQ(st.server_frames[0], uint64_t{2});
    EXPECT_EQ(st.server_frames[1], uint64_t{2});
    // 不剪枝：每台每轮都处理 N 条（与 filter 命中数无关）
    EXPECT_EQ(st.server_records_processed[0], uint64_t{1024});
    EXPECT_EQ(st.server_records_processed[1], uint64_t{1024});
    // 服务器侧常驻材料 = N × (7×16 + 16) = 128·N
    EXPECT_EQ(st.server_state_peak_bytes, uint64_t{1024} * (7 * 16 + 16));
    // 进程内口径：**没有**安装段（D34 的账目只在两进程出现）
    EXPECT_EQ(st.install_frames, uint64_t{0});
    EXPECT_EQ(st.install_rounds, uint64_t{0});
    EXPECT_EQ(st.install_bytes, uint64_t{0});
    std::printf("[mpa09] 进程内 Sum：sum=614、count=615、rounds=%llu、messages=%llu、"
                "wire=%llu、帧长 %llu/%llu、install_bytes=%llu（进程内必须为 0）✓\n",
                static_cast<unsigned long long>(st.rounds),
                static_cast<unsigned long long>(st.messages),
                static_cast<unsigned long long>(st.wire_messages),
                static_cast<unsigned long long>(st.frame_bytes_phase1),
                static_cast<unsigned long long>(st.frame_bytes_phase2),
                static_cast<unsigned long long>(st.install_bytes));
}

// ===========================================================================
// ④ 两进程口径（真实 gRPC）：D34 的安装段账目 + install 不并入 wire
// ===========================================================================
TEST(MpraqScaling, TwoProcessInstallAccountsMatchD34) {
    constexpr size_t kN = 1024;
    RemoteFixture f(kN);
    const ServerStats before0 = f.servers.stats(0);
    const ServerStats before1 = f.servers.stats(1);

    const CountResult cr =
        CountPredicates(*f.client, f.schema, {Range(0, 1, 4)});
    EXPECT_EQ(cr.count, uint64_t{615});
    EXPECT_EQ(cr.server_resp_calls[0], uint64_t{1});  // 两进程下一次 RunBatch 仍 = 1 RPC
    EXPECT_EQ(f.ch0->rpc_count() >= 3, true);         // InitTable + 上传 + 本查询

    SecureMulClientState mac(f.client->mac_key_shares(), f.client->modulus());
    random::DeterministicPrng prng(
        MakeAesSeed(std::vector<uint8_t>{'m', 'p', 'a', '9', 'r', 'e', 'm'}), 13);
    const SumResult s = SumOverFilter(cr, f.schema, /*attr_id=*/1, *f.client, *f.transport,
                                      *f.ep0, *f.ep1, mac, prng, /*salt=*/0x9A02);
    EXPECT_EQ(s.sum, static_cast<uint128_t>(614));
    EXPECT_EQ(s.count, uint64_t{615});

    const SecureMulBatchStats& st = s.securemul;
    // ---- D34：安装段（**两进程特有**）----
    EXPECT_EQ(st.install_frames, uint64_t{2});
    EXPECT_EQ(st.install_rounds, uint64_t{2});
    EXPECT_EQ(st.install_bytes,
              static_cast<uint64_t>(2 * (13 + 152 * static_cast<uint64_t>(kN))));
    // ---- 在线段不受影响：install **不**并入 wire_messages ----
    EXPECT_EQ(st.rounds, uint64_t{2});
    EXPECT_EQ(st.messages, static_cast<uint64_t>(2 * kN));
    EXPECT_EQ(st.wire_messages, static_cast<uint64_t>(4 * kN));
    EXPECT_EQ(st.frame_bytes_phase1, static_cast<uint64_t>(6 + 34 * kN));
    EXPECT_EQ(st.frame_bytes_phase2, static_cast<uint64_t>(6 + 58 * kN));
    EXPECT_EQ(st.server_frames[0], uint64_t{2});
    EXPECT_EQ(st.server_frames[1], uint64_t{2});

    // ---- 服务器进程侧**实测**（不是客户端按公式算的）----
    const ServerStats after0 = f.servers.stats(0);
    const ServerStats after1 = f.servers.stats(1);
    EXPECT_EQ(after0.relay_install_frames - before0.relay_install_frames, uint64_t{1});
    EXPECT_EQ(after1.relay_install_frames - before1.relay_install_frames, uint64_t{1});
    EXPECT_EQ(after0.relay_phase_frames - before0.relay_phase_frames, uint64_t{2});
    EXPECT_EQ(after1.relay_phase_frames - before1.relay_phase_frames, uint64_t{2});
    EXPECT_EQ(after0.relay_records_processed - before0.relay_records_processed,
              static_cast<uint64_t>(2 * kN));
    EXPECT_EQ(after1.relay_records_processed - before1.relay_records_processed,
              static_cast<uint64_t>(2 * kN));

    // ---- ⑤ 服务器实测存储 = §1 公式（两服务器实例各自独立核对）----
    const StoreParams& sp = f.client->store_params();
    const uint64_t formula =
        16ull * sp.column_count * sp.words_per_column +
        16ull * sp.num_records * sp.num_attributes();
    EXPECT_EQ(after0.storage_bytes, formula);
    EXPECT_EQ(after1.storage_bytes, formula);
    std::printf("[mpa09] 两进程 Sum：install_frames=%llu、install_rounds=%llu、"
                "install_bytes=%llu = 2×(13+152·%zu)、wire=%llu(=4N，install **未**并入)、"
                "服务器实测存储=%llu B = §1 公式 ✓\n",
                static_cast<unsigned long long>(st.install_frames),
                static_cast<unsigned long long>(st.install_rounds),
                static_cast<unsigned long long>(st.install_bytes), kN,
                static_cast<unsigned long long>(st.wire_messages),
                static_cast<unsigned long long>(after0.storage_bytes));
}

// ===========================================================================
// ⑤ 服务器存储 = §1 公式（双报含/不含补齐）+ `MpraqNode::StorageBytes()` 实测一致
// ===========================================================================
TEST(MpraqScaling, ServerStorageMatchesSection1Formula) {
    // (N, 显式 w) —— 都取**合法几何**（w 必须 ≥ ⌈N/128⌉、n = c·w、c 偶）
    struct Case {
        size_t n;
        uint64_t w;
    };
    // ⚠️ 只列**合法**几何：`w = 2^k`、`w ≥ ⌈N/128⌉`、`n = c·w` 且 `c` 偶（见用例 ⑨ 的结构性发现）
    const std::vector<Case> cases = {{128, 1}, {128, 8}, {300, 4}, {1024, 8},
                                     {1024, 32}, {4096, 32}};
    for (const Case& c : cases) {
        auto f = MakeFixture(c.n, kTestLambda, kTestEps, c.w);
        const StoreParams& sp = f->client->store_params();
        const uint64_t L = sp.words_per_column;
        const uint64_t feature_padded = 16ull * sp.column_count * L;
        const uint64_t feature_unpadded = 16ull * sp.real_column_count * L;
        const uint64_t attr_bytes = 16ull * sp.num_records * sp.num_attributes();
        // 显式 w 必须被**原样**采用（不偷偷改 w）
        EXPECT_EQ(f->client->plinko_params().w, c.w);
        EXPECT_EQ(sp.real_column_count, kRealColumns);
        EXPECT_TRUE(sp.column_count >= sp.real_column_count);
        EXPECT_EQ(sp.padding_columns(), sp.column_count - sp.real_column_count);
        // §1 公式（含补齐）+ 双报（不含补齐）
        EXPECT_EQ(sp.entry_count(), static_cast<uint64_t>(sp.column_count) * L);
        EXPECT_EQ(16ull * sp.entry_count() - feature_padded, uint64_t{0});
        for (int i = 0; i < 2; ++i) {
            EXPECT_EQ(f->client->node(i).StorageBytes(), feature_padded + attr_bytes);
            EXPECT_EQ(f->client->node(i).FeatureStorageBytes(), feature_padded);
            EXPECT_EQ(f->client->node(i).AttributeStorageBytes(), attr_bytes);
            EXPECT_EQ(f->client->storage_bytes(i), feature_padded + attr_bytes);
        }
        // 补齐的代价 = 补齐列数 × ⌈N/128⌉ × 16 B（**双报**的第二个数）
        EXPECT_EQ(feature_padded - feature_unpadded,
                  static_cast<uint64_t>(sp.padding_columns()) * L * 16ull);
        std::printf("[mpa09] N=%zu、w=%llu：服务器存储 %llu B（含补齐）= 公式 = 实测；"
                    "不含补齐 %llu B（差 %llu B = 补齐 %zu 列 × ⌈N/128⌉=%llu × 16）✓\n",
                    c.n, static_cast<unsigned long long>(c.w),
                    static_cast<unsigned long long>(feature_padded + attr_bytes),
                    static_cast<unsigned long long>(feature_unpadded + attr_bytes),
                    static_cast<unsigned long long>(feature_padded - feature_unpadded),
                    sp.padding_columns(), static_cast<unsigned long long>(L));
    }
}

// ===========================================================================
// ⑥ L14 预算：给定参数 ≤ min(q, n)；超预算的参数**拒绝运行**（fail-loudly）
// ===========================================================================
TEST(MpraqScaling, L14BudgetIsEnforcedAndOverBudgetIsRefused) {
    // ---- (a) 进程内：预算的两条上限都由库的几何给出，逐条核对 ----
    {
        // λ=80（部署值）：N=128 ⇒ ⌈N/128⌉=1、M=10 ⇒ m=16、n=16、w=1 ⇒ q=λw/2=40
        auto f = MakeFixture(128, /*lambda=*/80);
        const StoreParams& sp = f->client->store_params();
        const PlinkoParams& pp = f->client->plinko_params();
        EXPECT_EQ(sp.words_per_column, uint64_t{1});
        EXPECT_EQ(sp.column_count, size_t{16});
        EXPECT_EQ(sp.entry_count(), uint64_t{16});
        EXPECT_EQ(pp.backup_hints(), static_cast<uint64_t>(pp.lambda) * pp.w / 2);
        EXPECT_EQ(pp.hint_slots(),
                  pp.main_hints() + pp.backup_hints());  // H = λw + q
        const uint64_t budget =
            std::min<uint64_t>(pp.backup_hints(), sp.entry_count());
        EXPECT_EQ(budget, uint64_t{16});   // 较紧的是新鲜索引池 n
        // 合法计划：10 列 × 1 = 10 ≤ 16 ⇒ 跑得动
        const CountResult ok =
            CountPredicates(*f->client, f->schema, {Range(0, 1, 4)});
        EXPECT_TRUE(ok.queries_issued <= budget);
        EXPECT_TRUE(f->client->query_count() <= budget);
    }

    // ---- (b) 超预算的参数：`bench_mpraq` 必须**拒绝运行**（退出码 3 + 可读原因）----
    //     计划 = 列数 10 × ⌈N/128⌉ 1 × repeat 2 = 20 > min(q=40, n=16) = 16
    {
        const BenchRun r = RunBench(
            "--exp online --rows 128 --columns 10 --repeat 2 --no-sum --json");
        EXPECT_EQ(r.exit_code, kExitBudgetRejected);
        EXPECT_TRUE(Contains(r.err, "L14"));                 // 指明是哪条预算
        EXPECT_TRUE(Contains(r.err, "拒绝运行"));             // fail-loudly 的措辞
        EXPECT_TRUE(Contains(r.err, "min(q, n)"));           // 给出上限算式
        EXPECT_TRUE(Contains(r.err, "pool(n)"));             // 指出**较紧的是哪一条**
        // **不得**把失败推迟到 Plinko 的异常（那是"跑到一半炸"，不是参数校验）：
        // 运行期中止会打 `[FAIL-LOUDLY] ... 中止：` 且消息含 Plinko 的用尽措辞
        EXPECT_FALSE(Contains(r.err, "[FAIL-LOUDLY]"));
        EXPECT_FALSE(Contains(r.err, "备份 hint 已用尽"));
        // 拒绝发生在任何查询之前 ⇒ stdout 里**没有**任何测量点
        EXPECT_FALSE(Contains(r.out, "\"point\""));
        // `--json` 下错误也是机器可读的
        EXPECT_TRUE(Contains(r.err, "l14_budget_rejected"));
    }

    // ---- (c) 同一参数在预算内（repeat=1）⇒ 正常跑完并输出 JSONL ----
    {
        const BenchRun r = RunBench(
            "--exp online --rows 128 --columns 10 --repeat 1 --no-sum --json");
        EXPECT_EQ(r.exit_code, 0);
        EXPECT_TRUE(Contains(r.out, "\"point\""));
    }
}

// ===========================================================================
// ⑦ 备份 hint 用尽 ⇒ `PlinkoBackupsExhausted`（D8：不做摊销式离线，用尽必须**显式**报错）
//    口径：一次离线恰好支持 q = λw/2 次 **word 查询**（每次查询消费 1 条常规 hint 并提升
//    1 条备份）⇒ 第 q+1 次必须**在发出查询之前**报错（绝不静默降级/错值）
// ===========================================================================
TEST(MpraqScaling, BackupHintsExhaustedAfterExactlyQQueries) {
    // N=255、λ=20 ⇒ ⌈N/128⌉=2、M=10 ⇒ m=16、n=32、w=2（派生）、c=16、q = λw/2 = **20** < n=32
    // ⇒ 先耗尽的必然是 **hint 额度**（若 q ≥ n，先撞的是"新鲜索引池"，那是 L14 的第②条）
    auto f = MakeFixture(255, /*lambda=*/20);
    const PlinkoParams& pp = f->client->plinko_params();
    const uint64_t q = pp.backup_hints();
    const uint64_t n_entries = f->client->store_params().entry_count();
    EXPECT_EQ(q, static_cast<uint64_t>(pp.lambda) * pp.w / 2);
    EXPECT_EQ(q, uint64_t{20});
    EXPECT_EQ(n_entries, uint64_t{32});
    EXPECT_TRUE(q < n_entries);
    EXPECT_EQ(f->client->backup_remaining(), q);

    // ⚠️ 逐条（每次 1 个查询集）：一次性把 q 条都 QueryGen 出来会同时**预留** q 条 hint，
    //    可用池骤降 ⇒ 覆盖失败概率被人为放大（那是**批量预留**的假象，不是协议性质）
    for (uint64_t i = 0; i < q; ++i) {
        MpraqQueryBatch b = f->client->CreateQueriesForIndices({i});
        const std::vector<uint128_t> w = f->client->RunBatch(b);
        EXPECT_EQ(w[0], f->client->PlainFeatureWord(i));
    }
    EXPECT_EQ(f->client->query_count(), q);
    EXPECT_EQ(f->client->backup_remaining(), uint64_t{0});

    // 第 q+1 次：**必须**在发出查询之前抛 PlinkoBackupsExhausted（D8：不容忍静默降级）
    bool thrown = false;
    std::string what;
    try {
        MpraqQueryBatch extra = f->client->CreateQueriesForIndices({q});
        f->client->RunBatch(extra);
    } catch (const PlinkoBackupsExhausted& e) {
        thrown = true;
        what = e.what();
    }
    EXPECT_TRUE(thrown);
    EXPECT_TRUE(Contains(what, "备份 hint 已用尽"));
    EXPECT_TRUE(Contains(what, "HintInit"));  // 给出处置路径（重跑离线）
    std::printf("[mpa09] 用尽检查：q=%llu 次 word 查询全部成功（每次恰好提升 1 条备份），"
                "第 q+1 次抛 PlinkoBackupsExhausted（消息含'备份 hint 已用尽'与'HintInit'）✓\n",
                static_cast<unsigned long long>(q));
}

// ===========================================================================
// ⑧ `bench_mpraq --json` 的输出**可解析**、字段齐全、内部自洽
//    （`MPA-10` 与自动汇总都依赖这个契约）
// ===========================================================================
TEST(MpraqScaling, BenchJsonIsParseableAndSelfConsistent) {
    const std::string out_file =
        "/tmp/mpa09_bench_doc_" + std::to_string(::getpid()) + ".json";
    const BenchRun r = RunBench(
        "--exp online --rows 128 --columns 10 --repeat 1 --no-sum --json --json-out " +
        out_file);
    EXPECT_EQ(r.exit_code, 0);

    const std::vector<std::string> lines = SplitLines(r.out);
    EXPECT_EQ(lines.size(), size_t{1});          // 1 个实验点 ⇒ 1 行 JSONL
    for (const std::string& line : lines) {
        EXPECT_TRUE(Balanced(line));             // 花括号/引号配平
    }
    const std::string line = lines.empty() ? std::string() : lines.front();
    const std::string cfg = TopLevelObject(line, "config");
    const std::string pt = TopLevelObject(line, "point");
    EXPECT_TRUE(!cfg.empty());
    EXPECT_TRUE(!pt.empty());

    // ---- config：口径必须标明（local vs grpc-two-process）----
    EXPECT_EQ(ValueStr(cfg, "experiment"), std::string("online"));
    EXPECT_EQ(ValueStr(cfg, "mode"), std::string("local"));
    EXPECT_EQ(ValueU64(cfg, "lambda"), uint64_t{80});
    EXPECT_EQ(ValueU64(cfg, "raw_columns"), uint64_t{10});
    EXPECT_TRUE(HasKey(cfg, "query_set_unit"));
    EXPECT_TRUE(HasKey(cfg, "rpc_unit"));
    EXPECT_TRUE(HasKey(cfg, "block_access_unit"));
    // `MPA-09` 任务 B：**客户端收包上限**必须出现在任何一次运行的 config 里（显式设置）
    EXPECT_EQ(ValueU64(cfg, "client_max_receive_bytes"),
              static_cast<uint64_t>(kGrpcClientMaxReceiveBytes));

    // ---- point：每个实验都有的**全部**小节 ----
    for (const char* key : {"geometry", "budget", "init", "client_storage", "count", "sum",
                            "server_storage", "notes"}) {
        EXPECT_TRUE(HasKey(pt, key));
    }
    const std::string g = TopLevelObject(pt, "geometry");
    const std::string b = TopLevelObject(pt, "budget");
    const std::string c = TopLevelObject(pt, "count");
    const std::string ss = TopLevelObject(pt, "server_storage");
    const std::string sm = TopLevelObject(pt, "sum");
    EXPECT_TRUE(!g.empty() && !b.empty() && !c.empty() && !ss.empty() && !sm.empty());

    // ---- 几何自洽（本实验：N=128、λ=80 ⇒ w=1、c=16、q=40、H=120）----
    const uint64_t N = ValueU64(g, "records_N");
    const uint64_t L = ValueU64(g, "words_per_column");
    const uint64_t m = ValueU64(g, "columns_padded_m");
    const uint64_t n = ValueU64(g, "entries_n_words");
    const uint64_t w = ValueU64(g, "block_size_w");
    const uint64_t cc = ValueU64(g, "blocks_c");
    const uint64_t lam = ValueU64(g, "lambda");
    EXPECT_EQ(N, uint64_t{128});
    EXPECT_EQ(L, (N + 127) / 128);
    EXPECT_EQ(n, m * L);                              // n = m·⌈N/128⌉（word 数！）
    EXPECT_EQ(cc, n / w);                             // c = n/w
    EXPECT_EQ(ValueU64(g, "backup_hints_q"), lam * w / 2);          // q = λw/2
    EXPECT_EQ(ValueU64(g, "main_hints_lambda_w"), lam * w);         // λw
    EXPECT_EQ(ValueU64(g, "hint_slots_H"), lam * w + lam * w / 2);  // H = λw + q
    EXPECT_EQ(ValueU64(g, "block_accesses_per_query_set"), cc);     // 在线检索 = c 次区块访问
    // D35：`m0`（升级前）/ `m`（升级后）与升级标记都在 JSON 里可读
    EXPECT_EQ(ValueU64(g, "columns_min_pow2_m0"), m);               // 本实验无升级 ⇒ m0 == m
    EXPECT_EQ(ValueU64(g, "column_upgrade_factor"), uint64_t{1});
    EXPECT_EQ(FindValue(g, "column_upgrade_applied"), std::string("false"));

    // ---- 查询口径：查询集数 = 列数 × ⌈N/128⌉；每台 RPC = 1（一次 RunBatch）----
    EXPECT_EQ(ValueU64(c, "queries_per_column"), L);
    EXPECT_EQ(ValueU64(c, "columns_used"), uint64_t{10});
    EXPECT_EQ(ValueU64(c, "queries_issued"), uint64_t{10} * L);
    EXPECT_EQ(ValueU64(c, "pir_rpc_server0"), uint64_t{1});
    EXPECT_EQ(ValueU64(c, "pir_rpc_server1"), uint64_t{1});
    EXPECT_EQ(ValueU64(c, "scalar_server_resp_server0"), uint64_t{0});
    EXPECT_EQ(FindValue(c, "queries_identity_ok"), std::string("true"));  // 布尔字段
    EXPECT_EQ(FindValue(c, "filter_matches_baseline"), std::string("true"));
    EXPECT_EQ(ValueU64(c, "count"), ValueU64(c, "baseline_count"));  // 与明文副本一致

    // ---- L14 预算：计划 ≤ min(q, n) ----
    EXPECT_EQ(ValueU64(b, "planned_word_queries"), uint64_t{10} * L);
    EXPECT_EQ(ValueU64(b, "hint_cap_q"), lam * w / 2);
    EXPECT_EQ(ValueU64(b, "pool_cap_n"), n);
    EXPECT_EQ(ValueU64(b, "budget_min_q_n"), std::min(lam * w / 2, n));
    EXPECT_TRUE(ValueU64(b, "planned_word_queries") <= ValueU64(b, "budget_min_q_n"));

    // ---- 服务器存储：公式 = 实测（双报）----
    EXPECT_EQ(ValueU64(ss, "total_bytes_formula_padded"),
              ValueU64(ss, "total_bytes_measured_server0"));
    EXPECT_EQ(ValueU64(ss, "total_bytes_formula_padded"),
              ValueU64(ss, "total_bytes_measured_server1"));
    EXPECT_TRUE(ValueU64(ss, "total_bytes_formula_padded") >
                ValueU64(ss, "total_bytes_formula_unpadded"));

    // ---- `--no-sum` ⇒ sum.available = false（且两进程专属字段存在但为 0）----
    EXPECT_EQ(FindValue(sm, "available"), std::string("false"));  // 布尔字段
    EXPECT_EQ(ValueU64(sm, "install_formula_bytes"),
              static_cast<uint64_t>(2 * (13 + 152 * N)));

    // ---- 完整文档（`--json-out`）：config + points + summary 三段齐全 ----
    {
        std::ifstream in(out_file);
        ASSERT_TRUE(static_cast<bool>(in));
        std::ostringstream oss;
        oss << in.rdbuf();
        const std::string doc = oss.str();
        EXPECT_TRUE(Balanced(doc));
        EXPECT_TRUE(!TopLevelObject(doc, "config").empty());
        EXPECT_TRUE(!TopLevelObject(doc, "summary").empty());
        // points 是**数组**：数一下 "records_N"（每个点恰好一次）
        size_t count = 0;
        size_t at = 0;
        while ((at = doc.find("\"records_N\"", at)) != std::string::npos) {
            ++count;
            at += 11;
        }
        EXPECT_EQ(count, size_t{1});
    }
    ::unlink(out_file.c_str());
    std::printf("[mpa09] --json 契约：%zu 行 JSONL、字段齐全、几何/预算/查询/存储全部自洽；"
                "--json-out 文档含 config+points+summary ✓\n",
                lines.size());
}

// ===========================================================================
// ⑨ 决策 **D35**：列数 **×2 升级搜索** —— 奇数部分大的 ⌈N/128⌉ 现在**有解**
//    推导（落地在 `src/mpraq/init.cpp` 的 `DerivePaddedGeometry`）：
//      设 L = ⌈N/128⌉ = 2^t·q（q 为奇）、cols = 2^a、w = 2^b。几何合法性要求
//        ① `w >= L`（一个区块至少装下一整列 ⇒ b >= t + ⌈log₂q⌉）；
//        ② `c = n/w` 为**偶数**（PLINKO_SPEC §5.5）⇒ `b <= a + t − 1`（n = cols·L）；
//      ⇒ **存在合法 (a,b) ⇔ `a >= 1 + ⌈log₂q⌉`**（且 `2^a >= M`）。
//      只试最小列数 `NextPow2(M)`（a = ⌈log₂M⌉）在 `q > M/2` 时**必然无解**。
//    ⚠️ 边界纪律：本用例只断言"库给的几何**自洽**"，**不放宽**
//      `PlinkoParams::Validate`、也不改 `src/pir/**` —— 判据只有那一处。
// ===========================================================================
TEST(MpraqScaling, ColumnUpgradeSolvesOddWordCounts) {
    struct Expect {
        size_t N;
        size_t L;    // ⌈N/128⌉（奇数部分 q = L，因为 L 为奇）
        size_t m0;   // 升级前：NextPow2(M)
        size_t m;    // 升级后（D35）
        uint64_t n;
        uint64_t w;
        uint64_t c;
    };
    // 三个**此前无解**的 N：q = 9 / 11 / 13 > m0/2 = 8
    const std::vector<Expect> cases = {{1100, 9, 16, 32, 288, 16, 18},
                                      {1300, 11, 16, 32, 352, 16, 22},
                                      {1637, 13, 16, 32, 416, 16, 26}};
    for (const Expect& e : cases) {
        auto f = MakeFixture(e.N);   // ← D35 之前这里会抛 std::invalid_argument
        const StoreParams& sp = f->client->store_params();
        const PlinkoParams& pp = f->client->plinko_params();
        // ---- 几何**自洽**（判据是库的 `Validate()`，不是本文件自己重写的一套）----
        EXPECT_NO_THROW(pp.Validate());
        EXPECT_EQ(sp.num_records, e.N);
        EXPECT_EQ(sp.words_per_column, e.L);
        EXPECT_EQ(sp.real_column_count, kRealColumns);
        EXPECT_EQ(sp.column_count, e.m);
        EXPECT_TRUE(sp.column_count > e.m0);                  // **确实升级了**
        EXPECT_EQ(sp.padding_columns(), e.m - kRealColumns);
        EXPECT_EQ(sp.entry_count(), static_cast<uint64_t>(sp.column_count) * e.L);
        EXPECT_EQ(sp.entry_count(), e.n);
        EXPECT_EQ(pp.n, e.n);
        EXPECT_EQ(pp.w, e.w);
        EXPECT_EQ(pp.block_count(), e.c);
        EXPECT_EQ(pp.n % pp.w, uint64_t{0});
        EXPECT_EQ(pp.block_count() % 2, uint64_t{0});          // c 为偶数
        EXPECT_TRUE(pp.w >= e.L);                              // w ≥ ⌈N/128⌉
        EXPECT_TRUE((pp.w & (pp.w - 1)) == 0);                 // w 是 2 的幂
        // ---- 服务器存储（D26 口径 **双报**：升级前 m0 vs 升级后 m）----
        const uint64_t attr_bytes = 16ull * e.N * sp.num_attributes();
        const uint64_t storage = 16ull * e.m * e.L + attr_bytes;
        const uint64_t storage_no_upgrade = 16ull * e.m0 * e.L + attr_bytes;
        EXPECT_EQ(f->client->node(0).StorageBytes(), storage);
        EXPECT_EQ(f->client->node(1).StorageBytes(), storage);
        EXPECT_TRUE(storage > storage_no_upgrade);
        // ---- 升级后的几何**真的能用**：一次 Count 与明文基准逐位一致 ----
        const CountResult r =
            CountPredicates(*f->client, f->schema, {Range(0, 1, 4)});
        EXPECT_EQ(r.queries_issued, static_cast<uint64_t>(r.columns.size()) * e.L);
        const std::vector<uint8_t> bf = mpraq_baseline::Filter(f->baseline, kRangePreds);
        uint64_t bc = 0;
        for (uint8_t b : bf) bc += b ? 1 : 0;
        EXPECT_EQ(r.count, bc);
        EXPECT_TRUE(f->client->query_count() <=
                    std::min<uint64_t>(pp.backup_hints(), sp.entry_count()));
        std::printf("[mpa09/D35] N=%zu：q=%zu > m0/2=%zu ⇒ 升级 m0=%zu → **m=%zu**、"
                    "n=%llu、w=%llu、c=%llu（偶）；服务器存储 %llu → %llu B（+%llu B）；"
                    "Count=%llu = 基准 %llu ✓\n",
                    e.N, e.L, e.m0 / 2, e.m0, e.m,
                    static_cast<unsigned long long>(e.n),
                    static_cast<unsigned long long>(e.w),
                    static_cast<unsigned long long>(e.c),
                    static_cast<unsigned long long>(storage_no_upgrade),
                    static_cast<unsigned long long>(storage),
                    static_cast<unsigned long long>(storage - storage_no_upgrade),
                    static_cast<unsigned long long>(r.count),
                    static_cast<unsigned long long>(bc));
    }
}

// ===========================================================================
// ⑩ **回归守卫**：D35 只允许在"原本无解"时生效 ⇒ 原本有解的 N 必须**逐位不变**
//    （否则存储/延迟曲线会出现没人预期的漂移；主键 `n` 最小 + 升级只会放大 `n`，
//      因此"有解时不升级"是可证明的，本用例把它钉住）
// ===========================================================================
TEST(MpraqScaling, DerivedGeometryUnchangedWhereAlreadySolvable) {
    struct Expect {
        size_t N;
        size_t m;
        uint64_t n;
        uint64_t w;
        uint64_t c;
    };
    // ⚠️ 这些值取自 **D35 之前**的实测（`MPA-09` 报告的表 1/表 3/表 4）
    const std::vector<Expect> expect = {
        {128, 16, 16, 1, 16},     {130, 16, 32, 2, 16},    {300, 16, 48, 4, 12},
        {800, 16, 112, 8, 14},    {1000, 16, 128, 8, 16},  {1024, 16, 128, 8, 16},
        {1153, 16, 160, 16, 10},  {1409, 16, 192, 16, 12}, {2048, 16, 256, 16, 16},
        {4096, 16, 512, 32, 16},  {8192, 16, 1024, 64, 16}, {16384, 16, 2048, 128, 16}};
    for (const Expect& e : expect) {
        const MpraqPaddedGeometry g = DerivePaddedGeometry(kRealColumns, e.N, 80, 1e-4);
        EXPECT_EQ(g.column_count, e.m);
        EXPECT_EQ(g.plinko.n, e.n);
        EXPECT_EQ(g.plinko.w, e.w);
        EXPECT_EQ(g.plinko.block_count(), e.c);
        EXPECT_EQ(g.padding_columns, e.m - kRealColumns);
        EXPECT_NO_THROW(g.plinko.Validate());
    }
    std::printf("[mpa09/D35] 回归守卫：%zu 个原本有解的 N 几何**逐位不变**（升级只在无解时生效）✓\n",
                expect.size());
}

// ===========================================================================
// ⑪ 显式 `w` 也走同一条升级搜索（且 **w 原样保留**，D24④），失败时消息**准确**
// ===========================================================================
TEST(MpraqScaling, ExplicitWidthKeepsUpgradeSemantics) {
    // N=1637（L=13）：显式 w=16 ⇒ 最小列数 16 时 n=208、c=13 为奇 ✗；升级到 cols=32 ⇒
    // n=416、c=26 为偶 ✅（w 必须是 2 的幂、且不被改动）
    auto f = MakeFixture(1637, kTestLambda, kTestEps, /*w=*/16);
    const StoreParams& sp = f->client->store_params();
    EXPECT_EQ(f->client->plinko_params().w, uint64_t{16});   // 显式 w **原样保留**
    EXPECT_EQ(sp.column_count, size_t{32});                  // 只升级列数
    EXPECT_EQ(sp.entry_count(), uint64_t{416});
    EXPECT_EQ(f->client->plinko_params().block_count(), uint64_t{26});
    EXPECT_NO_THROW(f->client->plinko_params().Validate());

    // 显式 w 确实无解时（N=128 ⇒ n 最大 64，w=64 ⇒ c=1 退化）：
    // 消息必须写明"**已尝试列数 …（含 ×2 升级，上限 …）**"并给出**可执行的处置**，
    // 且**不得**再出现旧版那句对这类 N 有误导的"请改用默认派生的 w"（那是默认路径的建议）
    bool thrown = false;
    std::string what;
    try {
        auto bad = MakeFixture(128, kTestLambda, kTestEps, /*w=*/64);
        (void)bad;
    } catch (const std::invalid_argument& e) {
        thrown = true;
        what = e.what();
    }
    EXPECT_TRUE(thrown);
    EXPECT_TRUE(Contains(what, "已尝试列数"));
    EXPECT_TRUE(Contains(what, "含 ×2 升级"));
    EXPECT_TRUE(Contains(what, "奇数部分"));
    std::printf("[mpa09/D35] 显式 w 升级：w=16 原样保留、列数 16→32、c=26；无解时消息列出"
                "试过的 (w, 列数) 与原因 ✓\n");
}

// ===========================================================================
// ⑫ **确实不可行**的用例（连升级也救不了）：λ 超过 iPRF 的 2^32 域宽
//    `PlinkoParams::Validate`：`λw` 溢出检查 + `H = λw+q <= 2^32`（core/iprf 的 AES 输入块
//    只有 32 位字宽）⇒ λ = 4e9 时**任何** (cols, w) 都不合法。这是"升级搜索救不了"的
//    真实边界（**不是**为了变绿而放宽校验：判据仍只有 `Validate()` 一处）。
// ===========================================================================
TEST(MpraqScaling, InfeasibleGeometryStillRejectedLoudlyAfterUpgrade) {
    MpraqInitParams p;
    p.lambda = 4000000000u;   // 3λw/2 与 λw 都超 2^32（w >= 1）
    p.prp_epsilon = 1e-4;
    p.seed = 7;
    const Schema s = MakeSchema(128);
    const std::vector<MpraqRecord> recs = MakeRecords(128);

    bool thrown = false;
    std::string what;
    try {
        auto c = MpraqClient::Init(s, recs, p);
        (void)c;
    } catch (const std::invalid_argument& e) {
        thrown = true;
        what = e.what();
    }
    EXPECT_TRUE(thrown);
    // 新消息的三要素：**试过的列数（含升级）**、**诊断（奇数部分 q 与充要条件）**、
    // **具体原因**（这里就是 iPRF 的 2^32 域宽）
    EXPECT_TRUE(Contains(what, "已尝试列数"));
    EXPECT_TRUE(Contains(what, "×2 升级"));
    EXPECT_TRUE(Contains(what, "奇数部分"));
    EXPECT_TRUE(Contains(what, "2^32"));
    // 默认路径**不得**用旧版那句"请改用默认派生的 w"（对这类 N 是误导）
    EXPECT_FALSE(Contains(what, "改用**默认派生**的 w"));
    std::printf("[mpa09/D35] 不可行反例（λ=4e9 > iPRF 域宽）：Init 抛可读 "
                "std::invalid_argument，消息含「已尝试列数 …（含 ×2 升级）」与"
                "「H = λw+q 超过 2^32」✓\n");
}

// ===========================================================================
// ⑬ `MPA-09` 任务 B：**客户端 gRPC 收包上限**是**显式设置**的（不是 gRPC 默认的 4 MiB）
//    证据分两层：
//      ① 编译期/接口层：常量与两个客户端通道的访问器都等于 256 MiB（本用例）；
//      ② 端到端：`N = 2^17` 的两进程 Sum 在旧默认下第 1 轮就失败
//         （`Received message larger than max (5636122 vs. 4194304)`），改后必须能跑
//         （由 `MPA-09` 的 bench 手工探测记录，不在 ctest 里跑 —— 那需要 ~25 s 与 327 MB）。
// ===========================================================================
TEST(MpraqScaling, ClientGrpcReceiveLimitIsExplicitlyRaised) {
    constexpr uint64_t kGrpcDefault = 4ull * 1024 * 1024;   // gRPC 的默认收包上限
    EXPECT_EQ(kGrpcClientMaxReceiveBytes, 256 * 1024 * 1024);
    EXPECT_EQ(GrpcTransportClient::max_receive_bytes(), kGrpcClientMaxReceiveBytes);
    EXPECT_EQ(GrpcMpraqChannel::max_receive_bytes(), kGrpcClientMaxReceiveBytes);
    EXPECT_TRUE(kGrpcClientMaxReceiveBytes > static_cast<int>(kGrpcDefault));

    // 为什么必须显式设：两进程 SecureMul 的应答帧 = 19 + 43N（第 1 轮）/ 19 + 58N（第 2 轮）
    // ⇒ N = 2^17 时两帧都**超过** gRPC 默认的 4 MiB（旧上限下必炸），但都在新上限内。
    constexpr uint64_t kN = 131072;   // 2^17
    const uint64_t phase1 = 19 + 43 * kN;
    const uint64_t phase2 = 19 + 58 * kN;
    EXPECT_TRUE(phase1 > kGrpcDefault);
    EXPECT_TRUE(phase2 > kGrpcDefault);
    EXPECT_TRUE(phase1 < static_cast<uint64_t>(kGrpcClientMaxReceiveBytes));
    EXPECT_TRUE(phase2 < static_cast<uint64_t>(kGrpcClientMaxReceiveBytes));
    // 旧上限下的临界点（`MPA-09` 实测：N=2^16 侥幸能跑、2^17 必炸）
    EXPECT_EQ((kGrpcDefault - 19) / 58, uint64_t{72315});
    EXPECT_TRUE(19 + 58 * 72316 > kGrpcDefault);            // 72 316 就超了
    EXPECT_TRUE(19 + 58 * 65536 <= kGrpcDefault);           // 2^16 在旧上限内（3.80 MB）
    std::printf("[mpa09/B] 客户端收包上限 = %d B（%d MiB，显式设置）；旧默认 4 MiB 下 "
                "N=2^17 的帧 %llu/%llu B 必被拒，新上限可容纳 ✓\n",
                kGrpcClientMaxReceiveBytes, kGrpcClientMaxReceiveBytes / (1024 * 1024),
                static_cast<unsigned long long>(phase1),
                static_cast<unsigned long long>(phase2));
}
