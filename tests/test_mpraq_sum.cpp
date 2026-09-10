// MPA-06：`AggQuery` – `Sum` / `Avg`（批量 SecureMul 聚合）测试。
//
// 覆盖（对应任务书的硬性要求）：
//   1. **确定性期望值**（D6 铁律）：`sum`/`count`/`avg` 与
//      `tests/support/mpraq_baseline.hpp` 的暴力结果**逐值相等**，
//      并且还与本文件里**手算的常量**（用独立的 python 暴力脚本算出，见
//      `kExpect*` 的注释）逐值相等 —— 三路对照（协议 / 基准 / 手算常量）。
//   2. **不剪枝**：`filter` 全 0 时仍发 N 条（`records == N`、`messages == 2N`、
//      `wire_messages == 4N`、两台服务器的处理条数都是 N），`sum == 0`、`count == 0`。
//   3. **恰好 2 个往返**：`rounds == 2`、`messages == 2N`，并且用
//      `LocalTransport::RequestCount()` / `RequestLog()` **独立复核**
//      "每台服务器只收到 2 个批量帧（6+34N / 6+58N 字节）"，
//      而不是靠注释。
//   4. **逐记录校验**：篡改注入 ≥ 4 类（改 e / 改 d / 改共享 / 跨记录串味 /
//      帧内重放 / 跨查询重放（换盐）），逐类断言"**抛异常 + 分类正确 + 没有返回和**"。
//   5. 边界：`N` 非 128 倍数、单记录、全命中、零命中（空 filter）、
//      `f_bits.size() != N`、属性号越界、`count` 与 `popcount` 不一致。
//   6. 等价性：批量 ≡ 逐记录（`RunSecureMulPerRecord`）的 `z` 向量逐元素相等。
//   7. 确定性：同种子两次运行逐位一致（不 flaky）。
//   8. 规模：`N = 2^14` 的批量路径实测数字（`offline_triple_ms`/`online_ms`/
//      `verify_ms`/`server_state_peak_bytes`）+ 端到端 `Sum` 与基准对照。
//
// ⚠️ 本文件不写 main（用 `tests/support` 的 TEST/EXPECT_* 宏与共享的 test_main.cpp）。
// ⚠️ `count == 0` 时 `AvgOverFilter` **抛 `std::domain_error`**（见文件头 §8 的裁决：
//    与 `mpraq_baseline::Avg` / VMPQ 的"零命中返回 0"不同，理由写在测试里）。
// ⚠️ 篡改注入的**请求方向**用 `LocalTransport` 的子类覆写 `Submit()` 实现
//    （`LocalTransportOptions::tamper_hook` 只覆盖**应答**方向）——
//    这与 `test_mpraq_securemul.cpp` 的 `CountingTransport` 是同一手法
//    （在链路上就地改字节），只是本文件改的是客户端发出的帧。

#include "core/random.hpp"
#include "mpraq/aggquery.hpp"
#include "mpraq/aggvalue.hpp"
#include "mpraq/init.hpp"
#include "mpraq/lcte.hpp"
#include "mpraq/node.hpp"
#include "mpraq/predicate.hpp"
#include "net/transport.hpp"
#include "shared/secret_sharing.hpp"
#include "test_framework.hpp"

#include "mpraq_baseline.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
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
// 独立手算的期望值（**不是**从被测代码里抄的）
// ---------------------------------------------------------------------------
// 数据是确定性的公式（不是 PRNG）：attr0 = i % 5、attr1 = (i/2) % 3。
// 下面每个常量都由一段独立的 python 暴力脚本算出（逐记录判定谓词、累加），
// 与 `mpraq_baseline` 相互独立 ⇒ 三路对照（协议 / 基准 / 手算常量）。
//
//   case A：N=100，Φ = (attr0 ∈ [1,4)) ∧ (attr1 ≥ 1)，sum_attr = 1 ⇒ (39, 57)
//   case B：N=257，Φ = (attr0 ∈ [0,3)) ∧ (attr1 ≥ 1) ∧ (attr1 ≤ 1)，sum_attr = 0 ⇒ (50, 50)
//   case C：N=1024，Φ = (attr0 ≥ 1) ∧ (attr0 < 4) ∧ (attr1 ≠ 2)，sum_attr = 1 ⇒ (411, 206)
//   case D：N=1，Φ = (attr0 ∈ [0,1))，sum_attr = 1 ⇒ (1, 0)
//   case E：N=300，Φ = (attr0 ∈ [0,5))（**全命中**），sum_attr = 0 ⇒ (300, 600)
//   case E2：N=1024，Φ = (attr0 ∈ [0,5))（全命中），sum_attr = 0 ⇒ (1024, 2046)
//   case F：N=300，Φ = (attr0 ≥ 3) ∧ (attr0 ≤ 1)（**恒假 ⇒ 零命中**）⇒ (0, 0)
//   case G：N=16384，Φ = (attr0 ∈ [1,4)) ∧ (attr1 ≥ 1)，sum_attr = 1 ⇒ (6554, 9830)
constexpr uint64_t kCaseACount = 39, kCaseASum = 57;
constexpr uint64_t kCaseBCount = 50, kCaseBSum = 50;
constexpr uint64_t kCaseCCount = 411, kCaseCSum = 206;
constexpr uint64_t kCaseDCount = 1, kCaseDSum = 0;
constexpr uint64_t kCaseECount = 300, kCaseESum = 600;
constexpr uint64_t kCaseE2Count = 1024, kCaseE2Sum = 2046;
constexpr uint64_t kCaseGCount = 6554, kCaseGSum = 9830;

// 属性布局（与 `test_mpraq_count.cpp` 同构，便于对照）：
//   属性 0：R = [0,5]、m = 6、domain = [0,4]；属性 1：R = [0,3]、m = 4、domain = [0,2]
constexpr uint32_t kAttr0M = 6;
constexpr uint32_t kAttr1M = 4;
constexpr int64_t kAttr0DomainMax = 4;
constexpr int64_t kAttr1DomainMax = 2;
constexpr double kFastEps = 1e-4;

// 确定性随机源（显式种子；**不用** CSPRNG）
std::array<uint8_t, kAesKeyBytes> SeedKey(const std::string& seed) {
    std::vector<uint8_t> bytes(seed.begin(), seed.end());
    return MakeAesSeed(std::move(bytes));
}

// ---------------------------------------------------------------------------
// Schema / 记录（确定性；跨运行逐位一致）
// ---------------------------------------------------------------------------

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
        recs[i].feature = static_cast<int64_t>(i * 7 + 3);
        recs[i].attributes = {static_cast<int64_t>(i % 5),
                              static_cast<int64_t>((i / 2) % 3)};
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

// ---------------------------------------------------------------------------
// 谓词构造（`tsb::mpraq::Predicate` ↔ `mpraq_baseline::Pred` 的**显式转写**）
// ---------------------------------------------------------------------------

Predicate P(uint32_t attr, PredicateOp op, int64_t v) {
    Predicate p;
    p.by_id = true;
    p.attribute_id = attr;
    p.op = op;
    p.value = v;
    return p;
}
Predicate R(uint32_t attr, int64_t a, int64_t b) {
    Predicate p;
    p.by_id = true;
    p.attribute_id = attr;
    p.op = PredicateOp::kRange;
    p.lower = a;
    p.upper = b;
    return p;
}
mpraq_baseline::Pred BP(uint32_t attr, mpraq_baseline::Op op, int64_t v) {
    return mpraq_baseline::Pred{attr, op, v, 0, 0};
}
mpraq_baseline::Pred BR(uint32_t attr, int64_t a, int64_t b) {
    return mpraq_baseline::Pred{attr, mpraq_baseline::Op::kRange, 0, a, b};
}

// ---------------------------------------------------------------------------
// 夹具：`Init` 一次，多次 `Sum` 复用（`Sum` 不消耗 PIR 预算，只有 `Count` 消耗）
// ---------------------------------------------------------------------------

struct Fixture {
    size_t n = 0;
    Schema schema;
    std::vector<MpraqRecord> records;
    mpraq_baseline::Dataset baseline;
    std::unique_ptr<MpraqClient> client;
    // α / ⟨α⟩_p：**全局一份**（MPA-05 §6.6），从 `Init` 的 `mac_key_shares()` 构造
    SecureMulClientState mac{1, {1, 0}, kMpraqModulus};
    std::unique_ptr<random::DeterministicPrng> prng;

    static Fixture Make(size_t n, uint32_t lambda = 16, uint64_t init_seed = 7,
                        uint64_t prng_seed = 11) {
        Fixture f;
        f.n = n;
        f.schema = MakeSchema(n);
        f.records = MakeRecords(n);
        f.baseline = MakeBaseline(f.records);
        MpraqInitParams p;
        p.lambda = lambda;
        p.prp_epsilon = kFastEps;
        p.seed = init_seed;
        f.client = MpraqClient::Init(f.schema, f.records, p);
        f.mac = SecureMulClientState(f.client->mac_key_shares(), f.client->modulus());
        f.prng = std::make_unique<random::DeterministicPrng>(SeedKey("mpa06-sum"), prng_seed);
        return f;
    }

    uint128_t q() const { return client->modulus(); }

    std::vector<ModShare> E(size_t attr, int server) const {
        return client->AttributeShares(static_cast<uint32_t>(attr), server);
    }
};

// ---------------------------------------------------------------------------
// 一次 `Sum` 的尝试结果（把"有没有返回和"显式记下来）
// ---------------------------------------------------------------------------

struct Attempt {
    bool produced = false;        // **返回了** SumResult（注入用例里必须为 false）
    bool aborted = false;         // 抛了 SecureMulBatchAbort
    bool other_exception = false; // 抛了别的异常（也算 abort，但要单独看）
    SecureMulFailure failure = SecureMulFailure::kNone;
    SecureMulBatchError kind = SecureMulBatchError::kNone;
    size_t index = 0;
    uint128_t sum = 0;
    std::string what;
};

Attempt TrySum(Fixture& f, const CountResult& c, uint32_t attr, LocalTransport& net,
               uint64_t salt) {
    Attempt a;
    try {
        const SumResult s = SumOverFilter(c, f.schema, attr, *f.client, net, f.mac,
                                         *f.prng, salt);
        a.produced = true;
        a.sum = s.sum;
    } catch (const SecureMulBatchAbort& e) {
        a.aborted = true;
        a.failure = e.failure();
        a.kind = e.error_kind();
        a.index = e.record_index();
        a.what = e.what();
    } catch (const std::exception& e) {
        a.other_exception = true;
        a.what = e.what();
    }
    return a;
}

// 一次端到端 `Sum`（含与基准 + 手算常量的三路对照）
struct CheckedSum {
    CountResult c;
    SumResult s;
    uint128_t avg = 0;
};

CheckedSum RunAndCheckSum(Fixture& f, const std::vector<Predicate>& preds,
                          const std::vector<mpraq_baseline::Pred>& bpreds,
                          uint32_t sum_attr, uint64_t salt, uint64_t expect_count,
                          uint64_t expect_sum) {
    CheckedSum out;
    out.c = CountPredicates(*f.client, f.schema, preds);
    LocalTransport net(2);
    out.s = SumOverFilter(out.c, f.schema, sum_attr, *f.client, net, f.mac, *f.prng, salt);
    out.avg = AvgOverFilter(out.s);

    // (1) 与 baseline 的暴力结果逐值对照
    const mpraq_baseline::Moments m = mpraq_baseline::Aggregate(f.baseline, bpreds, sum_attr);
    EXPECT_EQ(out.c.count, m.count);
    EXPECT_EQ(out.s.count, m.count);
    EXPECT_EQ(out.s.sum, static_cast<uint128_t>(m.sum));
    EXPECT_EQ(out.avg, static_cast<uint128_t>(m.count == 0 ? 0 : m.sum / m.count));
    // filter 逐位一致（形状字符串对照，失败时肉眼可见差异）
    EXPECT_EQ(mpraq_baseline::FilterShape(mpraq_baseline::Filter(f.baseline, bpreds)),
              mpraq_baseline::FilterShape(out.c.filter));
    // (2) 与**独立手算的常量**对照（不同 N、非 128 倍数、全命中、零命中都覆盖）
    EXPECT_EQ(out.c.count, expect_count);
    EXPECT_EQ(out.s.count, expect_count);
    EXPECT_EQ(out.s.sum, static_cast<uint128_t>(expect_sum));
    // (3) 恒定模式账目
    EXPECT_EQ(out.s.securemul.records, f.n);
    EXPECT_EQ(out.s.securemul.rounds, uint64_t{2});
    EXPECT_EQ(out.s.securemul.messages, 2 * f.n);
    EXPECT_EQ(out.s.securemul.wire_messages, 4 * f.n);
    EXPECT_EQ(out.s.securemul.server_records_processed[0], f.n);
    EXPECT_EQ(out.s.securemul.server_records_processed[1], f.n);
    EXPECT_EQ(out.s.securemul.server_records_processed_phase2[0], f.n);
    EXPECT_EQ(out.s.securemul.server_records_processed_phase2[1], f.n);
    // (4) 属性口径：Sum 用的 ⟨E⟩ 重建出来必须 == 明文属性值（MPA-03 的加法共享）
    for (size_t i = 0; i < f.n; i += (f.n / 7 + 1)) {  // 抽样（全量在专用用例里做）
        const uint128_t e =
            ReconstructMod(f.E(sum_attr, 0)[i], f.E(sum_attr, 1)[i], f.q());
        EXPECT_EQ(e, static_cast<uint128_t>(f.records[i].attributes[sum_attr]));
    }
    return out;
}

// ---------------------------------------------------------------------------
// 篡改注入用的传输（请求方向覆写 `Submit`；应答方向覆写 `Collect`）
// ---------------------------------------------------------------------------
//
// ⚠️ 帧布局（与 `aggvalue.hpp` §1 一致；下面的常量在用例开头会被**实测复核**）：
//   帧 = 6 字节头 + N 条 MPA-05 定长消息
//     Phase1Request 34 B：ver type | session(2) challenge(10) d(18)
//     Phase1Response 27 B：ver type | session(2) e_computed(10) status(26)
//     Phase2Request 58 B：ver type | session(2) d(10) e(26) e_check(42)
//     Phase2Response 43 B：ver type | session(2) z_share(10) mac_share(26) status(42)
constexpr size_t kFrameHdr = 6;
constexpr size_t kP1Req = 34, kP1Res = 27, kP2Req = 58, kP2Res = 43;
constexpr size_t kP1FieldD = 18;
constexpr size_t kP2FieldD = 10, kP2FieldE = 26, kP2FieldECheck = 42;
constexpr size_t kR1FieldEComputed = 10, kR1FieldStatus = 26;
constexpr size_t kR2FieldZ = 10, kR2FieldMac = 26, kR2FieldStatus = 42;

size_t OffP1(size_t i, size_t field) { return kFrameHdr + i * kP1Req + field; }
size_t OffP2(size_t i, size_t field) { return kFrameHdr + i * kP2Req + field; }
size_t OffR1(size_t i, size_t field) { return kFrameHdr + i * kP1Res + field; }
size_t OffR2(size_t i, size_t field) { return kFrameHdr + i * kP2Res + field; }

class InjectTransport : public LocalTransport {
public:
    // 返回值 = 实际改动的字节数（0 表示注入没打中 ⇒ 用例会失败而不是静默通过）
    using FrameHook =
        std::function<size_t(int server_id, uint64_t round, Payload& frame)>;

    InjectTransport() : LocalTransport(2) {}

    void SetRequestHook(FrameHook h) { req_hook_ = std::move(h); }
    void SetResponseHook(FrameHook h) { resp_hook_ = std::move(h); }
    void ClearHooks() {
        req_hook_ = nullptr;
        resp_hook_ = nullptr;
    }
    void ResetRounds() {
        submit_round_ = {{0, 0}};
        resp_round_ = {{0, 0}};
        hits_ = 0;
    }
    size_t hits() const { return hits_; }
    // 记录所有提交过的帧（"跨查询重放"用例要搬旧帧里的子消息）
    const std::vector<Payload>& frames(int server_id) const {
        return frames_[static_cast<size_t>(server_id)];
    }

    void Submit(int server_id, Payload request) override {
        const uint64_t round = submit_round_[static_cast<size_t>(server_id)]++;
        frames_[static_cast<size_t>(server_id)].push_back(request);
        if (req_hook_) {
            hits_ += req_hook_(server_id, round, request);
        }
        LocalTransport::Submit(server_id, std::move(request));
    }

    std::vector<Response> Collect() override {
        std::vector<Response> responses = LocalTransport::Collect();
        if (!resp_hook_) {
            return responses;
        }
        // 本层的 Submit 顺序恒为 [server0, server1]（批量路径每轮各一个帧）
        // ⇒ 应答下标即 server_id；`Collect()` 的轮次就是"第 1 轮/第 2 轮"。
        for (size_t i = 0; i < responses.size() && i < 2; ++i) {
            if (!responses[i].ok) {
                continue;
            }
            const uint64_t round = resp_round_[i]++;
            hits_ += resp_hook_(static_cast<int>(i), round, responses[i].payload);
        }
        return responses;
    }

private:
    FrameHook req_hook_;
    FrameHook resp_hook_;
    std::array<uint64_t, 2> submit_round_{{0, 0}};
    std::array<uint64_t, 2> resp_round_{{0, 0}};
    std::array<std::vector<Payload>, 2> frames_;
    size_t hits_ = 0;
};

// 合成输入（性能/往返用例用：不经过 `Init`，直接给 f 与 ⟨E⟩）
std::vector<uint8_t> SyntheticFilter(size_t n) {
    std::vector<uint8_t> f(n);
    for (size_t i = 0; i < n; ++i) {
        f[i] = ((i * 7 + 1) % 5 == 0) ? 1 : 0;
    }
    return f;
}
std::vector<uint128_t> SyntheticValues(size_t n) {
    std::vector<uint128_t> v(n);
    for (size_t i = 0; i < n; ++i) {
        v[i] = static_cast<uint128_t>((i % 1000) + 1);
    }
    return v;
}
std::pair<std::vector<ModShare>, std::vector<ModShare>> ShareValues(
    const std::vector<uint128_t>& values, uint128_t q, random::DeterministicPrng& prng) {
    std::vector<ModShare> s0, s1;
    s0.reserve(values.size());
    s1.reserve(values.size());
    for (uint128_t v : values) {
        const auto p = ShareValueDeterministic(v, q, prng);
        s0.push_back(p.first);
        s1.push_back(p.second);
    }
    return {std::move(s0), std::move(s1)};
}
uint128_t SyntheticExpectedSum(const std::vector<uint8_t>& f,
                               const std::vector<uint128_t>& v, uint128_t q) {
    uint128_t sum = 0;
    for (size_t i = 0; i < f.size(); ++i) {
        sum = addMod(sum, mulMod(static_cast<uint128_t>(f[i]), v[i], q), q);
    }
    return sum;
}

uint64_t Popcount(const std::vector<uint8_t>& v) {
    uint64_t n = 0;
    for (uint8_t b : v) n += (b != 0) ? 1u : 0u;
    return n;
}

}  // namespace

// ===========================================================================
// 1. Sum 与明文基准逐值相等（3 组不同 N，含 N 非 128 的倍数）
// ===========================================================================

TEST(MpraqSum, SumMatchesPlaintextBaselineRangeAndGeWindow100) {
    Fixture f = Fixture::Make(100, /*lambda=*/16);
    // 组 A：N=100（**不是 128 的倍数**）
    const CheckedSum r = RunAndCheckSum(
        f, {R(0, 1, 4), P(1, PredicateOp::kGe, 1)},
        {BR(0, 1, 4), BP(1, mpraq_baseline::Op::kGe, 1)}, /*sum_attr=*/1, 0x1001'0001,
        kCaseACount, kCaseASum);
    EXPECT_EQ(r.s.sum, static_cast<uint128_t>(57));  // 手算常量（见文件头）
    EXPECT_EQ(r.avg, static_cast<uint128_t>(57 / 39));
}

TEST(MpraqSum, SumMatchesPlaintextBaselineThreePredicatesWindow257) {
    Fixture f = Fixture::Make(257, /*lambda=*/16);
    // 组 B：N=257（**不是 128 的倍数**，且 ⌈N/128⌉=3）
    const CheckedSum r = RunAndCheckSum(
        f, {R(0, 0, 3), P(1, PredicateOp::kGe, 1), P(1, PredicateOp::kLe, 1)},
        {BR(0, 0, 3), BP(1, mpraq_baseline::Op::kGe, 1), BP(1, mpraq_baseline::Op::kLe, 1)},
        /*sum_attr=*/0, 0x2002'0002, kCaseBCount, kCaseBSum);
    EXPECT_EQ(r.s.sum, static_cast<uint128_t>(50));
}

TEST(MpraqSum, SumMatchesPlaintextBaselineMultiPredicateWindow1024) {
    Fixture f = Fixture::Make(1024, /*lambda=*/32);
    // 组 C：N=1024（128 的倍数）+ 跨两个属性的 3 个谓词
    const CheckedSum r = RunAndCheckSum(
        f, {P(0, PredicateOp::kGe, 1), P(0, PredicateOp::kLt, 4), P(1, PredicateOp::kNeq, 2)},
        {BP(0, mpraq_baseline::Op::kGe, 1), BP(0, mpraq_baseline::Op::kLt, 4),
         BP(1, mpraq_baseline::Op::kNe, 2)},
        /*sum_attr=*/1, 0x3003'0003, kCaseCCount, kCaseCSum);
}

// ===========================================================================
// 2. 边界：单记录 / 全命中 / 零命中（空 filter）
// ===========================================================================

TEST(MpraqSum, SingleRecordAndAllHitWindowsMatchBaseline) {
    {
        // 组 D：N=1（单记录；attr0 = 0、attr1 = 0）
        Fixture f = Fixture::Make(1, /*lambda=*/16);
        const CheckedSum r = RunAndCheckSum(f, {R(0, 0, 1)}, {BR(0, 0, 1)},
                                           /*sum_attr=*/1, 0x4004'0004, kCaseDCount,
                                           kCaseDSum);
        EXPECT_EQ(r.avg, static_cast<uint128_t>(0));
    }
    {
        // 组 E：N=300（**不是 128 的倍数**）**全命中**：Φ = attr0 ∈ [0,5)
        Fixture f = Fixture::Make(300, /*lambda=*/16);
        const CheckedSum r = RunAndCheckSum(f, {R(0, 0, 5)}, {BR(0, 0, 5)},
                                           /*sum_attr=*/0, 0x5005'0005, kCaseECount,
                                           kCaseESum);
        EXPECT_EQ(r.c.count, f.n);  // 全命中
        EXPECT_EQ(r.avg, static_cast<uint128_t>(2));
    }
}

TEST(MpraqSum, CountZeroAbortsAvg) {
    // 组 F：N=300，Φ = (attr0 ≥ 3) ∧ (attr0 ≤ 1) —— 同一属性上的**矛盾**条件 ⇒ 恒假
    Fixture f = Fixture::Make(300, /*lambda=*/16);
    CheckedSum r;
    r.c = CountPredicates(*f.client, f.schema,
                          {P(0, PredicateOp::kGe, 3), P(0, PredicateOp::kLe, 1)});
    EXPECT_EQ(r.c.count, uint64_t{0});
    EXPECT_EQ(Popcount(r.c.filter), uint64_t{0});
    // Sum 本身**正常返回**（零命中的和就是 0，这是经 MAC 认证的正确结果）
    LocalTransport net(2);
    r.s = SumOverFilter(r.c, f.schema, /*attr_id=*/1, *f.client, net, f.mac, *f.prng,
                        0x6006'0006);
    EXPECT_EQ(r.s.count, uint64_t{0});
    EXPECT_EQ(r.s.sum, static_cast<uint128_t>(0));
    // ⚠️ 裁决点：`count == 0` 时 Avg **抛 std::domain_error**，
    //    不得静默返回 0（0 是可达的真实均值 ⇒ 两者不可区分）。
    EXPECT_THROW(AvgOverFilter(r.s), std::domain_error);
    // 手搓一个 count = 0 的 SumResult 也一样（防御性）
    SumResult zero;
    zero.sum = 0;
    zero.count = 0;
    EXPECT_THROW(AvgOverFilter(zero), std::domain_error);
    // 对照：baseline 在这个情形下**返回 0**（口径差异，见文件头 §8 的裁决说明）
    const mpraq_baseline::Moments m =
        mpraq_baseline::Aggregate(f.baseline, {BP(0, mpraq_baseline::Op::kGe, 3),
                                               BP(0, mpraq_baseline::Op::kLe, 1)},
                                  1);
    EXPECT_EQ(m.count, uint64_t{0});
    EXPECT_EQ(mpraq_baseline::Avg(f.baseline,
                                  {BP(0, mpraq_baseline::Op::kGe, 3),
                                   BP(0, mpraq_baseline::Op::kLe, 1)},
                                  1),
              uint64_t{0});
}

TEST(MpraqSum, NoPruningWhenFilterAllZero) {
    // 零命中（filter 全 0）时**不剪枝**：整列 N 条照发
    Fixture f = Fixture::Make(300, /*lambda=*/16);
    const CountResult c = CountPredicates(
        *f.client, f.schema, {P(0, PredicateOp::kGe, 3), P(0, PredicateOp::kLe, 1)});
    ASSERT_EQ(c.count, uint64_t{0});
    ASSERT_EQ(c.filter.size(), f.n);
    EXPECT_EQ(Popcount(c.filter), uint64_t{0});  // 真的是全 0

    LocalTransport net(2);
    net.ResetStats();
    const SumResult s = SumOverFilter(c, f.schema, /*attr_id=*/1, *f.client, net, f.mac,
                                     *f.prng, 0x7007'0007);

    // ① Sum 层账目（**不剪枝**）
    EXPECT_EQ(s.count, uint64_t{0});
    EXPECT_EQ(s.sum, static_cast<uint128_t>(0));
    EXPECT_EQ(s.securemul.records, f.n);
    EXPECT_EQ(s.securemul.rounds, uint64_t{2});
    EXPECT_EQ(s.securemul.phase1_messages, f.n);
    EXPECT_EQ(s.securemul.phase2_messages, f.n);
    EXPECT_EQ(s.securemul.messages, 2 * f.n);
    EXPECT_EQ(s.securemul.wire_messages, 4 * f.n);
    // ② "每一台服务器都处理了 N 条"——常量模式的**直接证据**
    EXPECT_EQ(s.securemul.server_records_processed[0], f.n);
    EXPECT_EQ(s.securemul.server_records_processed[1], f.n);
    EXPECT_EQ(s.securemul.server_records_processed_phase2[0], f.n);
    EXPECT_EQ(s.securemul.server_records_processed_phase2[1], f.n);
    EXPECT_EQ(s.securemul.server_frames[0], uint64_t{2});
    EXPECT_EQ(s.securemul.server_frames[1], uint64_t{2});
    // ③ 传输层独立复核：每台恰好 2 个帧（= 2 个往返），帧长 = 6 + 34N / 6 + 58N
    EXPECT_EQ(net.RequestCount(0), uint64_t{2});
    EXPECT_EQ(net.RequestCount(1), uint64_t{2});
    ASSERT_EQ(net.RequestLog(0).size(), size_t{2});
    EXPECT_EQ(net.RequestLog(0)[0].size(), kFrameHdr + kP1Req * f.n);
    EXPECT_EQ(net.RequestLog(0)[1].size(), kFrameHdr + kP2Req * f.n);
    EXPECT_EQ(net.RequestLog(1)[0].size(), kFrameHdr + kP1Req * f.n);
    EXPECT_EQ(net.RequestLog(1)[1].size(), kFrameHdr + kP2Req * f.n);
    EXPECT_EQ(s.securemul.frame_bytes_phase1, kFrameHdr + kP1Req * f.n);
    EXPECT_EQ(s.securemul.frame_bytes_phase2, kFrameHdr + kP2Req * f.n);
}

// ===========================================================================
// 3. Avg 的整数向下取整（与 VMPQ 同口径）
// ===========================================================================

TEST(MpraqSum, AvgIntegerDivisionMatchesVmpq) {
    Fixture f = Fixture::Make(1024, /*lambda=*/32);
    // 全命中：count = 1024、sum = 2046 ⇒ 2046/1024 = 1.998… ⇒ **向下取整 = 1**
    const CheckedSum r = RunAndCheckSum(f, {R(0, 0, 5)}, {BR(0, 0, 5)}, /*sum_attr=*/0,
                                        0x8008'0008, kCaseE2Count, kCaseE2Sum);
    EXPECT_EQ(r.s.sum, static_cast<uint128_t>(2046));
    EXPECT_EQ(r.avg, static_cast<uint128_t>(1));  // 不是四舍五入的 2
    // 向下取整的**判据**：avg·count ≤ sum < (avg+1)·count
    EXPECT_TRUE(r.avg * static_cast<uint128_t>(r.s.count) <= r.s.sum);
    EXPECT_TRUE(r.s.sum < (r.avg + 1) * static_cast<uint128_t>(r.s.count));
    // 与 baseline / VMPQ 同口径（整数除法）
    EXPECT_EQ(r.avg, static_cast<uint128_t>(mpraq_baseline::Avg(f.baseline, {BR(0, 0, 5)}, 0)));

    // 另一组不能整除的：N=1024 组 C 的 206/411 = 0.501… ⇒ 向下取整 = 0（四舍五入会是 1）
    Fixture f2 = Fixture::Make(1024, /*lambda=*/32);
    const CheckedSum r2 = RunAndCheckSum(
        f2, {P(0, PredicateOp::kGe, 1), P(0, PredicateOp::kLt, 4), P(1, PredicateOp::kNeq, 2)},
        {BP(0, mpraq_baseline::Op::kGe, 1), BP(0, mpraq_baseline::Op::kLt, 4),
         BP(1, mpraq_baseline::Op::kNe, 2)},
        /*sum_attr=*/1, 0x9009'0009, kCaseCCount, kCaseCSum);
    EXPECT_EQ(r2.s.sum, static_cast<uint128_t>(206));
    EXPECT_EQ(r2.avg, static_cast<uint128_t>(0));
    EXPECT_TRUE(r2.avg * static_cast<uint128_t>(r2.s.count) <= r2.s.sum);
    EXPECT_TRUE(r2.s.sum < (r2.avg + 1) * static_cast<uint128_t>(r2.s.count));
}

// ===========================================================================
// 4. 批量 ≡ 逐记录（等价性）
// ===========================================================================

TEST(MpraqSum, BatchEqualsPerRecord) {
    const uint128_t q = kMpraqModulus;
    const size_t n = 130;  // 非 128 的倍数
    const std::vector<uint8_t> f = SyntheticFilter(n);
    const std::vector<uint128_t> values = SyntheticValues(n);
    const uint128_t expected = SyntheticExpectedSum(f, values, q);

    // 两条路径用**同一粒度的随机源**：同一个种子 ⇒ triple 逐位相同
    random::DeterministicPrng prng_batch(SeedKey("mpa06-equivalence"), 21);
    random::DeterministicPrng prng_perrec(SeedKey("mpa06-equivalence"), 21);
    const auto shares_batch = ShareValues(values, q, prng_batch);
    // ⚠️ 共享必须在两条路径上**完全相同**（"同一输入"），因此这里不重新生成：
    //    逐记录路径直接用批量路径的那两份共享。
    const std::vector<ModShare>& e0 = shares_batch.first;
    const std::vector<ModShare>& e1 = shares_batch.second;
    SecureMulClientState mac = SecureMulClientState::GenerateMacKey(q);

    LocalTransport net_batch(2);
    const SecureMulBatchOutcome batch = RunSecureMulBatch(f, e0, e1, net_batch, mac,
                                                          prng_batch, 0xA0A0'0001);
    LocalTransport net_perrec(2);
    const SecureMulBatchOutcome perrec = RunSecureMulPerRecord(f, e0, e1, net_perrec, mac,
                                                               prng_perrec, 0xA0A0'0001);

    ASSERT_EQ(batch.z.size(), n);
    ASSERT_EQ(perrec.z.size(), n);
    EXPECT_TRUE(batch.all_ok());
    EXPECT_TRUE(perrec.all_ok());
    EXPECT_EQ(batch.first_failure, SIZE_MAX);
    EXPECT_EQ(perrec.first_failure, SIZE_MAX);
    size_t compared = 0;
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(batch.ok[i], perrec.ok[i]);
        EXPECT_EQ(batch.z[i], perrec.z[i]);          // 逐元素相等
        EXPECT_EQ(batch.z[i], mulMod(static_cast<uint128_t>(f[i]), values[i], q));
        ++compared;
    }
    EXPECT_EQ(compared, n);
    EXPECT_EQ(batch.SumOrThrow(q), expected);
    EXPECT_EQ(perrec.SumOrThrow(q), expected);

    // 账目对照：批量 2 往返 / 逐记录 2N 往返（同一份输入，代价差 N 倍）
    EXPECT_EQ(batch.stats.rounds, uint64_t{2});
    EXPECT_EQ(batch.stats.messages, 2 * n);
    EXPECT_EQ(batch.stats.wire_messages, 4 * n);
    EXPECT_EQ(batch.stats.server_frames[0], uint64_t{2});
    EXPECT_EQ(perrec.stats.rounds, 2 * n);
    EXPECT_EQ(perrec.stats.messages, 2 * n);
    EXPECT_EQ(perrec.stats.wire_messages, 4 * n);
    EXPECT_EQ(perrec.stats.server_frames[0], 2 * n);
    std::printf("[MPA-06] BatchEqualsPerRecord N=%zu：批量 rounds=%llu frames/台=%llu ；"
                "逐记录 rounds=%llu frames/台=%llu（消息条数两边同为 %llu）\n",
                n, static_cast<unsigned long long>(batch.stats.rounds),
                static_cast<unsigned long long>(batch.stats.server_frames[0]),
                static_cast<unsigned long long>(perrec.stats.rounds),
                static_cast<unsigned long long>(perrec.stats.server_frames[0]),
                static_cast<unsigned long long>(batch.stats.wire_messages));
}

// ===========================================================================
// 5. 往返/消息条数与 N 无关（恒为 2 / 2N）
// ===========================================================================

TEST(MpraqSum, RoundsAndMessagesAreConstant) {
    const uint128_t q = kMpraqModulus;
    SecureMulClientState mac = SecureMulClientState::GenerateMacKey(q);
    const size_t sizes[] = {1, 100, 128, 129, 1000};
    for (size_t n : sizes) {
        const std::vector<uint8_t> f = SyntheticFilter(n);
        const std::vector<uint128_t> values = SyntheticValues(n);
        const uint128_t expected = SyntheticExpectedSum(f, values, q);

        random::DeterministicPrng prng(SeedKey("mpa06-constant"), 31);
        const auto shares = ShareValues(values, q, prng);
        LocalTransport net(2);
        net.ResetStats();
        const SecureMulBatchOutcome out = RunSecureMulBatch(
            f, shares.first, shares.second, net, mac, prng, 0xB0B0'0001 + n);

        EXPECT_TRUE(out.all_ok());
        EXPECT_EQ(out.stats.records, n);
        EXPECT_EQ(out.stats.rounds, uint64_t{2});
        EXPECT_EQ(out.stats.phase1_messages, n);
        EXPECT_EQ(out.stats.phase2_messages, n);
        EXPECT_EQ(out.stats.messages, 2 * n);
        EXPECT_EQ(out.stats.wire_messages, 4 * n);
        EXPECT_EQ(out.stats.collect_calls_phase1, uint64_t{1});
        EXPECT_EQ(out.stats.collect_calls_phase2, uint64_t{1});
        EXPECT_EQ(out.stats.server_records_processed[0], n);
        EXPECT_EQ(out.stats.server_records_processed[1], n);
        EXPECT_EQ(out.stats.server_records_processed_phase2[0], n);
        EXPECT_EQ(out.stats.server_records_processed_phase2[1], n);
        // 传输层独立复核：每台恰好 2 个帧，帧长 = 6 + 34N / 6 + 58N
        ASSERT_EQ(net.RequestCount(0), uint64_t{2});
        ASSERT_EQ(net.RequestCount(1), uint64_t{2});
        ASSERT_EQ(net.RequestLog(0).size(), size_t{2});
        EXPECT_EQ(net.RequestLog(0)[0].size(), kFrameHdr + kP1Req * n);
        EXPECT_EQ(net.RequestLog(0)[1].size(), kFrameHdr + kP2Req * n);
        // 数值：Σ z == Σ f·E
        EXPECT_EQ(out.SumOrThrow(q), expected);
    }
}

// ===========================================================================
// 6. 篡改注入：抛异常 + 分类正确 + **没有返回和**
// ===========================================================================

TEST(MpraqSumTamper, TamperAborts) {
    // 帧布局常量与 MPA-05 的实测长度对齐（若 MPA-05 改格式，这里立刻失败）
    ASSERT_EQ(SecureMulBatchMessageBytes(SecureMulBatchMsgType::kPhase1Request), kP1Req);
    ASSERT_EQ(SecureMulBatchMessageBytes(SecureMulBatchMsgType::kPhase1Response), kP1Res);
    ASSERT_EQ(SecureMulBatchMessageBytes(SecureMulBatchMsgType::kPhase2Request), kP2Req);
    ASSERT_EQ(SecureMulBatchMessageBytes(SecureMulBatchMsgType::kPhase2Response), kP2Res);

    Fixture f = Fixture::Make(64, /*lambda=*/16);
    const CountResult c = CountPredicates(*f.client, f.schema, {R(0, 1, 4)});
    ASSERT_TRUE(c.count > 0);
    // 目标记录：**f=1** 的那条（f=0 时"改 e"在数学上无影响 ⇒ 不需要检出，见下）
    size_t target = SIZE_MAX;
    for (size_t i = 0; i < c.filter.size(); ++i) {
        if (c.filter[i] == 1) {
            target = i;
            break;
        }
    }
    ASSERT_TRUE(target != SIZE_MAX);
    ASSERT_TRUE(target + 1 < f.n);
    const size_t partner = target + 1;  // 另一条记录（跨记录串味的来源/目标）

    const uint64_t salt1 = 0xC0C0'0001;
    const uint64_t salt2 = 0xC0C0'0002;  // 与 salt1 **不同**（跨查询重放要换盐）

    // ---- (0) 无注入的对照：必须**正常返回**，并且和 == 基准 ----
    {
        InjectTransport net;
        const Attempt a = TrySum(f, c, 0, net, salt1);
        EXPECT_TRUE(a.produced);
        EXPECT_FALSE(a.aborted);
        EXPECT_EQ(a.sum, static_cast<uint128_t>(
                             mpraq_baseline::Sum(f.baseline, {BR(0, 1, 4)}, 0)));
    }

    // ---- (1) 改 e（**两台一致偏移**，第 2 轮请求）----
    // 这是论文只靠 `mac == α·z` 抓不住的那一类：z 与 mac 一起偏移，MAC 恒成立。
    // 能被检出**只因为** `VerifyAndReconstruct` 拿到了 `bundle.ctx`
    //（§4.5-A：z ≠ f·(e_sent + b)）⇒ 本用例的期望分类 `kClientLocalCheckFailed`
    //  本身就是"我们确实传了 ctx"的证据（不传 ctx 时该分类不可能出现）。
    {
        InjectTransport net;
        net.SetRequestHook([&](int /*sid*/, uint64_t round, Payload& frame) -> size_t {
            if (round != 1) return 0;  // 1 = 第 2 轮（Phase2Request 帧）
            const size_t off = OffP2(target, kP2FieldE);
            if (off >= frame.size()) return 0;
            frame[off] ^= 0x01;
            return 1;
        });
        const Attempt a = TrySum(f, c, 0, net, salt1);
        EXPECT_TRUE(net.hits() > 0);
        EXPECT_FALSE(a.produced);  // **没有返回任何 SumResult**
        EXPECT_TRUE(a.aborted);
        EXPECT_EQ(static_cast<int>(a.failure),
                  static_cast<int>(SecureMulFailure::kClientLocalCheckFailed));
        EXPECT_EQ(a.index, target);
    }

    // ---- (2) 改 d（两台，第 1 轮请求）----
    // 服务器第 2 轮会用"自己第 1 轮收到的 d"做跨轮一致性检查 ⇒ kDCheckFailed
    {
        InjectTransport net;
        net.SetRequestHook([&](int /*sid*/, uint64_t round, Payload& frame) -> size_t {
            if (round != 0) return 0;
            const size_t off = OffP1(target, kP1FieldD);
            if (off >= frame.size()) return 0;
            frame[off] ^= 0x01;
            return 1;
        });
        const Attempt a = TrySum(f, c, 0, net, salt1);
        EXPECT_TRUE(net.hits() > 0);
        EXPECT_FALSE(a.produced);
        EXPECT_TRUE(a.aborted);
        EXPECT_EQ(static_cast<int>(a.failure),
                  static_cast<int>(SecureMulFailure::kServerReported));
        EXPECT_EQ(a.index, target);
    }

    // ---- (3) 改共享：篡改某台的 ⟨e⟩_p 回执（第 1 轮应答）----
    // 客户端把它**收到的**值原样回给该台 ⇒ 该台自己的 e 一致性检查拒绝（kECheckFailed）
    {
        InjectTransport net;
        net.SetResponseHook([&](int sid, uint64_t round, Payload& frame) -> size_t {
            if (sid != 0 || round != 0) return 0;
            const size_t off = OffR1(target, kR1FieldEComputed);
            if (off >= frame.size()) return 0;
            frame[off] ^= 0x01;
            return 1;
        });
        const Attempt a = TrySum(f, c, 0, net, salt1);
        EXPECT_TRUE(net.hits() > 0);
        EXPECT_FALSE(a.produced);
        EXPECT_TRUE(a.aborted);
        EXPECT_EQ(static_cast<int>(a.failure),
                  static_cast<int>(SecureMulFailure::kServerReported));
        EXPECT_EQ(a.index, target);
    }

    // ---- (4) 改共享：篡改某台的 z_p（第 2 轮应答）----
    {
        InjectTransport net;
        net.SetResponseHook([&](int sid, uint64_t round, Payload& frame) -> size_t {
            if (sid != 1 || round != 1) return 0;
            const size_t off = OffR2(target, kR2FieldZ);
            if (off >= frame.size()) return 0;
            frame[off] ^= 0x01;
            return 1;
        });
        const Attempt a = TrySum(f, c, 0, net, salt1);
        EXPECT_TRUE(net.hits() > 0);
        EXPECT_FALSE(a.produced);
        EXPECT_TRUE(a.aborted);
        EXPECT_EQ(static_cast<int>(a.failure),
                  static_cast<int>(SecureMulFailure::kClientLocalCheckFailed));
        EXPECT_EQ(a.index, target);
    }

    // ---- (5) 改共享：篡改某台的 mac_p（第 2 轮应答）⇒ SPDZ MAC 失败 ----
    {
        InjectTransport net;
        net.SetResponseHook([&](int sid, uint64_t round, Payload& frame) -> size_t {
            if (sid != 0 || round != 1) return 0;
            const size_t off = OffR2(target, kR2FieldMac);
            if (off >= frame.size()) return 0;
            frame[off] ^= 0x01;
            return 1;
        });
        const Attempt a = TrySum(f, c, 0, net, salt1);
        EXPECT_TRUE(net.hits() > 0);
        EXPECT_FALSE(a.produced);
        EXPECT_TRUE(a.aborted);
        EXPECT_EQ(static_cast<int>(a.failure),
                  static_cast<int>(SecureMulFailure::kMacMismatch));
        EXPECT_EQ(a.index, target);
    }

    // ---- (6) 改状态字节：某台在第 2 轮自报 kECheckFailed ----
    {
        InjectTransport net;
        net.SetResponseHook([&](int sid, uint64_t round, Payload& frame) -> size_t {
            if (sid != 1 || round != 1) return 0;
            const size_t off = OffR2(target, kR2FieldStatus);
            if (off >= frame.size()) return 0;
            frame[off] = static_cast<uint8_t>(SecureMulStatus::kECheckFailed);
            return 1;
        });
        const Attempt a = TrySum(f, c, 0, net, salt1);
        EXPECT_TRUE(net.hits() > 0);
        EXPECT_FALSE(a.produced);
        EXPECT_TRUE(a.aborted);
        EXPECT_EQ(static_cast<int>(a.failure),
                  static_cast<int>(SecureMulFailure::kServerReported));
    }

    // ---- (7) 跨记录串味：把 partner 的 e_check 塞进 target 的 Phase2Request ----
    {
        InjectTransport net;
        net.SetRequestHook([&](int /*sid*/, uint64_t round, Payload& frame) -> size_t {
            if (round != 1) return 0;
            const size_t dst = OffP2(target, kP2FieldECheck);
            const size_t src = OffP2(partner, kP2FieldECheck);
            if (src + 16 > frame.size() || dst + 16 > frame.size()) return 0;
            std::copy(frame.begin() + static_cast<long>(src),
                      frame.begin() + static_cast<long>(src + 16),
                      frame.begin() + static_cast<long>(dst));
            return 16;
        });
        const Attempt a = TrySum(f, c, 0, net, salt1);
        EXPECT_TRUE(net.hits() > 0);
        EXPECT_FALSE(a.produced);
        EXPECT_TRUE(a.aborted);
        // 服务器侧的 e 一致性检查先拒绝（kECheckFailed ⇒ kServerReported）
        EXPECT_EQ(static_cast<int>(a.failure),
                  static_cast<int>(SecureMulFailure::kServerReported));
    }

    // ---- (8) 帧内重放：把更早那条记录的整条 Phase1Request 复制到 target 的槽位 ----
    // 分派按 session 走 ⇒ 被重放的那台 state 已消费 ⇒ 结构化拒绝；
    // 而 target 槽位收到的应答 session 是**别人的** ⇒ 客户端按 kSessionMismatch 检出。
    {
        InjectTransport net;
        const size_t src_rec = target - 1;
        net.SetRequestHook([&](int sid, uint64_t round, Payload& frame) -> size_t {
            if (sid != 0 || round != 0) return 0;
            const size_t dst = kFrameHdr + target * kP1Req;
            const size_t src = kFrameHdr + src_rec * kP1Req;
            if (src + kP1Req > frame.size() || dst + kP1Req > frame.size()) return 0;
            std::copy(frame.begin() + static_cast<long>(src),
                      frame.begin() + static_cast<long>(src + kP1Req),
                      frame.begin() + static_cast<long>(dst));
            return kP1Req;
        });
        const Attempt a = TrySum(f, c, 0, net, salt1);
        EXPECT_TRUE(net.hits() > 0);
        EXPECT_FALSE(a.produced);
        EXPECT_TRUE(a.aborted);
        EXPECT_TRUE(a.failure == SecureMulFailure::kSessionMismatch ||
                    a.failure == SecureMulFailure::kServerReported);
        EXPECT_EQ(a.index, target);
    }

    // ---- (9) 跨查询重放：把第 1 次查询的第 1 轮帧搬进第 2 次查询（**换盐**）----
    // 这是"每次查询必须换随机盐"（MPA-05 §6.5）的作用点：session 与记录号绑定、
    // 不随查询变化 ⇒ 旧帧会被分派到同一条记录的 state，但 **challenge 不同** ⇒ 拒绝。
    {
        InjectTransport net;
        const Attempt first = TrySum(f, c, 0, net, salt1);  // 查询 1（不注入）
        ASSERT_TRUE(first.produced);
        ASSERT_TRUE(net.frames(0).size() >= 1);
        const Payload old_frame = net.frames(0)[0];  // 查询 1 的第 1 轮帧

        net.ClearHooks();
        net.ResetRounds();
        net.SetRequestHook([&](int sid, uint64_t round, Payload& frame) -> size_t {
            if (sid != 0 || round != 0) return 0;
            const size_t off = kFrameHdr + target * kP1Req;
            if (off + kP1Req > frame.size() || off + kP1Req > old_frame.size()) return 0;
            std::copy(old_frame.begin() + static_cast<long>(off),
                      old_frame.begin() + static_cast<long>(off + kP1Req),
                      frame.begin() + static_cast<long>(off));
            return kP1Req;
        });
        const Attempt a = TrySum(f, c, 0, net, salt2);  // 查询 2（**不同的盐**）
        EXPECT_TRUE(net.hits() > 0);
        EXPECT_FALSE(a.produced);
        EXPECT_TRUE(a.aborted);
        // challenge 不符 ⇒ 服务器 kPhaseError ⇒ kServerReported（session 仍能对上）
        EXPECT_EQ(static_cast<int>(a.failure),
                  static_cast<int>(SecureMulFailure::kServerReported));
        EXPECT_EQ(a.index, target);
    }

    // ---- (10) 深下标：对**最后一条** f=1 的记录做同样的"改 e"注入 ----
    // 目的：证明**逐记录**校验是整列生效的（不是只看开头几条）——
    // 期望分类与序号都必须精确落在该记录上。
    {
        size_t last = SIZE_MAX;
        for (size_t i = c.filter.size(); i-- > 0;) {
            if (c.filter[i] == 1) {
                last = i;
                break;
            }
        }
        ASSERT_TRUE(last != SIZE_MAX);
        ASSERT_TRUE(last != target);
        InjectTransport net;
        net.SetRequestHook([&](int /*sid*/, uint64_t round, Payload& frame) -> size_t {
            if (round != 1) return 0;
            const size_t off = OffP2(last, kP2FieldE);
            if (off >= frame.size()) return 0;
            frame[off] ^= 0x01;
            return 1;
        });
        const Attempt a = TrySum(f, c, 0, net, salt1);
        EXPECT_TRUE(net.hits() > 0);
        EXPECT_FALSE(a.produced);
        EXPECT_TRUE(a.aborted);
        EXPECT_EQ(static_cast<int>(a.failure),
                  static_cast<int>(SecureMulFailure::kClientLocalCheckFailed));
        EXPECT_EQ(a.index, last);  // 精确到记录序号（整列都逐条校验）
    }

    // ---- (11) 边界（**已知不可检出但无害**）：对 f=0 的记录改 e ----
    // 代数：改 e 后 Δz_p = δ·⟨a⟩_p + δ·d·2^{-1} ⇒ 两台相加 Δz = δ(a+d) = δ·f，
    // 且 Δmac = α·δ·f ⇒ **f = 0 时 z 与 mac 都不变**（一致、且 z = f·E = 0 本来就是
    // 正确答案）⇒ 这一类注入在 f=0 的记录上**不可检出也不需要检出**。
    // 反之 f = 1 时 Δz = δ ≠ 0（用例 (1) 已断言被 §4.5-A 检出）。
    // ⇒ 这条边界必须如实记录，不能被当成"注入没生效"。
    {
        size_t zero_rec = SIZE_MAX;
        for (size_t i = 0; i < c.filter.size(); ++i) {
            if (c.filter[i] == 0) {
                zero_rec = i;
                break;
            }
        }
        ASSERT_TRUE(zero_rec != SIZE_MAX);
        InjectTransport net;
        net.SetRequestHook([&](int /*sid*/, uint64_t round, Payload& frame) -> size_t {
            if (round != 1) return 0;
            const size_t off = OffP2(zero_rec, kP2FieldE);
            if (off >= frame.size()) return 0;
            frame[off] ^= 0x01;
            return 1;
        });
        const Attempt a = TrySum(f, c, 0, net, salt1);
        EXPECT_TRUE(net.hits() > 0);  // 注入确实打中了字节
        EXPECT_TRUE(a.produced);      // 但 f=0 ⇒ 结果不变、无需检出（见上面的代数）
        EXPECT_FALSE(a.aborted);
        EXPECT_EQ(a.sum, static_cast<uint128_t>(
                             mpraq_baseline::Sum(f.baseline, {BR(0, 1, 4)}, 0)));
    }
}

// ===========================================================================
// 7. 非法输入
// ===========================================================================

TEST(MpraqSum, RejectsBadInputs) {
    Fixture f = Fixture::Make(64, /*lambda=*/16);
    const uint128_t q = f.q();
    LocalTransport net(2);
    const std::vector<ModShare> e0 = f.E(0, 0);
    const std::vector<ModShare> e1 = f.E(0, 1);
    std::vector<uint8_t> fbits(64, 1);

    // f_bits 为空
    EXPECT_THROW(RunSecureMulBatch({}, {}, {}, net, f.mac, *f.prng, 1),
                 std::invalid_argument);
    // 长度不匹配（f_bits / ⟨E⟩_0 / ⟨E⟩_1 三者必须相等）
    std::vector<ModShare> short_shares = e0;
    short_shares.pop_back();
    EXPECT_THROW(RunSecureMulBatch(fbits, short_shares, e1, net, f.mac, *f.prng, 1),
                 std::invalid_argument);
    EXPECT_THROW(RunSecureMulBatch(fbits, e0, short_shares, net, f.mac, *f.prng, 1),
                 std::invalid_argument);
    std::vector<uint8_t> short_bits = fbits;
    short_bits.pop_back();
    EXPECT_THROW(RunSecureMulBatch(short_bits, e0, e1, net, f.mac, *f.prng, 1),
                 std::invalid_argument);
    // f_bits 非 0/1
    std::vector<uint8_t> bad_bits = fbits;
    bad_bits[3] = 2;
    EXPECT_THROW(RunSecureMulBatch(bad_bits, e0, e1, net, f.mac, *f.prng, 1),
                 std::invalid_argument);
    // 逐记录路径同样拒绝
    EXPECT_THROW(RunSecureMulPerRecord({}, {}, {}, net, f.mac, *f.prng, 1),
                 std::invalid_argument);
    EXPECT_THROW(RunSecureMulPerRecord(bad_bits, e0, e1, net, f.mac, *f.prng, 1),
                 std::invalid_argument);

    // SumOverFilter：属性号越界
    const CountResult c = CountPredicates(*f.client, f.schema, {R(0, 1, 4)});
    EXPECT_THROW(SumOverFilter(c, f.schema, /*attr_id=*/7, *f.client, net, f.mac,
                               *f.prng, 1),
                 std::out_of_range);
    // count 与 popcount(filter) 不一致（手搓的 CountResult）
    CountResult bad_count = c;
    bad_count.count = c.count + 1;
    EXPECT_THROW(SumOverFilter(bad_count, f.schema, 0, *f.client, net, f.mac, *f.prng, 1),
                 std::invalid_argument);
    // filter 长度与属性列长度不一致（= "f_bits.size() != N"）
    CountResult short_filter = c;
    short_filter.filter.pop_back();
    short_filter.count = Popcount(short_filter.filter);
    EXPECT_THROW(SumOverFilter(short_filter, f.schema, 0, *f.client, net, f.mac, *f.prng, 1),
                 std::invalid_argument);
    // filter 为空
    CountResult empty_filter;
    empty_filter.count = 0;
    EXPECT_THROW(SumOverFilter(empty_filter, f.schema, 0, *f.client, net, f.mac, *f.prng, 1),
                 std::invalid_argument);
    // filter 含非 0/1
    CountResult bad_bit = c;
    bad_bit.filter[0] = 2;
    EXPECT_THROW(SumOverFilter(bad_bit, f.schema, 0, *f.client, net, f.mac, *f.prng, 1),
                 std::invalid_argument);
    // schema 声明的 window_size 与 filter 长度不一致
    Schema wrong_window = MakeSchema(32);  // 32 ≠ N = 64
    EXPECT_THROW(SumOverFilter(c, wrong_window, 0, *f.client, net, f.mac, *f.prng, 1),
                 std::invalid_argument);
    // 传输只有一台服务器
    LocalTransport one(1);
    EXPECT_THROW(RunSecureMulBatch(fbits, e0, e1, one, f.mac, *f.prng, 1),
                 std::invalid_argument);
    // `SumOrThrow` 在有失败记录时必须抛（绝不给部分和）
    SecureMulBatchOutcome partial;
    partial.z = {1, 2};
    partial.ok = {1, 0};
    partial.failure = {SecureMulFailure::kNone, SecureMulFailure::kMacMismatch};
    partial.first_failure = 1;
    EXPECT_THROW(partial.SumOrThrow(q), std::logic_error);
}

// ===========================================================================
// 8. 确定性（同种子逐位一致；不同盐不影响正确性）
// ===========================================================================

TEST(MpraqSum, SameSeedIsBitwiseReproducible) {
    const uint128_t q = kMpraqModulus;
    const size_t n = 200;
    const std::vector<uint8_t> fbits = SyntheticFilter(n);
    const std::vector<uint128_t> values = SyntheticValues(n);
    SecureMulClientState mac = SecureMulClientState::GenerateMacKey(q);

    // 同一 (共享, 种子, 盐) ⇒ z 向量逐位一致
    std::vector<uint128_t> z1, z2;
    for (int run = 0; run < 2; ++run) {
        random::DeterministicPrng prng(SeedKey("mpa06-determinism"), 41);
        const auto shares = ShareValues(values, q, prng);
        LocalTransport net(2);
        const SecureMulBatchOutcome out = RunSecureMulBatch(fbits, shares.first,
                                                            shares.second, net, mac, prng,
                                                            0xD0D0'0001);
        EXPECT_TRUE(out.all_ok());
        (run == 0 ? z1 : z2) = out.z;
    }
    ASSERT_EQ(z1.size(), n);
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(z1[i], z2[i]);
    }
    // 换盐只改 challenge（防重放），**不影响**数值
    random::DeterministicPrng prng(SeedKey("mpa06-determinism"), 41);
    const auto shares = ShareValues(values, q, prng);
    LocalTransport net(2);
    const SecureMulBatchOutcome other =
        RunSecureMulBatch(fbits, shares.first, shares.second, net, mac, prng, 0xD0D0'00FF);
    EXPECT_TRUE(other.all_ok());
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(z1[i], other.z[i]);
    }
}

// ===========================================================================
// 9. 规模：N = 2^14 的批量路径实测（合成输入；不经过 Init）
// ===========================================================================

TEST(MpraqSumPerf, BatchAtLargeWindowReportsMeasuredNumbers) {
    const uint128_t q = kMpraqModulus;
    const size_t n = 1u << 14;  // 16384
    const std::vector<uint8_t> fbits = SyntheticFilter(n);
    const std::vector<uint128_t> values = SyntheticValues(n);
    const uint128_t expected = SyntheticExpectedSum(fbits, values, q);
    SecureMulClientState mac = SecureMulClientState::GenerateMacKey(q);
    random::DeterministicPrng prng(SeedKey("mpa06-perf"), 51);
    const auto shares = ShareValues(values, q, prng);

    LocalTransport net(2);
    net.ResetStats();
    const auto t0 = Clock::now();
    const SecureMulBatchOutcome out =
        RunSecureMulBatch(fbits, shares.first, shares.second, net, mac, prng, 0xE0E0'0001);
    const double wall_ms = MsSince(t0);

    EXPECT_TRUE(out.all_ok());
    EXPECT_EQ(out.stats.records, n);
    EXPECT_EQ(out.stats.rounds, uint64_t{2});
    EXPECT_EQ(out.stats.phase1_messages, n);
    EXPECT_EQ(out.stats.phase2_messages, n);
    EXPECT_EQ(out.stats.messages, 2 * n);
    EXPECT_EQ(out.stats.wire_messages, 4 * n);
    EXPECT_EQ(out.stats.server_records_processed[0], n);
    EXPECT_EQ(out.stats.server_records_processed[1], n);
    EXPECT_EQ(out.stats.server_records_processed_phase2[0], n);
    EXPECT_EQ(out.stats.server_records_processed_phase2[1], n);
    ASSERT_EQ(net.RequestCount(0), uint64_t{2});
    ASSERT_EQ(net.RequestCount(1), uint64_t{2});
    ASSERT_EQ(net.RequestLog(0).size(), size_t{2});
    EXPECT_EQ(net.RequestLog(0)[0].size(), kFrameHdr + kP1Req * n);
    EXPECT_EQ(net.RequestLog(0)[1].size(), kFrameHdr + kP2Req * n);
    EXPECT_EQ(out.SumOrThrow(q), expected);

    std::printf(
        "[MPA-06] N=2^14 批量实测：rounds=%llu messages=%llu（wire=%llu）"
        "offline_triple_ms=%.1f offline_setup_ms=%.1f online_ms=%.1f verify_ms=%.1f "
        "wall_ms=%.1f server_state_peak_bytes/台=%llu（sizeof 口径 %llu）"
        "frame_bytes=%llu/%llu\n",
        static_cast<unsigned long long>(out.stats.rounds),
        static_cast<unsigned long long>(out.stats.messages),
        static_cast<unsigned long long>(out.stats.wire_messages),
        out.stats.offline_triple_ms, out.stats.offline_setup_ms, out.stats.online_ms,
        out.stats.verify_ms, wall_ms,
        static_cast<unsigned long long>(out.stats.server_state_peak_bytes),
        static_cast<unsigned long long>(out.stats.server_state_allocated_bytes),
        static_cast<unsigned long long>(out.stats.frame_bytes_phase1),
        static_cast<unsigned long long>(out.stats.frame_bytes_phase2));
}

// ===========================================================================
// 10. 端到端：N = 2^14 的 `Count` + `Sum`（真实 `Init`，与基准对照）
// ===========================================================================

TEST(MpraqSum, EndToEndSumAtLargeWindowMatchesBaseline) {
    const auto t0 = Clock::now();
    Fixture f = Fixture::Make(1u << 14, /*lambda=*/32);
    const double init_ms = MsSince(t0);
    // 组 G：N=16384，Φ = (attr0 ∈ [1,4)) ∧ (attr1 ≥ 1)，sum_attr = 1 ⇒ (6554, 9830)
    const CheckedSum r = RunAndCheckSum(
        f, {R(0, 1, 4), P(1, PredicateOp::kGe, 1)},
        {BR(0, 1, 4), BP(1, mpraq_baseline::Op::kGe, 1)}, /*sum_attr=*/1, 0xF0F0'0001,
        kCaseGCount, kCaseGSum);
    EXPECT_EQ(r.avg, static_cast<uint128_t>(9830 / 6554));
    std::printf("[MPA-06] N=2^14 端到端：Init=%.1f ms（λ=32, ε=1e-4）Count=%llu Sum=%llu "
                "Avg=%llu；SecureMul online_ms=%.1f verify_ms=%.1f records=%llu messages=%llu\n",
                init_ms, static_cast<unsigned long long>(r.c.count),
                static_cast<unsigned long long>(static_cast<uint64_t>(r.s.sum)),
                static_cast<unsigned long long>(static_cast<uint64_t>(r.avg)),
                r.s.securemul.online_ms, r.s.securemul.verify_ms,
                static_cast<unsigned long long>(r.s.securemul.records),
                static_cast<unsigned long long>(r.s.securemul.messages));
}

// ===========================================================================
// 11. 报告（把实测数字打出来，便于贴文档）
// ===========================================================================

TEST(MpraqSumReport, Summary) {
    std::printf(
        "[MPA-06] 口径：messages = phase1 + phase2 = 2N（**单台服务器视角**）；"
        "wire_messages = 4N（两台 × 两轮，线上真实条数）；"
        "rounds = Collect() 调用次数 = 2；"
        "server_state_peak_bytes = N × (7×16 + 16) B **每台**（材料口径）\n");
    EXPECT_TRUE(true);
}
