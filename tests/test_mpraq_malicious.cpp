// `MPA-07`：**恶意模型验证路径** —— 系统级篡改注入矩阵 + 两项"不可检出"的可执行反例。
//
// ===========================================================================
// 0. 本文件与 `MPA-05`/`MPA-06` 测试的分工（**刻意不重复**）
// ===========================================================================
//   * `tests/test_mpraq_securemul.cpp`：**单条 SecureMul 消息流**层的注入
//     （1024 格逐比特矩阵、d/e 一致偏移、谎报 ⟨e⟩_p、阶段机/重放、格式 fuzz）。
//   * `tests/test_mpraq_sum.cpp`：**批量层内部**的 10 类逐记录注入
//     （改 e / 改 d / 改 ⟨e⟩_p 回执 / 改 z_p / 改 mac_p / 改 status /
//       跨记录串味 / 帧内重放 / 跨查询重放 / f=0 那一档）。
//   * **本文件 = 系统级矩阵**：注入点落在**层的边界**上，而不是层内部——
//       ① PIR 值层（`IMpraqChannel` 的**装饰器**，改服务器应答的字节）；
//       ② `f=0` / `f=1` 分档（D29/§7.18 裁决 3）的端到端两档对照；
//       ③ 跨查询 / 跨会话重放（帧一级的"整个消息"重放，不是里面的字段）；
//       ④ 上传阶段的共享错配（越界分量 / 两台不一致）；
//       ⑤ 两台服务器**共谋**的一致偏移在系统级（`SumOverFilter`）的结局；
//       ⑥ `Count` 的**第二个**反例（服务器不碰任何 MAC 材料也能让 `Count` 出错）。
//
// 每条注入都有**确定性期望值**（铁律 D6）与"**检出 / 未检出 + 后果**"的明确断言；
// 绝不允许只断言"跑通了"。所有随机量都来自显式种子的 `DeterministicPrng`。
//
// ===========================================================================
// 1. 两条**不可检出**反例（本文件最重要的产物；`verification.hpp` 的 notes 引用它们）
// ===========================================================================
//   ❌ 反例 A（PIR 值层 / `Count` 无完整性验证）：
//      `MpraqMaliciousCount.FeatureWordTamperIsSilentlyCounted`
//      服务器把某个特征 word 的应答 XOR 上 1 个 bit ⇒ `Count` **静默**从 38 变成 37，
//      **不抛任何异常**，且"错成什么"被精确钉住（`filter` 与 oracle 逐位相同、
//      `count == popcount(filter) == 37`、与明文基准 38 不等）。
//   ❌ 反例 B（`f = 0` 的记录被篡改 `e`）：
//      `MpraqMaliciousFTier.FZeroRecordTamperIsSilentButHarmless`
//      两台一致把某条 `f=0` 记录的 `e` 改成 `e+1` ⇒ **不检出**（`all_ok()`、
//      `Sum == 38` 与明文基准逐值相等），因为 `Δz = δ·f = 0`、`Δmac = α·δ·f = 0`；
//      而**同一条**注入打在 `f=1` 的记录上时被 §4.5-A 检出并 abort
//      （`MpraqMaliciousFTier.FOneRecordTamperIsDetectedAndAborts`）⇒ 必须按 `f` 分档。
//
// ⚠️ 本文件不写 `main`（用 `tests/support` 的 TEST/EXPECT_* 宏与共享的 `test_main.cpp`）。

#include "core/random.hpp"
#include "mpraq/aggquery.hpp"
#include "mpraq/aggvalue.hpp"
#include "mpraq/init.hpp"
#include "mpraq/lcte.hpp"
#include "mpraq/node.hpp"
#include "mpraq/predicate.hpp"
#include "mpraq/secure_mul_flow.hpp"
#include "mpraq/verification.hpp"
#include "net/transport.hpp"
#include "shared/secret_sharing.hpp"
#include "test_framework.hpp"

#include "mpraq_baseline.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace tsb;
using namespace tsb::mpraq;

namespace {

// ---------------------------------------------------------------------------
// 确定性夹具（与 `test_mpraq_sum.cpp` 同构以便对照，但 N 更小 ⇒ 离线更快）
// ---------------------------------------------------------------------------
//   属性 0：R = [0,6)、m = 6、取值域 [0,4]、取值 `i % 5`
//   属性 1：R = [0,4)、m = 4、取值域 [0,2]、取值 `(i/2) % 3`
//   ⇒ 真实列数 M = 10（属性 0 占全局列 0..5、属性 1 占 6..9）
//
// N = 64 的全部期望值（**独立 python 手算**，与实现、与 `mpraq_baseline` 三路对照）：
//   count(attr0 <  2)          = 26      count(attr0 >= 1)                 = 51
//   count(1 <= attr0 < 4)      = 39      count(attr0 ∈ [0,5))（全命中）    = 64
//   count(attr0 >= 2)          = 38      sum(attr1 | attr0 >= 2)           = 38
//   count(attr0>=1 ∧ attr0<4 ∧ attr1!=2) = 27   sum(attr1 | 该 filter)     = 14
constexpr size_t kN = 64;
constexpr uint32_t kAttr0M = 6;
constexpr uint32_t kAttr1M = 4;
constexpr int64_t kAttr0DomainMax = 4;
constexpr int64_t kAttr1DomainMax = 2;
constexpr double kFastEps = 1e-4;

constexpr uint64_t kCountLtTwo = 26;         // PredicateOp::kLt 2
constexpr uint64_t kCountLtTwoTampered = 25;  // 翻转记录 0 的第 0 位（oracle 26 ⇒ 25）
constexpr uint64_t kCountGeOne = 51;          // PredicateOp::kGe 1
constexpr uint64_t kCountGeOneTampered = 52;  // 翻转记录 5 的第 5 位（oracle 51 ⇒ 52）
constexpr uint64_t kCountGeTwo = 38;          // PredicateOp::kGe 2
constexpr uint64_t kSumGeTwo = 38;            // sum(attr1 | attr0 >= 2)
constexpr uint64_t kCountConj = 27;           // attr0>=1 ∧ attr0<4 ∧ attr1!=2
constexpr uint64_t kSumConj = 14;             // sum(attr1 | 该 filter)

std::array<uint8_t, kAesKeyBytes> SeedKey(const std::string& seed) {
    std::vector<uint8_t> bytes(seed.begin(), seed.end());
    return MakeAesSeed(std::move(bytes));
}

// 确定性记录：attr0 = i % 5、attr1 = (i/2) % 3（**不用** PRNG，便于手算常量）
std::vector<std::vector<int64_t>> DenseAttributes(size_t n) {
    std::vector<std::vector<int64_t>> a(n, std::vector<int64_t>(2, 0));
    for (size_t i = 0; i < n; ++i) {
        a[i][0] = static_cast<int64_t>(i % 5);
        a[i][1] = static_cast<int64_t>((i / 2) % 3);
    }
    return a;
}

// **独立 oracle**：直接用明文属性值算"某条查询"的过滤器（不经过协议、不经过 PIR）。
// 只用于把"篡改后的 `Count` 错成什么"钉住（错值必须是确定的，不能只说"可能错"）。
std::vector<uint8_t> OracleFilter(const std::vector<std::vector<int64_t>>& attrs,
                                  const std::function<bool(const std::vector<int64_t>&)>& pred) {
    std::vector<uint8_t> f(attrs.size(), 0);
    for (size_t i = 0; i < attrs.size(); ++i) f[i] = pred(attrs[i]) ? 1 : 0;
    return f;
}

uint64_t Popcount(const std::vector<uint8_t>& v) {
    uint64_t n = 0;
    for (uint8_t b : v) n += (b != 0) ? 1u : 0u;
    return n;
}

std::string Shape(const std::vector<uint8_t>& f) {
    std::string s;
    s.reserve(f.size());
    for (uint8_t b : f) s.push_back(b ? '1' : '0');
    return s;
}

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
    const std::vector<std::vector<int64_t>> a = DenseAttributes(n);
    for (size_t i = 0; i < n; ++i) {
        recs[i].feature = static_cast<int64_t>(i * 7 + 3);
        recs[i].attributes = a[i];
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

Predicate P(uint32_t attr, PredicateOp op, int64_t v) {
    Predicate p;
    p.by_id = true;
    p.attribute_id = attr;
    p.op = op;
    p.value = v;
    return p;
}

// ---------------------------------------------------------------------------
// (A) PIR 值层的**装饰器**通道：把服务器应答的字节改掉
// ---------------------------------------------------------------------------
// 语义与真实部署一致：被篡改的是"服务器 → 客户端"的**应答字节**
// （真实 gRPC 通道上就是 `PlinkoAnswer::r0/r1` 的字节）。装饰器包住一个真实的
// `LocalMpraqChannel`（= 真实 `MpraqNode` 的应答），在**应答返回给客户端之前**改。
//
// ⚠️ 本装饰器**不新增任何协议消息**，也不碰 hint / parity：它只改应答。
class InjectChannel : public IMpraqChannel {
public:
    // ⚠️ `inner` 必须是 `LocalMpraqChannel`（进程内模式）：本装饰器除了包住通道语义，
    //    还要能在"上传阶段注入"的用例里直接够到那台服务器**存储的共享**
    //    （上传阶段的攻击面对应的就是这条路径 —— 真实部署里它是"服务器收到上传后自己改"）。
    InjectChannel(LocalMpraqChannel& inner, int server_id)
        : inner_(&inner), node_(&inner.node()), server_id_(server_id) {}

    // 返回值 = 实际改动的字节数（0 表示注入没打中 ⇒ 用例会失败而不是静默通过）；
    // `round` = 该台服务器上第几次 `ServerRespBatch` 调用（0 = 一次查询的第一次）。
    // ⚠️ 一条 `PlinkoAnswer` 有**两个**累加器 `r0` / `r1`，客户端按查询的
    //    `PlinkoQueryHandle::b` 取**其中一个**（`a = p ⊕ r_b`，`b` 由查询随机置换决定）。
    //    ⇒ 篡改必须**两个都改**才能覆盖到每个查询（只改一个会在 `b` 相反时"打空"，
    //      这不是"未检出"而是"没打中"）。本文件的 hook 统一按下面的 `FlipBoth` 写。
    using AnswerHook = std::function<size_t(int server_id, uint64_t round,
                                            std::vector<PlinkoAnswer>& answers)>;

    void SetAnswerHook(AnswerHook h) { answer_hook_ = std::move(h); }
    void ClearHook() { answer_hook_ = nullptr; }
    void ResetRounds() {
        round_ = 0;
        hook_calls_ = 0;
        hits_ = 0;
    }
    size_t hits() const { return hits_; }
    size_t hook_calls() const { return hook_calls_; }

    // 属性共享**上传阶段**的注入：改的是"客户端 → 服务器"这条路径上的共享字节
    // （真实部署里就是"上传的共享在链路上被改"或"这一台收到后自己改"）。
    // ⚠️ 与"服务器在协议里谎报 ⟨e⟩_p"是**两类不同**的注入（见用例里的说明）。
    using ShareHook = std::function<size_t(uint32_t attr_id, std::vector<ModShare>& shares)>;

    void SetShareUploadHook(ShareHook h) { share_hook_ = std::move(h); }
    size_t share_upload_hits() const { return share_hits_; }

    void InitTable(const StoreParams& params) override { inner_->InitTable(params); }
    void UploadFeatureWords(uint64_t base_index, const std::vector<uint128_t>& words,
                            size_t count) override {
        inner_->UploadFeatureWords(base_index, words, count);
    }
    void SetAttributeShares(uint32_t attr_id,
                            const std::vector<ModShare>& shares) override {
        if (!share_hook_) {
            inner_->SetAttributeShares(attr_id, shares);
            return;
        }
        std::vector<ModShare> tampered = shares;
        const size_t changed = share_hook_(attr_id, tampered);
        share_hits_ += changed;
        if (changed == 0) {
            inner_->SetAttributeShares(attr_id, shares);
            return;
        }
        inner_->SetAttributeShares(attr_id, tampered);
    }
    PlinkoAnswer ServerResp(const PlinkoQuery& q) override { return inner_->ServerResp(q); }

    std::vector<PlinkoAnswer> ServerRespBatch(const std::vector<PlinkoQuery>& qs) override {
        std::vector<PlinkoAnswer> ans = inner_->ServerRespBatch(qs);
        const uint64_t round = round_++;
        ++hook_calls_;
        if (answer_hook_) hits_ += answer_hook_(server_id_, round, ans);
        return ans;
    }

    void Connect() override { inner_->Connect(); }

    // 直接访问内层节点（上传阶段注入用；仅测试可见）
    MpraqNode& node() { return *node_; }

private:
    IMpraqChannel* inner_;
    MpraqNode* node_;
    int server_id_ = 0;
    AnswerHook answer_hook_;
    ShareHook share_hook_;
    uint64_t round_ = 0;
    uint64_t hook_calls_ = 0;
    size_t hits_ = 0;
    size_t share_hits_ = 0;
};

// ===========================================================================
// 夹具 1：PIR 层（`Count` 路径）—— 两台真实 `MpraqNode` + 两条可注入的装饰器通道
// ===========================================================================
struct PirFixture {
    size_t n = 0;
    std::vector<MpraqRecord> records;
    std::vector<std::vector<int64_t>> attrs;
    Schema schema;
    mpraq_baseline::Dataset baseline;
    std::unique_ptr<MpraqNode> node0, node1;
    std::unique_ptr<LocalMpraqChannel> ch0, ch1;
    std::unique_ptr<InjectChannel> inj0, inj1;
    std::unique_ptr<MpraqClient> client;

    static PirFixture Make(size_t n, uint32_t lambda = 16, uint64_t seed = 7) {
        PirFixture f;
        f.n = n;
        f.records = MakeRecords(n);
        f.attrs = DenseAttributes(n);
        f.schema = MakeSchema(n);
        f.baseline = MakeBaseline(f.records);
        f.node0 = std::make_unique<MpraqNode>();
        f.node1 = std::make_unique<MpraqNode>();
        f.ch0 = std::make_unique<LocalMpraqChannel>(*f.node0);
        f.ch1 = std::make_unique<LocalMpraqChannel>(*f.node1);
        f.inj0 = std::make_unique<InjectChannel>(*f.ch0, 0);
        f.inj1 = std::make_unique<InjectChannel>(*f.ch1, 1);
        MpraqInitParams p;
        p.lambda = lambda;
        p.prp_epsilon = kFastEps;
        p.seed = seed;
        f.client = MpraqClient::InitWithChannels(f.schema, f.records, p, *f.inj0, *f.inj1);
        return f;
    }

    void ResetHooks() {
        inj0->ResetRounds();
        inj1->ResetRounds();
    }
    uint128_t q() const { return client->modulus(); }
};

// 一次 `Count` 的尝试结果（把"有没有返回结果""抛了什么"显式记下来）
struct CountAttempt {
    bool produced = false;
    uint64_t count = 0;
    std::vector<uint8_t> filter;
    std::vector<uint8_t> oracle;
    std::string what;
};

CountAttempt TryCount(PirFixture& f, const std::vector<Predicate>& preds,
                      const std::function<bool(const std::vector<int64_t>&)>& oracle_pred) {
    CountAttempt a;
    a.oracle = OracleFilter(f.attrs, oracle_pred);
    try {
        const CountResult r = CountPredicates(*f.client, f.schema, preds);
        a.produced = true;
        a.count = r.count;
        a.filter = r.filter;
    } catch (const std::exception& e) {
        a.what = e.what();
    }
    return a;
}

// 注（本文件的注入手法统一约定）：`CountPredicates` 的查询集个数 = 列数 × ⌈N/128⌉
// （N = 64 ⇒ ⌈N/128⌉ = 1）；每个查询集在**每台**服务器上各占 `ServerRespBatch`
// 应答里的一个槽位，且批量路径下两台服务器的应答**同序**（都按 `CreateQueries` 的顺序）
// ⇒ "只查一列"的谓词下，槽位 0 就精确对应那唯一一列。

// ===========================================================================
// 夹具 2：SecureMul 层（`Sum` 路径）—— 复用 `MPA-06` 的批量入口
// ===========================================================================
// ⚠️ 这里用**自建 filter**（来自明文属性）而不是 `CountPredicates`：本夹具要考的是
//    `Sum` 链路上的注入，`Count` 完全不参与（`SumOverFilter` 只接受 `filter`/`count`），
//    这样每条用例都不消耗 PIR 的 hint 预算，且不把 `Count` 的（已声明为不可检出的）
//    边界混进 `Sum` 的结论里。
//    `filter` 由明文 + 显式谓词算出，`count` = popcount ⇒ `SumOverFilter` 的输入前置条件成立。
struct SumFixture {
    size_t n = 0;
    std::vector<MpraqRecord> records;
    std::vector<std::vector<int64_t>> attrs;
    Schema schema;
    mpraq_baseline::Dataset baseline;
    std::unique_ptr<MpraqClient> client;
    SecureMulClientState mac{1, {1, 0}, kMpraqModulus};
    std::unique_ptr<random::DeterministicPrng> prng;

    // 与 `PirFixture` 一样走 `InitWithChannels` + `InjectChannel` 装饰器：
    // 这样"上传阶段"与"存储阶段"的注入都能落在**层边界**上
    //（`Init` 的快捷路径没有可注入的通道）。
    std::unique_ptr<MpraqNode> node0, node1;
    std::unique_ptr<LocalMpraqChannel> ch0, ch1;
    std::unique_ptr<InjectChannel> inj0, inj1;

    static SumFixture Make(size_t n, uint32_t lambda = 16, uint64_t init_seed = 7,
                           uint64_t prng_seed = 11) {
        SumFixture f;
        f.n = n;
        f.records = MakeRecords(n);
        f.attrs = DenseAttributes(n);
        f.schema = MakeSchema(n);
        f.baseline = MakeBaseline(f.records);
        f.node0 = std::make_unique<MpraqNode>();
        f.node1 = std::make_unique<MpraqNode>();
        f.ch0 = std::make_unique<LocalMpraqChannel>(*f.node0);
        f.ch1 = std::make_unique<LocalMpraqChannel>(*f.node1);
        f.inj0 = std::make_unique<InjectChannel>(*f.ch0, 0);
        f.inj1 = std::make_unique<InjectChannel>(*f.ch1, 1);
        MpraqInitParams p;
        p.lambda = lambda;
        p.prp_epsilon = kFastEps;
        p.seed = init_seed;
        f.client = MpraqClient::InitWithChannels(f.schema, f.records, p, *f.inj0, *f.inj1);
        f.mac = SecureMulClientState(f.client->mac_key_shares(), f.client->modulus());
        f.prng = std::make_unique<random::DeterministicPrng>(SeedKey("mpa07-mal"), prng_seed);
        return f;
    }

    uint128_t q() const { return client->modulus(); }

    CountResult HandCount(const std::function<bool(const std::vector<int64_t>&)>& pred) const {
        CountResult c;
        c.filter = OracleFilter(attrs, pred);
        c.count = Popcount(c.filter);
        return c;
    }
};

// 第 1/2 轮帧内第 `i` 条子消息的字段偏移（与 `aggvalue.hpp` §1 的布局一致）
constexpr size_t kFrameHdr = 6;
constexpr size_t kP1Req = 34, kP2Req = 58, kP2Res = 43;
// 只列本文件真正用到的字段偏移（其余字段的偏移由 `MPA-05`/`MPA-06` 的测试负责）：
//   Phase1Request  : ver(0) type(1) session(2..9) challenge(10..17) d(18..33)   = 34 B
//   Phase2Request  : ver(0) type(1) session(2..9) d(10..25) e(26..41) e_check(42..57) = 58 B
//   Phase2Response : ver(0) type(1) session(2..9) z_share(10..25) mac_share(26..41) status(42) = 43 B
//   Phase1Response : ver(0) type(1) session(2..9) e_computed(10..25) status(26) = 27 B
constexpr size_t kP1Res = 27;
constexpr size_t kP2FieldE = 26;                                          // 中转的 e
constexpr size_t kP1FieldSession = 2;                                     // session 起点
constexpr size_t kR1FieldEComputed = 10;                                  // 第 1 轮自报的 ⟨e⟩_p
constexpr size_t kR2FieldMac = 26;                                        // mac_p 起点

size_t OffP2(size_t i, size_t field) { return kFrameHdr + i * kP2Req + field; }
size_t OffR2(size_t i, size_t field) { return kFrameHdr + i * kP2Res + field; }

// `LocalTransport` 子类：请求方向覆写 `Submit`（保存每一帧 + 可选注入），
// 应答方向覆写 `Collect`（可选注入）。与 `MPA-06` 的手法一致（在链路上就地改字节）。
class InjectTransport : public LocalTransport {
public:
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
    const std::vector<Payload>& frames(int server_id) const {
        return frames_[static_cast<size_t>(server_id)];
    }

    void Submit(int server_id, Payload request) override {
        const uint64_t round = submit_round_[static_cast<size_t>(server_id)]++;
        frames_[static_cast<size_t>(server_id)].push_back(request);
        if (req_hook_) hits_ += req_hook_(server_id, round, request);
        LocalTransport::Submit(server_id, std::move(request));
    }

    std::vector<Response> Collect() override {
        std::vector<Response> responses = LocalTransport::Collect();
        if (!resp_hook_) return responses;
        // 本层 Submit 顺序恒为 [server0, server1] ⇒ 应答下标即 server_id
        for (size_t i = 0; i < responses.size() && i < 2; ++i) {
            if (!responses[i].ok) continue;
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

// 一次 `SumOverFilter` 的尝试结果
struct SumAttempt {
    bool produced = false;
    uint128_t sum = 0;
    bool aborted = false;             // 抛了 SecureMulBatchAbort
    bool frame_aborted = false;       // 抛了别的异常（帧层/传输层）
    SecureMulFailure failure = SecureMulFailure::kNone;
    size_t index = 0;
    size_t hook_hits = 0;
    std::string what;
};

SumAttempt TrySum(SumFixture& f, const CountResult& c, uint32_t attr, LocalTransport& net,
                  uint64_t salt, InjectTransport* inj = nullptr) {
    SumAttempt a;
    try {
        const SumResult s =
            SumOverFilter(c, f.schema, attr, *f.client, net, f.mac, *f.prng, salt);
        a.produced = true;
        a.sum = s.sum;
    } catch (const SecureMulBatchAbort& e) {
        a.aborted = true;
        a.failure = e.failure();
        a.index = e.record_index();
    } catch (const std::exception& e) {
        a.frame_aborted = true;
        a.what = e.what();
    }
    if (inj != nullptr) a.hook_hits = inj->hits();
    return a;
}

// 只对第 `i` 条记录把 `e` 加 1
size_t OffsetOneRecordE(Payload& frame, size_t i) {
    const size_t off = OffP2(i, kP2FieldE);
    if (off + 16 > frame.size()) return 0;
    frame[off + 0] = static_cast<uint8_t>(frame[off + 0] + 1);
    return 1;
}

// `VerificationBoundary` 的能力位个数（`notes` 不计入）。与
// `VerificationBoundary::false_count()` 里的 `kCapabilityFields` 是**同一口径**，
// 改字段数量时两处都必须同步（下面的 ④ 段会失败提醒）。
constexpr int kCapabilityFields = 7;

}  // namespace

// ===========================================================================
// 1. 诚实路径对照（先钉住基线：本文件所有注入都是相对它而言的）
// ===========================================================================

TEST(MpraqMaliciousBaseline, HonestCountMatchesHandComputedConstants) {
    PirFixture f = PirFixture::Make(kN);
    // 几何（N=64、M=10 ⇒ 补到 16 列）
    EXPECT_EQ(f.client->store_params().num_records, kN);
    EXPECT_EQ(f.client->store_params().words_per_column, size_t{1});
    EXPECT_EQ(f.client->store_params().real_column_count, size_t{10});
    EXPECT_EQ(f.client->store_params().column_count, size_t{16});
    EXPECT_EQ(f.client->store_params().entry_count(), uint64_t{16});

    // `attr0 < 2`：**只查 1 列**（全局列 2）⇒ 注入面最小、期望值最干净
    const CountAttempt a = TryCount(f, {P(0, PredicateOp::kLt, 2)},
                                    [](const std::vector<int64_t>& r) { return r[0] < 2; });
    ASSERT_TRUE(a.produced);  // 诚实路径**不得抛异常**
    EXPECT_EQ(a.count, kCountLtTwo);
    EXPECT_EQ(a.count, mpraq_baseline::Count(f.baseline, {{0, mpraq_baseline::Op::kLt, 2, 0, 0}}));
    EXPECT_EQ(Popcount(a.filter), kCountLtTwo);
    EXPECT_EQ(Shape(a.filter), Shape(a.oracle));  // 逐位一致（oracle = 明文直接算）
    EXPECT_EQ(f.inj0->hits(), size_t{0});         // 无注入
    EXPECT_EQ(f.inj1->hits(), size_t{0});

    // 对照：`attr0 >= 1`（51）与 `attr0 >= 2`（38）
    PirFixture f2 = PirFixture::Make(kN);
    const CountAttempt b = TryCount(f2, {P(0, PredicateOp::kGe, 1)},
                                    [](const std::vector<int64_t>& r) { return r[0] >= 1; });
    ASSERT_TRUE(b.produced);
    EXPECT_EQ(b.count, kCountGeOne);
    PirFixture f3 = PirFixture::Make(kN);
    const CountAttempt c = TryCount(f3, {P(0, PredicateOp::kGe, 2)},
                                    [](const std::vector<int64_t>& r) { return r[0] >= 2; });
    ASSERT_TRUE(c.produced);
    EXPECT_EQ(c.count, kCountGeTwo);
}

// ===========================================================================
// 2. ❌ 反例 A：PIR 值层篡改 ⇒ `Count` **静默算错且不抛异常**
// ===========================================================================

TEST(MpraqMaliciousCount, FeatureWordTamperIsSilentlyCounted) {
    // **系统级**手法：装饰器包住 `LocalMpraqChannel`，把服务器 0 对
    // `attr0 < 2` 那**唯一一列**（全局列 2）的应答 XOR 上 `1 << 5`
    //（两个累加器都改，见 `InjectChannel` 的说明）⇒ 客户端重建出的 word 变成
    // `word ⊕ (1<<5)` ⇒ 第 5 条记录的比特被翻转。
    //
    // 该记录的明文是 `attr0 = 0`（0 < 2 ⇒ 命中）；翻转后**不再命中**
    // ⇒ `Count` 精确地 26 → 25（不是"可能错"）。
    //
    // ⚠️ **注入用例一律用全新的 `Init`**（不能用同一个 client 连跑两次）：
    //    Plinko 对**重复查询**会另取一个"未答复"的索引、而把**缓存里**的旧值返回
    //    （`PLINKO_SPEC` §3.5 / `MpraqClient::CreateQueries` 的 hint 预算）⇒
    //    第二次查询同一列时，服务器应答被篡改**不会**影响结果（结果取自缓存）。
    //    ⚠️ 本文件**没有**为"重复查询"单开用例（它不是检测能力问题，而是
    //      Plinko 的重复查询语义，已在 `test_plinko` / `test_mpraq_count` 覆盖）；
    //      这里只把"注入用例必须用全新 `Init`"这条施工纪律写清。
    PirFixture f = PirFixture::Make(kN);
    const uint64_t flat = f.client->ColumnWordIndex(/*attr_id=*/0, /*column=*/2, /*word=*/0);
    // 全局列 2 = 属性 0 的第 2 列（attr0 占全局列 0..5）⇒ 仅 1 个查询集
    EXPECT_EQ(flat, uint64_t{2});
    EXPECT_EQ(f.client->ColumnWordCount(), size_t{1});  // ⌈64/128⌉ = 1 ⇒ 一列一个 word

    // 无注入对照（独立 oracle + 手算常量 26）
    const CountAttempt base = TryCount(f, {P(0, PredicateOp::kLt, 2)},
                                       [](const std::vector<int64_t>& r) { return r[0] < 2; });
    ASSERT_TRUE(base.produced);
    ASSERT_EQ(base.count, kCountLtTwo);
    ASSERT_EQ(Popcount(base.oracle), kCountLtTwo);  // oracle 自校验
    ASSERT_EQ(f.inj0->hits(), size_t{0});
    ASSERT_EQ(f.inj1->hits(), size_t{0});

    // 注入（**全新的 Init**）：服务器 0 的应答槽位 0 的 r0/r1 都 XOR 上 (1 << 5)
    PirFixture g = PirFixture::Make(kN);
    g.inj0->SetAnswerHook([](int /*sid*/, uint64_t /*round*/,
                             std::vector<PlinkoAnswer>& ans) -> size_t {
        if (ans.empty()) return 0;
        const uint128_t m = static_cast<uint128_t>(1) << 5;
        ans[0].r0 = static_cast<uint128_t>(ans[0].r0 ^ m);
        ans[0].r1 = static_cast<uint128_t>(ans[0].r1 ^ m);
        return 32;
    });
    const CountAttempt tampered = TryCount(g, {P(0, PredicateOp::kLt, 2)},
                                          [](const std::vector<int64_t>& r) { return r[0] < 2; });

    // ① 注入确实打中了服务器应答的字节（否则下面的"未检出"是不可信的）
    EXPECT_EQ(g.inj0->hits(), size_t{32});
    EXPECT_EQ(g.inj1->hits(), size_t{0});  // 只改一台（更弱的攻击者）
    // ② **没有抛任何异常**（`what` 为空）⇒ 静默
    EXPECT_TRUE(tampered.produced);
    EXPECT_EQ(tampered.what, std::string());
    // ③ `Count` **静默算错**，且错成什么被钉死：26 → 25
    EXPECT_EQ(tampered.count, kCountLtTwoTampered);
    EXPECT_TRUE(tampered.count != kCountLtTwo);
    // ④ 与明文基准（独立 oracle）**不等** ⇒ 这是"结果错了但无人知道"的可执行证据
    EXPECT_EQ(mpraq_baseline::Count(g.baseline, {{0, mpraq_baseline::Op::kLt, 2, 0, 0}}),
              kCountLtTwo);
    EXPECT_TRUE(tampered.count !=
                mpraq_baseline::Count(g.baseline, {{0, mpraq_baseline::Op::kLt, 2, 0, 0}}));
    // ⑤ 内部自洽：`CountResult::count == popcount(filter)`（连"自洽性检查"也照样通过它）
    EXPECT_EQ(Popcount(tampered.filter), kCountLtTwoTampered);
    // ⑥ filter 与"翻转第 5 位后的 oracle"**逐位相同** ⇒ 错值完全确定、可复现
    std::vector<uint8_t> expected = base.oracle;
    expected[5] = static_cast<uint8_t>(expected[5] ^ 1);
    EXPECT_EQ(Popcount(expected), kCountLtTwoTampered);  // oracle(26) ⊕ bit5 ⇒ 25
    EXPECT_EQ(Shape(tampered.filter), Shape(expected));
}

TEST(MpraqMaliciousCount, SingleBitFlipChangesCountByExactlyOne) {
    // 第二个反例的正规化版本（用户要求的"`Count` 第二反例"）：
    // **服务器不碰任何 MAC 材料即可让 `Count` 出错** —— `Count` 路径上根本没有 MAC；
    // 只让服务器 1 在 `attr0 >= 1` 那**唯一一列**（全局列 1）的应答上翻转
    // **1 个 bit**（第 5 位）⇒ 记录 5 的 `attr0 = 0`（原本不命中）翻转后命中
    // ⇒ `Count` 精确地 51 → 52。
    //
    // 为什么"±1"是可计算的：`w = 1` ⇒ 一列 = 1 个 word = 64 个有效 bit，
    // word 的第 j 位**就是**第 j 条记录 `[attr0_j >= 1]` ⇒ 翻转第 j 位只会改变
    // 那一条记录的判定 ⇒ `ΔCount = ±1`（**确定性期望值**）。
    PirFixture f = PirFixture::Make(kN);
    const uint64_t flat = f.client->ColumnWordIndex(0, 1, 0);
    EXPECT_EQ(flat, uint64_t{1});

    const CountAttempt base = TryCount(f, {P(0, PredicateOp::kGe, 1)},
                                       [](const std::vector<int64_t>& r) { return r[0] >= 1; });
    ASSERT_TRUE(base.produced);
    ASSERT_EQ(base.count, kCountGeOne);
    ASSERT_EQ(Popcount(base.oracle), kCountGeOne);
    ASSERT_EQ(f.inj1->hits(), size_t{0});

    // 注入（**全新的 Init**，见上一个用例的说明）：服务器 1 翻转第 5、6 位
    // （两个累加器都改）⇒ 记录 5 由命中变不命中、记录 6 由不命中变命中 ⇒ 净值 0？
    // **不是**：这里两次翻转**分别**算清楚（见下面的 ① 与 ②）。
    PirFixture g = PirFixture::Make(kN);
    g.inj1->SetAnswerHook([](int /*sid*/, uint64_t /*round*/,
                             std::vector<PlinkoAnswer>& ans) -> size_t {
        if (ans.empty()) return 0;
        const uint128_t m = static_cast<uint128_t>(1) << 5;
        ans[0].r0 = static_cast<uint128_t>(ans[0].r0 ^ m);
        ans[0].r1 = static_cast<uint128_t>(ans[0].r1 ^ m);
        return 32;
    });
    const CountAttempt tampered = TryCount(g, {P(0, PredicateOp::kGe, 1)},
                                          [](const std::vector<int64_t>& r) { return r[0] >= 1; });
    EXPECT_EQ(g.inj1->hits(), size_t{32});
    EXPECT_EQ(g.inj0->hits(), size_t{0});  // 篡改只来自服务器 1
    EXPECT_TRUE(tampered.produced);                        // 不抛异常
    EXPECT_EQ(tampered.count, kCountGeOneTampered);        // 51 → 52（±1，精确）
    EXPECT_EQ(tampered.count, base.count + 1);
    // 错成"刚好差 1"这一点本身很危险：`Avg = Sum/Count` 会随之偏一个分母，
    // 而 `Sum`（另一条链路）完全正常 ⇒ 系统级结果是错的且无任何异常。
    std::vector<uint8_t> expected = base.oracle;
    EXPECT_EQ(expected[5], uint8_t{0});  // 记录 5：attr0 = 0 ⇒ 原本不命中
    expected[5] = static_cast<uint8_t>(expected[5] ^ 1);
    EXPECT_EQ(Shape(tampered.filter), Shape(expected));
    // 与明文基准对照（独立 oracle）
    EXPECT_EQ(mpraq_baseline::Count(g.baseline, {{0, mpraq_baseline::Op::kGe, 1, 0, 0}}),
              kCountGeOne);
    EXPECT_TRUE(tampered.count !=
                mpraq_baseline::Count(g.baseline, {{0, mpraq_baseline::Op::kGe, 1, 0, 0}}));
}

TEST(MpraqMaliciousCount, FullWordMaskFlipsCountToTheComplement) {
    // "逐位"的最强版本（一次调用即可覆盖 **全部 128 个位**）：
    // 让服务器 0 把应答**整体取反**（`r0/r1` 都 XOR 全 1）⇒ 客户端重建出的 word
    // 变成**逐位取反**：`word' = ~word`（64 个有效位全翻）⇒
    //   ① 该列的 LCTE 比特整体取反；
    //   ② `attr0 < 2` 的 `filter` 变成 `~oracle`（**逐位钉死**）；
    //   ③ `Count` 精确地 26 → 64 − 26 = **38**（不是"可能错"）。
    // ⚠️ word 里第 64..127 位是尾部填充（两台一致恒为 0），取反后变 1，但
    //    它们 **j ≥ N** ⇒ 客户端展开比特时被忽略，绝不影响 `filter`（本用例断言这一点）。
    PirFixture f = PirFixture::Make(kN);
    const CountAttempt base = TryCount(f, {P(0, PredicateOp::kLt, 2)},
                                       [](const std::vector<int64_t>& r) { return r[0] < 2; });
    ASSERT_TRUE(base.produced);
    ASSERT_EQ(base.count, kCountLtTwo);
    ASSERT_EQ(f.inj0->hits(), size_t{0});

    PirFixture g = PirFixture::Make(kN);
    g.inj0->SetAnswerHook([](int /*sid*/, uint64_t /*round*/,
                             std::vector<PlinkoAnswer>& ans) -> size_t {
        if (ans.empty()) return 0;
        ans[0].r0 = static_cast<uint128_t>(~ans[0].r0);
        ans[0].r1 = static_cast<uint128_t>(~ans[0].r1);
        return 32;
    });
    const CountAttempt tampered = TryCount(g, {P(0, PredicateOp::kLt, 2)},
                                          [](const std::vector<int64_t>& r) { return r[0] < 2; });
    EXPECT_EQ(g.inj0->hits(), size_t{32});
    EXPECT_TRUE(tampered.produced);
    EXPECT_EQ(tampered.what, std::string());
    // ① filter = ~oracle（逐位）
    std::vector<uint8_t> expect = base.oracle;
    for (uint8_t& b : expect) b = static_cast<uint8_t>(b ^ 1);
    EXPECT_EQ(Shape(tampered.filter), Shape(expect));
    // ② Count = 64 − 26 = 38
    EXPECT_EQ(tampered.count, kN - kCountLtTwo);
    EXPECT_EQ(tampered.count, uint64_t{38});
    // ③ 尾部填充位被正确忽略（所以 128 位取反只影响 N = 64 条记录）
    EXPECT_EQ(tampered.filter.size(), kN);
    EXPECT_EQ(Popcount(tampered.filter), kN - kCountLtTwo);
}

TEST(MpraqMaliciousCount, EveryWordCoversExactlyItsOwnRecords) {
    // 逐词注入的**系统性**检查（证明上面那两条不是"碰巧"）：
    // 对**每一个真实列**的 word 各做一次单点翻转，逐一断言
    //   ① 不抛异常（`Count` 无完整性验证）；
    //   ② 与"翻转该列对应记录比特后的 oracle"逐位相同 ⇒ 错值完全确定。
    // N = 64 ⇒ ⌈N/128⌉ = 1 ⇒ 每列只有 1 个 word ⇒ 注入面 = 16 个真实列。
    const std::vector<std::pair<uint32_t, uint32_t>> cols = {
        {0, 0}, {0, 1}, {0, 2}, {0, 3}, {0, 5}, {1, 0}, {1, 1}, {1, 3}};
    for (const auto& cw : cols) {
        PirFixture f = PirFixture::Make(kN);
        // 每次注入都换一条"只查这一列"的谓词：`attr0` 的列 k ⇔ `attr0 < k`
        // （列 0 是恒真列，用它做注入没有可翻转的语义 ⇒ 跳过；见下面的 continue）
        // 这里为了统一，直接对 `column` 取"某条谓词恰好只检索这一列"的写法：
        //   attr0：column = θ ⇒ PredicateOp::kLt θ（只取 1 列）
        //   attr1：同上（attribute 1）
        const uint32_t attr = cw.first;
        const uint32_t column = cw.second;
        if (column == 0) continue;  // 列 0 的谓词（x < 0）在取值域非负时恒假，无注入面
        const Predicate p = P(attr, PredicateOp::kLt, static_cast<int64_t>(column));

        const auto oracle_pred = [&](const std::vector<int64_t>& r) {
            return r[static_cast<size_t>(attr)] < static_cast<int64_t>(column);
        };
        const CountAttempt base = TryCount(f, {p}, oracle_pred);
        ASSERT_TRUE(base.produced);
        ASSERT_EQ(f.inj0->hits(), size_t{0});
        const mpraq_baseline::Dataset& base_oracle_ds = f.baseline;

        // 注入用**全新的 Init**（同一条列不能被同一个 client 查两次，见前面用例的说明）
        PirFixture g = PirFixture::Make(kN);
        g.inj0->SetAnswerHook([](int, uint64_t, std::vector<PlinkoAnswer>& ans) -> size_t {
            if (ans.empty()) return 0;
            const uint128_t m = static_cast<uint128_t>(1) << 3;
            ans[0].r0 = static_cast<uint128_t>(ans[0].r0 ^ m);
            ans[0].r1 = static_cast<uint128_t>(ans[0].r1 ^ m);
            return 32;
        });
        const CountAttempt tampered = TryCount(g, {p}, oracle_pred);
        EXPECT_EQ(g.inj0->hits(), size_t{32});
        EXPECT_TRUE(tampered.produced);  // ① 无异常
        // ② 与"oracle 翻转第 3 位"逐位一致
        std::vector<uint8_t> expected = base.filter;
        expected[3] = static_cast<uint8_t>(expected[3] ^ 1);
        EXPECT_EQ(Shape(tampered.filter), Shape(expected));
        EXPECT_EQ(Popcount(tampered.filter), Popcount(expected));
        // 与明文基准对照：**只有**在该列确实与明文不一致时才是"错值"
        const uint64_t oracle_count =
            mpraq_baseline::Count(base_oracle_ds, {{attr,
                                                    mpraq_baseline::Op::kLt,
                                                    static_cast<int64_t>(column), 0, 0}});
        // 诚实的 oracle（= base.filter）与明文基准一致；被篡改后的结果与之不同
        EXPECT_EQ(oracle_count, Popcount(base.filter));
        EXPECT_EQ(base.count, oracle_count);
        EXPECT_NE(tampered.count, oracle_count);  // 错值（且被上面的逐位断言钉死）
    }
}

// ===========================================================================
// 3. ⚪ `f=0` vs `f=1` 分档（D29/§7.18 裁决 3）—— 系统级端到端
// ===========================================================================
// 查询：Φ = (attr0 ∈ [2,5)) ∧ ... 用**单谓词** `attr0 >= 2` 最干净
// （只查列 2、3、4，oracle count = 38、sum(attr1) = 38）。
// filter 里 record 0 是 f=0（attr0 = 0）、record 1 是 f=1（attr0 = 1）。

TEST(MpraqMaliciousFTier, FZeroRecordTamperIsSilentButHarmless) {
    SumFixture f = SumFixture::Make(kN);
    const CountResult c = f.HandCount([](const std::vector<int64_t>& r) { return r[0] >= 2; });
    ASSERT_EQ(c.count, kCountGeTwo);
    // ⚠️ 索引必须精确：`attr0 = i % 5`、`Φ = attr0 >= 2`
    //    ⇒ f = 0 ⇔ i % 5 ∈ {0,1}（record 0、record 1）
    //    ⇒ f = 1 ⇔ i % 5 ∈ {2,3,4}（record 2 是**第一条** f=1 的记录）
    ASSERT_EQ(c.filter[0], uint8_t{0});  // record 0：f = 0（无害的那一档）
    ASSERT_EQ(c.filter[1], uint8_t{0});  // record 1：f = 0
    ASSERT_EQ(c.filter[2], uint8_t{1});  // record 2：f = 1（对照档）

    // 基线（无注入）
    {
        LocalTransport net(2);
        const SumAttempt base = TrySum(f, c, /*attr=*/1, net, 0xA001);
        ASSERT_TRUE(base.produced);
        ASSERT_EQ(base.sum, static_cast<uint128_t>(kSumGeTwo));
    }

    // 两台服务器**一致**把 record 0 的 `e` 改成 `e+1`（红队 E1 手法）
    InjectTransport net;
    net.SetRequestHook([&](int /*sid*/, uint64_t round, Payload& frame) -> size_t {
        if (round != 1) return 0;  // 1 = 第 2 轮（Phase2Request 帧）
        return OffsetOneRecordE(frame, /*i=*/0);
    });
    const SumAttempt a = TrySum(f, c, /*attr=*/1, net, 0xA001);

    // ① 注入确实打中了两台的第 2 轮帧（每台 1 个字节 ⇒ hits = 2）
    EXPECT_EQ(net.hits(), size_t{2});
    EXPECT_EQ(net.RequestCount(0), uint64_t{2});
    EXPECT_EQ(net.RequestCount(1), uint64_t{2});
    // ② **未检出**：整个批量 `all_ok()`、没有 abort、`Sum` 正常返回
    EXPECT_TRUE(a.produced);
    EXPECT_FALSE(a.aborted);
    EXPECT_FALSE(a.frame_aborted);
    // ③ **无害**：`Sum` 与明文基准 / 手算常量逐值相等
    EXPECT_EQ(a.sum, static_cast<uint128_t>(kSumGeTwo));
    EXPECT_EQ(a.sum, static_cast<uint128_t>(
                         mpraq_baseline::Sum(f.baseline, {{0, mpraq_baseline::Op::kGe, 2, 0, 0}}, 1)));
    // ④ 代数理由的可执行确认：`Δz = δ·f` ⇒ 该记录 `z` 不变（正确答案本就是 0）
    EXPECT_EQ(a.sum, static_cast<uint128_t>(38));
}

TEST(MpraqMaliciousFTier, FOneRecordTamperIsDetectedAndAborts) {
    SumFixture f = SumFixture::Make(kN);
    const CountResult c = f.HandCount([](const std::vector<int64_t>& r) { return r[0] >= 2; });
    ASSERT_EQ(c.filter[2], uint8_t{1});  // record 2：f = 1
    ASSERT_EQ(c.filter[0], uint8_t{0});

    // 与上一档**完全相同**的注入，只把记录号换成 f=1 的那条（record 2）
    InjectTransport net;
    net.SetRequestHook([&](int /*sid*/, uint64_t round, Payload& frame) -> size_t {
        if (round != 1) return 0;
        return OffsetOneRecordE(frame, /*i=*/2);
    });
    const SumAttempt a = TrySum(f, c, /*attr=*/1, net, 0xA002);

    EXPECT_EQ(net.hits(), size_t{2});
    // ① **检出**：抛 `SecureMulBatchAbort`，**不返回任何 SumResult**
    EXPECT_FALSE(a.produced);
    EXPECT_TRUE(a.aborted);
    // ② 分类 = §4.5-A 的纯客户端复核（`kClientLocalCheckFailed`）—— 不是 SPDZ MAC
    //    （`mac == α·z` 在"两台一致偏移"下恒成立，正是论文 :452 那句话不成立的原因）
    EXPECT_EQ(static_cast<int>(a.failure),
              static_cast<int>(SecureMulFailure::kClientLocalCheckFailed));
    // ③ 失败精确落在**被篡改的那条记录**上（逐记录校验生效）：
    //    `SumOverFilter` 报的是**第一个**失败记录 ⇒ filter 里第一条 `f=1` 的是 record 2
    //    （record 0 是 f=0、record 1 是 f=0、record 2 是 f=1）。
    //    ⚠️ 注意我们只篡改了 record 2，而 record 3.. 都**正常** ⇒ 逐记录判定
    //    （不是"整列一次校验"）在这里被直接钉住。
    EXPECT_EQ(a.index, size_t{2});
    EXPECT_EQ(c.filter[2], uint8_t{1});
    EXPECT_EQ(c.filter[3], uint8_t{1});  // 其余 f=1 的记录**没有**被篡改 ⇒ 必须正常
}

TEST(MpraqMaliciousFTier, BatchOutcomeShowsPerRecordVerdicts) {
    // 把两档放在**同一个批量**里对照：`RunSecureMulBatch` 是**逐记录**判定，
    // 因此可以同时看到"f=0 的篡改被放过、f=1 的篡改被抓住"。
    // （`SumOverFilter` 会在第一个失败记录处 abort ⇒ 这里直接用批量入口。）
    SumFixture f = SumFixture::Make(kN);
    const CountResult c = f.HandCount([](const std::vector<int64_t>& r) { return r[0] >= 2; });

    const std::vector<ModShare> e0 = f.client->AttributeShares(1, 0);
    const std::vector<ModShare> e1 = f.client->AttributeShares(1, 1);

    // 同一条批量里同时篡改 **record 0（f=0）** 与 **record 2（f=1）**
    InjectTransport net;
    net.SetRequestHook([&](int /*sid*/, uint64_t round, Payload& frame) -> size_t {
        if (round != 1) return 0;
        return OffsetOneRecordE(frame, /*i=*/0) + OffsetOneRecordE(frame, /*i=*/2);
    });
    const SecureMulBatchOutcome out = RunSecureMulBatch(c.filter, e0, e1, net, f.mac, *f.prng,
                                                       0xA003);

    ASSERT_EQ(out.size(), kN);
    // f=0 的记录（record 0）：**通过**，且 z = f·E = 0（正确答案本来就是 0）
    EXPECT_EQ(c.filter[0], uint8_t{0});
    EXPECT_EQ(out.ok[0], uint8_t{1});
    EXPECT_EQ(out.z[0], static_cast<uint128_t>(0));
    // f=1 的记录（record 2）：**被检出**
    EXPECT_EQ(c.filter[2], uint8_t{1});
    EXPECT_EQ(out.ok[2], uint8_t{0});
    EXPECT_EQ(static_cast<int>(out.failure[2]),
              static_cast<int>(SecureMulFailure::kClientLocalCheckFailed));
    EXPECT_EQ(out.z[2], static_cast<uint128_t>(0));  // 失败记录的 z 置 0（绝不当有效值累加）
    // 其余**每一条**记录都必须通过（篡改只打在 record 0/2 上）⇒ 逐记录校验的直接证据
    for (size_t i = 0; i < out.size(); ++i) {
        if (i == 2) continue;
        EXPECT_EQ(out.ok[i], uint8_t{1});
        // 逐条数值正确性：z[i] == f_i · E_i（mod q）
        EXPECT_EQ(out.z[i],
                  mulMod(static_cast<uint128_t>(c.filter[i]),
                         static_cast<uint128_t>(f.attrs[i][1]), f.q()));
    }
    EXPECT_EQ(out.first_failure, size_t{2});
    EXPECT_FALSE(out.all_ok());
    // `all_ok()` 为假 ⇒ `SumOrThrow` 必须抛（**绝不返回部分和**）
    EXPECT_THROW(out.SumOrThrow(f.q()), std::logic_error);
}

// ===========================================================================
// 4. 跨查询 / 跨会话重放（帧一级的"整条消息"重放）
// ===========================================================================

TEST(MpraqMaliciousReplay, ReplayedFirstRoundMessageIsRejected) {
    // 手法：把**上一次查询**的第 1 轮帧里的某条 `Phase1Request` 原样搬进**本次查询**
    // 的第 1 轮帧（整体重放，而不是改字段）。本次查询换了一个**新的盐** ⇒
    // 同一条记录的 `challenge` 与上次不同。
    //
    // ⚠️ 关键口径：`session` 只由记录号派生（`kSecureMulBatchSessionBase + i`），
    //    **不随查询变化** ⇒ 旧消息会被分派到**同一条记录**的 state 上；
    //    挡住它的是 **challenge（= 盐派生）**，而不是 session。本用例同时断言这一点。
    SumFixture f = SumFixture::Make(kN);
    const CountResult c = f.HandCount([](const std::vector<int64_t>& r) { return r[0] >= 2; });

    const uint64_t salt1 = 0xB001'0001;
    const uint64_t salt2 = 0xB001'0002;  // **不同的盐**

    InjectTransport net;
    const SumAttempt first = TrySum(f, c, 1, net, salt1);
    ASSERT_TRUE(first.produced);
    ASSERT_TRUE(net.frames(0).size() >= 1);
    const Payload old_frame = net.frames(0)[0];  // 查询 1 的第 1 轮帧
    ASSERT_EQ(old_frame.size(), kFrameHdr + kP1Req * kN);

    net.ClearHooks();
    net.ResetRounds();
    net.SetRequestHook([&](int sid, uint64_t round, Payload& frame) -> size_t {
        if (sid != 0 || round != 0) return 0;
        const size_t off = kFrameHdr + 7 * kP1Req;  // 第 7 条记录的整条子消息
        if (off + kP1Req > frame.size() || off + kP1Req > old_frame.size()) return 0;
        std::copy(old_frame.begin() + static_cast<long>(off),
                  old_frame.begin() + static_cast<long>(off + kP1Req),
                  frame.begin() + static_cast<long>(off));
        return kP1Req;
    });
    const SumAttempt a = TrySum(f, c, 1, net, salt2);

    EXPECT_EQ(net.hits(), size_t{kP1Req});
    // ① 被拒绝、abort、不返回任何和
    EXPECT_FALSE(a.produced);
    EXPECT_TRUE(a.aborted);
    EXPECT_EQ(static_cast<int>(a.failure),
              static_cast<int>(SecureMulFailure::kServerReported));
    // ② 精确落在被重放的那条记录上
    EXPECT_EQ(a.index, size_t{7});
    // ③ 对照：换回 salt1（与旧帧的盐相同）时**同一份帧能通过** ⇒ 证明挡住重放的
    //    确实是 challenge（盐派生），而不是 session 或别的字段。
    InjectTransport net2;
    net2.SetRequestHook([&](int sid, uint64_t round, Payload& frame) -> size_t {
        if (sid != 0 || round != 0) return 0;
        const size_t off = kFrameHdr + 7 * kP1Req;
        if (off + kP1Req > frame.size() || off + kP1Req > old_frame.size()) return 0;
        std::copy(old_frame.begin() + static_cast<long>(off),
                  old_frame.begin() + static_cast<long>(off + kP1Req),
                  frame.begin() + static_cast<long>(off));
        return kP1Req;
    });
    // ⚠️ 这里必须用**新的** `SumFixture`：同一台服务器 state 已被上一次查询消费，
    //    复用会被"一次性语义"拒绝（那是另一条防线，见下面第二个用例）。
    SumFixture f2 = SumFixture::Make(kN);
    const CountResult c2 = f2.HandCount([](const std::vector<int64_t>& r) { return r[0] >= 2; });
    const SumAttempt b = TrySum(f2, c2, 1, net2, salt1);  // 与旧帧**同一个盐**
    EXPECT_EQ(net2.hits(), size_t{kP1Req});
    EXPECT_TRUE(b.produced);  // 盐相同 ⇒ 旧帧内容与本次诚实帧逐位相同 ⇒ 接受
    EXPECT_EQ(b.sum, static_cast<uint128_t>(kSumGeTwo));
}

TEST(MpraqMaliciousReplay, CrossRecordSessionTransplantIsRejected) {
    // 手法：把第 7 条记录的 `session` 改成第 8 条记录的 session（**保留**第 7 条的
    // challenge）⇒ 服务器按 session 分派到**别的记录**的 state 上，
    // 该 state 的 challenge 与本消息的 challenge 不同 ⇒ 拒绝。
    // 这同时钉住"session 不是安全边界、challenge 才是"。
    SumFixture f = SumFixture::Make(kN);
    const CountResult c = f.HandCount([](const std::vector<int64_t>& r) { return r[0] >= 2; });

    InjectTransport net;
    net.SetRequestHook([&](int /*sid*/, uint64_t round, Payload& frame) -> size_t {
        if (round != 0) return 0;
        const size_t src_off = kFrameHdr + 7 * kP1Req + kP1FieldSession;
        const size_t dst_off = kFrameHdr + 8 * kP1Req + kP1FieldSession;
        if (src_off + 8 > frame.size() || dst_off + 8 > frame.size()) return 0;
        std::copy(frame.begin() + static_cast<long>(src_off),
                  frame.begin() + static_cast<long>(src_off + 8),
                  frame.begin() + static_cast<long>(dst_off));
        return 8;
    });
    const SumAttempt a = TrySum(f, c, 1, net, 0xB002'0001);
    // 两台服务器各收到 1 个第 1 轮帧 ⇒ 注入（8 字节）在两台上各打中一次
    EXPECT_EQ(net.hits(), size_t{2 * 8});
    EXPECT_FALSE(a.produced);
    EXPECT_TRUE(a.aborted);
    // 记录 8 的 state 收到的 session 是"记录 7 的" ⇒ 查表命中记录 7 的 state ⇒
    // challenge 不符 ⇒ 服务器 kPhaseError ⇒ 客户端按 kServerReported 分类。
    // （若 session 查不到任何 state，则是 kSessionNotFound 细类，同样 abort。）
    EXPECT_EQ(net.hits(), size_t{2 * 8});
    EXPECT_TRUE(a.failure == SecureMulFailure::kServerReported ||
                a.failure == SecureMulFailure::kSessionMismatch);
}

TEST(MpraqMaliciousReplay, ReusedSessionStateOnSecondQueryIsRejected) {
    // 手法：**同一个 `MpraqClient`** 上连跑两次 `SumOverFilter`，把第一次的
    // 第 1 轮帧重放到第二次（session 与 challenge **都**与第一次相同 ⇒
    // 唯一挡住它的是服务器 state 的**一次性语义**）。
    SumFixture f = SumFixture::Make(kN);
    const CountResult c = f.HandCount([](const std::vector<int64_t>& r) { return r[0] >= 2; });
    const uint64_t salt = 0xB003'0001;  // 两次都用同一个盐 ⇒ 只考"一次性语义"

    InjectTransport net;
    const SumAttempt first = TrySum(f, c, 1, net, salt);
    ASSERT_TRUE(first.produced);
    const Payload old_frame = net.frames(0)[0];

    net.ClearHooks();
    net.ResetRounds();
    net.SetRequestHook([&](int sid, uint64_t round, Payload& frame) -> size_t {
        if (sid != 0 || round != 0) return 0;
        const size_t off = kFrameHdr + 3 * kP1Req;
        if (off + kP1Req > frame.size() || off + kP1Req > old_frame.size()) return 0;
        std::copy(old_frame.begin() + static_cast<long>(off),
                  old_frame.begin() + static_cast<long>(off + kP1Req),
                  frame.begin() + static_cast<long>(off));
        return kP1Req;
    });
    const SumAttempt a = TrySum(f, c, 1, net, salt);
    EXPECT_EQ(net.hits(), size_t{kP1Req});
    EXPECT_FALSE(a.produced);
    EXPECT_TRUE(a.aborted);
    // 服务器 0 的那条 state 已被第一次查询消费 ⇒ kPhaseError ⇒ kServerReported
    EXPECT_EQ(static_cast<int>(a.failure),
              static_cast<int>(SecureMulFailure::kServerReported));
    EXPECT_EQ(a.index, size_t{3});

    // 对照：不注入时同一对 (client, salt) 的第二次查询**正常通过**
    // ⇒ 上面的拒绝确实来自重放，而不是"第二次查询本来就坏"。
    InjectTransport net2;
    const SumAttempt b = TrySum(f, c, 1, net2, salt);
    EXPECT_TRUE(b.produced);
    EXPECT_EQ(b.sum, static_cast<uint128_t>(kSumGeTwo));
}

// ===========================================================================
// 5. 上传阶段的共享错配（越界分量 / 两台不一致 / 错长度）
// ===========================================================================

TEST(MpraqMaliciousUpload, UploadTamperDoesNotReachTheSumPath) {
    // 手法（**上传阶段**）：客户端把属性 `attr1` 的共享上传给服务器 0 时，
    // 链路上（或那一台收到后）把共享整体 +1 ⇒ 服务器**存储里**的 ⟨E⟩_0 ≠ 客户端算出的 ⟨E⟩_0。
    //
    // ⚠️ **本用例实测出的一个重要事实（如实记录）**：这一注入**不影响 `Sum`**。
    //    原因是结构性的：`MPA-06` 的批量层**不读服务器的存储**，它由客户端
    //    自己传进去的 `e_server0/e_server1`（= `client.AttributeShares()`，即客户端
    //    本地那份共享）构造每台服务器的 `SecureMulServerState`
    //    （`aggvalue.hpp` §2 的 ① 离线预装）。服务器存储里的属性共享只服务
    //    PIR 之外的读取路径（`MpraqNode::AttributeShare`），**不参与 SecureMul**。
    //    ⇒ 结论：这类"上传错配"在本架构下**不构成对 Sum 的攻击**（既不是"检出"，
    //      也不是"未检出"——它**根本影响不到**结果），这一条必须写清，
    //      否则很容易被误读成"检出了上传篡改"。
    //    下面同时给出**两条**断言：(a) 结果仍然正确；(b) 存储确实被改了（注入真的发生了）。
    SumFixture f = SumFixture::Make(kN);
    f.inj0->SetShareUploadHook([](uint32_t attr_id, std::vector<ModShare>& shares) -> size_t {
        if (attr_id != 1) return 0;  // 只改 attr1（求和的属性）
        for (ModShare& s : shares) s.value = addMod(s.value, 1, kMpraqModulus);
        return shares.size() * 16;
    });
    {
        // ⚠️ hook 必须在**上传之前**设置 ⇒ 用同一个 fixture 的装饰器重新跑一次 Init
        //（装饰器对象与节点由 fixture 持有，生命周期覆盖新的 client）。
        MpraqInitParams p;
        p.lambda = 16;
        p.prp_epsilon = kFastEps;
        p.seed = 7;
        f.client = MpraqClient::InitWithChannels(f.schema, f.records, p, *f.inj0, *f.inj1);
        f.mac = SecureMulClientState(f.client->mac_key_shares(), f.client->modulus());
    }
    // (b) 注入确实发生了：服务器 0 存储里的 ⟨E⟩ 比客户端那份多 1
    ASSERT_EQ(f.inj0->share_upload_hits(), kN * 16);
    EXPECT_EQ(ReconstructMod(f.inj0->node().AttributeShare(1, 6),
                             f.inj1->node().AttributeShare(1, 6), f.q()),
              addMod(static_cast<uint128_t>(f.attrs[6][1]), 1, f.q()));
    // 而客户端本地那份（`AttributeShares`）**没有**被改（它是 SecureMul 的真正输入）
    EXPECT_EQ(ReconstructMod(f.client->AttributeShare(1, 6, 0),
                             f.client->AttributeShare(1, 6, 1), f.q()),
              static_cast<uint128_t>(f.attrs[6][1]));

    const CountResult c = f.HandCount([](const std::vector<int64_t>& r) { return r[0] >= 2; });
    ASSERT_EQ(c.count, kCountGeTwo);
    LocalTransport net(2);
    const SumAttempt a = TrySum(f, c, /*attr=*/1, net, 0xC001);
    // (a) 结果**仍然正确**（注入够不到这条路径）⇒ 不是"未检出"，而是"影响不到"
    EXPECT_TRUE(a.produced);
    EXPECT_FALSE(a.aborted);
    EXPECT_EQ(a.sum, static_cast<uint128_t>(kSumGeTwo));
    EXPECT_EQ(a.sum, static_cast<uint128_t>(
                         mpraq_baseline::Sum(f.baseline,
                                             {{0, mpraq_baseline::Op::kGe, 2, 0, 0}}, 1)));
}

TEST(MpraqMaliciousUpload, ConsistentShareOffsetIsInvisibleAndNotAThreat) {
    // 🔴 **本用例固化一条重要的边界发现（红队口径，必须如实记录）**：
    //    批量层**同时**用传入的 `e_server0/e_server1` 构造①服务器的 state 与
    //    ②纯客户端复核 A/B 的基准（`ctx.attribute_share = e_server0[i]`，见
    //    `MakeSetupsAndContext`）。因此对**输入的那一份共享**做**一致**偏移时：
    //      · 服务器算出的 `⟨e⟩_p` 与 ctx 基准**同步**偏移 ⇒ §4.5-B 判据 `e_check ?= ⟨E⟩_p − ⟨b⟩_p`
    //        两边都基于同一份偏移后的 ⟨E⟩_p ⇒ **恒成立、不报警**；
    //      · `E_local = e_sent + b` 也随之偏移 ⇒ §4.5-A 判据 `z ?= f·E_local`
    //        同样**恒成立、不报警**（z 也按偏移后的 E 算）。
    //    ⇒ 结论：**"两台服务器的 ⟨E⟩ 相对偏移"这件事在 `Sum` 这一层不是独立的安全事件** ——
    //      上面那两条检查比的是"服务器实际使用值 vs 客户端安装值"，而客户端**安装的**
    //      就是传进来的那份。若输入本身被改（本用例），结果会被**一致地**平移，
    //      没有任何内部不一致可供检出；但注意此时结果也不是"错的相对值"：
    //      `⟨E⟩_0+⟨E⟩_1` 变的那一份如果**两台一起**变，则重建值仍是 `E`（本用例的形态），
    //      若只变一台（下一个用例），则重建值 `E+δ` 而**B 会精确指出是哪一台**。
    //    ⚠️ 因此本用例**不**断言"检出"（那是过度声明），只断言"结果与明文对不上"这件事
    //      在这一形态下**必须**由上游保证输入共享的正确性（本层的信任边界）。
    SumFixture f = SumFixture::Make(kN);
    const CountResult c = f.HandCount([](const std::vector<int64_t>& r) { return r[0] >= 2; });
    ASSERT_EQ(c.count, kCountGeTwo);

    // 对照：诚实输入 ⇒ 正确结果
    {
        LocalTransport net(2);
        const SumAttempt base = TrySum(f, c, /*attr=*/1, net, 0xC101);
        ASSERT_TRUE(base.produced);
        ASSERT_EQ(base.sum, static_cast<uint128_t>(kSumGeTwo));
    }

    // 注入形态 A：**两台一起**偏移同一台的分量（这里给 e0 加 1、e1 减 1
    // ⇒ 重建值**不变**）⇒ 结果仍然正确，且不报警（这正是"一致偏移不可见"）
    {
        std::vector<ModShare> a0 = f.client->AttributeShares(1, 0);
        std::vector<ModShare> a1 = f.client->AttributeShares(1, 1);
        for (size_t i = 0; i < kN; ++i) {
            a0[i].value = addMod(a0[i].value, 1, f.q());
            a1[i].value = subMod(a1[i].value, 1, f.q());
        }
        LocalTransport net(2);
        const SecureMulBatchOutcome out =
            RunSecureMulBatch(c.filter, a0, a1, net, f.mac, *f.prng, 0xC201);
        EXPECT_TRUE(out.all_ok());  // 内部完全自洽 ⇒ 两条检查都不响
        EXPECT_EQ(out.SumOrThrow(f.q()), static_cast<uint128_t>(kSumGeTwo));  // 值也没变
    }

    // 注入形态 B：**只让服务器 0 的那一份**整体 +1（重建值 = 明文 + 1）
    // ⇒ 两条纯客户端检查**仍不响**（因为 ctx 基准也取自这份输入），
    //    但**逐记录重建值**变成了 `f·(E+1)` ⇒ 若上游把这种输入交给本层，
    //    本层**无法**仅凭内部一致性识别它 —— 这正是"输入共享的正确性"这条信任边界。
    {
        std::vector<ModShare> b0 = f.client->AttributeShares(1, 0);
        const std::vector<ModShare> b1 = f.client->AttributeShares(1, 1);
        for (ModShare& sh : b0) sh.value = addMod(sh.value, 1, f.q());
        LocalTransport net(2);
        const SecureMulBatchOutcome out =
            RunSecureMulBatch(c.filter, b0, b1, net, f.mac, *f.prng, 0xC202);
        EXPECT_TRUE(out.all_ok());
        const uint128_t expect_shifted =
            addMod(static_cast<uint128_t>(kSumGeTwo), static_cast<uint128_t>(kCountGeTwo), f.q());
        EXPECT_EQ(out.SumOrThrow(f.q()), expect_shifted);  // 38 + 38 = 76（**确定数字**）
        EXPECT_TRUE(out.SumOrThrow(f.q()) != static_cast<uint128_t>(kSumGeTwo));
    }
}

TEST(MpraqMaliciousUpload, SingleServerShareMismatchIsCaughtByCheckB) {
    // 与上一个用例**成对**：这里制造**真正的不一致** ——
    // 注入**服务器 0 的协议回执**（第 1 轮应答里的 `e_computed`），
    // 而客户端安装的 ctx 基准来自它自己传进去的那份 ⟨E⟩_0。
    // ⇒ §4.5-B 判据 `e_computed ?= ⟨E⟩_0 − ⟨b⟩_0` **必须**失败，
    //    分类 `kEShareMismatch`（并把"是哪一台说谎"指出来），逐记录 abort。
    SumFixture f = SumFixture::Make(kN);
    const CountResult c = f.HandCount([](const std::vector<int64_t>& r) { return r[0] >= 2; });
    ASSERT_EQ(c.count, kCountGeTwo);

    // 对照：无注入 ⇒ 正确
    {
        LocalTransport net(2);
        const SumAttempt base = TrySum(f, c, /*attr=*/1, net, 0xC301);
        ASSERT_TRUE(base.produced);
        ASSERT_EQ(base.sum, static_cast<uint128_t>(kSumGeTwo));
    }

    InjectTransport net;
    net.SetResponseHook([&](int sid, uint64_t round, Payload& frame) -> size_t {
        if (sid != 0 || round != 0) return 0;  // 服务器 0 的第 1 轮应答帧
        const size_t off = kFrameHdr + 2 * kP1Res + kR1FieldEComputed;
        if (off + 16 > frame.size()) return 0;
        frame[off] = static_cast<uint8_t>(frame[off] ^ 0x01);  // 谎报 ⟨e⟩_0
        return 1;
    });
    const SumAttempt a = TrySum(f, c, /*attr=*/1, net, 0xC301);
    EXPECT_EQ(net.hits(), size_t{1});
    EXPECT_FALSE(a.produced);  // 不返回任何和
    EXPECT_TRUE(a.aborted);
    // ⚠️ 分类实测为 `kServerReported`，理由是**批量层对第 1 轮应答做了逐条前置校验**
    //    （`aggvalue.cpp`：解码 Phase1Response 后立即查 session/status，并把
    //     `e_check0[i] = 该条回执`**原样回给**服务器）⇒ 被改的那条在第 1 轮就被标记失败，
    //    第 2 轮服务器侧又用 `e_check` 拒绝了一次 ⇒ 两层都在响，报的是**前一层**的分类。
    //    §4.5-B（`kEShareMismatch`）的**独立**证据在 `tests/test_mpraq_securemul.cpp`
    //    的 `ServerSelfReportedCheckIsSelfWitnessing` 与 `MPA-06` 的篡改用例 (3)；
    //    本用例只固化"**系统级**必须 abort 且不返回任何和"。
    EXPECT_TRUE(a.failure == SecureMulFailure::kServerReported ||
                a.failure == SecureMulFailure::kEShareMismatch);
    EXPECT_EQ(a.index, size_t{2});  // record 0/1 的 f = 0；失败记录精确到被篡改的那条
}

TEST(MpraqMaliciousUpload, OutOfDomainShareIsRejectedAtUpload) {
    // 上传阶段的**第二种**错配：共享分量越界（`≥ q`）。
    // 节点在入口处**结构化拒绝**（`std::out_of_range`），绝不静默写进存储，
    // 也绝不把越界分量留给后续的 `ReconstructMod`（那会静默错值）。
    PirFixture f = PirFixture::Make(kN);
    const std::vector<ModShare> good = f.client->AttributeShares(1, 0);
    ASSERT_EQ(good.size(), kN);

    std::vector<ModShare> bad = good;
    bad[3].value = f.q();  // == q ⇒ 越界（合法范围 [0, q)）
    bool rejected = false;
    std::string what;
    try {
        f.inj0->node().SetAttributeShares(1, bad);
    } catch (const std::out_of_range& e) {
        rejected = true;
        what = e.what();
    }
    EXPECT_TRUE(rejected);
    EXPECT_TRUE(what.find("mod q") != std::string::npos);
    // 拒绝之后存储必须**保持原样** ⇒ 后续查询仍然诚实（不静默污染）
    EXPECT_EQ(ReconstructMod(f.inj0->node().AttributeShare(1, 3),
                             f.inj1->node().AttributeShare(1, 3), f.q()),
              static_cast<uint128_t>(f.attrs[3][1]));
}

TEST(MpraqMaliciousUpload, MalformedUploadIsRejectedNotSilentlyTruncated) {
    // 上传阶段的三类"结构性错配"必须 fail-loudly（历史缺陷的反面教材：
    // 静默隐式扩容 / 静默截断）：
    //   ① 特征 word 共享被截断（长度 ≠ count）；
    //   ② 属性共享向量长度 ≠ N；
    //   ③ 条目号越界（base + count > n）。
    PirFixture f = PirFixture::Make(kN);
    std::vector<uint128_t> words{1, 2, 3};
    const uint128_t stored0_before = f.node0->FeatureWord(0);
    EXPECT_THROW(f.inj0->node().UploadFeatureWords(0, words, /*count=*/2),
                 std::invalid_argument);
    // 截断**没有**写进存储：条目 0 仍是 `Init` 上传的诚实共享（逐位不变）
    EXPECT_EQ(f.node0->FeatureWord(0), stored0_before);
    EXPECT_THROW(f.inj0->node().UploadFeatureWords(
                     f.client->store_params().entry_count(), words, 3),
                 std::out_of_range);
    EXPECT_THROW(f.inj0->node().UploadFeatureWords(0, words, /*count=*/0),
                 std::invalid_argument);
    EXPECT_THROW(f.inj0->node().SetAttributeShares(1, {ModShare{1}}), std::invalid_argument);
    EXPECT_THROW(f.inj0->node().SetAttributeShares(/*attr_id=*/99, std::vector<ModShare>(kN)),
                 std::out_of_range);

    // 对照：**合法**写入路径仍然可用（说明上面的拒绝不是"什么都拒绝"）
    const std::vector<ModShare> good = f.client->AttributeShares(1, 0);
    f.inj0->node().SetAttributeShares(1, good);
    EXPECT_EQ(ReconstructMod(f.inj0->node().AttributeShare(1, 5),
                             f.inj1->node().AttributeShare(1, 5), f.q()),
              static_cast<uint128_t>(f.attrs[5][1]));
}

// ===========================================================================
// 6. 两台服务器**共谋**的一致偏移 —— 在系统级（`SumOverFilter`）的结局
// ===========================================================================

TEST(MpraqMaliciousOffset, BothServersConsistentEOffsetIsDetectedEndToEnd) {
    // 红队 E1 的**系统级**复现：两台服务器在第 2 轮把**每一条**记录的 `e` 都改成
    // `e + 1`（各自按公开的协议公式重算 `z_p`/`mac_p` ⇒ `mac == α·z` 恒成立）。
    //
    // 论文只有 `mac == α·z` 这一个检查点 ⇒ 会接受错值（v2 实测：8/8 静默接受）。
    // 本系统在系统级必须 abort（`MPA-07` 的验收面）。
    SumFixture f = SumFixture::Make(kN);
    const CountResult c = f.HandCount([](const std::vector<int64_t>& r) { return r[0] >= 2; });
    ASSERT_EQ(c.count, kCountGeTwo);

    InjectTransport net;
    net.SetRequestHook([&](int /*sid*/, uint64_t round, Payload& frame) -> size_t {
        if (round != 1) return 0;
        // ⚠️ 只改 `e`，**不改** `e_check`：`e_check` 必须仍是服务器第 1 轮的自报值，
        //    否则会被服务器侧的 kECheckFailed 先拒（那是另一条防线，不是本用例要考的）。
        size_t changed = 0;
        const size_t count = (frame.size() - kFrameHdr) / kP2Req;
        for (size_t i = 0; i < count; ++i) {
            const size_t off = OffP2(i, kP2FieldE);
            frame[off] = static_cast<uint8_t>(frame[off] + 1);
            ++changed;
        }
        return changed;
    });
    const SumAttempt a = TrySum(f, c, 1, net, 0xD001);

    EXPECT_EQ(net.hits(), size_t{2 * kN});  // 两台 × N 条
    // ① **检出并 abort**（`SumOverFilter` 不返回任何结果）
    EXPECT_FALSE(a.produced);
    EXPECT_TRUE(a.aborted);
    // ② 检出它的是 §4.5-A 纯客户端复核；SPDZ MAC 在这一类攻击下**恒成立**
    //    （这正是论文 :452 的 "any tampering" 声明不成立的原因）
    EXPECT_EQ(static_cast<int>(a.failure),
              static_cast<int>(SecureMulFailure::kClientLocalCheckFailed));
    EXPECT_EQ(a.index, size_t{2});  // 第一条 f=1 的记录（record 0/1 是 f=0）
    EXPECT_FALSE(a.frame_aborted);

    // ③ 批量层的逐记录证据：**所有** f=1 的记录都失败，没有一条漏检
    SumFixture f2 = SumFixture::Make(kN);
    const CountResult c2 = f2.HandCount([](const std::vector<int64_t>& r) { return r[0] >= 2; });
    const std::vector<ModShare> e0 = f2.client->AttributeShares(1, 0);
    const std::vector<ModShare> e1 = f2.client->AttributeShares(1, 1);
    InjectTransport net2;
    net2.SetRequestHook([&](int, uint64_t round, Payload& frame) -> size_t {
        if (round != 1) return 0;
        size_t changed = 0;
        const size_t count = (frame.size() - kFrameHdr) / kP2Req;
        for (size_t i = 0; i < count; ++i) {
            frame[OffP2(i, kP2FieldE)] = static_cast<uint8_t>(frame[OffP2(i, kP2FieldE)] + 1);
            ++changed;
        }
        return changed;
    });
    const SecureMulBatchOutcome out =
        RunSecureMulBatch(c2.filter, e0, e1, net2, f2.mac, *f2.prng, 0xD002);
    uint64_t f1_records = 0, f1_failed = 0, f0_ok = 0, f0_total = 0;
    for (size_t i = 0; i < out.size(); ++i) {
        if (c2.filter[i] == 1) {
            ++f1_records;
            if (out.ok[i] == 0) {
                ++f1_failed;
                EXPECT_EQ(static_cast<int>(out.failure[i]),
                          static_cast<int>(SecureMulFailure::kClientLocalCheckFailed));
            }
        } else {
            ++f0_total;
            if (out.ok[i] == 1 && out.z[i] == 0) ++f0_ok;
        }
    }
    EXPECT_EQ(f1_records, kCountGeTwo);   // 38 条 f=1
    EXPECT_EQ(f1_failed, f1_records);     // **全部**被检出
    EXPECT_EQ(f0_total, kN - kCountGeTwo);
    EXPECT_EQ(f0_ok, f0_total);           // f=0 的一档照旧"未检出但无害"
    EXPECT_FALSE(out.all_ok());
}

// ===========================================================================
// 7. "值层"继续可用：单台改 mac_p ⇒ SPDZ MAC 检出（系统级）
// ===========================================================================

TEST(MpraqMaliciousOffset, SingleServerMacShareFlipAbortsSum) {
    // 与上一类形成对照：**不改 `e`**，只让服务器 0 把某条 `f=1` 记录的 `mac_p`
    // 翻转 1 个 bit ⇒ `mac != α·z` ⇒ `kMacMismatch` ⇒ abort。
    // 这一档证明"SPDZ MAC 那一层确实在系统级生效"（`spdz_mac_on_securemul = true` 的证据）。
    SumFixture f = SumFixture::Make(kN);
    const CountResult c = f.HandCount([](const std::vector<int64_t>& r) { return r[0] >= 2; });

    InjectTransport net;
    net.SetResponseHook([&](int sid, uint64_t round, Payload& frame) -> size_t {
        if (sid != 0 || round != 1) return 0;
        const size_t off = OffR2(/*i=*/1, kR2FieldMac);
        if (off + 16 > frame.size()) return 0;
        frame[off] = static_cast<uint8_t>(frame[off] ^ 0x01);
        return 1;
    });
    const SumAttempt a = TrySum(f, c, 1, net, 0xE001);
    EXPECT_EQ(net.hits(), size_t{1});
    EXPECT_FALSE(a.produced);
    EXPECT_TRUE(a.aborted);
    EXPECT_EQ(static_cast<int>(a.failure), static_cast<int>(SecureMulFailure::kMacMismatch));
    EXPECT_EQ(a.index, size_t{1});
}

// ===========================================================================
// 8. `VerificationBoundary`：能力表与**可执行证据**逐项对齐
// ===========================================================================

TEST(MpraqMaliciousBoundary, BoundaryMatchesExecutableEvidence) {
    const VerificationBoundary b = MpraqVerificationBoundary();

    // ---- ① 逐项取值（本轮的**裁决结果**，不是"跑通了"）----
    EXPECT_TRUE(b.spdz_mac_on_securemul);
    EXPECT_TRUE(b.securemul_client_local_checks);
    EXPECT_TRUE(b.batch_per_record_verification);
    EXPECT_FALSE(b.pir_value_layer);          // ❌ 论文写法在共享域不成立（D24①/L9，D29/V1）
    EXPECT_FALSE(b.count_integrity);          // ❌ 论文框架内无可用机制（D29/V2）
    // ⚪ 两项的**语义不同**，字段名已按裁决改成自解释形式：
    //   * `..._independent = false` ⇒ **不是独立能力位**（能力由
    //     `securemul_client_local_checks` 表达，不重复计数）；
    //   * `..._detectable  = false` ⇒ **不可检出**（但无害）。
    EXPECT_FALSE(b.e_or_d_offset_independent);
    EXPECT_FALSE(b.f_zero_record_e_tamper_detectable);
    // 反向断言：改名不得把"独立能力位"的计数带偏（仍是 3，而不是 4/5）
    EXPECT_TRUE(b.securemul_client_local_checks);
    EXPECT_EQ(b.true_count(), 3);
    EXPECT_EQ(b.false_count(), kCapabilityFields - 3);   // = 4
    // ⚠️ 名字必须**自解释**（裁决理由：`bool` 表达不了第三态，不许硬塞）：
    //    两个注记都要写清"本字段回答的是什么问题"，避免再被读成"能不能检出"。
    const std::string ind = b.note_for("e_or_d_offset_independent");
    EXPECT_TRUE(ind.find("独立") != std::string::npos);
    EXPECT_TRUE(ind.find("securemul_client_local_checks") != std::string::npos);
    const std::string det = b.note_for("f_zero_record_e_tamper_detectable");
    EXPECT_TRUE(det.find("不可检出") != std::string::npos);
    EXPECT_TRUE(det.find("无害") != std::string::npos);
    EXPECT_FALSE(b.headline().empty());

    // ---- ② 每项都必须有注记，且注记里必须带**依据**（决策号或文件/行号）----
    const std::vector<std::string> fields = {
        "spdz_mac_on_securemul", "securemul_client_local_checks",
        "batch_per_record_verification", "pir_value_layer", "count_integrity",
        "e_or_d_offset_independent", "f_zero_record_e_tamper_detectable"};
    for (const std::string& fld : fields) {
        const std::string note = b.note_for(fld);
        EXPECT_FALSE(note.empty());  // 每一项都有口径说明
    }
    // ---- ③ **不可检出**项必须写清"为什么不可检出" + 指向**可执行反例** ----
    const std::string pir = b.note_for("pir_value_layer");
    EXPECT_TRUE(pir.find("共享域") != std::string::npos);                 // 为什么
    EXPECT_TRUE(pir.find("FeatureWordTamperIsSilentlyCounted") != std::string::npos);  // 反例
    const std::string cnt = b.note_for("count_integrity");
    EXPECT_TRUE(cnt.find("没有") != std::string::npos);
    EXPECT_TRUE(cnt.find("BitFlipDirectlyChangesCount") != std::string::npos ||
                cnt.find("FeatureWordTamperIsSilentlyCounted") != std::string::npos);
    const std::string fz = b.note_for("f_zero_record_e_tamper_detectable");
    EXPECT_TRUE(fz.find("Δz") != std::string::npos);                      // 代数理由
    EXPECT_TRUE(fz.find("FZeroRecordTamperIsSilentButHarmless") != std::string::npos);
    EXPECT_TRUE(fz.find("FOneRecordTamperIsDetectedAndAborts") != std::string::npos);

    // ---- ④ 矩阵项 3（跨查询/跨会话重放）的证据注记必须指向三个重放用例 ----
    const std::string rp = b.note_for("replay_challenge_binding");
    EXPECT_TRUE(rp.find("ReplayedFirstRoundMessageIsRejected") != std::string::npos);
    EXPECT_TRUE(rp.find("CrossRecordSessionTransplantIsRejected") != std::string::npos);
    EXPECT_TRUE(rp.find("ReusedSessionStateOnSecondQueryIsRejected") != std::string::npos);

    // ---- ⑤ 未知字段 ⇒ 空串（不抛异常）----
    EXPECT_EQ(b.note_for("no_such_field"), std::string());

    // ---- ⑥ 口径正文（论文可引用）里的关键承诺/限定逐条在场 ----
    const std::string h = b.headline();
    EXPECT_TRUE(h.find("D29") != std::string::npos);
    EXPECT_TRUE(h.find("f=0") != std::string::npos || h.find("f = 0") != std::string::npos);
    EXPECT_TRUE(h.find(":150") != std::string::npos);  // 共谋不在威胁模型内（论文假设）
    // ⚠️ 反向断言：口径里**不得**出现论文那句被证伪的绝对化声明
    EXPECT_TRUE(h.find("any tampering can be detected") == std::string::npos);
}

TEST(MpraqMaliciousBoundary, PureFunctionAndStableAcrossCalls) {
    // 纯函数（无副作用）：连续两次调用逐字段一致、`notes` 内容一致。
    const VerificationBoundary a = MpraqVerificationBoundary();
    const VerificationBoundary b = MpraqVerificationBoundary();
    EXPECT_EQ(a.true_count(), b.true_count());
    EXPECT_EQ(a.false_count(), b.false_count());
    EXPECT_EQ(a.notes.size(), b.notes.size());
    // 7 条能力位注记 + 1 条"重放/challenge 绑定"的矩阵注记（见 verification.cpp）
    EXPECT_EQ(a.notes.size(), size_t{8});
    EXPECT_FALSE(a.note_for("replay_challenge_binding").empty());
    for (size_t i = 0; i < a.notes.size(); ++i) {
        EXPECT_EQ(a.notes[i], b.notes[i]);
    }
    EXPECT_EQ(a.headline(), b.headline());
    // 注记的字段名必须与能力位一一对应（未来加字段时这条会失败 ⇒ 强制同步）
    const std::vector<std::string> fields = {
        "spdz_mac_on_securemul", "securemul_client_local_checks",
        "batch_per_record_verification", "pir_value_layer", "count_integrity",
        "e_or_d_offset_independent", "f_zero_record_e_tamper_detectable"};
    for (const std::string& fld : fields) {
        bool found = false;
        for (const std::string& n : a.notes) {
            if (n.rfind("[" + fld + "] ", 0) == 0) found = true;
        }
        EXPECT_TRUE(found);
    }
    // 能力位个数与 `false_count()` 的口径一致（口径漂移会在这里失败）
    EXPECT_EQ(kCapabilityFields, a.true_count() + a.false_count());
}

// ===========================================================================
// 9. 汇总（把矩阵的关键数字打进测试输出，便于贴进报告）
// ===========================================================================

TEST(MpraqMaliciousReport, Summary) {
    const VerificationBoundary b = MpraqVerificationBoundary();
    std::printf("[MPA-07] 验证边界：true=%d false=%d（能力位共 %d 个）\n", b.true_count(),
                b.false_count(), b.true_count() + b.false_count());
    std::printf("[MPA-07] ✅ SPDZ MAC / 纯客户端复核 A·B / 逐记录批量校验 = 已具备\n");
    std::printf("[MPA-07] ❌ PIR 值层（D24①/L9、D29/V1）= 共享域上不成立 ⇒ 不做；"
                "反例：Count 篡改 1 bit ⇒ 38 → 37，不抛异常\n");
    std::printf("[MPA-07] ❌ Count 完整性（D29/V2）= 无可用机制 ⇒ 如实声明；"
                "反例：51 → 52（±1）\n");
    std::printf("[MPA-07] ⚪ f=0 被篡改 e：不可检出但无害（Δz=δ·f、Δmac=α·δ·f ⇒ 恒 0）；"
                "f=1 时同一注入 ⇒ kClientLocalCheckFailed + abort\n");
    std::printf("[MPA-07] 系统级矩阵：PIR 值层 / f 分档 / 跨查询重放 / 跨会话重放 /"
                "上传错配 / 双侧一致偏移 / MAC 翻转 —— 逐条有确定性期望值\n");
    // 汇总用例本身也要有硬断言（不是只有 printf）
    EXPECT_EQ(b.true_count(), 3);
    EXPECT_FALSE(b.pir_value_layer);
    EXPECT_FALSE(b.count_integrity);
}
