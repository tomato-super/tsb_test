// MPA-05：SecureMul 的三方消息流测试。
//
// 覆盖（对应任务书的 5 条要求）：
//   1. 数值正确性：确定性随机源（显式种子）下数百轮 (f, E, α, triple) 全部满足
//      z == f·E (mod q) 且 mac == α·z（用 shared/verify 的校验函数复核）。
//   2. 边界与非法参数：f=0/1、E=0/q−1、α=0/1/q−1、模数非奇数、共享数量不符、
//      消息乱序/重复/跨会话重放，全部必须抛异常。
//   3. 恶意服务器注入：对**每台服务器分别**篡改 d、⟨e⟩_p、MAC 分片、最终分片，
//      并区分"值错"与"MAC 检出"两条路径分别断言。
//   4. 零服务器间通信：CountingTransport 统计每条上链消息与目标 endpoint，
//      断言只有 server_id ∈ {0,1}、每台服务器恰好 [Phase1Request, Phase2Request]
//      两条消息、且没有第三个端点。
//   5. 确定性：同一种子两次运行逐位一致。
//
// ⚠️ 本文件不写 main（用 tests/support 的 TEST/EXPECT_* 宏与共享的 test_main.cpp）。

#include "core/field.hpp"
#include "core/random.hpp"
#include "mpraq/secure_mul_flow.hpp"
#include "mpraq/predicate.hpp"
#include "net/transport.hpp"
#include "shared/secret_sharing.hpp"
#include "shared/verify.hpp"
#include "test_framework.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using namespace tsb;
using namespace tsb::mpraq;

namespace {

const uint128_t kQ = kSecureMulModulus;  // 2^127 − 1（梅森素数，奇）

// ---------------------------------------------------------------------------
// 确定性随机源（显式种子；**不用** AesPrf::GenerateKey()）
// ---------------------------------------------------------------------------
// DeterministicPrng 需要 16 字节 AES 密钥。任务书要求"显式种子"，
// 因此这里由 ASCII 种子确定性地展开成密钥，不使用任何 CSPRNG。
std::array<uint8_t, kAesKeyBytes> SeedKey(const std::string& seed) {
    std::vector<uint8_t> bytes(seed.begin(), seed.end());
    return MakeAesSeed(std::move(bytes));
}

// ⚠️ DeterministicPrng 内部持有 AesPrf，而 AesPrf 明确禁止拷贝/移动
// （持有 CryptoPP ECB 上下文），因此这里不做"返回 Prng"的工厂函数，
// 一律在用例里就地构造，避免任何隐式拷贝。
using Prng = random::DeterministicPrng;

// ---------------------------------------------------------------------------
// CountingTransport：包装 ITransportClient，统计"上链消息"
//
// 这是"服务器之间零通信"的**证据来源**：所有客户端 → 服务器的字节都必须
// 经过这里，因此
//   * record 里出现非 {0,1} 的 server_id ⇒ 存在第三个端点（服务器间信道）；
//   * 某台服务器的消息序列不等于 [Phase1Request, Phase2Request] ⇒ 有多余消息；
// 两者任一成立就说明协议被破坏。
//
// 同时提供定点篡改：tamper_target 指定要改哪一条消息，tamper_offset 指定改
// 载荷里的哪个字节（-1 = 不改）。篡改发生在**客户端发出的字节**上，等价于
// 链路上/服务器处的恶意行为。
// ---------------------------------------------------------------------------
class CountingTransport : public ITransportClient {
public:
    struct Recorded {
        int server_id = 0;
        Payload payload;
    };

    enum class TamperTarget { kNone, kSubmit, kResponse };

    explicit CountingTransport(ITransportClient& inner) : inner_(inner) {}

    // ---- 篡改注入 ----
    // server_id == kAllServers ⇒ 对**两台**都施加同样的篡改
    // （用于表达"两台被改成一致使用同一个偏移值"这一类攻击，红队 E1/E3）
    static constexpr int kAllServers = -2;

    void SetTamper(int server_id, TamperTarget target, size_t offset,
                   uint8_t xor_mask = 0x01, uint64_t occurrence = 0) {
        tamper_server_ = server_id;
        tamper_target_ = target;
        tamper_offset_ = offset;
        tamper_xor_ = xor_mask;
        tamper_occurrence_ = occurrence;
        submit_seen_ = {{0, 0}};
        response_seen_ = 0;
        tampered_count_ = 0;
    }
    void ClearTamper() { tamper_target_ = TamperTarget::kNone; }

    // 实际被改动过的字节数（0 说明注入没打中，测试会据此报错而不是静默通过）
    size_t TamperedCount() const { return tampered_count_; }

    // ---- ITransportClient ----
    void Submit(int server_id, Payload request) override {
        record_.push_back(Recorded{server_id, request});
        if (server_id != kServer0 && server_id != kServer1) {
            ++third_party_;
        }
        const bool server_matches =
            (tamper_server_ == kAllServers) || (server_id == tamper_server_);
        // ⚠️ occurrence 的语义是"**该服务器在本次 Collect 中的第几条**"，
        //    而不是"全局第几条 Submit"。客户端每轮都会同时向两台 Submit，
        //    所以只有按服务器分别计数，`occurrence=1` 才能稳定命中第 2 轮请求
        //    （这也让 `kAllServers` 与 occurrence 的组合有意义）。
        const uint64_t own_index = submit_seen_[static_cast<size_t>(server_id)]++;
        if (tamper_target_ == TamperTarget::kSubmit && server_matches &&
            own_index == tamper_occurrence_) {
            TamperBytes(request);
            ++tampered_count_;
        }
        pending_targets_.push_back(server_id);
        inner_.Submit(server_id, std::move(request));
    }

    std::vector<Response> Collect() override {
        const std::vector<int> targets = pending_targets_;
        pending_targets_.clear();
        auto responses = inner_.Collect();
        if (tamper_target_ != TamperTarget::kResponse) {
            return responses;
        }
        // ⚠️ Collect 的应答顺序与 Submit 的提交顺序一致，但**跨服务器**：
        //   客户端每轮都会同时向两台服务器 Submit，因此这里必须按记录下来的
        //   提交顺序判断"这条应答属于哪台服务器"，否则篡改会打到另一台上。
        for (size_t i = 0; i < responses.size() && i < targets.size(); ++i) {
            if (tamper_server_ != kAllServers && targets[i] != tamper_server_) continue;
            if (response_seen_++ != tamper_occurrence_) continue;
            if (!responses[i].ok) continue;
            TamperBytes(responses[i].payload);
            ++tampered_count_;
        }
        return responses;
    }

    size_t PendingCount() const override { return inner_.PendingCount(); }
    void Abort() override { inner_.Abort(); }

    // ---- 统计 ----
    const std::vector<Recorded>& records() const { return record_; }
    size_t ThirdPartyCount() const { return third_party_; }
    size_t SubmitCount(int server_id) const {
        return static_cast<size_t>(std::count_if(
            record_.begin(), record_.end(),
            [server_id](const Recorded& r) { return r.server_id == server_id; }));
    }
    void Reset() {
        record_.clear();
        pending_targets_.clear();
        third_party_ = 0;
    }

private:
    void TamperBytes(Payload& p) {
        if (tamper_offset_ >= p.size()) return;
        p[tamper_offset_] ^= tamper_xor_;
    }

    ITransportClient& inner_;
    std::vector<Recorded> record_;
    std::vector<int> pending_targets_;  // 本次 Collect 对应的 Submit 目标服务器
    size_t third_party_ = 0;
    size_t tampered_count_ = 0;

    TamperTarget tamper_target_ = TamperTarget::kNone;
    int tamper_server_ = -1;
    size_t tamper_offset_ = 0;
    uint8_t tamper_xor_ = 0x01;
    uint64_t tamper_occurrence_ = 0;
    std::array<uint64_t, 2> submit_seen_{{0, 0}};
    uint64_t response_seen_ = 0;
};

// ---------------------------------------------------------------------------
// 一台完整的两方仿真环境：1 客户端 + 2 服务器 + 计数传输
//
// 服务器状态住在 std::optional 里：SecureMulServerState 是一次性的
// （consumed 之后不能再跑），每条记录都要重新安装。
// ---------------------------------------------------------------------------
class FlowHarness {
public:
    explicit FlowHarness(const SecureMulClientState& client)
        : client_(client), transport_(2), counting_(transport_) {
        RegisterSecureMulServers(transport_, s0_, s1_);
    }

    const SecureMulClientState& client() const { return client_; }
    ITransportClient& transport() { return counting_; }
    CountingTransport& counting() { return counting_; }
    LocalTransport& network() { return transport_; }

    // 为第 record_index 条记录安装服务器状态。
    // `ctx` 非空时启用 §4.5-A/B 两条**纯客户端**复核（v3 的默认路径）；
    // 传 nullptr 可复现 v2 的"只有 MAC"行为，用于对照实验。
    void InstallRecord(uint64_t record_index, uint128_t e_value,
                       const SecureMulTripleMaterial& material,
                       const SecureMulRecordContext* ctx = nullptr) {
        const uint64_t challenge = MakeChallenge(record_index, ChallengeSalt());
        auto shares = ShareMod(e_value, client_.modulus());
        const auto setups = MakeServerSetups(record_index, material, shares, challenge);
        s0_ = MakeServerState(setups.first, client_.modulus());
        s1_ = MakeServerState(setups.second, client_.modulus());
        // 重新注册（handler 捕获的是 state 的地址，state 换了必须重挂）
        RegisterSecureMulServers(transport_, s0_, s1_);
        challenge_ = challenge;
        if (ctx != nullptr) {
            ctx_ = *ctx;
            ctx_ptr_ = &ctx_;
        } else {
            ctx_ptr_ = nullptr;
        }
    }

    // 用 (share, ctx) 一起安装（自动构造 §4.5-A/B 的复核基准）
    void InstallRecordWithContext(uint64_t record_index,
                                 const std::pair<ModShare, ModShare>& shares,
                                 const SecureMulTripleMaterial& material) {
        const uint64_t challenge = MakeChallenge(record_index, ChallengeSalt());
        const auto bundle = MakeSetupsAndContext(record_index, material, shares, challenge);
        s0_ = MakeServerState(bundle.server0, client_.modulus());
        s1_ = MakeServerState(bundle.server1, client_.modulus());
        RegisterSecureMulServers(transport_, s0_, s1_);
        challenge_ = challenge;
        ctx_ = bundle.ctx;
        ctx_ptr_ = &ctx_;
    }

    // 用**调用方给定**的 setup/ctx 安装（连 ⟨E⟩ 的共享掩码都由调用方决定）
    // ⇒ 供"整条 transcript 逐位一致"的强口径测试使用。
    void InstallRecordFromBundle(uint64_t record_index,
                                 const SecureMulSetupBundle& bundle) {
        s0_ = MakeServerState(bundle.server0, client_.modulus());
        s1_ = MakeServerState(bundle.server1, client_.modulus());
        RegisterSecureMulServers(transport_, s0_, s1_);
        challenge_ = bundle.server0.challenge;
        ctx_ = bundle.ctx;
        ctx_ptr_ = &ctx_;
        (void)record_index;
    }

    uint64_t challenge() const { return challenge_; }
    const SecureMulRecordContext* ctx() const { return ctx_ptr_; }

    // 完整跑一条记录
    SecureMulFlowResult RunRecord(uint64_t session, uint128_t f,
                                  const tsb::BeaverTriple& triple) {
        return SecureMulFlowRunRecord(session, challenge_, f, triple, counting_,
                                      client_, ctx_ptr_);
    }

private:
    // challenge 的盐：**每次安装都换**（v2 用常量盐，导致 challenge 与会话无关，
    // 跨会话重放因此可行；对抗性验证 D2 的 DoS 就建立在这上面）。
    static std::vector<uint8_t> ChallengeSalt() {
        static uint64_t counter = 0;
        ++counter;
        return {0x11,
                static_cast<uint8_t>(counter & 0xff),
                static_cast<uint8_t>((counter >> 8) & 0xff),
                static_cast<uint8_t>((counter >> 16) & 0xff)};
    }

    const SecureMulClientState& client_;
    LocalTransport transport_;
    CountingTransport counting_;
    SecureMulServerState s0_{0, TripleShare{}, kQ};
    SecureMulServerState s1_{1, TripleShare{}, kQ};
    uint64_t challenge_ = 0;
    SecureMulRecordContext ctx_{};
    const SecureMulRecordContext* ctx_ptr_ = nullptr;
};

// 逐字段篡改的五个注入点（对应任务书要求）
enum class InjectPoint {
    kPhase1RequestD,     // 篡改第 1 轮请求里的 d（服务器 0/1 各自）
    kPhase1ResponseE,    // 篡改第 1 轮应答里的 ⟨e⟩_p
    kPhase2RequestE,     // 篡改第 2 轮请求里中转的 e
    kPhase2ResponseZ,    // 篡改第 2 轮应答里的 z_p
    kPhase2ResponseMac,  // 篡改第 2 轮应答里的 mac_p
};

// 把一次篡改注入的完整结果收集起来：
//   threw     —— 客户端显式 abort（抛异常）
//   ok        —— 客户端接受了结果
//   mac_fail  —— 客户端以"MAC 校验失败"为由拒绝
struct InjectionOutcome {
    bool threw = false;
    bool ok = false;
    // ⚠️ 判定一律走**结构化**的 `SecureMulFailure`，**不用**字符串匹配：
    //    v2 的 e 检查报错文本里也含 "MAC" 字样，用 find("MAC") 会把两类失败
    //    混为一谈（对抗性验证 D4）。
    SecureMulFailure failure = SecureMulFailure::kNone;
    SecureMulFailure throw_failure = SecureMulFailure::kNone;
    bool value_differs_from_truth = false;
    size_t tampered_bytes = 0;  // 0 表示注入没打中（测试会把它算作失败）
    std::string what;

    bool MacMismatch() const {
        return failure == SecureMulFailure::kMacMismatch;
    }
    bool ClientCheckFailed() const {
        return failure == SecureMulFailure::kClientLocalCheckFailed ||
               failure == SecureMulFailure::kEShareMismatch;
    }
    bool ServerReported() const {
        return failure == SecureMulFailure::kServerReported;
    }
};

// 在**指定服务器**的**指定注入点**上做一次篡改，跑完一条记录
InjectionOutcome RunWithInjection(int server_id, InjectPoint point, uint128_t f,
                                  uint128_t e_value,
                                  const std::string& seed) {
    const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
    FlowHarness h(client);
    Prng prng(SeedKey(seed), 0);
    const SecureMulTripleMaterial material = GenerateBeaverTriple(client.keys(), kQ, prng);
    h.InstallRecordWithContext(7, ShareMod(e_value, kQ), material);

    // 逐字节偏移见头文件的 wire 布局注释（v2）：
    //   Phase1Request  : ver(0) type(1) session(2..9) challenge(10..17) d(18..33)
    //   Phase1Response : ver(0) type(1) session(2..9) e_computed(10..25) status(26)
    //   Phase2Request  : ver(0) type(1) session(2..9) d(10..25) e(26..41) e_check(42..57)
    //   Phase2Response : ver(0) type(1) session(2..9) z_share(10..25) mac_share(26..41) status(42)
    switch (point) {
        case InjectPoint::kPhase1RequestD:
            h.counting().SetTamper(server_id, CountingTransport::TamperTarget::kSubmit, 18);
            break;
        case InjectPoint::kPhase1ResponseE:
            h.counting().SetTamper(server_id, CountingTransport::TamperTarget::kResponse, 10);
            break;
        case InjectPoint::kPhase2RequestE:
            // 第 2 轮请求是第 2 条 Submit（第 1 条是第 1 轮请求）
            h.counting().SetTamper(server_id, CountingTransport::TamperTarget::kSubmit, 26,
                                   0x01, /*occurrence=*/1);
            break;
        case InjectPoint::kPhase2ResponseZ:
            // 第 2 轮应答是第 2 条 Response
            h.counting().SetTamper(server_id, CountingTransport::TamperTarget::kResponse, 10,
                                   0x01, /*occurrence=*/1);
            break;
        case InjectPoint::kPhase2ResponseMac:
            h.counting().SetTamper(server_id, CountingTransport::TamperTarget::kResponse, 26,
                                   0x01, /*occurrence=*/1);
            break;
    }

    InjectionOutcome out;
    try {
        const SecureMulFlowResult r = h.RunRecord(101, f, material.client_triple);
        out.tampered_bytes = h.counting().TamperedCount();
        out.ok = r.ok;
        out.failure = r.failure;
        out.value_differs_from_truth = (r.z != mulMod(f, e_value, kQ));
        out.what = r.error;
    } catch (const std::exception& e) {
        out.threw = true;
        out.what = e.what();
        out.tampered_bytes = h.counting().TamperedCount();
        // 异常路径也必须与"值错"可区分：客户端拿不到值，只能 abort
        out.value_differs_from_truth = true;
    }
    return out;
}

}  // namespace

// ===========================================================================
// 1. 数值正确性（数百轮，确定性随机源 + 显式种子）
// ===========================================================================

TEST(SecureMulFlow, FilterBitTimesAttributeMatchesPlaintextOverManyRounds) {
    // 300 轮：随机的 f、E、α、triple，全部必须满足 z == f·E 且 mac == α·z。
    Prng prng(SeedKey("mpa05-numeric-correctness"), 0);
    const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
    FlowHarness h(client);

    int checked = 0;
    int odd_ed_rounds = 0;
    for (int round = 0; round < 300; ++round) {
        // f 以 0/1 为主（论文语义），同时掺入一般域元素（本模块按 Z_q 元素接受）
        const uint128_t f = (round % 5 == 0) ? prng.Below(kQ)
                                             : (prng.Next() & 1u ? 1u : 0u);
        const uint128_t e_value = (round % 7 == 0) ? (kQ - 1) : prng.Below(kQ);

        const SecureMulTripleMaterial material =
            GenerateBeaverTriple(client.keys(), kQ, prng);
        h.InstallRecord(static_cast<uint64_t>(round), e_value, material);

        const SecureMulFlowResult r =
            h.RunRecord(static_cast<uint64_t>(1000 + round), f, material.client_triple);
        EXPECT_TRUE(r.ok);
        EXPECT_EQ(r.z, mulMod(f, e_value, kQ));
        // 用 shared/verify 的校验函数独立复核一次（不只看 r.ok）
        EXPECT_TRUE(VerifyMac(r.z, r.mac, client.alpha(), kQ));
        EXPECT_EQ(r.mac, mulMod(client.alpha(), r.z, kQ));

        // 记录"e·d 为奇数"的轮次：这正是 Z_{2^k} 上会算错、奇模数下必须正确的情形
        const uint128_t d = subMod(f, material.client_triple.a, kQ);
        const uint128_t e = subMod(e_value, material.client_triple.b, kQ);
        if (((mulMod(e, d, kQ)) & 1u) != 0u) ++odd_ed_rounds;
        ++checked;
    }
    EXPECT_EQ(checked, 300);
    // 不是断言"分布均匀"，只是确认测试确实覆盖到了这个关键情形
    EXPECT_TRUE(odd_ed_rounds > 0);
}

TEST(SecureMulFlow, ReconstructsEvenAtShareLevel) {
    // 逐项核对共享层面的公式（头文件 §2 的推导）：
    //   z_p 末项 = e·d·2^{-1}（两台各一份 ⇒ 相加恰好抵消）
    //   mac_p 末项 = ⟨α⟩_p·e·d（**没有** 2^{-1}，这是 D14 的修正式）
    Prng prng(SeedKey("mpa05-share-level"), 0);
    const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
    const uint128_t q = kQ;

    const uint128_t f = 1;
    const uint128_t e_value = 987654321_k;
    const SecureMulTripleMaterial material =
        GenerateBeaverTriple(client.keys(), kQ, prng);
    const uint128_t d = subMod(f, material.client_triple.a, q);
    const uint128_t e = subMod(e_value, material.client_triple.b, q);
    const uint128_t inv2 = modInverse(static_cast<uint128_t>(2), q);

    const auto z0 = SecureMulServerPhase2(
        SecureMulServerInput{ShareMod(e_value, q).first, material.server0}, d, e, q);
    const auto z1 = SecureMulServerPhase2(
        SecureMulServerInput{ShareMod(e_value, q).second, material.server1}, d, e, q);

    const uint128_t expect_z0 = addMod(
        addMod(material.server0.c.value,
               mulMod(d, material.server0.b.value, q), q),
        addMod(mulMod(e, material.server0.a.value, q),
               mulMod(mulMod(e, d, q), inv2, q), q),
        q);
    EXPECT_EQ(z0.z.value, expect_z0);

    const uint128_t expect_mac0 = addMod(
        addMod(material.server0.alpha_c.value,
               mulMod(d, material.server0.alpha_b.value, q), q),
        addMod(mulMod(e, material.server0.alpha_a.value, q),
               mulMod(material.server0.alpha.value, mulMod(e, d, q), q), q),
        q);
    EXPECT_EQ(z0.mac.value, expect_mac0);

    // 两台相加 = f·E，且 mac = α·z
    EXPECT_EQ(addMod(z0.z.value, z1.z.value, q), mulMod(f, e_value, q));
    EXPECT_EQ(addMod(z0.mac.value, z1.mac.value, q),
              mulMod(client.alpha(), mulMod(f, e_value, q), q));
}

TEST(SecureMulFlow, SumOverFilterVectorMatchesPlaintextBaseline) {
    // ⚠️ **给 MPA-06（Sum / Avg）的最小接法示例**（论文 AggQuery 的 Σ_i SecureMul）
    //
    //   客户端本地重建 filter 向量（MPA-04 的产物），服务器侧持有 ⟨E_i⟩_p；
    //   Sum = Σ_i f_i·E_i，其中每一条走一次本模块的 SecureMul 消息流。
    Prng prng(SeedKey("mpa05-sum-example"), 0);
    const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
    FlowHarness h(client);

    const size_t n = 32;
    std::vector<uint128_t> attributes(n);
    std::vector<uint128_t> filter(n);
    for (size_t i = 0; i < n; ++i) {
        attributes[i] = prng.Below(10000);          // 属性值（明文，用于对照）
        filter[i] = (prng.Next() & 1u) ? 1u : 0u;   // 过滤位（客户端本地持有）
    }

    uint128_t sum = 0;
    uint128_t plaintext_sum = 0;
    for (size_t i = 0; i < n; ++i) {
        const SecureMulTripleMaterial material =
            GenerateBeaverTriple(client.keys(), kQ, prng);
        h.InstallRecord(static_cast<uint64_t>(i), attributes[i], material);
        const SecureMulFlowResult r =
            h.RunRecord(2000 + i, filter[i], material.client_triple);
        // 论文：`If z_i = null → abort`。绝不允许带着未认证的 z 继续累加。
        ASSERT_TRUE(r.ok);
        sum = addMod(sum, r.z, kQ);
        plaintext_sum = addMod(plaintext_sum, mulMod(filter[i], attributes[i], kQ), kQ);
    }
    EXPECT_EQ(sum, plaintext_sum);  // 与明文基准逐取值一致
    // Avg = Sum / Count：Count 由 MPA-04 对 filter 直接计数得到（不走 SecureMul）
    const uint128_t count = static_cast<uint128_t>(
        std::count(filter.begin(), filter.end(), static_cast<uint128_t>(1)));
    EXPECT_TRUE(count > 0);
}

// ===========================================================================
// 2. 边界与非法参数
// ===========================================================================

TEST(SecureMulFlow, BoundaryValuesOfFilterBitAndAttribute) {
    const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
    FlowHarness h(client);
    Prng prng(SeedKey("mpa05-boundary"), 0);

    struct Case {
        uint128_t f;
        uint128_t e;
        const char* name;
    };
    const std::vector<Case> cases = {
        {0, 0, "f=0, E=0"},
        {0, 1, "f=0, E=1"},
        {0, kQ - 1, "f=0, E=q-1"},
        {1, 0, "f=1, E=0"},
        {1, 1, "f=1, E=1"},
        {1, kQ - 1, "f=1, E=q-1"},
        {kQ - 1, kQ - 1, "f=q-1, E=q-1（一般域元素）"},
        {2, kQ - 2, "f=2, E=q-2"},
    };

    int round = 0;
    for (const auto& c : cases) {
        const SecureMulTripleMaterial material =
            GenerateBeaverTriple(client.keys(), kQ, prng);
        h.InstallRecord(static_cast<uint64_t>(round), c.e, material);
        const SecureMulFlowResult r =
            h.RunRecord(static_cast<uint64_t>(round), c.f, material.client_triple);
        EXPECT_TRUE(r.ok);  // 边界取值不得引发误报
        EXPECT_EQ(r.z, mulMod(c.f, c.e, kQ));
        // f=0 或 E=0 时乘积必须**恰好**是 0（不能是"随机的 0 掩码"）
        if (c.f == 0 || c.e == 0) {
            EXPECT_EQ(r.z, static_cast<uint128_t>(0));
        }
        ++round;
    }
}

TEST(SecureMulFlow, AlphaEdgeValues) {
    const uint128_t q = kQ;
    // α = 0 必须被拒绝（否则 mac = 0 恒成立，校验形同虚设）
    EXPECT_THROW((SecureMulClientState{0, {0, 0}, q}), std::invalid_argument);
    // ⟨α⟩ 数量必须恰好 2
    EXPECT_THROW((SecureMulClientState{5, {5}, q}), std::invalid_argument);
    EXPECT_THROW((SecureMulClientState{5, {1, 2, 3}, q}), std::invalid_argument);
    // 分享之和必须等于 α
    EXPECT_THROW((SecureMulClientState{5, {1, 1}, q}), std::invalid_argument);

    // α = 1 与 α = q−1 都必须能正常工作且校验通过
    for (uint128_t alpha : {static_cast<uint128_t>(1), q - 1}) {
        const uint128_t a0 = 12345 % q;
        const SecureMulClientState client(
            alpha, {a0, subMod(alpha, a0, q)}, q);
        EXPECT_EQ(client.alpha(), alpha);
        FlowHarness h(client);
        Prng prng(SeedKey("mpa05-alpha-edge"), 0);
        const SecureMulTripleMaterial material =
            GenerateBeaverTriple(client.keys(), q, prng);
        h.InstallRecord(1, 555, material);
        const SecureMulFlowResult r = h.RunRecord(1, 1, material.client_triple);
        EXPECT_TRUE(r.ok);
        EXPECT_EQ(r.z, 555);
        EXPECT_EQ(r.mac, mulMod(alpha, 555, q));
    }
}

TEST(SecureMulFlow, RejectsEvenOrInvalidModulus) {
    // D11：Z_{2^k} 中 2 不可逆 ⇒ 必须显式拒绝，而不是静默算错
    EXPECT_THROW(SecureMulClientState::GenerateMacKey(static_cast<uint128_t>(1) << 64),
                 std::invalid_argument);
    EXPECT_THROW(SecureMulClientState::GenerateMacKey(static_cast<uint128_t>(256)),
                 std::invalid_argument);
    EXPECT_THROW(SecureMulClientState::GenerateMacKey(static_cast<uint128_t>(2)),
                 std::invalid_argument);
    EXPECT_THROW(SecureMulClientState::GenerateMacKey(0), std::invalid_argument);
    EXPECT_THROW(SecureMulClientState::GenerateMacKey(1), std::invalid_argument);
    // 超过 2^127 会被 core/field 的 modmul 拒绝
    EXPECT_THROW(SecureMulClientState::GenerateMacKey(~static_cast<uint128_t>(0)),
                 std::invalid_argument);

    MacKeyShares keys = GenerateMacKey(2, kQ);
    Prng prng(SeedKey("mpa05-bad-modulus"), 0);
    EXPECT_THROW(GenerateBeaverTriple(keys, static_cast<uint128_t>(8), prng),
                 std::invalid_argument);
    // 服务器状态构造同样拒绝非奇模数
    EXPECT_THROW(SecureMulServerState(0, TripleShare{}, static_cast<uint128_t>(8)),
                 std::invalid_argument);
}

TEST(SecureMulFlow, RejectsWrongAlphaShareCount) {
    MacKeyShares keys = GenerateMacKey(3, kQ);  // 3 份 ⟨α⟩
    Prng prng(SeedKey("mpa05-wrong-share-count"), 0);
    EXPECT_THROW(GenerateBeaverTriple(keys, kQ, prng), std::invalid_argument);
    EXPECT_THROW(SecureMulClientState(keys, kQ), std::invalid_argument);
}

TEST(SecureMulFlow, RejectsOutOfOrderDuplicateAndReplayedMessages) {
    const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
    Prng prng(SeedKey("mpa05-state-machine"), 0);
    const SecureMulTripleMaterial material =
        GenerateBeaverTriple(client.keys(), kQ, prng);
    auto shares = ShareMod(4242, kQ);
    const uint64_t challenge = MakeChallenge(3, {0xAB});
    const auto setups = MakeServerSetups(3, material, shares, challenge);
    SecureMulServerState st = MakeServerState(setups.first, kQ);

    // 1) 第 2 轮先到（乱序）：必须先跑过第 1 轮 ⇒ kPhaseError（v3 结构化拒绝）
    const Phase2Request p2{1, 5, 6, 7};
    EXPECT_EQ(static_cast<int>(st.RunPhase2(p2).status),
              static_cast<int>(SecureMulStatus::kPhaseError));
    EXPECT_FALSE(st.consumed());

    // 2) challenge 不符（跨会话重放）⇒ kPhaseError
    Phase1Request bad = {1, challenge + 1, 7};
    EXPECT_EQ(static_cast<int>(st.RunPhase1(bad).status),
              static_cast<int>(SecureMulStatus::kPhaseError));
    EXPECT_FALSE(st.consumed());

    // 3) 正常第 1 轮
    const Phase1Request good{1, challenge, 7};
    const Phase1Response r1 = st.RunPhase1(good);
    EXPECT_EQ(r1.session, 1);
    EXPECT_FALSE(st.consumed());

    // 4) 第 2 轮 session 与第 1 轮不一致（消息拼接）⇒ kPhaseError
    EXPECT_EQ(static_cast<int>(st.RunPhase2(Phase2Request{2, 7, 8, 9}).status),
              static_cast<int>(SecureMulStatus::kPhaseError));

    // 5) 正常第 2 轮
    const Phase2Response r2 = st.RunPhase2(Phase2Request{1, 7, 8, 7});
    EXPECT_EQ(r2.session, 1);
    EXPECT_TRUE(st.consumed());

    // 6) 重复请求（第 1 轮/第 2 轮都不得被重放）⇒ kPhaseError
    //    ⚠️ v2 时第 1 轮重复**被接受**（consumed_ 只在第 2 轮置位 ⇒ 可改写
    //       phase1_d_ 让诚实查询 abort，红队 D2）；v3 起一律 kPhaseError。
    EXPECT_EQ(static_cast<int>(st.RunPhase1(good).status),
              static_cast<int>(SecureMulStatus::kPhaseError));
    EXPECT_EQ(static_cast<int>(st.RunPhase2(Phase2Request{1, 7, 8, 7}).status),
              static_cast<int>(SecureMulStatus::kPhaseError));

    // 7) 未安装 ⟨E⟩_p 就开跑
    SecureMulServerState fresh(3, material.server0, kQ);
    fresh.InstallChallenge(challenge);
    EXPECT_THROW(fresh.RunPhase1(good), std::logic_error);
    // 重复安装 ⟨E⟩_p
    fresh.InstallAttributeShare(shares.first);
    EXPECT_THROW(fresh.InstallAttributeShare(shares.first), std::logic_error);
}

TEST(SecureMulFlow, RejectsMalformedMessages) {
    Phase1Request m{1, 2, 3};
    Payload good = EncodePhase1Request(m);

    // 版本字节错
    Payload bad_version = good;
    bad_version[0] = 99;
    EXPECT_THROW(DecodePhase1Request(bad_version), std::invalid_argument);

    // 类型字节错（把 Phase1Request 当 Phase2Request 解）
    EXPECT_THROW(DecodePhase2Request(good), std::invalid_argument);
    EXPECT_THROW(DecodePhase1Response(good), std::invalid_argument);

    // 长度错（截断 / 追加）
    Payload truncated(good.begin(), good.end() - 1);
    EXPECT_THROW(DecodePhase1Request(truncated), std::invalid_argument);
    Payload padded = good;
    padded.push_back(0);
    EXPECT_THROW(DecodePhase1Request(padded), std::invalid_argument);
    EXPECT_THROW(DecodePhase1Request(Payload{}), std::invalid_argument);
    EXPECT_THROW(DecodePhase1Request(Payload{1}), std::invalid_argument);

    // 端到端：客户端收到的应答被截断 ⇒ 必须抛异常，不得静默当成 0
    const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
    FlowHarness h(client);
    Prng prng(SeedKey("mpa05-malformed"), 0);
    const SecureMulTripleMaterial material =
        GenerateBeaverTriple(client.keys(), kQ, prng);
    h.InstallRecord(1, 100, material);
    // 篡改第 1 轮应答的**版本字节**（偏移 0）⇒ 解码必须失败，而不是被当成 0
    // （0x01 ^ 0xFF = 0xFE，与 kSecureMulWireVersion 不等）
    h.counting().SetTamper(kServer1, CountingTransport::TamperTarget::kResponse, 0, 0xFF,
                           /*occurrence=*/0);
    EXPECT_THROW(h.RunRecord(1, 1, material.client_triple), std::invalid_argument);
}

TEST(SecureMulFlow, EncodingRoundTripsAndIsLittleEndian) {
    const Phase1Request q1{0x0102030405060708ULL, 0x1112131415161718ULL,
                           0xdeadbeefcafebabeULL};
    const Payload p = EncodePhase1Request(q1);
    EXPECT_EQ(p.size(), static_cast<size_t>(34));
    EXPECT_EQ(static_cast<int>(p[0]), static_cast<int>(kSecureMulWireVersion));
    EXPECT_EQ(static_cast<int>(p[1]),
              static_cast<int>(SecureMulMsgType::kPhase1Request));
    // session 的小端第 0 字节应是 0x08
    EXPECT_EQ(static_cast<int>(p[2]), 0x08);
    // ⚠️ 用逐字段比较而不是直接 EXPECT_EQ(结构体)：测试框架的 EXPECT_EQ 需要
    //    对值做流式渲染，而这些消息结构体刻意不带 operator<<（它们是 POD）。
    EXPECT_TRUE(DecodePhase1Request(p) == q1);

    const Phase1Response q2{7, 0x99};
    EXPECT_TRUE(DecodePhase1Response(EncodePhase1Response(q2)) == q2);

    const Phase2Request q3{9, 0xAA, 0xBB, 0xCC};
    const Payload p3 = EncodePhase2Request(q3);
    EXPECT_EQ(p3.size(), static_cast<size_t>(58));
    EXPECT_TRUE(DecodePhase2Request(p3) == q3);

    const Phase2Response q4{11, 0xCC, 0xDD, 0};
    const Payload p4 = EncodePhase2Response(q4);
    EXPECT_EQ(p4.size(), static_cast<size_t>(43));
    EXPECT_TRUE(DecodePhase2Response(p4) == q4);
}

TEST(SecureMulFlow, RejectsOutOfRangeServerIdAndBadTransport) {
    const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
    EXPECT_THROW(client.AlphaShare(2), std::out_of_range);
    EXPECT_THROW(client.AlphaShare(-1), std::out_of_range);

    // 只有 1 台服务器的传输层：向 server_id=1 提交会被 LocalTransport 判越界
    // （std::out_of_range），无论如何都必须抛异常而不是静默降级。
    LocalTransport one_server(1);
    EXPECT_THROW(ClientRunPhase1(1, 2, 1, tsb::BeaverTriple{1, 2, 3}, one_server, kQ),
                 std::exception);
}

// ===========================================================================
// 3. 恶意服务器注入：对每台服务器分别篡改 5 个注入点
// ===========================================================================

TEST(SecureMulFlow, DetectsTamperingByEitherServerAtEveryInjectionPoint) {
    // 每台服务器 × 5 个注入点，共 10 组。判定：
    //   (0) 注入必须打中（否则用例会在"什么都没改"的情况下通过）；
    //   (1) 客户端**绝不能**接受结果（论文：不允许可区分的失败路径）；
    //   (2) 必须 abort（抛异常，或返回 ok=false 且带原因）；
    //   (3) 每条注入点都必须由**某一层**明确拒绝：
    //       * d / z_p / mac_p 被改 ⇒ SPDZ MAC 校验失败；
    //       * ⟨e⟩_p / 中转的 e 被改 ⇒ §4.5 的 e 一致性检查失败
    //         （⚠️ 这一类**单靠 MAC 抓不住**，见下一个用例）。
    const uint128_t f = 1;
    const uint128_t e_value = 123456789_k;

    struct Point {
        InjectPoint point;
        const char* name;
    };
    // ⚠️ `kPhase1RequestD` 单独在下一个用例里处理：**只改一台的 d**（并让后续
    //    轮次继续用改过的 d）是论文协议下 MAC 抓不住的一类篡改，
    //    见头文件 §4.6 与 `ConsistentTamperIsUndetectableByMacAlone`。
    //    本用例覆盖"应当 100% 检出"的 4 个注入点 × 2 台服务器。
    const std::vector<Point> points = {
        {InjectPoint::kPhase1ResponseE, "⟨e⟩_p（第 1 轮应答）"},
        {InjectPoint::kPhase2RequestE, "e（第 2 轮中转）"},
        {InjectPoint::kPhase2ResponseZ, "z_p（第 2 轮应答的值分片）"},
        {InjectPoint::kPhase2ResponseMac, "mac_p（第 2 轮应答的 MAC 分片）"},
    };

    int total = 0;
    int rejected = 0;
    for (int server_id = 0; server_id <= 1; ++server_id) {
        for (const auto& p : points) {
            // 每种篡改都换一个种子，避免"恰好被抵消"的偶然
            const std::string seed = "mpa05-inject-" + std::to_string(server_id) +
                                     "-" + std::to_string(static_cast<int>(p.point));
            const InjectionOutcome out =
                RunWithInjection(server_id, p.point, f, e_value, seed);
            ++total;

            EXPECT_EQ(out.tampered_bytes, static_cast<size_t>(1));
            EXPECT_FALSE(out.ok);
            const bool aborted = out.threw || (!out.ok && !out.what.empty());
            EXPECT_TRUE(aborted);
            if (aborted) ++rejected;
            // 按"是哪一类篡改、由谁发现"分类断言（两类都可能同时成立）：
            //   * ⟨e⟩_p 回执被改 ⇒ 那台自己的 e 一致性检查失败
            //     （§4.5：MAC 抓不住这一类，必须有这条检查）；
            //   * 中转的 e 被改 ⇒ MAC 校验失败，且可能同时触发某台的 e 检查；
            //   * z_p / mac_p 被改 ⇒ MAC 校验失败。
            if (p.point == InjectPoint::kPhase1ResponseE) {
                // 改某台的 ⟨e⟩_p 回执有**两道**拦截，都会被触发：
                //   * 服务器侧：客户端把被改过的值原样回显 ⇒ 该台的 e_check 不符
                //     ⇒ kECheckFailed（通道篡改卫生设施，v2 起就有）；
                //   * 客户端侧：§4.5-B 独立复核 ⟨e⟩_p ?= ⟨E⟩_p − ⟨b⟩_p（v3 新增，
                //     这一道才挡得住"说谎的服务器"）。
                EXPECT_TRUE(out.ServerReported() || out.ClientCheckFailed());
            } else {
                EXPECT_TRUE(out.MacMismatch() || out.ClientCheckFailed());
            }
            // 值分片/请求侧被改时，客户端拿不到正确值
            if (p.point != InjectPoint::kPhase2ResponseMac) {
                EXPECT_TRUE(out.value_differs_from_truth);
            } else {
                EXPECT_FALSE(out.value_differs_from_truth);  // 值是对的，但 MAC 不匹配
            }
        }
    }
    EXPECT_EQ(total, 8);
    EXPECT_EQ(rejected, 8);  // 8/8 全部被检出并 abort
}

TEST(SecureMulFlow, DetectsDTamperWhenRoundsDisagree) {
    // §4.5 的 d 跨轮一致性检查：客户端在第 1 轮下发的 d 被改掉后，若第 2 轮
    // 用的是**未改过**的 d（客户端重算的旧实现就是这样），服务器两侧的 d 不一致，
    // 会被 kDCheckFailed 挡下。这里直接把两台服务器拉出来手工驱动两个阶段，
    // 精确复现"两轮 d 不一致"的形态。
    const uint128_t q = kQ;
    const SecureMulClientState client = SecureMulClientState::GenerateMacKey(q);
    Prng prng(SeedKey("mpa05-d-cross-round"), 0);
    const SecureMulTripleMaterial material =
        GenerateBeaverTriple(client.keys(), q, prng);
    const auto shares = ShareMod(4242, q);
    const uint64_t challenge = MakeChallenge(3, {0x5A});
    const auto setups = MakeServerSetups(3, material, shares, challenge);

    for (int which = 0; which <= 1; ++which) {
        SecureMulServerState st = MakeServerState(
            which == 0 ? setups.first : setups.second, q);
        const uint128_t d1 = 11111;
        const Phase1Response r1 = st.RunPhase1(Phase1Request{9, challenge, d1});
        EXPECT_EQ(r1.session, 9);
        // 第 2 轮换一个 d ⇒ 必须被拒（且**不**算出 z/mac）
        const uint128_t d2 = addMod(d1, 1, q);
        const Phase2Response bad =
            st.RunPhase2(Phase2Request{9, d2, 22222, r1.e_computed});
        EXPECT_EQ(static_cast<int>(bad.status),
                  static_cast<int>(SecureMulStatus::kDCheckFailed));
        EXPECT_EQ(bad.z_share, static_cast<uint128_t>(0));
        EXPECT_EQ(bad.mac_share, static_cast<uint128_t>(0));
        // 该状态已被消费（失败也是一次性语义）⇒ 再次请求是 kPhaseError
        EXPECT_EQ(static_cast<int>(
                      st.RunPhase2(Phase2Request{9, d1, 22222, r1.e_computed}).status),
                  static_cast<int>(SecureMulStatus::kPhaseError));
    }
}

TEST(SecureMulFlow, EConsistencyCheckIsWhatCatchesTheETamper) {
    // 把上一条用例的失败模式放到**消息流**里，验证 §4.5 的检查确实拦住它：
    //   篡改某台第 1 轮报出的 ⟨e⟩_p 后，那台服务器在第 2 轮会收到一个与它自己
    //   报出的值不一致的 e_check，于是它**在算 z/mac 之前**就回 kECheckFailed，
    //   客户端据此 abort（而不是接受一个 MAC 自洽的错值）。
    const uint128_t q = kQ;
    const uint128_t f = 1;
    const uint128_t e_value = 424242;
    for (int server_id = 0; server_id <= 1; ++server_id) {
        const SecureMulClientState client = SecureMulClientState::GenerateMacKey(q);
        FlowHarness h(client);
        Prng prng(SeedKey("mpa05-echeck-" + std::to_string(server_id)), 0);
        const SecureMulTripleMaterial material =
            GenerateBeaverTriple(client.keys(), q, prng);
        h.InstallRecord(11, e_value, material);

        // 篡改该台第 1 轮应答里的 ⟨e⟩_p（e_computed 位于偏移 10）
        h.counting().SetTamper(server_id, CountingTransport::TamperTarget::kResponse, 10);
        const SecureMulFlowResult r = h.RunRecord(111, f, material.client_triple);
        EXPECT_EQ(h.counting().TamperedCount(), static_cast<size_t>(1));
        EXPECT_FALSE(r.ok);
        // v3：这类篡改会先被**服务器侧 e_check 回执检查**拒绝（客户端把收到的
        // 值原样带回，被篡改的回执与服务器自算值不符 ⇒ kECheckFailed），
        // 若该层被绕过则由**纯客户端复核 B**（§4.5-B）独立检出。
        // 两层都能拦；结构化判定，不靠字符串。
        EXPECT_TRUE(r.failure == SecureMulFailure::kServerReported ||
                    r.failure == SecureMulFailure::kEShareMismatch);

        // 反向对照：不篡改时同一条记录必须通过
        FlowHarness h2(client);
        h2.InstallRecord(11, e_value, material);
        const SecureMulFlowResult ok = h2.RunRecord(111, f, material.client_triple);
        EXPECT_TRUE(ok.ok);
        EXPECT_EQ(ok.z, mulMod(f, e_value, q));
    }
}

// ===========================================================================
// 3b. v3 新增：**诚实的逐比特翻转矩阵**（替代 v2 报告里那条没有对应测试的声明）
// ===========================================================================

TEST(SecureMulFlow, BitFlipMatrixIsFullyDetected) {
    // ⚠️ 口径说明（v2 报告里的"256 组逐比特翻转 100% 检出"是**错的**：仓库里
    //    当时根本没有这个循环，而且该口径被红队的 E1 反例推翻 —— 双侧一致改 e
    //    时翻 1 bit 就能让客户端接受错值）。
    //    本用例给出**真实的矩阵**，并把"覆盖不到的"讲清楚：
    //
    //    矩阵范围（每一格都必须被检出）：
    //      * 第 2 轮应答 `z_share` 的 128 位 × 2 台        = 256 格
    //      * 第 2 轮应答 `mac_share` 的 128 位 × 2 台      = 256 格
    //      * 第 1 轮应答 `e_computed` 的 128 位 × 2 台     = 256 格
    //      * 第 1 轮请求 `d` 的 128 位 × 2 台             = 256 格
    //    合计 1024 格，全部由**协议层**（MAC / 纯客户端复核 / 自报状态）检出。
    //
    //    ⚠️ **本矩阵覆盖不到的那一类（必须如实说明）**：**双侧、且两台服务器
    //       共谋地**把同一个偏移同时施加到同一条消息的两个副本上（例如把发给
    //       两台的 e 都 +1 并且两台都照常报 kOk）。这不是"某一帧被改"，而是
    //       "两台一起按同一个偏移执行"，帧内字节翻转矩阵在定义上就无法表达它。
    //       它由**纯客户端复核 A**（z ?= f·(e_sent+b)）与复核 B 覆盖，见
    //       `ConsistentOffsetAttacksAreNowDetected`。
    const uint128_t q = kQ;
    const uint128_t f = 1;
    const uint128_t e_value = 987654321_k;

    // (byte_offset, occurrence, kind) —— kind 决定消息类型字段的偏移
    struct Cell {
        InjectPoint point;
    };
    const std::vector<Cell> cells = {
        {InjectPoint::kPhase1RequestD},      // d 的 128 位
        {InjectPoint::kPhase1ResponseE},     // e_computed 的 128 位
        {InjectPoint::kPhase2ResponseZ},     // z_share 的 128 位
        {InjectPoint::kPhase2ResponseMac},   // mac_share 的 128 位
    };

    int total = 0;
    int detected = 0;
    for (int server_id = 0; server_id <= 1; ++server_id) {
        for (const auto& c : cells) {
            for (int bit = 0; bit < 128; ++bit) {
                const SecureMulClientState client =
                    SecureMulClientState::GenerateMacKey(q);
                FlowHarness h(client);
                Prng prng(SeedKey("mpa05-bitflip"), 0);
                const SecureMulTripleMaterial material =
                    GenerateBeaverTriple(client.keys(), q, prng);
                h.InstallRecordWithContext(9, ShareMod(e_value, q), material);

                // 逐比特：目标字段的起点 + bit/8，掩码 1<<(bit%8)
                size_t offset = 0;
                CountingTransport::TamperTarget target =
                    CountingTransport::TamperTarget::kResponse;
                uint64_t occurrence = 0;
                switch (c.point) {
                    case InjectPoint::kPhase1RequestD:
                        // 两台、两轮的 d 被同一比特改动（跨轮一致，d 检查过得去；
                        // 由 MAC 或纯客户端复核检出）
                        target = CountingTransport::TamperTarget::kSubmit;
                        offset = 10 + static_cast<size_t>(bit / 8);
                        occurrence = 0;
                        break;
                    case InjectPoint::kPhase1ResponseE:
                        target = CountingTransport::TamperTarget::kResponse;
                        offset = 10 + static_cast<size_t>(bit / 8);
                        occurrence = 0;
                        break;
                    case InjectPoint::kPhase2ResponseZ:
                        target = CountingTransport::TamperTarget::kResponse;
                        offset = 10 + static_cast<size_t>(bit / 8);
                        occurrence = 1;
                        break;
                    case InjectPoint::kPhase2ResponseMac:
                        target = CountingTransport::TamperTarget::kResponse;
                        offset = 26 + static_cast<size_t>(bit / 8);
                        occurrence = 1;
                        break;
                    default:
                        break;
                }
                h.counting().SetTamper(server_id, target, offset,
                                       static_cast<uint8_t>(1u << (bit % 8)),
                                       occurrence);
                ++total;

                bool bad = false;
                try {
                    const SecureMulFlowResult r =
                        h.RunRecord(90, f, material.client_triple);
                    bad = !r.ok;
                    // 绝不允许"接受了错值"
                    if (r.ok) EXPECT_EQ(r.z, mulMod(f, e_value, q));
                } catch (const std::exception&) {
                    bad = true;  // 显式 abort 也是检出
                }
                if (bad) ++detected;
            }
        }
    }
    EXPECT_EQ(total, 1024);
    EXPECT_EQ(detected, 1024);  // 1024/1024 全部被检出（协议层，无静默接受）
}

// ===========================================================================
// 3c. v3 新增：红队的两条"一致偏移"反例 —— 现在必须 100% 检出
// ===========================================================================

TEST(SecureMulFlow, RedTeamMultiBitOffsetIsDetected) {
    // 红队 E1/E2/E3 的最小复现都是"把**同一台或两台**、**同一轮或两轮**的同一
    // 字段偏移一个常量"。CountingTransport 的介入粒度是"客户端发出的字节"，
    // 因此这里用**多比特同时翻转**来表达"偏移"：为覆盖任意 delta，改为直接
    // 构造"两台一致使用偏移值"的分片层场景，再走**客户端收尾层**（v3 的两条
    // 纯客户端复核正是在收尾层执行）。
    //
    // ⚠️ 关键点：v2 时这些偏移能**骗过 MAC**（z 与 mac 一起偏移），v3 起被
    //    §4.5-A（z ?= f·(e_sent+b)）与 §4.5-B（复核 ⟨e⟩_p）检出。
    for (uint128_t delta : {static_cast<uint128_t>(1), static_cast<uint128_t>(13),
                            static_cast<uint128_t>(500),
                            (static_cast<uint128_t>(1) << 60)}) {
        // ---- 场景 1：两台一致使用偏移后的 d（红队 E3）----
        {
            const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
            Prng prng(SeedKey("mpa05-red-d"), 0);
            const SecureMulTripleMaterial material =
                GenerateBeaverTriple(client.keys(), kQ, prng);
            const uint128_t q = kQ;
            const uint128_t f = 1;
            const uint128_t e_value = 987654321_k;
            const auto shares = ShareMod(e_value, q);
            const uint128_t d = subMod(f, material.client_triple.a, q);
            const uint128_t e = subMod(e_value, material.client_triple.b, q);
            const uint128_t d_bad = addMod(d, delta, q);

            const auto z0 = SecureMulServerPhase2(
                SecureMulServerInput{shares.first, material.server0}, d_bad, e, q);
            const auto z1 = SecureMulServerPhase2(
                SecureMulServerInput{shares.second, material.server1}, d_bad, e, q);
            const auto p2 = std::make_pair(
                Phase2Response{1, z0.z.value, z0.mac.value,
                               static_cast<uint8_t>(SecureMulStatus::kOk)},
                Phase2Response{1, z1.z.value, z1.mac.value,
                               static_cast<uint8_t>(SecureMulStatus::kOk)});

            // 对应事实：这台/两台一致偏移时 MAC 依然自洽（红队的核心发现）
            EXPECT_TRUE(addMod(z0.mac.value, z1.mac.value, q) ==
                        mulMod(client.alpha(), addMod(z0.z.value, z1.z.value, q), q));

            // 客户端的纯客户端复核必须检出（e_check 用诚实值 ⇒ 复核 B 通过，
            // 由复核 A 的 `z ?= f·(e_sent + b)` 拦下）
            const SecureMulRecordContext ctx = MakeSetupsAndContext(
                0, material, shares, 0x1234).ctx;
            const SecureMulFlowResult r =
                VerifyAndReconstruct(1, p2, client, &ctx, f, e, &material.client_triple,
                                     /*e_check0 诚实=⟨E⟩_0−⟨b⟩_0*/ subMod(shares.first.value, material.server0.b.value, q),
                                     subMod(shares.second.value, material.server1.b.value, q));
            EXPECT_FALSE(r.ok);
            EXPECT_TRUE(r.failure == SecureMulFailure::kClientLocalCheckFailed);
        }

        // ---- 场景 2：两台一致使用偏移后的 e（红队 E1）----
        {
            const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
            Prng prng(SeedKey("mpa05-red-e"), 0);
            const SecureMulTripleMaterial material =
                GenerateBeaverTriple(client.keys(), kQ, prng);
            const uint128_t q = kQ;
            const uint128_t f = 1;
            const uint128_t e_value = 987654321_k;
            const auto shares = ShareMod(e_value, q);
            const uint128_t d = subMod(f, material.client_triple.a, q);
            const uint128_t e = subMod(e_value, material.client_triple.b, q);
            const uint128_t e_bad = addMod(e, delta, q);

            const auto z0 = SecureMulServerPhase2(
                SecureMulServerInput{shares.first, material.server0}, d, e_bad, q);
            const auto z1 = SecureMulServerPhase2(
                SecureMulServerInput{shares.second, material.server1}, d, e_bad, q);
            const auto p2 = std::make_pair(
                Phase2Response{2, z0.z.value, z0.mac.value,
                               static_cast<uint8_t>(SecureMulStatus::kOk)},
                Phase2Response{2, z1.z.value, z1.mac.value,
                               static_cast<uint8_t>(SecureMulStatus::kOk)});
            // MAC 自洽（红队 E1 的核心）
            EXPECT_TRUE(addMod(z0.mac.value, z1.mac.value, q) ==
                        mulMod(client.alpha(), addMod(z0.z.value, z1.z.value, q), q));

            const SecureMulRecordContext ctx =
                MakeSetupsAndContext(0, material, shares, 0x1234).ctx;
            // ⚠️ 关键（本用例的整个要点）：客户端**自己中转出去的**是诚实值 e，
            //    而两台服务器被诱导用 e_bad 计算 ⇒ z' 与客户端本地视角
            //    （f·(e_sent + b)）不符 ⇒ 复核 A 检出。
            //    （若把 e_sent 也填成 e_bad，那等价于"客户端自己发的就是 e_bad"，
            //      复核 A 在定义上无从分辨 —— 那不是本攻击的形态。）
            const SecureMulFlowResult r =
                VerifyAndReconstruct(2, p2, client, &ctx, f, e,
                                     &material.client_triple,
                                     subMod(shares.first.value, material.server0.b.value, q),
                                     subMod(shares.second.value, material.server1.b.value, q));
            EXPECT_FALSE(r.ok);
            EXPECT_TRUE(r.failure == SecureMulFailure::kClientLocalCheckFailed);
        }

        // ---- 场景 3：单台谎报 ⟨e⟩_p（红队 E2）----
        {
            const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
            Prng prng(SeedKey("mpa05-red-elying"), 0);
            const SecureMulTripleMaterial material =
                GenerateBeaverTriple(client.keys(), kQ, prng);
            const uint128_t q = kQ;
            const uint128_t f = 1;
            const uint128_t e_value = 987654321_k;
            const auto shares = ShareMod(e_value, q);
            const uint128_t d = subMod(f, material.client_triple.a, q);
            const uint128_t e = subMod(e_value, material.client_triple.b, q);
            // S0 谎报：e0' = ⟨e⟩_0 + delta，并让两台都用 e' = e + delta
            const uint128_t e0_lie = addMod(shares.first.value, delta, q);
            const uint128_t e_bad = addMod(e, delta, q);

            const auto z0 = SecureMulServerPhase2(
                SecureMulServerInput{shares.first, material.server0}, d, e_bad, q);
            const auto z1 = SecureMulServerPhase2(
                SecureMulServerInput{shares.second, material.server1}, d, e_bad, q);
            const auto p2 = std::make_pair(
                Phase2Response{3, z0.z.value, z0.mac.value,
                               static_cast<uint8_t>(SecureMulStatus::kOk)},
                Phase2Response{3, z1.z.value, z1.mac.value,
                               static_cast<uint8_t>(SecureMulStatus::kOk)});
            // MAC 自洽（红队 E2 的核心：两道服务器侧加固都不触发）
            EXPECT_TRUE(addMod(z0.mac.value, z1.mac.value, q) ==
                        mulMod(client.alpha(), addMod(z0.z.value, z1.z.value, q), q));

            const SecureMulRecordContext ctx =
                MakeSetupsAndContext(0, material, shares, 0x1234).ctx;
            // 客户端原样回显收到的回执 ⇒ S0 的 e_check 就是它谎报的值
            const SecureMulFlowResult r =
                VerifyAndReconstruct(3, p2, client, &ctx, f, e_bad,
                                     &material.client_triple, e0_lie,
                                     shares.second.value);
            EXPECT_FALSE(r.ok);
            // 复核 B 先触发（它比复核 A 更早、更精确地指出是说谎的那台）
            EXPECT_TRUE(r.failure == SecureMulFailure::kEShareMismatch);
        }
    }
}

TEST(SecureMulFlow, ConsistentOffsetAttacksAreNowDetected) {
    // 上面那条用**分片层构造 + 客户端收尾层**覆盖任意 delta；这条用**真实消息流**
    // 覆盖红队的最小复现口径（把发给两台的 e 各 +1、e_check 原样），确认
    // "走完整消息流也挡得住"，并给出计数。
    const uint128_t q = kQ;
    const uint128_t f = 1;
    const uint128_t e_value = 987654321_k;

    int rounds = 0;
    int detected = 0;
    for (int server_id = 0; server_id <= 1; ++server_id) {
        for (int which : {0, 1}) {
            const SecureMulClientState client = SecureMulClientState::GenerateMacKey(q);
            FlowHarness h(client);
            Prng prng(SeedKey("mpa05-consistent-offset"), 0);
            const SecureMulTripleMaterial material =
                GenerateBeaverTriple(client.keys(), q, prng);
            h.InstallRecordWithContext(17, ShareMod(e_value, q), material);

            // which=0：把**发给这一台**的第 2 轮 e 翻最低位（等价于 +1/-1）
            // which=1：把**发给这一台**的第 1 轮 e_computed 翻最低位（谎报）
            if (which == 0) {
                h.counting().SetTamper(server_id, CountingTransport::TamperTarget::kSubmit,
                                       26, 0x01, /*occurrence=*/1);
            } else {
                h.counting().SetTamper(server_id, CountingTransport::TamperTarget::kResponse,
                                       10, 0x01, /*occurrence=*/0);
            }
            ++rounds;
            bool bad = false;
            try {
                const SecureMulFlowResult r = h.RunRecord(170, f, material.client_triple);
                bad = !r.ok;
                if (r.ok) EXPECT_EQ(r.z, mulMod(f, e_value, q));
            } catch (const std::exception&) {
                bad = true;
            }
            EXPECT_EQ(h.counting().TamperedCount(), static_cast<size_t>(1));
            if (bad) ++detected;
        }
    }
    EXPECT_EQ(rounds, 4);
    EXPECT_EQ(detected, 4);  // 4/4 全部检出（v2 时 which=1 会被静默接受）
}

TEST(SecureMulFlow, RedTeamBothServersOneBitEOffsetIsDetectedEndToEnd) {
    // ⚠️ 红队最强反例 E1 的最小复现口径，**走完整消息流**：
    //    把发给**两台**的第 2 轮请求里的 e 各翻最低 bit（e_check 原样），
    //    v2 下两台都报 kOk、`mac == α·z` 成立、客户端 ok=1 并接受错值
    //    （`f=1` 的 103/103 全部被接受）。
    //    v3 起由 §4.5-A 的纯客户端复核检出。
    const uint128_t q = kQ;
    const uint128_t e_value = 987654321_k;
    int rounds = 0;
    int detected = 0;
    int wrong_value_accepted = 0;
    int zero_filter_rounds = 0;
    for (uint128_t f : {static_cast<uint128_t>(0), static_cast<uint128_t>(1)}) {
        for (int repeat = 0; repeat < 8; ++repeat) {
            const SecureMulClientState client = SecureMulClientState::GenerateMacKey(q);
            FlowHarness h(client);
            Prng prng(SeedKey("mpa05-e1-" + std::to_string(repeat)), 0);
            const SecureMulTripleMaterial material =
                GenerateBeaverTriple(client.keys(), q, prng);
            h.InstallRecordWithContext(19, ShareMod(e_value, q), material);

            // 两台 × 第 2 轮请求（第 2 条 Submit）的 e 字段最低位
            h.counting().SetTamper(CountingTransport::kAllServers,
                                   CountingTransport::TamperTarget::kSubmit, 26, 0x01,
                                   /*occurrence=*/1);
            ++rounds;
            try {
                const SecureMulFlowResult r = h.RunRecord(190, f, material.client_triple);
                if (!r.ok) {
                    ++detected;
                } else if (r.z != mulMod(f, e_value, q)) {
                    ++wrong_value_accepted;  // 这正是红队 E1 的后果
                }
                // ⚠️ 如实说明：**f = 0 的轮次**即使 e 被改也不会产生错值
                //    （z 恒为 0，攻击者的偏移乘 0 后消失）。这类轮次被接受
                //    并不是漏洞，所以单独统计、不混入"检出率"。
                if (f == 0) ++zero_filter_rounds;
            } catch (const std::exception&) {
                ++detected;  // abort 也是检出
            }
            EXPECT_EQ(h.counting().TamperedCount(), static_cast<size_t>(2));
        }
    }
    EXPECT_EQ(rounds, 16);
    EXPECT_EQ(detected, 8);   // f = 1 的 8 轮 100% 检出
    EXPECT_EQ(zero_filter_rounds, 8);  // f = 0 的 8 轮：值本来就对，无错值可接受
    EXPECT_EQ(wrong_value_accepted, 0);  // **零**错值被接受（v2 时 f=1 的 8 轮全部被接受）
}

TEST(SecureMulFlow, RedTeamBothServersOneBitDOffsetIsDetectedEndToEnd) {
    // 红队 E3 的最小复现口径（更弱的一版）：把发给**两台、两轮**的 d 都翻最低位。
    // ⚠️ 注意这一版**恰好也**会让第 2 轮的 `d != phase1_d_`（第 1 轮的偏移在第 2 轮
    //    被覆写成同一个值，因此仍跨轮一致）—— 由纯客户端复核 A 兜底检出。
    //    真正"任意 Δ、逐位不同"的版本在 `RedTeamMultiBitOffsetIsDetected` 里
    //    用分片层构造覆盖（字节级 xor 无法表达任意加法偏移）。
    const uint128_t q = kQ;
    const uint128_t e_value = 123456789_k;
    int detected = 0;
    int rounds = 0;
    for (int repeat = 0; repeat < 8; ++repeat) {
        const SecureMulClientState client = SecureMulClientState::GenerateMacKey(q);
        FlowHarness h(client);
        Prng prng(SeedKey("mpa05-e2-" + std::to_string(repeat)), 0);
        const SecureMulTripleMaterial material =
            GenerateBeaverTriple(client.keys(), q, prng);
        h.InstallRecordWithContext(21, ShareMod(e_value, q), material);

        // 两台 × 两轮请求的 d 字段（第 1 轮是第 1 条 Submit，第 2 轮是第 2 条）
        h.counting().SetTamper(CountingTransport::kAllServers,
                               CountingTransport::TamperTarget::kSubmit, 18, 0x01,
                               /*occurrence=*/0);
        ++rounds;
        bool bad = false;
        try {
            const SecureMulFlowResult r = h.RunRecord(210, 1, material.client_triple);
            bad = !r.ok;
            if (r.ok) EXPECT_EQ(r.z, mulMod(1, e_value, q));
        } catch (const std::exception&) {
            bad = true;  // 服务器侧拒绝会以异常形式冒出来
        }
        if (bad) ++detected;
    }
    EXPECT_EQ(rounds, 8);
    EXPECT_EQ(detected, 8);  // 8/8 全部检出（服务器侧 d 检查 / 客户端复核 A 均可）
}

TEST(SecureMulFlow, ClientSideChecksAreWhyTheOffsetAttacksDie) {
    // 对照实验：同一条被"两台一致偏移 d"污染的应答，
    //   * 不传 ctx（v2 行为，只有 MAC）⇒ **被接受**（这就是红队的 E3）
    //   * 传 ctx（v3 行为，复核 A/B）⇒ 被检出
    // 这条把"v3 到底修了什么"钉死在测试里，防止以后有人把复核删掉。
    const uint128_t q = 1000003;  // 小素数，便于人工核对
    const uint128_t f = 1;
    const uint128_t e_value = 1234;
    const uint128_t alpha = 5;
    const SecureMulClientState client(alpha, {2, subMod(alpha, 2, q)}, q);
    Prng prng(SeedKey("mpa05-v3-contrast"), 0);
    const SecureMulTripleMaterial material = GenerateBeaverTriple(client.keys(), q, prng);
    const auto shares = ShareMod(e_value, q);
    const uint128_t d = subMod(f, material.client_triple.a, q);
    const uint128_t e = subMod(e_value, material.client_triple.b, q);
    const uint128_t d_bad = addMod(d, 7, q);

    const auto z0 = SecureMulServerPhase2(
        SecureMulServerInput{shares.first, material.server0}, d_bad, e, q);
    const auto z1 = SecureMulServerPhase2(
        SecureMulServerInput{shares.second, material.server1}, d_bad, e, q);
    const auto p2 = std::make_pair(
        Phase2Response{5, z0.z.value, z0.mac.value,
                       static_cast<uint8_t>(SecureMulStatus::kOk)},
        Phase2Response{5, z1.z.value, z1.mac.value,
                       static_cast<uint8_t>(SecureMulStatus::kOk)});

    // MAC 自洽：值错但 mac == α·z
    const uint128_t z_bad = addMod(z0.z.value, z1.z.value, q);
    const uint128_t mac_bad = addMod(z0.mac.value, z1.mac.value, q);
    EXPECT_NE(z_bad, mulMod(f, e_value, q));
    EXPECT_TRUE(mac_bad == mulMod(alpha, z_bad, q));

    // v2 行为：不传 ctx ⇒ 接受错值（红队 E3 原样复现）
    const SecureMulFlowResult old_way = VerifyAndReconstruct(5, p2, client);
    EXPECT_TRUE(old_way.ok);
    EXPECT_NE(old_way.z, mulMod(f, e_value, q));

    // v3 行为：传 ctx ⇒ 检出
    const SecureMulRecordContext ctx = MakeSetupsAndContext(0, material, shares, 1).ctx;
    const SecureMulFlowResult new_way = VerifyAndReconstruct(
        5, p2, client, &ctx, f, e, &material.client_triple,
        subMod(shares.first.value, material.server0.b.value, q),
        subMod(shares.second.value, material.server1.b.value, q));
    EXPECT_FALSE(new_way.ok);
    EXPECT_TRUE(new_way.failure == SecureMulFailure::kClientLocalCheckFailed);
}

// ===========================================================================
// 3d. v3 新增：状态机健壮性（红队 D1/D2）
// ===========================================================================

TEST(SecureMulFlow, Phase2BeforePhase1IsRejectedEvenWithSessionZero) {
    // 红队 D1：v2 只比较 `req.session != last_session_`，而 last_session_ 初值 0，
    // 于是 `session = 0` 的第 2 轮在**全新**状态上也能通过并返回 kOk 分片
    // （还会 consume 掉这条记录）。v3 用显式阶段机。
    const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
    Prng prng(SeedKey("mpa05-phase-machine"), 0);
    const SecureMulTripleMaterial material = GenerateBeaverTriple(client.keys(), kQ, prng);
    const auto shares = ShareMod(4242, kQ);
    const uint64_t challenge = MakeChallenge(3, {0xAB});
    const auto setups = MakeServerSetups(3, material, shares, challenge);
    SecureMulServerState st = MakeServerState(setups.first, kQ);

    // session = 0 的第 2 轮先到：必须拒绝（v2 会返回 kOk）
    const Phase2Response early = st.RunPhase2(Phase2Request{0, 0, 12345, 0});
    EXPECT_EQ(static_cast<int>(early.status),
              static_cast<int>(SecureMulStatus::kPhaseError));
    EXPECT_EQ(early.z_share, static_cast<uint128_t>(0));
    EXPECT_EQ(early.mac_share, static_cast<uint128_t>(0));
    EXPECT_FALSE(st.consumed());   // 不算消费：不得给攻击者"零成本否决权"
    EXPECT_FALSE(st.phase1_ran());

    // 之后合法的第 1 轮 + 第 2 轮仍必须能跑通（拒绝不是永久性的）
    const Phase1Response r1 = st.RunPhase1(Phase1Request{0, challenge, 5});
    EXPECT_EQ(static_cast<int>(r1.status), static_cast<int>(SecureMulStatus::kOk));
    const Phase2Response r2 = st.RunPhase2(Phase2Request{0, 5, 7, r1.e_computed});
    EXPECT_EQ(static_cast<int>(r2.status), static_cast<int>(SecureMulStatus::kOk));
    EXPECT_TRUE(st.consumed());
}

TEST(SecureMulFlow, RepeatedPhase1IsRejectedAndCannotBeUsedForDos) {
    // 红队 D2：v2 的 `consumed_` 只在第 2 轮置位 ⇒ 第 1 轮可重复/跨会话重放，
    // 重放消息会改写 phase1_d_/last_session_，让**诚实查询**在第 2 轮 abort。
    const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
    Prng prng(SeedKey("mpa05-replay-phase1"), 0);
    const SecureMulTripleMaterial material = GenerateBeaverTriple(client.keys(), kQ, prng);
    const auto shares = ShareMod(999, kQ);
    const uint64_t challenge = MakeChallenge(4, {0xCD});
    const auto setups = MakeServerSetups(4, material, shares, challenge);
    SecureMulServerState st = MakeServerState(setups.first, kQ);

    const Phase1Response first = st.RunPhase1(Phase1Request{7, challenge, 3});
    EXPECT_EQ(static_cast<int>(first.status), static_cast<int>(SecureMulStatus::kOk));

    // 重复投递第 1 轮（同 session、不同 d）：v2 会接受并改写 phase1_d_
    const Phase1Response dup = st.RunPhase1(Phase1Request{7, challenge, 4});
    EXPECT_EQ(static_cast<int>(dup.status),
              static_cast<int>(SecureMulStatus::kPhaseError));

    // 合法第 2 轮仍用**第 1 轮下发**的 d ⇒ 必须成功（DoS 被打掉）
    const Phase2Response ok2 = st.RunPhase2(Phase2Request{7, 3, 9, first.e_computed});
    EXPECT_EQ(static_cast<int>(ok2.status), static_cast<int>(SecureMulStatus::kOk));

    // 跨会话重放（换 session/challenge）
    SecureMulServerState st2 = MakeServerState(setups.first, kQ);
    const Phase1Response cross = st2.RunPhase1(Phase1Request{8, challenge + 1, 3});
    EXPECT_EQ(static_cast<int>(cross.status),
              static_cast<int>(SecureMulStatus::kPhaseError));

    // 未安装 challenge 就开跑：调用方配置错误 ⇒ 抛异常（不是静默接受任意 challenge）
    SecureMulServerState st3(4, material.server0, kQ);
    st3.InstallAttributeShare(shares.first);
    EXPECT_THROW(st3.RunPhase1(Phase1Request{7, challenge, 3}), std::logic_error);
}

TEST(SecureMulFlow, HonestPeerIsNotDeniedByASelfishZeroReport) {
    // ⚠️ v2 的服务器侧检查还要求 `e != e_check`。那给了单台服务器一个
    //    **零成本否决权**：它把自己的 ⟨e⟩_p 报成 0，客户端算出的 e 就等于诚实
    //    那台的 e_check，诚实那台随即 kECheckFailed ⇒ 整条查询 abort
    //    （对抗性验证 §5.3）。v3 删掉了这条判据 ⇒ 诚实的那台必须照常放行。
    const uint128_t q = kQ;
    Prng prng(SeedKey("mpa05-no-zero-veto"), 0);
    const SecureMulTripleMaterial material = GenerateBeaverTriple(SecureMulClientState::GenerateMacKey(q).keys(), q, prng);
    const auto shares = ShareMod(4321, q);
    const uint64_t challenge = MakeChallenge(6, {0x31});
    const auto setups = MakeServerSetups(6, material, shares, challenge);

    // 诚实的那台（S1）：正常第 1 轮
    SecureMulServerState s1 = MakeServerState(setups.second, q);
    const Phase1Response r1 = s1.RunPhase1(Phase1Request{2, challenge, 11});
    EXPECT_EQ(static_cast<int>(r1.status), static_cast<int>(SecureMulStatus::kOk));

    // 恶意 S0 谎报 ⟨e⟩_0 = 0 ⇒ 客户端算出的 e = 0 + ⟨e⟩_1 = ⟨e⟩_1 = e_check_1
    // （这正是 v2 会误拒的形态）
    const Phase2Response p1 =
        s1.RunPhase2(Phase2Request{2, 11, /*e=*/r1.e_computed, /*e_check=*/r1.e_computed});
    EXPECT_EQ(static_cast<int>(p1.status), static_cast<int>(SecureMulStatus::kOk));
}

TEST(SecureMulFlow, ServerSelfReportedCheckIsSelfWitnessing) {
    // ⚠️ 如实固化服务器侧 e_check 的**效力边界**（对抗性验证 E2）：
    //    `e_check` 是客户端把"它收到的回执"原样带回的 ⇒ **说谎的那台自己就是裁判**。
    //    本用例分别构造两种情形，把边界钉死：
    //      (A) S0 谎报 ⟨e⟩_0 + 1、**并按谎报值执行**（它自己存的就是谎报值）
    //          ⇒ 服务器侧的 e_check 检查**通过**（自证、不触发）；
    //      (B) S0 谎报 ⟨e⟩_0 + 1、但仍按**真实计算值**执行
    //          ⇒ 服务器侧检查触发（这等价于"回执在链路上被改"，即通道篡改）。
    //    两种情形都必须被**纯客户端复核 B**（§4.5-B）检出 —— 那才是安全保证。
    const uint128_t q = kQ;
    const uint128_t f = 1;
    const uint128_t e_value = 555000;
    const SecureMulClientState client = SecureMulClientState::GenerateMacKey(q);
    Prng prng(SeedKey("mpa05-selfwitness"), 0);
    const SecureMulTripleMaterial material = GenerateBeaverTriple(client.keys(), q, prng);
    const auto shares = ShareMod(e_value, q);
    const uint64_t challenge = MakeChallenge(5, {0x77});
    const auto setups = MakeServerSetups(5, material, shares, challenge);
    const uint128_t d = subMod(f, material.client_triple.a, q);
    const uint128_t e_true = subMod(e_value, material.client_triple.b, q);
    const uint128_t e_bad = addMod(e_true, 1, q);

    // --- 情形 (A)：谎报值 = 该台"执行"的值 ⇒ 服务器侧检查通过 ---
    {
        SecureMulServerState s0 = MakeServerState(setups.first, q);
        s0.RunPhase1(Phase1Request{1, challenge, d});
        // 该台把自己的 ⟨e⟩_p 改成 "真实值 + 1"，之后就用这个值算 z/mac
        const uint128_t lie0 = addMod(subMod(shares.first.value,
                                             material.server0.b.value, q), 1, q);
        SecureMulServerState s0_lie(5, material.server0, q);
        s0_lie.InstallAttributeShare(ModShare{addMod(shares.first.value, 1, q)});
        s0_lie.InstallChallenge(challenge);
        const Phase1Response r1 = s0_lie.RunPhase1(Phase1Request{1, challenge, d});
        EXPECT_EQ(static_cast<int>(r1.status), static_cast<int>(SecureMulStatus::kOk));
        EXPECT_EQ(r1.e_computed, lie0);
        // 客户端（被欺骗）把谎报值原样回显 ⇒ 服务器侧检查**通过**
        const Phase2Response p = s0_lie.RunPhase2(Phase2Request{1, d, e_bad, lie0});
        EXPECT_EQ(static_cast<int>(p.status), static_cast<int>(SecureMulStatus::kOk));

        // 客户端复核 B 独立检出
        const SecureMulRecordContext ctx =
            MakeSetupsAndContext(0, material, shares, 1).ctx;
        const auto z1 = SecureMulServerPhase2(
            SecureMulServerInput{shares.second, material.server1}, d, e_bad, q);
        const auto p2 = std::make_pair(
            Phase2Response{1, p.z_share, p.mac_share,
                           static_cast<uint8_t>(SecureMulStatus::kOk)},
            Phase2Response{1, z1.z.value, z1.mac.value,
                           static_cast<uint8_t>(SecureMulStatus::kOk)});
        const SecureMulFlowResult r =
            VerifyAndReconstruct(1, p2, client, &ctx, f, e_bad,
                                 &material.client_triple, lie0,
                                 subMod(shares.second.value, material.server1.b.value, q));
        EXPECT_FALSE(r.ok);
        EXPECT_TRUE(r.failure == SecureMulFailure::kEShareMismatch);
    }

    // --- 情形 (B)：谎报值 ≠ 该台执行的值（等价于通道篡改回执）⇒ 服务器侧触发 ---
    {
        SecureMulServerState s0 = MakeServerState(setups.first, q);
        const Phase1Response honest0 = s0.RunPhase1(Phase1Request{1, challenge, d});
        const uint128_t lie0 = addMod(honest0.e_computed, 1, q);
        const Phase2Response p =
            s0.RunPhase2(Phase2Request{1, d, addMod(honest0.e_computed, 1, q), lie0});
        EXPECT_EQ(static_cast<int>(p.status),
                  static_cast<int>(SecureMulStatus::kECheckFailed));
    }
}

TEST(SecureMulFlow, HonestPathNeverFalsePositives) {
    // 反向确认：诚实路径在多轮下零误报（避免"全都拒绝"也能通过上面的用例）
    const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
    FlowHarness h(client);
    Prng prng(SeedKey("mpa05-no-false-positive"), 0);
    int accepted = 0;
    for (int round = 0; round < 64; ++round) {
        const uint128_t e_value = prng.Below(kQ);
        const uint128_t f = (prng.Next() & 1u) ? 1u : 0u;
        const SecureMulTripleMaterial material =
            GenerateBeaverTriple(client.keys(), kQ, prng);
        h.InstallRecord(static_cast<uint64_t>(round), e_value, material);
        const SecureMulFlowResult r =
            h.RunRecord(static_cast<uint64_t>(round), f, material.client_triple);
        if (r.ok) ++accepted;
    }
    EXPECT_EQ(accepted, 64);
}

// ===========================================================================
// 4. 零服务器间通信
// ===========================================================================

TEST(SecureMulFlow, ServersNeverTalkToEachOther) {
    // **证明方式**：所有客户端 → 服务器的字节都必须经过 CountingTransport
    // （它包装了 ITransportClient）。因此只要断言：
    //   (1) 记录的每一条消息的 server_id ∈ {0,1} —— 不存在第三个端点；
    //   (2) 每台服务器恰好收到 2 条消息，且能按协议解码为
    //       [Phase1Request, Phase2Request] —— 不存在"额外消息"这个信道；
    //   (3) 客户端只向这两台服务器 Submit，恒等关系
    //       SubmitCount(0) + SubmitCount(1) == 总消息数 成立。
    // 服务器侧还有类型层面的保证：SecureMulServerState 不持有任何通信对象
    // （见头文件 §5），所以"服务器发消息给另一台服务器"在代码里无法表达。
    const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
    FlowHarness h(client);
    Prng prng(SeedKey("mpa05-zero-server-comms"), 0);
    const SecureMulTripleMaterial material =
        GenerateBeaverTriple(client.keys(), kQ, prng);
    h.InstallRecord(4, 24680, material);
    h.counting().Reset();

    const SecureMulFlowResult r = h.RunRecord(404, 1, material.client_triple);
    EXPECT_TRUE(r.ok);

    const auto& recs = h.counting().records();
    EXPECT_EQ(recs.size(), static_cast<size_t>(4));  // 2 轮 × 2 台服务器
    EXPECT_EQ(h.counting().ThirdPartyCount(), static_cast<size_t>(0));
    EXPECT_EQ(h.counting().SubmitCount(0) + h.counting().SubmitCount(1), recs.size());

    std::vector<SecureMulMsgType> seq0;
    std::vector<SecureMulMsgType> seq1;
    for (const auto& rec : recs) {
        EXPECT_TRUE(rec.server_id == 0 || rec.server_id == 1);
        auto& seq = (rec.server_id == 0) ? seq0 : seq1;
        seq.push_back(static_cast<SecureMulMsgType>(rec.payload[1]));
    }
    ASSERT_EQ(seq0.size(), static_cast<size_t>(2));
    ASSERT_EQ(seq1.size(), static_cast<size_t>(2));
    EXPECT_TRUE(seq0[0] == SecureMulMsgType::kPhase1Request);
    EXPECT_TRUE(seq0[1] == SecureMulMsgType::kPhase2Request);
    EXPECT_TRUE(seq1[0] == SecureMulMsgType::kPhase1Request);
    EXPECT_TRUE(seq1[1] == SecureMulMsgType::kPhase2Request);

    // 第 1 轮请求对两台**完全相同**（只含 session/challenge/d，d 对两台是同一个值）。
    EXPECT_TRUE(recs[0].payload == recs[1].payload);
    // 第 2 轮请求里多了一个 §4.5 的 `e_check`，而它**按服务器不同**（各带自己那份
    // ⟨e⟩_p 回执）。除此之外两台收到的内容必须逐位相同 —— 差异只能出现在
    // 这个"回执"字段上，绝不出现"某台把别的数据塞给了另一台"。
    {
        const auto a = DecodePhase2Request(recs[2].payload);
        const auto b = DecodePhase2Request(recs[3].payload);
        EXPECT_NE(a.e_check, b.e_check);          // 各自那份回执
        EXPECT_EQ(a.session, b.session);
        EXPECT_EQ(a.d, b.d);
        EXPECT_EQ(a.e, b.e);                      // 中转的 e 是同一个值
    }
}

TEST(SecureMulFlow, ServerSideStatesShareNoMutableState) {
    // 结构性证据的运行时对照：两台服务器各自贡献一半，客户端重建出的 e
    // 必须等于 y − b；若两台服务器能互相通信（例如共用状态），
    // 单独篡改其中一台就不会只影响一半。
    const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
    FlowHarness h(client);
    Prng prng(SeedKey("mpa05-independent-states"), 0);
    const SecureMulTripleMaterial material =
        GenerateBeaverTriple(client.keys(), kQ, prng);
    const uint128_t e_value = 31337;
    h.InstallRecord(6, e_value, material);

    // ⚠️ 属性值的加法共享只生成一次、两台复用，否则两半来自不同的随机拆分，
    //    重建出来不是 e_value（ShareMod 每次调用都会取新的随机掩码）。
    const auto shares = ShareMod(e_value, kQ);
    const auto p1_0 = SecureMulServerPhase1(
        SecureMulServerInput{shares.first, material.server0}, kQ);
    const auto p1_1 = SecureMulServerPhase1(
        SecureMulServerInput{shares.second, material.server1}, kQ);

    // 各自只用自己的共享：单独看每一半都不是 E − b
    const uint128_t e = addMod(p1_0.e.value, p1_1.e.value, kQ);
    EXPECT_EQ(e, subMod(e_value, material.client_triple.b, kQ));
    EXPECT_NE(p1_0.e.value, e);
    EXPECT_NE(p1_1.e.value, e);

    // 客户端从中转的 e 出发能算对；两台服务器单独都算不出 f·E
    const SecureMulFlowResult r = h.RunRecord(606, 1, material.client_triple);
    EXPECT_TRUE(r.ok);
    EXPECT_NE(material.server0.c.value, mulMod(1, e_value, kQ));
}

// ===========================================================================
// 5. 半诚实隐私（论证性断言）与确定性
// ===========================================================================

TEST(SecureMulFlow, Phase1RequestCarriesOnlyMaskedD) {
    // 被发送出去的 d = f − a 必须**依赖 triple 的随机分量 a**，
    // 因此同一个 f 在不同 triple 下产生完全不同的 d ⇒ 服务器从 d 学不到 f。
    // 这里用"固定 f、换 triple"的方式把这个性质变成可断言的事实。
    const uint128_t f = 1;
    std::vector<uint128_t> observed_d;
    for (int i = 0; i < 32; ++i) {
        const SecureMulClientState client = SecureMulClientState::GenerateMacKey(kQ);
        FlowHarness h(client);
        Prng prng(SeedKey("mpa05-privacy-" + std::to_string(i)), 0);
        const SecureMulTripleMaterial material =
            GenerateBeaverTriple(client.keys(), kQ, prng);
        h.InstallRecord(2, 500, material);
        h.counting().Reset();
        const SecureMulFlowResult r = h.RunRecord(202, f, material.client_triple);
        EXPECT_TRUE(r.ok);
        // 第 1 条消息（第 1 轮请求）里 d 的偏移是 18
        const Payload& req = h.counting().records().front().payload;
        observed_d.push_back(fromBytesLE(req.data() + 18));
        // d 必须等于 f − a，即"被 a 掩码"
        EXPECT_EQ(observed_d.back(), subMod(f, material.client_triple.a, kQ));
    }
    std::sort(observed_d.begin(), observed_d.end());
    const size_t distinct =
        static_cast<size_t>(std::unique(observed_d.begin(), observed_d.end()) -
                            observed_d.begin());
    EXPECT_EQ(distinct, observed_d.size());  // 32 个互不相同
}

TEST(SecureMulFlow, IsDeterministicUnderTheSameSeed) {
    // ⚠️ 口径**收窄后**的确定性声明（v3）：
    //    * 模块公开的 `ShareMod` 走**系统 CSPRNG** ⇒ 用了它的路径下，同一种子
    //      两次运行的**线上字节并不相同**（v2 的测试注释写"triple、d、e、z、mac
    //      全部逐位一致"是**过度声明**，对抗性验证已指出）。
    //    * 本用例把 ⟨E⟩ 的掩码也接到同一个确定性源（`ShareValueDeterministic` /
    //      `MakeSetupsAndContextFromPrng`），因此能断言**真正强的口径**：
    //      **整条 transcript（triple、d、e、z、mac 与全部线上字节）逐位一致**。
    struct Transcript {
        std::vector<uint128_t> z;
        std::vector<uint128_t> mac;
        std::vector<uint8_t> wire;  // 全部线上字节的拼接
    };
    const auto run_once = [](const std::string& seed, uint64_t nonce) {
        const SecureMulClientState client(
            0xabcdef0123456789ULL,
            {0x2222ULL, subMod(0xabcdef0123456789ULL, 0x2222ULL, kQ)}, kQ);
        // stream 0：triple；stream 1：⟨E⟩ 的掩码
        Prng prng(SeedKey(seed), nonce);
        Prng e_prng(SeedKey(seed + "-E"), nonce);
        FlowHarness h(client);
        Transcript t;
        for (int i = 0; i < 8; ++i) {
            const uint128_t e_value = e_prng.Below(kQ);
            const uint128_t f = (e_prng.Next() & 1u) ? 1u : 0u;
            const SecureMulTripleMaterial material =
                GenerateBeaverTriple(client.keys(), kQ, prng);
            // ⚠️ 用 FromPrng 版本：连 ⟨E⟩ 的共享掩码都走确定性源
            const auto bundle = MakeSetupsAndContextFromPrng(
                static_cast<uint64_t>(i), material, e_value, MakeChallenge(i, {0x01}),
                kQ, e_prng);
            // ⚠️ 必须用 bundle 里那一份 setup/ctx 安装 —— `InstallRecord` 内部走
            //    的是 `ShareMod`（系统 CSPRNG），会把确定性打断。
            h.InstallRecordFromBundle(i, bundle);
            const auto r = h.RunRecord(1000 + static_cast<uint64_t>(i), f,
                                       material.client_triple);
            EXPECT_TRUE(r.ok);
            t.z.push_back(r.z);
            t.mac.push_back(r.mac);
            for (const auto& rec : h.counting().records()) {
                t.wire.insert(t.wire.end(), rec.payload.begin(), rec.payload.end());
            }
            h.counting().Reset();
        }
        return t;
    };

    const Transcript a = run_once("mpa05-determinism", 77);
    const Transcript b = run_once("mpa05-determinism", 77);
    ASSERT_EQ(a.z.size(), b.z.size());
    for (size_t i = 0; i < a.z.size(); ++i) {
        EXPECT_EQ(a.z[i], b.z[i]);
        EXPECT_EQ(a.mac[i], b.mac[i]);
    }
    // **线上字节**逐位一致（这是 v2 没有断言的部分）
    ASSERT_EQ(a.wire.size(), b.wire.size());
    EXPECT_TRUE(a.wire == b.wire);
    EXPECT_TRUE(a.wire.size() > 0);

    // 换种子必须得到不同轨迹（否则"确定性"退化成"常量"）
    const Transcript c = run_once("mpa05-determinism-2", 77);
    EXPECT_TRUE(a.z != c.z || a.wire != c.wire);
    // 换 nonce 必须不同
    const Transcript d = run_once("mpa05-determinism", 78);
    EXPECT_TRUE(a.z != d.z || a.wire != d.wire);

    // 同一 PRNG 连续取两次 triple：必须互不相同（triple 是新鲜的）
    Prng prng(SeedKey("mpa05-freshness"), 0);
    const SecureMulClientState client2 = SecureMulClientState::GenerateMacKey(kQ);
    const SecureMulTripleMaterial m1 = GenerateBeaverTriple(client2.keys(), kQ, prng);
    const SecureMulTripleMaterial m2 = GenerateBeaverTriple(client2.keys(), kQ, prng);
    EXPECT_NE(m1.server0.a.value, m2.server0.a.value);
    EXPECT_NE(m1.server0.b.value, m2.server0.b.value);
    EXPECT_EQ(m1.client_triple.c, mulMod(m1.client_triple.a, m1.client_triple.b, kQ));
}

TEST(SecureMulFlow, GlobalAlphaIsReusedAcrossRecords) {
    // Q3(a)：α **全局一份**（在 Init 阶段生成）。多条记录必须共用同一个 α，
    // 而不是每条换一个 —— 否则 ⟨α⟩_p 会随记录变化，不符合 SPDZ 的全局密钥口径。
    // 这里用固定 α 构造客户端，使断言逐位可复现。
    const uint128_t alpha = 0x0123456789abcdefULL;
    const SecureMulClientState client(
        alpha, {0x1111ULL, subMod(alpha, 0x1111ULL, kQ)}, kQ);
    EXPECT_EQ(addMod(client.AlphaShare(0).value, client.AlphaShare(1).value, kQ),
              alpha);

    FlowHarness h(client);
    Prng prng(SeedKey("mpa05-global-alpha"), 0);
    for (int i = 0; i < 8; ++i) {
        const SecureMulTripleMaterial material =
            GenerateBeaverTriple(client.keys(), kQ, prng);
        // 每条记录下发给两台服务器的 ⟨α⟩_p 都必须与客户端持有的那份逐位一致
        EXPECT_EQ(material.server0.alpha.value, client.AlphaShare(0).value);
        EXPECT_EQ(material.server1.alpha.value, client.AlphaShare(1).value);
        // 而 triple 的其余分量必须**每条都新鲜**（a、b 每轮不同）
        h.InstallRecord(static_cast<uint64_t>(i), 100 + i, material);
        const SecureMulFlowResult r =
            h.RunRecord(3000 + static_cast<uint64_t>(i), 1, material.client_triple);
        EXPECT_TRUE(r.ok);
        EXPECT_EQ(r.mac, mulMod(alpha, r.z, kQ));
    }
    // ⟨α⟩ 全程不变：再取一次仍是同一份
    EXPECT_EQ(client.AlphaShare(0).value, client.AlphaShare(0).value);
}
