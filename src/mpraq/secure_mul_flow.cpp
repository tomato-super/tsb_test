#include "mpraq/secure_mul_flow.hpp"

#include <sstream>
#include <stdexcept>

namespace tsb {
namespace mpraq {

// ===========================================================================
// 内部工具
// ===========================================================================
namespace {

constexpr size_t kUint64Bytes = 8;

// ---- 小端编解码（显式、与主机字节序无关）----

void PutU8(Payload& out, uint8_t v) { out.push_back(v); }

void PutU64(Payload& out, uint64_t v) {
    for (size_t i = 0; i < kUint64Bytes; ++i) {
        out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xffu));
    }
}

void PutU128(Payload& out, uint128_t v) {
    uint8_t buf[kUint128Bytes];
    toBytesLE(v, buf);
    out.insert(out.end(), buf, buf + kUint128Bytes);
}

void RequireSize(const Payload& p, size_t expected, const char* what) {
    if (p.size() != expected) {
        std::ostringstream oss;
        oss << what << ": 消息长度不符（期望 " << expected << " 字节，实际 "
            << p.size() << " 字节）";
        throw std::invalid_argument(oss.str());
    }
}

// 共同的消息头校验：版本 + 类型。
void CheckHeader(const Payload& p, SecureMulMsgType expected, const char* what) {
    if (p.size() < 2) {
        std::ostringstream oss;
        oss << what << ": 消息太短（至少需要 2 字节的版本+类型头）";
        throw std::invalid_argument(oss.str());
    }
    if (p[0] != kSecureMulWireVersion) {
        std::ostringstream oss;
        oss << what << ": 消息版本不符（期望 " << static_cast<int>(kSecureMulWireVersion)
            << "，实际 " << static_cast<int>(p[0]) << "）";
        throw std::invalid_argument(oss.str());
    }
    if (p[1] != static_cast<uint8_t>(expected)) {
        std::ostringstream oss;
        oss << what << ": 消息类型不符（期望 " << static_cast<int>(expected)
            << "，实际 " << static_cast<int>(p[1]) << "）";
        throw std::invalid_argument(oss.str());
    }
}

// 从缓冲区的 [offset, offset+8) 读一个小端 u64
uint64_t ReadU64(const Payload& p, size_t offset) {
    uint64_t v = 0;
    for (size_t i = 0; i < kUint64Bytes; ++i) {
        v |= static_cast<uint64_t>(p[offset + i]) << (8 * i);
    }
    return v;
}

uint128_t ReadU128(const Payload& p, size_t offset) {
    return fromBytesLE(p.data() + offset);
}

// ---- 参数校验 ----

// 模数校验：与 `shared/mpc` 的 `RequireOddModulus` 同口径（D11）。
// 这里**重复**一次而不是直接调用，是为了在消息流层就把错误挡在门口，
// 报错信息里带上本模块的名字，便于定位。
void RequireSecureMulModulus(uint128_t q) {
    if (q < 3) {
        throw std::invalid_argument("SecureMulFlow: 模数 q 必须 >= 3");
    }
    if ((q & 1u) == 0) {
        throw std::invalid_argument(
            "SecureMulFlow: 模数 q 必须为奇数（Z_{2^k} 中 2 不可逆，公式里的 "
            "e·d·2^{-1} 无定义；见 TASK_PLAN 决策 D11）");
    }
    if (q > (static_cast<uint128_t>(1) << 127)) {
        throw std::invalid_argument(
            "SecureMulFlow: 模数 q 必须 <= 2^127（core/field 的 modmul 约束）");
    }
}

int RequireServerId(int server_id) {
    if (server_id != kServer0 && server_id != kServer1) {
        std::ostringstream oss;
        oss << "SecureMulFlow: 只支持 server_id ∈ {0,1}，收到 " << server_id;
        throw std::out_of_range(oss.str());
    }
    return server_id;
}

}  // namespace

// ===========================================================================
// 编解码
// ===========================================================================
// 布局（全部小端；v2 增加了 §4.5 的一致性检查字段）：
//   Phase1Request  : ver(1) type(1) session(8) challenge(8) d(16)                    = 34 B
//   Phase1Response : ver(1) type(1) session(8) e_computed(16) status(1)              = 27 B
//   Phase2Request  : ver(1) type(1) session(8) d(16) e(16) e_check(16)               = 58 B
//   Phase2Response : ver(1) type(1) session(8) z_share(16) mac_share(16) status(1)   = 43 B

Payload EncodePhase1Request(const Phase1Request& m) {
    Payload out;
    out.reserve(34);
    PutU8(out, kSecureMulWireVersion);
    PutU8(out, static_cast<uint8_t>(SecureMulMsgType::kPhase1Request));
    PutU64(out, m.session);
    PutU64(out, m.challenge);
    PutU128(out, m.d);
    return out;
}

Payload EncodePhase1Response(const Phase1Response& m) {
    Payload out;
    out.reserve(27);
    PutU8(out, kSecureMulWireVersion);
    PutU8(out, static_cast<uint8_t>(SecureMulMsgType::kPhase1Response));
    PutU64(out, m.session);
    PutU128(out, m.e_computed);
    PutU8(out, m.status);
    return out;
}

Payload EncodePhase2Request(const Phase2Request& m) {
    Payload out;
    out.reserve(58);
    PutU8(out, kSecureMulWireVersion);
    PutU8(out, static_cast<uint8_t>(SecureMulMsgType::kPhase2Request));
    PutU64(out, m.session);
    PutU128(out, m.d);
    PutU128(out, m.e);
    PutU128(out, m.e_check);
    return out;
}

Payload EncodePhase2Response(const Phase2Response& m) {
    Payload out;
    out.reserve(43);
    PutU8(out, kSecureMulWireVersion);
    PutU8(out, static_cast<uint8_t>(SecureMulMsgType::kPhase2Response));
    PutU64(out, m.session);
    PutU128(out, m.z_share);
    PutU128(out, m.mac_share);
    PutU8(out, m.status);
    return out;
}

Phase1Request DecodePhase1Request(const Payload& p) {
    CheckHeader(p, SecureMulMsgType::kPhase1Request, "DecodePhase1Request");
    RequireSize(p, 34, "DecodePhase1Request");
    Phase1Request m;
    m.session = ReadU64(p, 2);
    m.challenge = ReadU64(p, 10);
    m.d = ReadU128(p, 18);
    return m;
}

Phase1Response DecodePhase1Response(const Payload& p) {
    CheckHeader(p, SecureMulMsgType::kPhase1Response, "DecodePhase1Response");
    RequireSize(p, 27, "DecodePhase1Response");
    Phase1Response m;
    m.session = ReadU64(p, 2);
    m.e_computed = ReadU128(p, 10);
    m.status = p[26];
    return m;
}

Phase2Request DecodePhase2Request(const Payload& p) {
    CheckHeader(p, SecureMulMsgType::kPhase2Request, "DecodePhase2Request");
    RequireSize(p, 58, "DecodePhase2Request");
    Phase2Request m;
    m.session = ReadU64(p, 2);
    m.d = ReadU128(p, 10);
    m.e = ReadU128(p, 26);
    m.e_check = ReadU128(p, 42);
    return m;
}

Phase2Response DecodePhase2Response(const Payload& p) {
    CheckHeader(p, SecureMulMsgType::kPhase2Response, "DecodePhase2Response");
    RequireSize(p, 43, "DecodePhase2Response");
    Phase2Response m;
    m.session = ReadU64(p, 2);
    m.z_share = ReadU128(p, 10);
    m.mac_share = ReadU128(p, 26);
    m.status = p[42];
    return m;
}

// ===========================================================================
// SecureMulServerState
// ===========================================================================

SecureMulServerState::SecureMulServerState(uint64_t record_index,
                                           const TripleShare& triple, uint128_t q)
    : record_index_(record_index), q_(q), triple_(triple) {
    RequireSecureMulModulus(q_);
    // ⟨α⟩_p 必须存在（GenerateMacKey 已经分发给两台服务器）；为 0 是合法值
    // （它只表示"这一份恰好是 0"），但 triple 的其余分量不在这里做语义检查 ——
    // 一致性由 MAC 校验兜底，这正是 SPDZ 的设计。
}

void SecureMulServerState::InstallAttributeShare(const ModShare& e_share) {
    if (attribute_installed_) {
        throw std::logic_error(
            "SecureMulServerState::InstallAttributeShare: ⟨E⟩_p 只能安装一次"
            "（重复安装会破坏加法共享的一致性）");
    }
    attribute_share_ = e_share;
    attribute_installed_ = true;
}

void SecureMulServerState::InstallChallenge(uint64_t challenge) {
    challenge_ = challenge;
    challenge_installed_ = true;
}

Phase1Response SecureMulServerState::RunPhase1(const Phase1Request& req) {
    if (!attribute_installed_) {
        throw std::logic_error(
            "SecureMulServerState::RunPhase1: 尚未安装 ⟨E⟩_p（Init 阶段未完成）");
    }
    if (!challenge_installed_) {
        // challenge 是防重放/防串会话的锚点；没安装就开跑属于调用方配置错误
        throw std::logic_error(
            "SecureMulServerState::RunPhase1: 尚未安装 challenge"
            "（Init 阶段未完成；缺了它就无法区分会话）");
    }
    // 一次性语义：一条记录的实例状态只接受**一次**第 1 轮请求。
    // ⚠️ 这里返回 kPhaseError 而不是抛异常：重复/重放是**对端行为**，属于
    //    "消息不被接受"，不是"调用方用错 API"（用错 API 才抛异常）。
    //    v2 只在 RunPhase2 置一次性标志，导致第 1 轮可被重复/跨会话重放并改写
    //    phase1_d_/last_session_，从而让诚实查询在第 2 轮 abort（对抗性验证 D2）。
    if (stage_ != Stage::kFresh) {
        Phase1Response dup;
        dup.session = req.session;
        dup.status = static_cast<uint8_t>(SecureMulStatus::kPhaseError);
        return dup;
    }
    if (req.challenge != challenge_) {
        // 挑战不符 = 消息来自另一次会话（乱序/重放/串会话）
        Phase1Response bad;
        bad.session = req.session;
        bad.status = static_cast<uint8_t>(SecureMulStatus::kPhaseError);
        return bad;
    }
    stage_ = Stage::kPhase1Done;
    last_session_ = req.session;
    phase1_d_ = req.d;  // 记下第 1 轮的 d，供第 2 轮的跨轮一致性检查（见 RunPhase2）

    // 唯一的一步代数计算交给 shared/mpc，本模块不重复实现公式。
    const SecureMulServerInput in{attribute_share_, triple_};
    const SecureMulRound1 r1 = SecureMulServerPhase1(in, q_);
    // 记下本方报出的 ⟨e⟩_p：第 2 轮的 e 一致性检查要拿它当基准（§4.5）
    e_computed_share_ = r1.e;
    e_computed_ = true;
    Phase1Response ok;
    ok.session = req.session;
    ok.e_computed = r1.e.value;
    ok.status = static_cast<uint8_t>(SecureMulStatus::kOk);
    return ok;
}

const ModShare& SecureMulServerState::computed_e_share() const {
    if (!e_computed_) {
        throw std::logic_error(
            "SecureMulServerState::computed_e_share: 尚未跑过第 1 轮");
    }
    return e_computed_share_;
}

Phase2Response SecureMulServerState::RunPhase2(const Phase2Request& req) {
    if (!attribute_installed_) {
        throw std::logic_error(
            "SecureMulServerState::RunPhase2: 尚未安装 ⟨E⟩_p（Init 阶段未完成）");
    }
    // ⚠️ 阶段判定（对抗性验证 D1）：必须先成功跑过第 1 轮。
    //    v2 只比较 `req.session != last_session_`，而 last_session_ 初值为 0，
    //    于是 `session = 0` 的第 2 轮请求在**全新**状态上也能通过，返回一个
    //    kOk 的 (z_p, mac_p) 并 consume 掉这条记录。
    if (stage_ != Stage::kPhase1Done) {
        Phase2Response bad;
        bad.session = req.session;
        bad.status = static_cast<uint8_t>(SecureMulStatus::kPhaseError);
        // 只有"已被消费"才把阶段再推一步；kFresh（第 2 轮先到）不算消费，
        // 之后仍允许合法的第 1 轮 + 第 2 轮（不给攻击者一个"零成本否决权"）。
        return bad;
    }
    if (req.session != last_session_) {
        Phase2Response bad;
        bad.session = req.session;
        bad.status = static_cast<uint8_t>(SecureMulStatus::kPhaseError);
        return bad;
    }

    // -----------------------------------------------------------------------
    // (0) d 跨轮一致性检查（**本模块的加固**，见头文件 §4.5 末段）
    //     第 2 轮的 d 必须与**本服务器在第 1 轮收到的那个 d** 逐位相同。
    //     合法协议里 d 是同一轮查询的常量；这条检查挡住"第 1 轮与第 2 轮之间
    //     d 被改"的注入（实测：不检查时这类注入会被静默忽略，因为客户端
    //     第 2 轮重算的 d 会与第 1 轮下发的不一致 —— 见 SecureMulPhase1Out）。
    // -----------------------------------------------------------------------
    if (req.d != phase1_d_) {
        stage_ = Stage::kConsumed;
        Phase2Response bad_d;
        bad_d.session = req.session;
        bad_d.status = static_cast<uint8_t>(SecureMulStatus::kDCheckFailed);
        return bad_d;
    }

    // -----------------------------------------------------------------------
    // 服务器侧的 e 回执检查（**通道篡改卫生设施**，不是安全保证）
    //
    // 判据：`e_check` 必须逐位等于本方第 1 轮报出的 ⟨e⟩_p。
    // 效力边界（对抗性验证 E2 已证实，务必按此理解）：`e_check` 是客户端把
    // **它收到的回执**原样带回的，所以"谎报 ⟨e⟩_p 的那台服务器"自己就是裁判，
    // 它只要继续报 kOk 就能绕过这一层。因此这一层只能检出
    // **回执在链路上被改动、而服务器诚实执行**的情形（属于通道篡改，论文
    // `MPARQ.tex:150` 本就把 MITM 排除在威胁模型外）。
    // 真正能挡住"说谎的服务器"的是 §4.5-A/B 两条**纯客户端**复核，它们在
    // `VerifyAndReconstruct` 里执行，不依赖任何自报值。
    //
    // ⚠️ v3 还删掉了 v2 的 `req.e != req.e_check` 判据：它给单台服务器一个
    //    **零成本否决权**（把自己的 ⟨e⟩_p 报成 0 ⇒ 诚实那台刚好 e == e_check
    //    ⇒ 整条查询 abort，对抗性验证 §5.3 的 DoS），而它想防的"两台被改成
    //    同一个值"已由 §4.5-B 更严格地覆盖。
    if (req.e_check != e_computed_share_.value) {
        stage_ = Stage::kConsumed;  // 一次性语义照旧：这条状态不再可用
        Phase2Response bad;
        bad.session = req.session;
        bad.status = static_cast<uint8_t>(SecureMulStatus::kECheckFailed);
        return bad;
    }
    stage_ = Stage::kConsumed;

    // ⚠️ 这里落地的是 §2 的公式（论文原文 vs 修正式）：
    //   z_p   = ⟨c⟩_p + d·⟨b⟩_p + e·⟨a⟩_p + e·d·2^{-1}      ← 与论文 (P-z) 相同
    //   mac_p = ⟨αc⟩_p + d·⟨αb⟩_p + e·⟨αa⟩_p + ⟨α⟩_p·e·d    ← 论文 (P-mac) 去掉末项 2^{-1}
    // 两个公式都在 `tsb::SecureMulServerPhase2` 里，本模块只做搬运。
    // （z 侧那个 2^{-1} 被"两台服务器各贡献一次"抵消，因此**不能**去掉；
    //   mac 侧的 2^{-1} 若不删则校验恒失败 —— 详见头文件 §2 的推导。）
    const SecureMulServerInput in{attribute_share_, triple_};
    const SecureMulRound2 r2 = SecureMulServerPhase2(in, req.d, req.e, q_);
    Phase2Response out;
    out.session = req.session;
    out.z_share = r2.z.value;
    out.mac_share = r2.mac.value;
    out.status = static_cast<uint8_t>(SecureMulStatus::kOk);
    return out;
}

// ===========================================================================
// SecureMulClientState
// ===========================================================================

SecureMulClientState SecureMulClientState::GenerateMacKey(uint128_t q) {
    RequireSecureMulModulus(q);
    // 全局一份的 α（TASK_PLAN §7.6 Q3(a)）：只在 Init 阶段生成一次。
    return SecureMulClientState(tsb::GenerateMacKey(2, q), q);
}

SecureMulClientState::SecureMulClientState(MacKeyShares keys, uint128_t q)
    : keys_(std::move(keys)), q_(q) {
    RequireSecureMulModulus(q_);
    if (keys_.alpha_shares.size() != 2) {
        throw std::invalid_argument(
            "SecureMulClientState: 需要恰好 2 份 ⟨α⟩ 分享（双服务器）");
    }
    if (reduce(keys_.alpha, q_) == 0) {
        throw std::invalid_argument(
            "SecureMulClientState: MAC 密钥 α 不能为 0（退化参数，校验会恒成立）");
    }
    uint128_t acc = 0;
    for (uint128_t s : keys_.alpha_shares) {
        acc = addMod(acc, s, q_);
    }
    if (acc != reduce(keys_.alpha, q_)) {
        throw std::invalid_argument(
            "SecureMulClientState: ⟨α⟩_0 + ⟨α⟩_1 ≠ α（分享与密钥不一致）");
    }
    keys_.alpha = reduce(keys_.alpha, q_);
}

SecureMulClientState::SecureMulClientState(uint128_t alpha,
                                           std::vector<uint128_t> alpha_shares,
                                           uint128_t q) {
    MacKeyShares keys;
    keys.alpha = alpha;
    keys.alpha_shares = std::move(alpha_shares);
    // 复用上面那个构造函数的全部校验（2 份分享、α≠0、分享之和 == α）
    *this = SecureMulClientState(std::move(keys), q);
}

const ModShare& SecureMulClientState::AlphaShare(int server_id) const {
    RequireServerId(server_id);
    alpha_share_cache_[static_cast<size_t>(server_id)] =
        ModShare{keys_.alpha_shares[static_cast<size_t>(server_id)]};
    return alpha_share_cache_[static_cast<size_t>(server_id)];
}

// ===========================================================================
// triple 生成（Q2(a) 每查询现生成；接口为 Q2(b) 预留）
// ===========================================================================

SecureMulTripleMaterial GenerateBeaverTriple(const MacKeyShares& keys,
                                             uint128_t q) {
    RequireSecureMulModulus(q);
    if (keys.alpha_shares.size() != 2) {
        throw std::invalid_argument(
            "GenerateBeaverTriple: 需要恰好 2 份 ⟨α⟩ 分享（双服务器）");
    }
    // 生产路径的目标就是 `tsb::GenerateTripleShares` 的语义，直接用系统 CSPRNG
    // 的那个实现，避免维护两套逻辑。
    auto [s0, s1] = tsb::GenerateTripleShares(keys, q);
    SecureMulTripleMaterial out;
    out.server0 = s0;
    out.server1 = s1;
    // 客户端本地的 triple 明文：由两份共享重建（客户端是唯一能看到明文的一方）
    out.client_triple.a = addMod(s0.a.value, s1.a.value, q);
    out.client_triple.b = addMod(s0.b.value, s1.b.value, q);
    out.client_triple.c = addMod(s0.c.value, s1.c.value, q);
    return out;
}

SecureMulTripleMaterial GenerateBeaverTriple(const MacKeyShares& keys, uint128_t q,
                                             random::DeterministicPrng& prng) {
    RequireSecureMulModulus(q);
    if (keys.alpha_shares.size() != 2) {
        throw std::invalid_argument(
            "GenerateBeaverTriple: 需要恰好 2 份 ⟨α⟩ 分享（双服务器）");
    }

    const uint128_t alpha = reduce(keys.alpha, q);
    const uint128_t a = prng.Below(q);
    const uint128_t b = prng.Below(q);
    const uint128_t c = mulMod(a, b, q);

    // 与 `tsb::GenerateTripleShares` 完全同构，只是随机源换成确定性 PRNG。
    // ⚠️ 每个共享分量都用**独立的** PRNG 输出做掩码：绝不能复用 ⟨a⟩ 的掩码
    //    去算 ⟨αa⟩，否则 ⟨αa⟩ 与 ⟨a⟩ 相关联会泄露 α。
    const auto share = [&prng, q](uint128_t v) {
        const uint128_t mask = prng.Below(q);
        return std::pair<ModShare, ModShare>{ModShare{mask},
                                             ModShare{subMod(v, mask, q)}};
    };

    SecureMulTripleMaterial out;
    auto [a0, a1] = share(a);
    auto [b0, b1] = share(b);
    auto [c0, c1] = share(c);
    auto [aa0, aa1] = share(mulMod(alpha, a, q));
    auto [ab0, ab1] = share(mulMod(alpha, b, q));
    auto [ac0, ac1] = share(mulMod(alpha, c, q));

    // ⟨α⟩ 的分享由调用方提供（全局 MAC 密钥），这里直接取用，不重新生成
    out.server0 = TripleShare{a0,    b0,    c0,    aa0,    ab0,
                              ac0,   ModShare{keys.alpha_shares[0]}};
    out.server1 = TripleShare{a1,    b1,    c1,    aa1,    ab1,
                              ac1,   ModShare{keys.alpha_shares[1]}};
    out.client_triple = tsb::BeaverTriple{a, b, c};
    return out;
}

std::array<uint8_t, kAesKeyBytes> MakeAesSeed(std::vector<uint8_t> seed_bytes) {
    if (seed_bytes.empty()) {
        throw std::invalid_argument("MakeAesSeed: 种子字节不能为空");
    }
    std::array<uint8_t, kAesKeyBytes> key{};
    // 简单展开：不足 16 字节时循环填补，超过时按位置累加（仅用于测试复现，
    // 不是 KDF；生产路径不经过这里）。
    for (size_t i = 0; i < seed_bytes.size(); ++i) {
        key[i % kAesKeyBytes] ^= seed_bytes[i];
        key[(i * 7 + 3) % kAesKeyBytes] =
            static_cast<uint8_t>(key[(i * 7 + 3) % kAesKeyBytes] + seed_bytes[i]);
    }
    return key;
}

// ===========================================================================
// Init 阶段的安装
// ===========================================================================

std::pair<SecureMulServerSetup, SecureMulServerSetup> MakeServerSetups(
    uint64_t record_index, const SecureMulTripleMaterial& material,
    const std::pair<ModShare, ModShare>& attribute_shares, uint64_t challenge) {
    SecureMulServerSetup s0;
    s0.record_index = record_index;
    s0.triple = material.server0;
    s0.e_share = attribute_shares.first;
    s0.challenge = challenge;

    SecureMulServerSetup s1;
    s1.record_index = record_index;
    s1.triple = material.server1;
    s1.e_share = attribute_shares.second;
    s1.challenge = challenge;
    return {s0, s1};
}

SecureMulSetupBundle MakeSetupsAndContext(
    uint64_t record_index, const SecureMulTripleMaterial& material,
    const std::pair<ModShare, ModShare>& attribute_shares, uint64_t challenge) {
    const auto setups =
        MakeServerSetups(record_index, material, attribute_shares, challenge);
    SecureMulSetupBundle out;
    out.server0 = setups.first;
    out.server1 = setups.second;
    // §4.5-A/B 的复核基准：客户端**自己安装**的那些量
    out.ctx.server0.attribute_share = attribute_shares.first;
    out.ctx.server0.b_share = material.server0.b;
    out.ctx.server1.attribute_share = attribute_shares.second;
    out.ctx.server1.b_share = material.server1.b;
    return out;
}

std::pair<ModShare, ModShare> ShareValueDeterministic(uint128_t value, uint128_t q,
                                                      random::DeterministicPrng& prng) {
    RequireSecureMulModulus(q);
    const uint128_t mask = prng.Below(q);
    return {ModShare{mask}, ModShare{subMod(reduce(value, q), mask, q)}};
}

SecureMulSetupBundle MakeSetupsAndContextFromPrng(
    uint64_t record_index, const SecureMulTripleMaterial& material, uint128_t e_value,
    uint64_t challenge, uint128_t q, random::DeterministicPrng& prng) {
    const auto shares = ShareValueDeterministic(e_value, q, prng);
    return MakeSetupsAndContext(record_index, material, shares, challenge);
}

SecureMulServerState MakeServerState(const SecureMulServerSetup& setup,
                                     uint128_t q) {
    SecureMulServerState st(setup.record_index, setup.triple, q);
    st.InstallAttributeShare(setup.e_share);
    st.InstallChallenge(setup.challenge);
    return st;
}

uint64_t MakeChallenge(uint64_t record_index, const std::vector<uint8_t>& salt) {
    // 只是"一次性/防重放"的锚点，不是密码学承诺。用 FNV-1a 风格的混合，
    // 避免引入额外的哈希依赖；真实部署里 salt 用 CSPRNG 生成即可。
    uint64_t h = 1469598103934665603ULL;  // FNV offset basis
    const auto mix = [&h](uint64_t v) {
        h ^= v;
        h *= 1099511628211ULL;  // FNV prime
    };
    mix(record_index);
    for (uint8_t b : salt) {
        mix(static_cast<uint64_t>(b) + 1);
    }
    return h;
}

// ===========================================================================
// 在线阶段
// ===========================================================================

SecureMulPhase1Out ClientRunPhase1(uint64_t session, uint64_t challenge, uint128_t f,
                                   const tsb::BeaverTriple& triple,
                                   ITransportClient& transport, uint128_t q) {
    RequireSecureMulModulus(q);

    // d = f − a：a 是均匀随机的 triple 分量，因此 d 是一次一密式的掩码值，
    // 服务器从 d 学不到 f 的任何信息（§4 的论证）。
    const uint128_t d = subMod(reduce(f, q), reduce(triple.a, q), q);
    const Phase1Request req{session, challenge, d};

    transport.Submit(kServer0, EncodePhase1Request(req));
    transport.Submit(kServer1, EncodePhase1Request(req));
    auto responses = transport.Collect();
    if (responses.size() != 2) {
        throw std::runtime_error(
            "ClientRunPhase1: 应答数量与请求不一致（期望 2 条，实际 " +
            std::to_string(responses.size()) + " 条）");
    }
    if (!responses[0].ok) {
        throw std::runtime_error("ClientRunPhase1: 服务器 0 报错: " +
                                 responses[0].error);
    }
    if (!responses[1].ok) {
        throw std::runtime_error("ClientRunPhase1: 服务器 1 报错: " +
                                 responses[1].error);
    }

    Phase1Response r0 = DecodePhase1Response(responses[0].payload);
    Phase1Response r1 = DecodePhase1Response(responses[1].payload);
    if (r0.session != session || r1.session != session) {
        throw std::runtime_error(
            "ClientRunPhase1: 应答 session 与请求不一致（跨会话应答/重放）");
    }
    // v3：第 1 轮也可能被服务器拒绝（重复投递/跨会话重放/challenge 不符），
    //     必须显式 abort，而不是把 status 忽略掉继续跑第 2 轮。
    std::string err;
    if (!SecureMulStatusIsOk(r0.status, &err)) {
        throw std::runtime_error("ClientRunPhase1: 服务器 0: " + err);
    }
    if (!SecureMulStatusIsOk(r1.status, &err)) {
        throw std::runtime_error("ClientRunPhase1: 服务器 1: " + err);
    }

    SecureMulPhase1Out out;
    out.server0 = r0;
    out.server1 = r1;
    out.d = d;
    // §4.5-A/B：客户端把"它本轮**实际**下发/中转的值"记下来。
    // ⚠️ 这里就是红队 E2 的关键修正点：v2 把"客户端收到的回执"原样回显，
    //    谎报的服务器因此自己给自己当裁判。现在客户端**同时记住自己收到了什么**
    //    与**自己下发了什么**，两者在收尾时互相印证。
    out.e_check_sent0 = reduce(r0.e_computed, q);
    out.e_check_sent1 = reduce(r1.e_computed, q);
    out.e_sent = addMod(out.e_check_sent0, out.e_check_sent1, q);
    return out;
}

Payload ServerHandlePhase1(SecureMulServerState& state, const Payload& request) {
    const Phase1Request req = DecodePhase1Request(request);
    const Phase1Response resp = state.RunPhase1(req);
    return EncodePhase1Response(resp);
}

std::pair<Phase2Response, Phase2Response> ClientRunPhase2(
    uint64_t session, const SecureMulPhase1Out& phase1, ITransportClient& transport,
    uint128_t q) {
    RequireSecureMulModulus(q);
    if (phase1.server0.session != session || phase1.server1.session != session) {
        throw std::invalid_argument(
            "ClientRunPhase2: 第 1 轮应答的 session 与本轮不一致");
    }

    // 客户端中转：e = ⟨e⟩_0 + ⟨e⟩_1。
    // 这是协议规定的唯一"服务器 → 客户端 → 另一台服务器"的中转动作；
    // 转发的只是这个标量，**不是**任何服务器的整条消息。
    const uint128_t e0 = reduce(phase1.e_check_sent0, q);
    const uint128_t e1 = reduce(phase1.e_check_sent1, q);
    const uint128_t e = addMod(e0, e1, q);
    // ⚠️ 用第 1 轮**实际下发**的 d（由 SecureMulPhase1Out 带出），不重算 f − a
    const uint128_t d = reduce(phase1.d, q);

    // §4.5：把**各自**第 1 轮报出的 ⟨e⟩_p 作为 e_check 带回给对应的服务器。
    // 每台收到的 e_check 都是它自己那一份，因此任何被改动的回执都会在
    // 服务器侧被立刻发现。
    const Phase2Request req0{session, d, e, e0};
    const Phase2Request req1{session, d, e, e1};

    transport.Submit(kServer0, EncodePhase2Request(req0));
    transport.Submit(kServer1, EncodePhase2Request(req1));
    auto responses = transport.Collect();
    if (responses.size() != 2) {
        throw std::runtime_error(
            "ClientRunPhase2: 应答数量与请求不一致（期望 2 条，实际 " +
            std::to_string(responses.size()) + " 条）");
    }
    if (!responses[0].ok) {
        throw std::runtime_error("ClientRunPhase2: 服务器 0 报错: " +
                                 responses[0].error);
    }
    if (!responses[1].ok) {
        throw std::runtime_error("ClientRunPhase2: 服务器 1 报错: " +
                                 responses[1].error);
    }
    Phase2Response r0 = DecodePhase2Response(responses[0].payload);
    Phase2Response r1 = DecodePhase2Response(responses[1].payload);
    if (r0.session != session || r1.session != session) {
        throw std::runtime_error(
            "ClientRunPhase2: 应答 session 与请求不一致（跨会话应答/重放）");
    }
    return {r0, r1};
}

Payload ServerHandlePhase2(SecureMulServerState& state, const Payload& request) {
    const Phase2Request req = DecodePhase2Request(request);
    const Phase2Response resp = state.RunPhase2(req);
    return EncodePhase2Response(resp);
}

bool SecureMulStatusIsOk(uint8_t status, std::string* error) {
    switch (static_cast<SecureMulStatus>(status)) {
        case SecureMulStatus::kOk:
            return true;
        case SecureMulStatus::kDCheckFailed:
            if (error != nullptr) {
                *error =
                    "SecureMulFlow: 服务器拒绝——d 跨轮一致性检查失败"
                    "（第 2 轮的 d 与第 1 轮收到的不同，说明 d 在链路上被篡改），"
                    "abort 当前查询";
            }
            return false;
        case SecureMulStatus::kPhaseError:
            if (error != nullptr) {
                *error =
                    "SecureMulFlow: 服务器拒绝——阶段错误"
                    "（状态已被消费、第 2 轮先到或 challenge 不符；"
                    "消息被重复投递/乱序/跨会话重放），abort 当前查询";
            }
            return false;
        case SecureMulStatus::kECheckFailed:
            if (error != nullptr) {
                // ⚠️ 这正是论文只靠 `mac == α·z` 抓不住的那一类篡改（§4.5）：
                //    恶意服务器改掉中转的 e 会让 z 与 mac 一起变，MAC 依然自洽。
                *error =
                    "SecureMulFlow: 服务器拒绝——e 一致性检查失败"
                    "（中转的 e 与某台第 1 轮报出的 ⟨e⟩_p 不自洽，"
                    "说明 e 在链路上被篡改；MAC 校验抓不住这一类篡改），abort 当前查询";
            }
            return false;
        default:
            if (error != nullptr) {
                *error = "SecureMulFlow: 服务器返回未知状态码 " +
                         std::to_string(static_cast<int>(status));
            }
            return false;
    }
}

SecureMulFlowResult VerifyAndReconstruct(
    uint64_t session, const std::pair<Phase2Response, Phase2Response>& phase2,
    const SecureMulClientState& client, const SecureMulRecordContext* ctx,
    uint128_t f, uint128_t e_sent, const tsb::BeaverTriple* triple,
    uint128_t phase1_e_check0, uint128_t phase1_e_check1) {
    const uint128_t q = client.modulus();

    SecureMulFlowResult out;
    if (phase2.first.session != session || phase2.second.session != session) {
        out.error = "SecureMulFlow: 第 2 轮应答的 session 与请求不一致";
        out.failure = SecureMulFailure::kSessionMismatch;
        return out;
    }

    // =======================================================================
    // 第 1 层：服务器自报状态（**结构化**判定，不靠错误字符串）
    // =======================================================================
    // status 不为 kOk 时 z/mac 无意义，直接 abort。
    // ⚠️ 这一层是**卫生设施**：status 由被检查方自己给出，因此它只对
    //    "通道篡改 + 服务器诚实执行"有保证（对抗性验证 E2）。真正的保证来自
    //    下面的第 2、3 层（纯客户端复核）与第 4 层（SPDZ MAC）。
    if (!SecureMulStatusIsOk(phase2.first.status, &out.error)) {
        out.error = "服务器 0: " + out.error;
        out.failure = SecureMulFailure::kServerReported;
        return out;
    }
    if (!SecureMulStatusIsOk(phase2.second.status, &out.error)) {
        out.error = "服务器 1: " + out.error;
        out.failure = SecureMulFailure::kServerReported;
        return out;
    }

    // =======================================================================
    // 第 2 层（v3 新增）：§4.5-B 复核"每台自报的 ⟨e⟩_p" —— **纯客户端**
    // =======================================================================
    // 客户端在 Init 阶段**自己安装**了两台的 ⟨E⟩_p 与 ⟨b⟩_p，因此可以独立复核
    //      某台自报的 ⟨e⟩_p  ?=  ⟨E⟩_p − ⟨b⟩_p
    // 判据完全不依赖被检查方的任何自报值（被复核的那个值本身就是待检对象），
    // 所以它能挡住"**说谎的服务器**"—— 而服务器侧的 e_check 回执检查挡不住
    // （那一条是自证的：谎报的那台自己就是裁判，对抗性验证 E2）。
    // ⚠️ 这一层必须排在 §4.5-A 之前：它能把"哪一台在说谎"指出来，而 A 只能说
    //    "整体不一致"。
    if (ctx != nullptr) {
        const uint128_t expected0 =
            subMod(reduce(ctx->server0.attribute_share.value, q),
                   reduce(ctx->server0.b_share.value, q), q);
        const uint128_t expected1 =
            subMod(reduce(ctx->server1.attribute_share.value, q),
                   reduce(ctx->server1.b_share.value, q), q);
        if (reduce(phase1_e_check0, q) != expected0) {
            out.error =
                "SecureMulFlow: 服务器 0 谎报 ⟨e⟩_p"
                "（自报值 ≠ 客户端安装的 ⟨E⟩_0 − ⟨b⟩_0），abort 当前查询";
            out.failure = SecureMulFailure::kEShareMismatch;
            return out;
        }
        if (reduce(phase1_e_check1, q) != expected1) {
            out.error =
                "SecureMulFlow: 服务器 1 谎报 ⟨e⟩_p"
                "（自报值 ≠ 客户端安装的 ⟨E⟩_1 − ⟨b⟩_1），abort 当前查询";
            out.failure = SecureMulFailure::kEShareMismatch;
            return out;
        }
    }

    // z = z_0 + z_1、mac = mac_0 + mac_1
    //
    // ⚠️ 公式检查点（§2）：`shared/mpc` 的 z_p 末项含 2^{-1} 且**两台各算一次**，
    //    因此 z = c + d·b + e·a + 2·(e·d·2^{-1}) = f·E；
    //    而 mac_p 末项是 ⟨α⟩_p·e·d（**没有** 2^{-1}），两台相加得 α·e·d，
    //    与 α·z 的末项 α·e·d 对齐 ⇒ mac == α·z。
    //    若有人"顺手"把 z 末项的 2^{-1} 也去掉，z 会变成 f·E + d·e，恒错。
    const AuthenticatedShare a0{phase2.first.z_share, phase2.first.mac_share};
    const AuthenticatedShare a1{phase2.second.z_share, phase2.second.mac_share};
    const MacVerificationResult v =
        VerifyAuthenticatedDetailed(a0, a1, client.alpha(), q);
    out.z = v.z;
    out.mac = v.mac;
    out.expected_mac = v.expected_mac;

    // =======================================================================
    // 第 3 层（v3 新增）：§4.5-A 复核"z 与客户端本地视角的属性值一致"
    // =======================================================================
    // 前提：triple 由客户端自己生成 ⇒ 客户端知道 b，且它知道自己中转出去的 e，
    // 于是**能**算出一个本地属性值候选
    //      E_local = e_sent + b
    // 并要求 `z == f · E_local`。
    //
    // 这条复核把"两台服务器一致使用被偏移过的 d/e（z 与 mac 一起偏移，MAC 通过）"
    // 这一类攻击彻底封死：无论 Δ 怎么取，`z' = z + Δ·f`（或 `z + δ·f`）都不再等于
    // `f · (e_sent + b)`。代价：**零条新消息**。
    //
    // ⚠️ 若将来 triple 生成被移出客户端（第三方 dealer / 离线服务器），客户端
    //    不再知道 b，本条复核**失效** ⇒ 那时 `d` 偏移重新不可检出，需要承诺机制
    //    （见 §4.6 与头文件"边界"一节）。§4.5-B 不受此影响。
    if (ctx != nullptr && triple != nullptr) {
        const uint128_t e_local = addMod(reduce(e_sent, q), reduce(triple->b, q), q);
        const uint128_t expected_z = mulMod(reduce(f, q), e_local, q);
        if (out.z != expected_z) {
            out.error =
                "SecureMulFlow: z 与客户端本地重建的属性值不一致"
                "（z ≠ f·(e_sent + b)），abort 当前查询"
                "（d/e 被一致偏移；这一类攻击 mac == α·z 恒成立，MAC 抓不住）";
            out.failure = SecureMulFailure::kClientLocalCheckFailed;
            return out;
        }
    }

    // =======================================================================
    // 第 4 层：SPDZ MAC
    // =======================================================================
    out.ok = v.ok;
    if (!v.ok) {
        // 论文 AggQuery：`If Verify = reject → abort`。
        // 值可能已被污染，**绝不允许**带着错误的 z 继续聚合。
        out.error =
            "SecureMulFlow: SPDZ MAC 校验失败（mac ≠ α·z），abort 当前查询"
            "（服务器篡改或共享不一致）";
        out.failure = SecureMulFailure::kMacMismatch;
    }
    return out;
}

SecureMulFlowResult SecureMulFlowRunRecord(
    uint64_t session, uint64_t challenge, uint128_t f,
    const tsb::BeaverTriple& triple, ITransportClient& transport,
    const SecureMulClientState& client, const SecureMulRecordContext* ctx) {
    const uint128_t q = client.modulus();

    const auto phase1 = ClientRunPhase1(session, challenge, f, triple, transport, q);
    // 第 2 轮沿用第 1 轮实际下发的 d（见 SecureMulPhase1Out 的注释）
    const auto phase2 = ClientRunPhase2(session, phase1, transport, q);
    // v3：把 context 与"客户端本地视角"（b、e_sent、下发的 e_check）一起交给收尾层，
    //     由它执行两条**纯客户端**复核（§4.5-A/B）。
    return VerifyAndReconstruct(session, phase2, client, ctx, f, phase1.e_sent, &triple,
                               phase1.e_check_sent0, phase1.e_check_sent1);
}

void RegisterSecureMulServers(ITransportServer& server, SecureMulServerState& s0,
                              SecureMulServerState& s1) {
    if (server.NumServers() < 2) {
        throw std::invalid_argument(
            "RegisterSecureMulServers: 服务器数 < 2（SecureMul 需要两台服务器）");
    }
    // 两个 handler 只捕获各自的 state 引用；它们之间**没有共享的可变状态**，
    // 因此不存在"服务器间信道"的实现空间（§5）。
    //
    // 第 1 轮与第 2 轮共用同一个 state（state 内部有阶段机与一次性语义），
    // 因此按消息类型分发到对应阶段的处理函数。
    const auto make_handler = [](SecureMulServerState& st) {
        return [&st](const Payload& req) -> Payload {
            if (req.size() >= 2 &&
                req[1] == static_cast<uint8_t>(SecureMulMsgType::kPhase2Request)) {
                return ServerHandlePhase2(st, req);
            }
            return ServerHandlePhase1(st, req);
        };
    };
    server.SetHandler(kServer0, make_handler(s0));
    server.SetHandler(kServer1, make_handler(s1));
}

}  // namespace mpraq
}  // namespace tsb
