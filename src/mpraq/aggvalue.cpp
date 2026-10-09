#include "mpraq/aggvalue.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace tsb {
namespace mpraq {

// ===========================================================================
// 内部工具
// ===========================================================================
namespace {

using Clock = std::chrono::steady_clock;

double MsSince(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

std::string Num(uint64_t v) { return std::to_string(v); }

// MPA-05 的单记录定长消息长度（**只读**照抄它的布局；见 `EnsureLayoutMatchesMpa05`）。
size_t ExpectedMessageBytes(SecureMulBatchMsgType type) {
    switch (type) {
        case SecureMulBatchMsgType::kPhase1Request: return 34;
        case SecureMulBatchMsgType::kPhase1Response: return 27;
        case SecureMulBatchMsgType::kPhase2Request: return 58;
        case SecureMulBatchMsgType::kPhase2Response: return 43;
    }
    throw std::invalid_argument("SecureMulBatch: 未知的批量帧消息类型");
}

bool IsPhase2(SecureMulBatchMsgType type) {
    return type == SecureMulBatchMsgType::kPhase2Request ||
           type == SecureMulBatchMsgType::kPhase2Response;
}

// 用 MPA-05 的**编码器**实测复核"本层假定的定长消息长度"与它一致。
// 目的：若将来有人改了 `secure_mul_flow` 的线格式，本层会立刻报错，
// 而不是静默按旧长度切片（那会变成"批量帧解析出垃圾"）。
void EnsureLayoutMatchesMpa05() {
    static const bool kChecked = [] {
        const auto check = [](size_t got, size_t want, const char* what) {
            if (got != want) {
                throw std::logic_error(
                    std::string("SecureMulBatch: 与 MPA-05 的线格式不一致（") + what +
                    " 实测 " + std::to_string(got) + " B，本层假定 " +
                    std::to_string(want) +
                    " B）—— 批量帧的切片会错位，必须同步修改本层常量。");
            }
        };
        check(EncodePhase1Request(Phase1Request{}).size(), 34, "Phase1Request");
        check(EncodePhase1Response(Phase1Response{}).size(), 27, "Phase1Response");
        check(EncodePhase2Request(Phase2Request{}).size(), 58, "Phase2Request");
        check(EncodePhase2Response(Phase2Response{}).size(), 43, "Phase2Response");
        return true;
    }();
    (void)kChecked;
}

// 把调用方给的 64 位盐展开成 8 字节小端（`MakeChallenge` 的 salt 参数）。
std::vector<uint8_t> SaltBytes(uint64_t salt) {
    std::vector<uint8_t> out(8, 0);
    for (size_t i = 0; i < 8; ++i) {
        out[i] = static_cast<uint8_t>((salt >> (8 * i)) & 0xffu);
    }
    return out;
}

uint32_t ReadU32LE(const Payload& p, size_t off) {
    return static_cast<uint32_t>(p[off]) | (static_cast<uint32_t>(p[off + 1]) << 8) |
           (static_cast<uint32_t>(p[off + 2]) << 16) |
           (static_cast<uint32_t>(p[off + 3]) << 24);
}

// 取 MPA-05 子消息里的 session（两种请求/应答的 session 都在偏移 2..10）。
uint64_t PeekSession(const Payload& msg) {
    if (msg.size() < 10) {
        throw std::invalid_argument("SecureMulBatch: 子消息太短，读不出 session");
    }
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(msg[2 + i]) << (8 * i);
    }
    return v;
}

// ---------------------------------------------------------------------------
// 一台服务器的批量会话状态表（`(session → state)` 分派表，见文件头 §1）
// ---------------------------------------------------------------------------
// ⚠️ 这是 `MPA-05` §6.1 要求的"自建一层"的核心：`MPA-05` 的
// `RegisterSecureMulServers` 每台只挂**一个** state，而批量要在两轮之间
// 同时保活 `N` 个 state ⇒ 必须自己建表 + 自己分派。
//
// ⚠️ `MPA-08` 的授权改动把本类**公开化**（`SecureMulBatchServerTable`，
//    aggvalue.hpp）：两进程模式的**服务器进程**要用**同一份**服务端逻辑，
//    绝不允许复刻第二份（复刻必然漂移）。本文件内部不再保留别名。

// 结构化拒绝：与 `MPA-05` 的"状态机拒绝"同语义（`status = kPhaseError`，
// 而不是抛异常 —— 抛异常是"调用方用错 API"才该有的行为）。
Payload EncodeReject(SecureMulBatchMsgType request_type, uint64_t session) {
    if (IsPhase2(request_type)) {
        Phase2Response bad;
        bad.session = session;
        bad.status = static_cast<uint8_t>(SecureMulStatus::kPhaseError);
        return EncodePhase2Response(bad);
    }
    Phase1Response bad;
    bad.session = session;
    bad.status = static_cast<uint8_t>(SecureMulStatus::kPhaseError);
    return EncodePhase1Response(bad);
}

}  // namespace

// ---------------------------------------------------------------------------
// `SecureMulBatchServerTable`（公开类的实现；逻辑 = 改动前的 `ServerTable` +
// `HandleBatchFrame`，**一个字节都没改**）
// ---------------------------------------------------------------------------

void SecureMulBatchServerTable::Install(uint64_t session,
                                        const SecureMulServerSetup& setup) {
    const size_t idx = states_.size();
    states_.push_back(MakeServerState(setup, q_));
    const auto [it, inserted] = by_session_.emplace(session, idx);
    if (!inserted) {
        // 回滚刚压入的 state（否则表与下标表会不一致）
        states_.pop_back();
        throw std::logic_error(
            "SecureMulBatch: session 重复（同一 session 不能挂两个 state）");
    }
    (void)it;
}

void SecureMulBatchServerTable::Clear() {
    states_.clear();
    by_session_.clear();
    processed_phase1_ = 0;
    processed_phase2_ = 0;
    frames_ = 0;
}

// 服务器 handler：
//   ① 解批量帧（版本/类型/长度严格校验 —— 失败就抛，`LocalTransport`/Relay 会把它
//      变成 `Response::Err`/`RelayResponse.ok=false`，客户端侧归类为 `kTransportError`）；
//   ② 逐条子消息按 session 查表分派；
//   ③ 逐条调用 `MPA-05` 的 `ServerHandlePhase1/2`（**复用它的语义**）；
//   ④ 把 N 条应答打成**一个**应答帧。
//
// ⚠️ 逐条异常（查不到 session / 单条解码失败 / 状态机抛错）都转成**结构化拒绝**的
//    应答，而不是让异常冒出去吃掉整帧 —— 这样"哪一条坏了"能精确定位到记录序号。
Payload SecureMulBatchServerTable::HandleFrame(const Payload& frame) {
    if (frame.size() < kBatchFrameHeaderBytes) {
        throw std::invalid_argument(
            "SecureMulBatch(server): 批量帧太短（至少需要 6 字节头）");
    }
    if (frame[0] != kBatchWireVersion) {
        throw std::invalid_argument(
            "SecureMulBatch(server): 批量帧版本不符（期望 " +
            Num(kBatchWireVersion) + "，实际 " + Num(frame[0]) + "）");
    }
    const auto type = static_cast<SecureMulBatchMsgType>(frame[1]);
    const bool phase2 = IsPhase2(type);
    // `DecodeBatchFrame` 会再做一次版本/类型/长度校验（这里传入 expected=type）
    const std::vector<Payload> msgs = DecodeBatchFrame(frame, type);

    ++frames_;
    std::vector<Payload> answers;
    answers.reserve(msgs.size());
    for (const Payload& msg : msgs) {
        if (phase2) {
            ++processed_phase2_;
        } else {
            ++processed_phase1_;
        }
        uint64_t session = 0;
        bool session_known = false;
        try {
            session = PeekSession(msg);
            session_known = true;
        } catch (const std::exception&) {
            session_known = false;
        }
        if (!session_known) {
            answers.push_back(EncodeReject(type, 0));
            continue;
        }
        const auto it = by_session_.find(session);
        if (it == by_session_.end()) {
            // 跨记录串味 / 未知 session：结构化拒绝（不猜、不落到别的记录上）
            answers.push_back(EncodeReject(type, session));
            continue;
        }
        try {
            answers.push_back(phase2 ? ServerHandlePhase2(states_[it->second], msg)
                                     : ServerHandlePhase1(states_[it->second], msg));
        } catch (const std::exception&) {
            answers.push_back(EncodeReject(type, session));
        }
    }
    return EncodeBatchFrame(phase2 ? SecureMulBatchMsgType::kPhase2Response
                                   : SecureMulBatchMsgType::kPhase1Response,
                            answers);
}

namespace {

// ---------------------------------------------------------------------------
// 本地端点：服务端一侧在**本进程**（改动前的行为，逐位保留）
// ---------------------------------------------------------------------------
//   * `Install` 直接进本进程的表；
//   * handler 通过 `ITransportServer::SetHandler` 注册（指向本对象的表）；
//   * `SubmitFrame` 把**原样的批量帧**交给 `ITransportClient::Submit`；
//   * `UnwrapResponse` 是恒等（应答里本来就是批量帧）。
// ⇒ 与改动前的 `LocalTransport` 路径**字节级等价**。
class LocalSecureMulBatchEndpoint final : public ISecureMulBatchEndpoint {
public:
    LocalSecureMulBatchEndpoint(ITransportClient& client, ITransportServer& server,
                               int server_id, uint128_t q)
        : client_(&client), server_(&server), server_id_(server_id), table_(q) {
        server_->SetHandler(server_id_, [this](const Payload& frame) -> Payload {
            return table_.HandleFrame(frame);
        });
    }

    LocalSecureMulBatchEndpoint(const LocalSecureMulBatchEndpoint&) = delete;
    LocalSecureMulBatchEndpoint& operator=(const LocalSecureMulBatchEndpoint&) = delete;

    void BeginSession() override {}  // 本对象 = 一次会话（表与计数天然是新的）
    void Install(uint64_t session, const SecureMulServerSetup& setup) override {
        table_.Install(session, setup);
    }
    void FlushInstalls() override {}  // 本地安装不产生任何消息
    void SubmitFrame(const Payload& frame) override {
        client_->Submit(server_id_, frame);
    }
    Response UnwrapResponse(const Response& raw) override { return raw; }

    uint64_t frames() const override { return table_.frames(); }
    uint64_t processed_phase1() const override { return table_.processed_phase1(); }
    uint64_t processed_phase2() const override { return table_.processed_phase2(); }
    uint64_t install_frames() const override { return 0; }
    uint64_t install_bytes() const override { return 0; }
    uint64_t recv_bytes() const override { return 0; }   // 进程内：无线上字节

    // 会话结束后把 handler 换成"拒绝一切"的桩：
    // handler 捕获的是 `this`（端点在调用方栈上）⇒ 不换掉就会留下**悬垂捕获**
    // （返回后再 Collect 就是 UB）。换桩之后误用会得到一条清晰的异常，
    // 而不是静默读到别的内存。
    void Close() override {
        server_->SetHandler(server_id_, [](const Payload&) -> Payload {
            throw std::logic_error(
                "MPRAQ 批量 SecureMul 会话已结束：服务器 handler 是失效桩。"
                "请重新调用 RunSecureMulBatch（本层不做跨调用的状态复用）。");
        });
    }

private:
    ITransportClient* client_;
    ITransportServer* server_;
    int server_id_;
    SecureMulBatchServerTable table_;
};

// RAII：无论正常返回还是异常退出，都把两端点换成失效桩。
struct ClosedHandlerGuard {
    ISecureMulBatchEndpoint* e0 = nullptr;
    ISecureMulBatchEndpoint* e1 = nullptr;
    ~ClosedHandlerGuard() {
        if (e0 != nullptr) {
            e0->Close();
        }
        if (e1 != nullptr) {
            e1->Close();
        }
    }
};


// 逐记录驱动用的**计数包装**：把 `ITransportClient` 包一层，统计真实的
// Submit / Collect 次数，并按 MPA-05 的消息类型（wire 第 2 字节）分类 ——
// "用计数器验证，不是靠注释"。
class CountingClient : public ITransportClient {
public:
    explicit CountingClient(ITransportClient& inner) : inner_(inner) {}

    void Submit(int server_id, Payload request) override {
        ++submits_;
        submits_per_server_[static_cast<size_t>(server_id)]++;
        // 只看类型字节：这段字节由 `MPA-05` 的编码器产出，本层不解释其余内容
        if (request.size() >= 2) {
            if (request[1] == static_cast<uint8_t>(SecureMulMsgType::kPhase1Request)) {
                phase1_by_server_[static_cast<size_t>(server_id)]++;
            } else if (request[1] ==
                       static_cast<uint8_t>(SecureMulMsgType::kPhase2Request)) {
                phase2_by_server_[static_cast<size_t>(server_id)]++;
            }
        }
        inner_.Submit(server_id, std::move(request));
    }
    std::vector<Response> Collect() override {
        ++collects_;
        return inner_.Collect();
    }
    size_t PendingCount() const override { return inner_.PendingCount(); }
    void Abort() override { inner_.Abort(); }

    uint64_t submits() const { return submits_; }
    uint64_t collects() const { return collects_; }
    uint64_t submits_of(int server_id) const {
        return submits_per_server_[static_cast<size_t>(server_id)];
    }
    // 单台服务器视角的每轮消息条数（本次会话累计）
    uint64_t phase1_of(int server_id) const {
        return phase1_by_server_[static_cast<size_t>(server_id)];
    }
    uint64_t phase2_of(int server_id) const {
        return phase2_by_server_[static_cast<size_t>(server_id)];
    }

private:
    ITransportClient& inner_;
    uint64_t submits_ = 0;
    uint64_t collects_ = 0;
    std::array<uint64_t, 2> submits_per_server_{{0, 0}};
    std::array<uint64_t, 2> phase1_by_server_{{0, 0}};
    std::array<uint64_t, 2> phase2_by_server_{{0, 0}};
};

// 一次批量/逐记录会话的公共输入校验（边界见文件头 §7）。
// ⚠️ `MPA-08` 起改为接受"服务器台数"（原来是 `const LocalTransport&`，只为读
//    `NumServers()`）：接口版与两进程版都能用它，且行为零变化。
void ValidateInputs(const std::vector<uint8_t>& f_bits,
                    const std::vector<ModShare>& e_server0,
                    const std::vector<ModShare>& e_server1, int num_servers) {
    if (f_bits.empty()) {
        throw std::invalid_argument(
            "SecureMulBatch: f_bits 为空 —— 没有记录可算（空 filter 是调用方错误，"
            "不是「零命中」；零命中应当传入长度 N、内容全 0 的 filter）");
    }
    if (e_server0.size() != f_bits.size() || e_server1.size() != f_bits.size()) {
        std::ostringstream oss;
        oss << "SecureMulBatch: 长度不匹配（f_bits=" << f_bits.size()
            << "，⟨E⟩_0=" << e_server0.size() << "，⟨E⟩_1=" << e_server1.size()
            << "）—— 三者必须都等于 N";
        throw std::invalid_argument(oss.str());
    }
    for (size_t i = 0; i < f_bits.size(); ++i) {
        if (f_bits[i] > 1) {
            throw std::invalid_argument(
                "SecureMulBatch: f_bits[" + Num(i) + "] = " + Num(f_bits[i]) +
                " 不是 0/1 —— filter 必须是比特向量（本层按 Z_q 元素接受，但拒绝非比特值）");
        }
    }
    if (num_servers < 2) {
        throw std::invalid_argument(
            "SecureMulBatch: 需要两台服务器的传输（LocalTransport(2) / 两条端点）");
    }
}

}  // namespace

// ===========================================================================
// 批量帧编解码（格式见头文件 §1）
// ===========================================================================

size_t SecureMulBatchMessageBytes(SecureMulBatchMsgType type) {
    return ExpectedMessageBytes(type);
}

Payload EncodeBatchFrame(SecureMulBatchMsgType type,
                         const std::vector<Payload>& messages) {
    EnsureLayoutMatchesMpa05();
    const size_t per = ExpectedMessageBytes(type);
    if (messages.size() > 0xFFFFFFFFull) {
        throw std::invalid_argument("SecureMulBatch: 帧内消息数超过 uint32 上限");
    }
    Payload out;
    out.reserve(kBatchFrameHeaderBytes + per * messages.size());
    out.push_back(kBatchWireVersion);
    out.push_back(static_cast<uint8_t>(type));
    const uint32_t count = static_cast<uint32_t>(messages.size());
    for (size_t i = 0; i < 4; ++i) {
        out.push_back(static_cast<uint8_t>((count >> (8 * i)) & 0xffu));
    }
    for (size_t i = 0; i < messages.size(); ++i) {
        if (messages[i].size() != per) {
            std::ostringstream oss;
            oss << "SecureMulBatch: 第 " << i << " 条子消息长度不符（期望 " << per
                << " B，实际 " << messages[i].size() << " B）";
            throw std::invalid_argument(oss.str());
        }
        // ⚠️ 子消息**原样**拷贝：它的版本/类型/字段布局由 MPA-05 的编码器负责，
        //    本层不改一个字节（只调 `MPA-05` 的编解码）。
        out.insert(out.end(), messages[i].begin(), messages[i].end());
    }
    return out;
}

std::vector<Payload> DecodeBatchFrame(const Payload& frame,
                                      SecureMulBatchMsgType expected) {
    EnsureLayoutMatchesMpa05();
    const size_t per = ExpectedMessageBytes(expected);
    if (frame.size() < kBatchFrameHeaderBytes) {
        throw std::invalid_argument("DecodeBatchFrame: 批量帧太短（至少 6 字节头）");
    }
    if (frame[0] != kBatchWireVersion) {
        throw std::invalid_argument("DecodeBatchFrame: 批量帧版本不符（期望 " +
                                    Num(kBatchWireVersion) + "，实际 " +
                                    Num(frame[0]) + "）");
    }
    if (frame[1] != static_cast<uint8_t>(expected)) {
        throw std::invalid_argument("DecodeBatchFrame: 批量帧类型不符（期望 " +
                                    Num(static_cast<int>(expected)) + "，实际 " +
                                    Num(frame[1]) + "）");
    }
    const uint32_t count = ReadU32LE(frame, 2);
    const size_t want = kBatchFrameHeaderBytes + per * static_cast<size_t>(count);
    if (frame.size() != want) {
        std::ostringstream oss;
        oss << "DecodeBatchFrame: 批量帧长度不符（count=" << count << " ⇒ 期望 "
            << want << " B，实际 " << frame.size() << " B）";
        throw std::invalid_argument(oss.str());
    }
    std::vector<Payload> out;
    out.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t* p = frame.data() + kBatchFrameHeaderBytes + per * i;
        out.emplace_back(p, p + per);
    }
    return out;
}

// ===========================================================================
// 分类名（**仅供人读的诊断/报告**；判定一律走枚举值，禁止字符串匹配）
// ===========================================================================

const char* SecureMulBatchFailureName(SecureMulFailure f) {
    switch (f) {
        case SecureMulFailure::kNone: return "kNone";
        case SecureMulFailure::kSessionMismatch: return "kSessionMismatch";
        case SecureMulFailure::kServerReported: return "kServerReported";
        case SecureMulFailure::kEShareMismatch: return "kEShareMismatch";
        case SecureMulFailure::kClientLocalCheckFailed: return "kClientLocalCheckFailed";
        case SecureMulFailure::kMacMismatch: return "kMacMismatch";
    }
    return "?";
}

const char* SecureMulBatchErrorName(SecureMulBatchError e) {
    switch (e) {
        case SecureMulBatchError::kNone: return "kNone";
        case SecureMulBatchError::kTransportError: return "kTransportError";
        case SecureMulBatchError::kFrameDecodeError: return "kFrameDecodeError";
        case SecureMulBatchError::kRecordCountMismatch: return "kRecordCountMismatch";
        case SecureMulBatchError::kSessionNotFound: return "kSessionNotFound";
    }
    return "?";
}

// ===========================================================================
// SecureMulBatchOutcome / SecureMulBatchAbort
// ===========================================================================

uint128_t SecureMulBatchOutcome::SumOrThrow(uint128_t q) const {
    if (!all_ok()) {
        std::ostringstream oss;
        oss << "SecureMulBatchOutcome::SumOrThrow: 存在校验失败的记录"
            << "（first_failure=" << first_failure
            << "，分类=" << SecureMulBatchFailureName(failure[first_failure])
            << "）—— 绝不允许把部分和当成聚合结果（论文 AggQuery: abort）";
        throw std::logic_error(oss.str());
    }
    uint128_t sum = 0;
    for (size_t i = 0; i < z.size(); ++i) {
        sum = addMod(sum, reduce(z[i], q), q);
    }
    return sum;
}

SecureMulBatchAbort::SecureMulBatchAbort(const std::string& what,
                                        SecureMulFailure failure,
                                        size_t record_index,
                                        SecureMulBatchError error_kind)
    : std::runtime_error(what),
      failure_(failure),
      record_index_(record_index),
      error_kind_(error_kind) {}

// ===========================================================================
// 批量驱动（2 个往返处理整列）
// ===========================================================================
// ⚠️ `MPA-08` 起，本函数是**唯一的**批量驱动实现，三个公开入口都转调它：
//     * `LocalTransport&`  —— 两个本地端点（行为与改动前逐位相同）；
//     * `SecureMulTransport` —— 两个本地端点，但传输是任意 `ITransportClient/Server`；
//     * `ITransportClient& + 两个 ISecureMulBatchEndpoint&` —— 服务端在**另一个进程**。
namespace {

// 入口前置校验：与 `ValidateInputs` 里那条"需要两台服务器"**同一句消息**，但必须在
// **构造端点之前**执行 —— 端点的构造函数会 `SetHandler`，而 `LocalTransport(1)` 上的
// `SetHandler(1, ...)` 会先抛 `std::out_of_range`，把"输入校验失败"这个更准确的原因
// 掩盖成越界（`test_mpraq_sum.cpp` 的 `RejectsBadInputs` 正是钉住这一点的用例）。
void RequireTwoServers(int num_servers) {
    if (num_servers < 2) {
        throw std::invalid_argument(
            "SecureMulBatch: 需要两台服务器的传输（LocalTransport(2) / 两条端点）");
    }
}

SecureMulBatchOutcome RunSecureMulBatchImpl(const std::vector<uint8_t>& f_bits,
                                            const std::vector<ModShare>& e_server0,
                                            const std::vector<ModShare>& e_server1,
                                            ITransportClient& client,
                                            ISecureMulBatchEndpoint& ep0,
                                            ISecureMulBatchEndpoint& ep1,
                                            int num_servers,
                                            SecureMulClientState& mac,
                                            random::DeterministicPrng& prng,
                                            uint64_t challenge_salt) {
    ValidateInputs(f_bits, e_server0, e_server1, num_servers);
    const uint128_t q = mac.modulus();
    const size_t n = f_bits.size();

    // ⚠️ 失效桩 guard 必须**第一件事**就构造：端点对象的 handler 在它们的构造函数里
    //    就注册好了，因此**任何**一条退出路径（含下面的入参校验抛异常）都必须把
    //    handler 换掉，否则会留下指向已销毁端点的悬垂捕获。
    ClosedHandlerGuard guard{&ep0, &ep1};

    SecureMulBatchOutcome out;
    out.z.assign(n, 0);
    out.ok.assign(n, 0);
    out.failure.assign(n, SecureMulFailure::kNone);
    out.error_kind.assign(n, SecureMulBatchError::kNone);
    out.detail.assign(n, std::string());
    out.first_failure = SIZE_MAX;
    out.stats.records = n;

    // 会话内的"每条记录的计划"：客户端侧的全部材料（triple 明文、d、ctx）。
    struct RecordPlan {
        uint64_t session = 0;
        uint64_t challenge = 0;
        uint128_t f = 0;
        uint128_t d = 0;
        SecureMulTripleMaterial material{};
        SecureMulRecordContext ctx{};
    };
    std::vector<RecordPlan> plans(n);

    const std::vector<uint8_t> salt = SaltBytes(challenge_salt);

    // ---- ① 离线：N 组 Beaver triple（确定性源）----
    {
        const auto t0 = Clock::now();
        for (size_t i = 0; i < n; ++i) {
            plans[i].material = GenerateBeaverTriple(mac.keys(), q, prng);
        }
        out.stats.offline_triple_ms = MsSince(t0);
    }

    // ---- ① 离线：setup/ctx + 每台预装 N 个 state（两轮之间保活）----
    // 会话边界：端点在"服务端在另一个进程"时会被**跨查询复用** ⇒ 显式开一个新会话
    // （计数器/缓冲清零）。本地端点这里是空操作。
    ep0.BeginSession();
    ep1.BeginSession();
    {
        const auto t0 = Clock::now();
        for (size_t i = 0; i < n; ++i) {
            RecordPlan& p = plans[i];
            p.session = kSecureMulBatchSessionBase + static_cast<uint64_t>(i);
            p.challenge = MakeChallenge(static_cast<uint64_t>(i), salt);
            p.f = reduce(f_bits[i], q);
            // d = f − a：与 `MPA-05` 的 `ClientRunPhase1` 同一公式（本层不重实现别的代数）
            p.d = subMod(p.f, reduce(p.material.client_triple.a, q), q);
            const auto bundle = MakeSetupsAndContext(
                static_cast<uint64_t>(i), p.material, {e_server0[i], e_server1[i]},
                p.challenge);
            // ⚠️ ctx **必须**带上（MPA-05 §6.7）：它承载 §4.5-A/B 两条纯客户端复核
            //    所需的 ⟨E⟩_p 与 ⟨b⟩_p；不传等于退回"只有 MAC"。
            p.ctx = bundle.ctx;
            ep0.Install(p.session, bundle.server0);
            ep1.Install(p.session, bundle.server1);
        }
        out.stats.offline_setup_ms = MsSince(t0);
    }
    // 安装落线（本地模式 = 空操作；远程模式 = 每台一次往返，把 N 条 setup 送过去）
    {
        ep0.FlushInstalls();
        ep1.FlushInstalls();
        out.stats.install_frames = ep0.install_frames() + ep1.install_frames();
        out.stats.install_bytes = ep0.install_bytes() + ep1.install_bytes();
        // ⚠️ `recv_bytes` **不在这里取**：此刻两轮相位还没跑（下面 681/756 行才跑），
        //    在这里取值只会数到"安装回执"两个空帧（实测 13 B/台）。见函数尾部。
        out.stats.install_rounds = ep0.install_frames() + ep1.install_frames();
    }
    // 常驻材料口径（每台）：N × (7×16 B triple 共享 + 16 B ⟨E⟩_p)
    out.stats.server_state_peak_bytes =
        kServerStateMaterialBytesPerRecord * static_cast<uint64_t>(n);
    // 实测口径（`sizeof`）：机器/编译器相关，只作对照
    out.stats.server_state_allocated_bytes =
        static_cast<uint64_t>(sizeof(SecureMulServerState)) * static_cast<uint64_t>(n);

    // ---- ② 第 1 轮：一个帧承载 N 条 Phase1Request ----
    const auto t_online = Clock::now();
    std::vector<Payload> p1_msgs(n);
    for (size_t i = 0; i < n; ++i) {
        // session / challenge / d 都来自本记录的 plan；challenge 与服务器预装的逐位一致
        p1_msgs[i] = EncodePhase1Request(
            Phase1Request{plans[i].session, plans[i].challenge, plans[i].d});
    }
    const Payload frame1 = EncodeBatchFrame(SecureMulBatchMsgType::kPhase1Request, p1_msgs);
    out.stats.frame_bytes_phase1 = frame1.size();
    out.stats.phase1_messages = p1_msgs.size();          // 单台视角 = N
    out.stats.wire_messages += 2 * p1_msgs.size();       // 两台各 N 条

    ep0.SubmitFrame(frame1);
    ep1.SubmitFrame(frame1);
    const std::vector<Response> resp1 = client.Collect();
    ++out.stats.rounds;  // 计数器（不是注释）
    ++out.stats.collect_calls_phase1;
    if (resp1.size() != 2) {
        throw std::runtime_error(
            "RunSecureMulBatch: 第 1 轮应答数量与请求不一致（期望 2 条，实际 " +
            Num(resp1.size()) + " 条）");
    }

    // ---- 解码第 1 轮应答（逐条；失败只影响对应记录）----
    std::vector<uint8_t> failed(n, 0);
    const auto mark_fail = [&](size_t i, SecureMulFailure f, SecureMulBatchError k,
                               const std::string& why) {
        if (failed[i]) {
            return;  // 只记第一次失败（first_failure 的口径 = 最小的记录序号）
        }
        failed[i] = 1;
        out.failure[i] = f;
        out.error_kind[i] = k;
        out.detail[i] = why;
    };
    const auto decode_responses = [&](const Response& resp, int server_id,
                                      SecureMulBatchMsgType type,
                                      std::vector<Payload>* msgs_out) -> bool {
        if (!resp.ok) {
            for (size_t i = 0; i < n; ++i) {
                mark_fail(i, SecureMulFailure::kServerReported,
                          SecureMulBatchError::kTransportError,
                          "服务器 " + Num(server_id) + " 应答失败: " + resp.error);
            }
            return false;
        }
        std::vector<Payload> msgs;
        try {
            msgs = DecodeBatchFrame(resp.payload, type);
        } catch (const std::exception& e) {
            for (size_t i = 0; i < n; ++i) {
                mark_fail(i, SecureMulFailure::kServerReported,
                          SecureMulBatchError::kFrameDecodeError,
                          "服务器 " + Num(server_id) + " 的应答帧解析失败: " + e.what());
            }
            return false;
        }
        if (msgs.size() != n) {
            for (size_t i = 0; i < n; ++i) {
                mark_fail(i, SecureMulFailure::kServerReported,
                          SecureMulBatchError::kRecordCountMismatch,
                          "服务器 " + Num(server_id) + " 的应答帧条数 " +
                              Num(msgs.size()) + " ≠ N=" + Num(n));
            }
            return false;
        }
        *msgs_out = std::move(msgs);
        return true;
    };

    std::vector<Payload> r1_raw0, r1_raw1;
    // ⚠️ 应答先过端点拆封（本地模式恒等；远程模式校验标记封套并剥出内层应答帧）
    const bool ok1_0 = decode_responses(ep0.UnwrapResponse(resp1[0]), 0,
                                        SecureMulBatchMsgType::kPhase1Response, &r1_raw0);
    const bool ok1_1 = decode_responses(ep1.UnwrapResponse(resp1[1]), 1,
                                        SecureMulBatchMsgType::kPhase1Response, &r1_raw1);

    // 逐条解码 + 逐条校验（session / status）
    std::vector<Phase1Response> ph1_0(n), ph1_1(n);
    for (size_t i = 0; i < n; ++i) {
        const auto decode_one = [&](const std::vector<Payload>& raw, int server_id,
                                    Phase1Response* dst) {
            try {
                *dst = DecodePhase1Response(raw[i]);
            } catch (const std::exception& e) {
                mark_fail(i, SecureMulFailure::kServerReported,
                          SecureMulBatchError::kFrameDecodeError,
                          "服务器 " + Num(server_id) + " 的第 " + Num(i) +
                              " 条 Phase1Response 解析失败: " + e.what());
                return;
            }
            if (dst->session != plans[i].session) {
                mark_fail(i, SecureMulFailure::kSessionMismatch,
                          SecureMulBatchError::kSessionNotFound,
                          "服务器 " + Num(server_id) + " 的第 " + Num(i) +
                              " 条 Phase1Response 的 session 与请求不一致（跨记录串味/重放）");
                return;
            }
            std::string err;
            if (!SecureMulStatusIsOk(dst->status, &err)) {
                mark_fail(i, SecureMulFailure::kServerReported,
                          SecureMulBatchError::kSessionNotFound,
                          "服务器 " + Num(server_id) + " 的第 " + Num(i) + " 条被拒绝: " + err);
            }
        };
        if (ok1_0) {
            decode_one(r1_raw0, 0, &ph1_0[i]);
        }
        if (ok1_1) {
            decode_one(r1_raw1, 1, &ph1_1[i]);
        }
    }

    // ---- ③ 中转 e = ⟨e⟩_0 + ⟨e⟩_1（协议规定的唯一中转动作）----
    // ---- ④ 第 2 轮：一个帧承载 N 条 Phase2Request（每台各带自己那份 e_check）----
    // ⚠️ 即使某条记录在前段已失败，第 2 轮**仍然发满 N 条**（常量模式：
    //    消息条数不得随"哪条失败/命中多少"变化；失败照样要 abort）。
    std::vector<Payload> p2_for0(n), p2_for1(n);
    std::vector<uint128_t> e_sent(n, 0), e_check0(n, 0), e_check1(n, 0);
    for (size_t i = 0; i < n; ++i) {
        e_check0[i] = reduce(ph1_0[i].e_computed, q);
        e_check1[i] = reduce(ph1_1[i].e_computed, q);
        e_sent[i] = addMod(e_check0[i], e_check1[i], q);
        p2_for0[i] = EncodePhase2Request(
            Phase2Request{plans[i].session, plans[i].d, e_sent[i], e_check0[i]});
        p2_for1[i] = EncodePhase2Request(
            Phase2Request{plans[i].session, plans[i].d, e_sent[i], e_check1[i]});
    }
    const Payload frame2_0 = EncodeBatchFrame(SecureMulBatchMsgType::kPhase2Request, p2_for0);
    const Payload frame2_1 = EncodeBatchFrame(SecureMulBatchMsgType::kPhase2Request, p2_for1);
    out.stats.frame_bytes_phase2 = frame2_0.size();
    out.stats.phase2_messages = p2_for0.size();
    out.stats.wire_messages += 2 * p2_for0.size();

    ep0.SubmitFrame(frame2_0);
    ep1.SubmitFrame(frame2_1);
    const std::vector<Response> resp2 = client.Collect();
    ++out.stats.rounds;
    ++out.stats.collect_calls_phase2;
    if (resp2.size() != 2) {
        throw std::runtime_error(
            "RunSecureMulBatch: 第 2 轮应答数量与请求不一致（期望 2 条，实际 " +
            Num(resp2.size()) + " 条）");
    }
    out.stats.online_ms = MsSince(t_online);

    std::vector<Payload> r2_raw0, r2_raw1;
    const bool ok2_0 = decode_responses(ep0.UnwrapResponse(resp2[0]), 0,
                                        SecureMulBatchMsgType::kPhase2Response, &r2_raw0);
    const bool ok2_1 = decode_responses(ep1.UnwrapResponse(resp2[1]), 1,
                                        SecureMulBatchMsgType::kPhase2Response, &r2_raw1);

    // ---- ⑤ 逐记录校验 + ⑥ 逐记录把关（**不累加失败记录**）----
    const auto t_verify = Clock::now();
    std::vector<Phase2Response> ph2_0(n), ph2_1(n);
    for (size_t i = 0; i < n; ++i) {
        if (failed[i]) {
            // 前段已失败：不校验、不采信、不累加（z 保持 0）
            continue;
        }
        const auto decode_one = [&](const std::vector<Payload>& raw, int server_id,
                                    Phase2Response* dst) -> bool {
            try {
                *dst = DecodePhase2Response(raw[i]);
            } catch (const std::exception& e) {
                mark_fail(i, SecureMulFailure::kServerReported,
                          SecureMulBatchError::kFrameDecodeError,
                          "服务器 " + Num(server_id) + " 的第 " + Num(i) +
                              " 条 Phase2Response 解析失败: " + e.what());
                return false;
            }
            return true;
        };
        if (ok2_0 && !decode_one(r2_raw0, 0, &ph2_0[i])) {
            continue;
        }
        if (ok2_1 && !decode_one(r2_raw1, 1, &ph2_1[i])) {
            continue;
        }
        // ⚠️ `MPA-05` 的收尾：**逐记录**调用 `VerifyAndReconstruct`，并且
        //    **必须**传 ctx / f / e_sent / triple / 两份 e_check（否则退回"只有 MAC"，
        //    一致偏移类篡改会被静默接受 —— 见 `MPA-05` §4.5 与文件头 §6.7）。
        const SecureMulFlowResult r = VerifyAndReconstruct(
            plans[i].session, {ph2_0[i], ph2_1[i]}, mac, &plans[i].ctx, plans[i].f,
            e_sent[i], &plans[i].material.client_triple, e_check0[i], e_check1[i]);
        if (!r.ok) {
            // 失败记录的 z 一律置 0：`VerifyAndReconstruct` 在 MAC 失败时仍会写出
            // 重建值（MPA-05 §6.3），**绝不允许**把它当有效值暴露出去。
            out.z[i] = 0;
            out.failure[i] = r.failure;
            out.error_kind[i] = SecureMulBatchError::kNone;
            out.detail[i] = r.error;
            failed[i] = 1;  // 标记已失败（first_failure 用 ok 判定，这里只为一致性）
            continue;
        }
        out.ok[i] = 1;
        out.z[i] = r.z;
    }
    out.stats.verify_ms = MsSince(t_verify);
    // **下行应答字节**（两台之和）：必须在**两轮相位都跑完之后**取 ——
    // Phase1Response(27 B/条) + Phase2Response(43 B/条)，是 Sum 的下行大头。
    out.stats.recv_bytes = ep0.recv_bytes() + ep1.recv_bytes();
    // 服务器侧**实测**计数（本地：端点直接读表；远程：端点从服务器回执里取得
    // "本轮实际处理的子消息数"——同样是服务端自报的**实测**值，不是按 N 估算的）
    out.stats.server_records_processed[0] = static_cast<uint64_t>(ep0.processed_phase1());
    out.stats.server_records_processed[1] = static_cast<uint64_t>(ep1.processed_phase1());
    out.stats.server_records_processed_phase2[0] =
        static_cast<uint64_t>(ep0.processed_phase2());
    out.stats.server_records_processed_phase2[1] =
        static_cast<uint64_t>(ep1.processed_phase2());
    out.stats.server_frames[0] = ep0.frames();
    out.stats.server_frames[1] = ep1.frames();
    out.stats.messages = out.stats.phase1_messages + out.stats.phase2_messages;

    for (size_t i = 0; i < n; ++i) {
        if (!out.ok[i]) {
            out.first_failure = i;
            break;
        }
    }
    return out;
}

}  // namespace

// ---- 三个公开入口（都转调 `RunSecureMulBatchImpl`）----

// ① 既有的 `LocalTransport&` 重载：**源兼容**，行为逐位不变（两个本地端点）。
SecureMulBatchOutcome RunSecureMulBatch(const std::vector<uint8_t>& f_bits,
                                        const std::vector<ModShare>& e_server0,
                                        const std::vector<ModShare>& e_server1,
                                        LocalTransport& net, SecureMulClientState& mac,
                                        random::DeterministicPrng& prng,
                                        uint64_t challenge_salt) {
    RequireTwoServers(net.NumServers());
    LocalSecureMulBatchEndpoint ep0(net, net, kServer0, mac.modulus());
    LocalSecureMulBatchEndpoint ep1(net, net, kServer1, mac.modulus());
    return RunSecureMulBatchImpl(f_bits, e_server0, e_server1, net, ep0, ep1,
                                 net.NumServers(), mac, prng, challenge_salt);
}

// ② 接口版（服务端一侧仍在**本进程**：LocalTransport / 进程内 gRPC 回环）
SecureMulBatchOutcome RunSecureMulBatch(const std::vector<uint8_t>& f_bits,
                                        const std::vector<ModShare>& e_server0,
                                        const std::vector<ModShare>& e_server1,
                                        SecureMulTransport net, SecureMulClientState& mac,
                                        random::DeterministicPrng& prng,
                                        uint64_t challenge_salt) {
    RequireTwoServers(net.server.NumServers());
    LocalSecureMulBatchEndpoint ep0(net.client, net.server, kServer0, mac.modulus());
    LocalSecureMulBatchEndpoint ep1(net.client, net.server, kServer1, mac.modulus());
    return RunSecureMulBatchImpl(f_bits, e_server0, e_server1, net.client, ep0, ep1,
                                 net.server.NumServers(), mac, prng, challenge_salt);
}

// ③ 两进程版（服务端在另一个进程 ⇒ 端点由调用方提供）
SecureMulBatchOutcome RunSecureMulBatch(const std::vector<uint8_t>& f_bits,
                                        const std::vector<ModShare>& e_server0,
                                        const std::vector<ModShare>& e_server1,
                                        ITransportClient& client,
                                        ISecureMulBatchEndpoint& server0,
                                        ISecureMulBatchEndpoint& server1,
                                        SecureMulClientState& mac,
                                        random::DeterministicPrng& prng,
                                        uint64_t challenge_salt) {
    if (&server0 == &server1) {
        throw std::invalid_argument(
            "SecureMulBatch: server0 与 server1 必须是**两个不同的**端点对象"
            "（同一对象等于一台服务器冒充两台，两半共享会落在同一台上）");
    }
    // 端点数由调用方给定（两个不同对象）⇒ 恒为 2
    return RunSecureMulBatchImpl(f_bits, e_server0, e_server1, client, server0, server1,
                                 /*num_servers=*/2, mac, prng, challenge_salt);
}

// ===========================================================================
// 逐记录参考驱动（"批量 ≡ 逐记录"的等价性测试用）
// ===========================================================================

namespace {

SecureMulBatchOutcome RunSecureMulPerRecordImpl(
    const std::vector<uint8_t>& f_bits, const std::vector<ModShare>& e_server0,
    const std::vector<ModShare>& e_server1, ITransportClient& client,
    ITransportServer& server, const std::function<uint64_t(int)>* frame_count_of,
    SecureMulClientState& mac, random::DeterministicPrng& prng,
    uint64_t challenge_salt) {
    ValidateInputs(f_bits, e_server0, e_server1, server.NumServers());
    const uint128_t q = mac.modulus();
    const size_t n = f_bits.size();

    SecureMulBatchOutcome out;
    out.z.assign(n, 0);
    out.ok.assign(n, 0);
    out.failure.assign(n, SecureMulFailure::kNone);
    out.error_kind.assign(n, SecureMulBatchError::kNone);
    out.detail.assign(n, std::string());
    out.stats.records = n;
    // 逐记录路径一次只装一条记录的 state ⇒ 常驻峰值就是 1 条记录的材料（每台）
    out.stats.server_state_peak_bytes = kServerStateMaterialBytesPerRecord;
    out.stats.server_state_allocated_bytes = sizeof(SecureMulServerState);

    const std::vector<uint8_t> salt = SaltBytes(challenge_salt);

    // 与批量路径**同样的消费顺序**：先离线把 N 组 triple 全部生成出来，
    // 这样同一 `prng` 种子下两条路径拿到的 triple 逐位相同（等价性测试更强）。
    std::vector<SecureMulTripleMaterial> materials(n);
    {
        const auto t0 = Clock::now();
        for (size_t i = 0; i < n; ++i) {
            materials[i] = GenerateBeaverTriple(mac.keys(), q, prng);
        }
        out.stats.offline_triple_ms = MsSince(t0);
    }

    CountingClient counting(client);
    // `RegisterSecureMulServers` 捕获 state 的地址 ⇒ state 必须在整个循环里保活
    std::optional<SecureMulServerState> s0;
    std::optional<SecureMulServerState> s1;

    const auto t_online = Clock::now();
    for (size_t i = 0; i < n; ++i) {
        const uint64_t session = kSecureMulBatchSessionBase + static_cast<uint64_t>(i);
        const uint64_t challenge = MakeChallenge(static_cast<uint64_t>(i), salt);
        const uint128_t f = reduce(f_bits[i], q);
        const auto t_setup = Clock::now();
        const auto bundle = MakeSetupsAndContext(static_cast<uint64_t>(i), materials[i],
                                                 {e_server0[i], e_server1[i]}, challenge);
        s0 = MakeServerState(bundle.server0, q);
        s1 = MakeServerState(bundle.server1, q);
        RegisterSecureMulServers(server, *s0, *s1);
        out.stats.offline_setup_ms += MsSince(t_setup);

        // 一条记录 = `MPA-05` 的 2 个往返（`ClientRunPhase1` / `ClientRunPhase2`
        // 各 `Collect()` 一次）；这里用 `CountingClient` **实测**计数，
        // 而不是"每记录加 2"。
        const SecureMulFlowResult r = SecureMulFlowRunRecord(
            session, challenge, f, materials[i].client_triple, counting, mac, &bundle.ctx);
        if (!r.ok) {
            out.failure[i] = r.failure;
            out.detail[i] = r.error;
            out.z[i] = 0;
            continue;
        }
        out.ok[i] = 1;
        out.z[i] = r.z;
    }
    // 逐记录路径的两轮在线与逐记录校验**在同一个函数调用里**发生
    // （`SecureMulFlowRunRecord` = Phase1 + Phase2 + VerifyAndReconstruct）
    // ⇒ 只能给出合并耗时；如实记在 `online_ms`，并把 `verify_ms` 标为 0
    //（不编造一个分离不了的数字）。
    out.stats.online_ms = MsSince(t_online);
    out.stats.verify_ms = 0.0;

    out.stats.rounds = counting.collects();
    // 单台服务器视角的每轮条数：直接取**实测**计数（两台应当相等；
    // 若不等说明协议被破坏，测试会据此报错，这里取最小值以免虚报）
    out.stats.phase1_messages =
        std::min(counting.phase1_of(kServer0), counting.phase1_of(kServer1));
    out.stats.phase2_messages =
        std::min(counting.phase2_of(kServer0), counting.phase2_of(kServer1));
    out.stats.messages = out.stats.phase1_messages + out.stats.phase2_messages;
    out.stats.wire_messages = counting.submits();  // 线上真实条数（两台 × 两轮）
    // 帧数一律**实测**：*frame_count_of 非空时用调用方给的（`LocalTransport::RequestCount`），
    // 否则用本函数内部那个 `CountingClient` 数出来的 Submit 次数（两者口径等价）。
    out.stats.server_frames[0] =
        frame_count_of != nullptr ? (*frame_count_of)(kServer0) : counting.submits_of(kServer0);
    out.stats.server_frames[1] =
        frame_count_of != nullptr ? (*frame_count_of)(kServer1) : counting.submits_of(kServer1);
    out.stats.server_records_processed[0] = n;
    out.stats.server_records_processed[1] = n;
    out.stats.server_records_processed_phase2[0] = n;
    out.stats.server_records_processed_phase2[1] = n;
    out.stats.frame_bytes_phase1 = 0;  // 逐记录路径没有批量帧
    out.stats.frame_bytes_phase2 = 0;

    for (size_t i = 0; i < n; ++i) {
        if (!out.ok[i]) {
            out.first_failure = i;
            break;
        }
    }
    return out;
}

}  // namespace

// ---- 两个公开入口（都转调 `RunSecureMulPerRecordImpl`）----
//
// ⚠️ 逐记录路径的"服务器 handler"由 `RegisterSecureMulServers(ITransportServer&, ...)`
//    安装 ⇒ 只支持"服务端一侧在本进程"的部署（既有的 `LocalTransport&` 与新的
//    `SecureMulTransport`）。两进程模式一律走批量路径（见头文件 §10）。
SecureMulBatchOutcome RunSecureMulPerRecord(const std::vector<uint8_t>& f_bits,
                                            const std::vector<ModShare>& e_server0,
                                            const std::vector<ModShare>& e_server1,
                                            LocalTransport& net, SecureMulClientState& mac,
                                            random::DeterministicPrng& prng,
                                            uint64_t challenge_salt) {
    // 帧计数口径与改动前**逐位相同**：`LocalTransport::RequestCount`（实测）
    const std::function<uint64_t(int)> count = [&net](int id) {
        return net.RequestCount(id);
    };
    return RunSecureMulPerRecordImpl(f_bits, e_server0, e_server1, net, net, &count, mac,
                                     prng, challenge_salt);
}

SecureMulBatchOutcome RunSecureMulPerRecord(const std::vector<uint8_t>& f_bits,
                                            const std::vector<ModShare>& e_server0,
                                            const std::vector<ModShare>& e_server1,
                                            SecureMulTransport net, SecureMulClientState& mac,
                                            random::DeterministicPrng& prng,
                                            uint64_t challenge_salt) {
    RequireTwoServers(net.server.NumServers());
    // 通用传输没有 `RequestCount`（那是 `LocalTransport` 的具体类型诊断接口）⇒
    // 传 nullptr：由实现内部那个 `CountingClient` 数 Submit 次数（一次 Submit =
    // 一个请求帧，与 `RequestCount` 口径等价，且是**数出来**的而不是估算的）。
    return RunSecureMulPerRecordImpl(f_bits, e_server0, e_server1, net.client, net.server,
                                     /*frame_count_of=*/nullptr, mac, prng,
                                     challenge_salt);
}

// ===========================================================================
// Sum / Avg
// ===========================================================================

namespace {

// 三个公开入口共用的实现：只差"服务端在哪里"（本地端点 / 接口端点 / 远程端点）。
SumResult SumOverFilterImpl(const CountResult& c, const Schema& schema, uint32_t attr_id,
                            MpraqClient& client, ITransportClient& transport,
                            ISecureMulBatchEndpoint& server0,
                            ISecureMulBatchEndpoint& server1, SecureMulClientState& mac,
                            random::DeterministicPrng& prng, uint64_t challenge_salt) {
    const size_t n = c.filter.size();
    if (n == 0) {
        throw std::invalid_argument(
            "SumOverFilter: CountResult::filter 为空 —— 没有记录可求和"
            "（零命中应当传入长度 N、内容全 0 的 filter；长度 0 是调用方错误）");
    }
    if (!schema.HasAttribute(attr_id)) {
        std::ostringstream oss;
        oss << "SumOverFilter: 属性号越界（attr_id=" << attr_id << "，schema 只有 "
            << schema.num_attributes() << " 个属性）";
        throw std::out_of_range(oss.str());
    }
    // filter 必须是 0/1，且 `count` 与 `filter` 自洽（MPA-04 的口径：count = popcount）
    uint64_t popcount = 0;
    for (size_t i = 0; i < n; ++i) {
        if (c.filter[i] > 1) {
            throw std::invalid_argument(
                "SumOverFilter: filter[" + Num(i) + "] = " + Num(c.filter[i]) +
                " 不是 0/1 —— CountResult::filter 必须是比特向量");
        }
        popcount += (c.filter[i] != 0) ? 1u : 0u;
    }
    if (popcount != c.count) {
        std::ostringstream oss;
        oss << "SumOverFilter: CountResult 自相矛盾（count=" << c.count
            << "，但 popcount(filter)=" << popcount
            << "）—— 请用 MPA-04 的 `CountResult`，不要手搓";
        throw std::invalid_argument(oss.str());
    }
    // schema 里该属性若声明了窗口大小，必须与 filter 的长度一致
    const AttributeSchema& attr = schema.ById(attr_id);
    if (attr.lcte.window_size != 0 &&
        static_cast<size_t>(attr.lcte.window_size) != n) {
        std::ostringstream oss;
        oss << "SumOverFilter: 长度不匹配（filter 长度 " << n
            << "，schema 属性 " << attr_id << " 的 window_size "
            << attr.lcte.window_size << "）";
        throw std::invalid_argument(oss.str());
    }

    // ⟨E⟩ 的两份加法共享：**原属性值**的 mod q 加法共享（MPA-03 的落地口径；
    // 见头文件 §0 与 `init.cpp` 的 `ShareAttributeVector`）。
    std::vector<ModShare> e0 = client.AttributeShares(attr_id, kServer0);
    std::vector<ModShare> e1 = client.AttributeShares(attr_id, kServer1);
    if (e0.size() != n || e1.size() != n) {
        std::ostringstream oss;
        oss << "SumOverFilter: 长度不匹配（filter 长度 " << n << "，属性 " << attr_id
            << " 的共享长度 ⟨E⟩_0=" << e0.size() << " / ⟨E⟩_1=" << e1.size()
            << "）—— filter 与属性列必须是同一个 N";
        throw std::invalid_argument(oss.str());
    }

    const auto t0 = Clock::now();
    SecureMulBatchOutcome out = RunSecureMulBatch(c.filter, e0, e1, transport, server0,
                                                  server1, mac, prng, challenge_salt);
    if (!out.all_ok()) {
        const size_t i = out.first_failure;
        std::ostringstream oss;
        oss << "SumOverFilter: 第 " << i << "/" << n << " 条记录校验失败（分类="
            << SecureMulBatchFailureName(out.failure[i]) << "，细类="
            << SecureMulBatchErrorName(out.error_kind[i])
            << "）⇒ abort 整个查询，**绝不返回部分和**。原因：" << out.detail[i];
        throw SecureMulBatchAbort(oss.str(), out.failure[i], i, out.error_kind[i]);
    }

    SumResult r;
    r.sum = out.SumOrThrow(mac.modulus());
    r.count = c.count;
    r.securemul = out.stats;
    r.sum_ms = MsSince(t0);
    return r;
}

}  // namespace

// ---- 三个公开入口（都转调 `SumOverFilterImpl`）----

// ① 既有的 `LocalTransport&` 重载：**源兼容**，行为逐条不变。
SumResult SumOverFilter(const CountResult& c, const Schema& schema, uint32_t attr_id,
                        MpraqClient& client, LocalTransport& net,
                        SecureMulClientState& mac, random::DeterministicPrng& prng,
                        uint64_t challenge_salt) {
    RequireTwoServers(net.NumServers());
    LocalSecureMulBatchEndpoint ep0(net, net, kServer0, mac.modulus());
    LocalSecureMulBatchEndpoint ep1(net, net, kServer1, mac.modulus());
    return SumOverFilterImpl(c, schema, attr_id, client, net, ep0, ep1, mac, prng,
                             challenge_salt);
}

// ② 接口版（服务端一侧仍在**本进程**）
SumResult SumOverFilter(const CountResult& c, const Schema& schema, uint32_t attr_id,
                        MpraqClient& client, SecureMulTransport net,
                        SecureMulClientState& mac, random::DeterministicPrng& prng,
                        uint64_t challenge_salt) {
    RequireTwoServers(net.server.NumServers());
    LocalSecureMulBatchEndpoint ep0(net.client, net.server, kServer0, mac.modulus());
    LocalSecureMulBatchEndpoint ep1(net.client, net.server, kServer1, mac.modulus());
    return SumOverFilterImpl(c, schema, attr_id, client, net.client, ep0, ep1, mac, prng,
                             challenge_salt);
}

// ③ 两进程版（服务端在另一个进程 ⇒ 端点由调用方提供）
SumResult SumOverFilter(const CountResult& c, const Schema& schema, uint32_t attr_id,
                        MpraqClient& client, ITransportClient& transport,
                        ISecureMulBatchEndpoint& server0,
                        ISecureMulBatchEndpoint& server1, SecureMulClientState& mac,
                        random::DeterministicPrng& prng, uint64_t challenge_salt) {
    if (&server0 == &server1) {
        throw std::invalid_argument(
            "SumOverFilter: server0 与 server1 必须是两个不同的端点对象");
    }
    return SumOverFilterImpl(c, schema, attr_id, client, transport, server0, server1, mac,
                             prng, challenge_salt);
}

uint128_t AvgOverFilter(const SumResult& r) {
    if (r.count == 0) {
        throw std::domain_error(
            "AvgOverFilter: count == 0（没有任何记录满足谓词）⇒ 平均值在数学上无定义。"
            "本口径**不**返回 0：0 是一个可达的真实均值（例如所有命中记录的取值都为 0），"
            "静默返回 0 会让「没有记录满足」与「均值恰好为 0」不可区分。"
            "请先用 CountResult::count 判断再决定是否调用。");
    }
    // 无符号整数除法 = 向下取整（与 VMPQ 的 `AvgWithFilter` 同口径）
    return r.sum / static_cast<uint128_t>(r.count);
}

}  // namespace mpraq
}  // namespace tsb
