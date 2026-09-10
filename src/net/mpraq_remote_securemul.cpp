#include "net/mpraq_remote_securemul.hpp"

#include <atomic>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <utility>

#include "core/field.hpp"

namespace tsb {
namespace mpraq {

namespace {

std::string Num(uint64_t v) { return std::to_string(v); }

uint32_t ReadU32LE(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

void WriteU64LE(uint64_t v, std::vector<uint8_t>* out) {
    for (size_t i = 0; i < 8; ++i) {
        out->push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xffu));
    }
}

uint64_t ReadU64LE(const uint8_t* p) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(p[i]) << (8 * i);
    }
    return v;
}

void AppendU128(uint128_t v, std::vector<uint8_t>* out) {
    uint8_t buf[kUint128Bytes];
    toBytesLE(v, buf);
    out->insert(out->end(), buf, buf + kUint128Bytes);
}

uint128_t ReadU128(const uint8_t* p) { return fromBytesLE(p); }

// triple 共享的 7 个分量（顺序 = `TripleShare` 的声明顺序，**不要改**）
void AppendTriple(const TripleShare& t, std::vector<uint8_t>* out) {
    AppendU128(t.a.value, out);
    AppendU128(t.b.value, out);
    AppendU128(t.c.value, out);
    AppendU128(t.alpha_a.value, out);
    AppendU128(t.alpha_b.value, out);
    AppendU128(t.alpha_c.value, out);
    AppendU128(t.alpha.value, out);
}

TripleShare ReadTriple(const uint8_t* p) {
    TripleShare t;
    size_t off = 0;
    const auto next = [&]() {
        const uint128_t v = ReadU128(p + off);
        off += kUint128Bytes;
        return v;
    };
    t.a = ModShare{next()};
    t.b = ModShare{next()};
    t.c = ModShare{next()};
    t.alpha_a = ModShare{next()};
    t.alpha_b = ModShare{next()};
    t.alpha_c = ModShare{next()};
    t.alpha = ModShare{next()};
    return t;
}

bool IsPhase1Kind(RelayFrameKind k) { return k == RelayFrameKind::kPhase1Batch; }
bool IsPhase2Kind(RelayFrameKind k) { return k == RelayFrameKind::kPhase2Batch; }

// 内层批量帧的"类型字节 → 期望的封套 kind"（结构性一致性检查，见文件头 §1）
RelayFrameKind ExpectedKindForBatchType(uint8_t type_byte, bool response) {
    switch (static_cast<SecureMulBatchMsgType>(type_byte)) {
        case SecureMulBatchMsgType::kPhase1Request:
            return response ? RelayFrameKind::kPhase1Ack : RelayFrameKind::kPhase1Batch;
        case SecureMulBatchMsgType::kPhase1Response:
            return RelayFrameKind::kPhase1Ack;
        case SecureMulBatchMsgType::kPhase2Request:
            return response ? RelayFrameKind::kPhase2Ack : RelayFrameKind::kPhase2Batch;
        case SecureMulBatchMsgType::kPhase2Response:
            return RelayFrameKind::kPhase2Ack;
    }
    throw std::invalid_argument(
        "MPA-08 Relay: 内层批量帧的类型字节非法（" + Num(type_byte) + "）");
}

// 读内层批量帧头里的 count（第 2..6 字节小端；格式见 aggvalue.hpp §1）
uint32_t InnerCount(const Payload& inner) {
    if (inner.size() < kBatchFrameHeaderBytes) {
        throw std::invalid_argument("MPA-08 Relay: 内层批量帧太短（< 6 字节头）");
    }
    return ReadU32LE(inner.data() + 2);
}

}  // namespace

const char* RelayFrameKindName(RelayFrameKind kind) {
    switch (kind) {
        case RelayFrameKind::kInstallSetups: return "kInstallSetups";
        case RelayFrameKind::kInstallAck: return "kInstallAck";
        case RelayFrameKind::kPhase1Batch: return "kPhase1Batch";
        case RelayFrameKind::kPhase1Ack: return "kPhase1Ack";
        case RelayFrameKind::kPhase2Batch: return "kPhase2Batch";
        case RelayFrameKind::kPhase2Ack: return "kPhase2Ack";
        case RelayFrameKind::kStatsRequest: return "kStatsRequest";
        case RelayFrameKind::kStatsAck: return "kStatsAck";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// 标记封套编解码
// ---------------------------------------------------------------------------

Payload EncodeRelayFrame(RelayFrameKind kind, uint32_t count, const Payload& payload) {
    if (payload.size() > 0xFFFFFFFFull) {
        throw std::invalid_argument("EncodeRelayFrame: payload 超过 uint32 长度上限");
    }
    // 逐段拷贝（而不是 reserve+insert）——避免 GCC 对 `insert` 的
    // `-Wstringop-overflow` 误报，也让帧布局在代码里一眼可见。
    Payload out(kRelayHeaderBytes + payload.size(), 0);
    std::memcpy(out.data(), kRelayFrameMagic, 4);
    out[4] = static_cast<uint8_t>(kind);
    const uint32_t len = static_cast<uint32_t>(payload.size());
    for (size_t i = 0; i < 4; ++i) {
        out[5 + i] = static_cast<uint8_t>((count >> (8 * i)) & 0xffu);
        out[9 + i] = static_cast<uint8_t>((len >> (8 * i)) & 0xffu);
    }
    if (!payload.empty()) {
        std::memcpy(out.data() + kRelayHeaderBytes, payload.data(), payload.size());
    }
    return out;
}

RelayFrame DecodeRelayFrame(const Payload& frame) {
    if (frame.size() < kRelayHeaderBytes) {
        throw std::invalid_argument(
            "DecodeRelayFrame: 帧太短（需要 " + Num(kRelayHeaderBytes) + " 字节头，实际 " +
            Num(frame.size()) + "）");
    }
    if (std::memcmp(frame.data(), kRelayFrameMagic, 4) != 0) {
        throw std::invalid_argument(
            "DecodeRelayFrame: 魔数不符（不是 MPA-08 的标记帧；本协议不猜字节）");
    }
    const uint8_t kind_byte = frame[4];
    RelayFrame out;
    switch (kind_byte) {
        case static_cast<uint8_t>(RelayFrameKind::kInstallSetups):
            out.kind = RelayFrameKind::kInstallSetups;
            break;
        case static_cast<uint8_t>(RelayFrameKind::kInstallAck):
            out.kind = RelayFrameKind::kInstallAck;
            break;
        case static_cast<uint8_t>(RelayFrameKind::kPhase1Batch):
            out.kind = RelayFrameKind::kPhase1Batch;
            break;
        case static_cast<uint8_t>(RelayFrameKind::kPhase1Ack):
            out.kind = RelayFrameKind::kPhase1Ack;
            break;
        case static_cast<uint8_t>(RelayFrameKind::kPhase2Batch):
            out.kind = RelayFrameKind::kPhase2Batch;
            break;
        case static_cast<uint8_t>(RelayFrameKind::kPhase2Ack):
            out.kind = RelayFrameKind::kPhase2Ack;
            break;
        case static_cast<uint8_t>(RelayFrameKind::kStatsRequest):
            out.kind = RelayFrameKind::kStatsRequest;
            break;
        case static_cast<uint8_t>(RelayFrameKind::kStatsAck):
            out.kind = RelayFrameKind::kStatsAck;
            break;
        default:
            throw std::invalid_argument("DecodeRelayFrame: 未知的标记帧类型 " +
                                        Num(kind_byte));
    }
    out.count = ReadU32LE(frame.data() + 5);
    const uint32_t payload_len = ReadU32LE(frame.data() + 9);
    const size_t want = kRelayHeaderBytes + static_cast<size_t>(payload_len);
    if (frame.size() != want) {
        std::ostringstream oss;
        oss << "DecodeRelayFrame: 长度不符（payload_len=" << payload_len << " ⇒ 期望 "
            << want << " B，实际 " << frame.size() << " B）";
        throw std::invalid_argument(oss.str());
    }
    out.payload.assign(frame.begin() + static_cast<long>(kRelayHeaderBytes), frame.end());
    return out;
}

Payload EncodeInstallPayload(const std::vector<uint64_t>& sessions,
                             const std::vector<SecureMulServerSetup>& setups) {
    if (sessions.size() != setups.size()) {
        throw std::invalid_argument(
            "EncodeInstallPayload: sessions 与 setups 条数不一致（" + Num(sessions.size()) +
            " vs " + Num(setups.size()) + "）");
    }
    Payload out;
    out.reserve(kInstallEntryBytes * sessions.size());
    for (size_t i = 0; i < sessions.size(); ++i) {
        WriteU64LE(sessions[i], &out);
        WriteU64LE(setups[i].record_index, &out);
        AppendTriple(setups[i].triple, &out);
        AppendU128(setups[i].e_share.value, &out);
        WriteU64LE(setups[i].challenge, &out);
    }
    if (out.size() != kInstallEntryBytes * sessions.size()) {
        throw std::logic_error("EncodeInstallPayload: 内部长度自检失败");
    }
    return out;
}

InstallPayload DecodeInstallPayload(const Payload& payload, uint32_t count) {
    const size_t want = kInstallEntryBytes * static_cast<size_t>(count);
    if (payload.size() != want) {
        std::ostringstream oss;
        oss << "DecodeInstallPayload: 载荷长度不符（count=" << count << " ⇒ 期望 " << want
            << " B，实际 " << payload.size() << " B）";
        throw std::invalid_argument(oss.str());
    }
    InstallPayload out;
    out.sessions.reserve(count);
    out.setups.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t* p = payload.data() + kInstallEntryBytes * i;
        const uint64_t session = ReadU64LE(p);
        SecureMulServerSetup s;
        s.record_index = ReadU64LE(p + 8);
        s.triple = ReadTriple(p + 16);
        s.e_share = ModShare{ReadU128(p + 16 + 7 * kUint128Bytes)};
        s.challenge = ReadU64LE(p + 16 + 8 * kUint128Bytes);
        out.sessions.push_back(session);
        out.setups.push_back(s);
    }
    return out;
}

// ---------------------------------------------------------------------------
// MpraqSecureMulServer
// ---------------------------------------------------------------------------

Payload MpraqSecureMulServer::Handle(const Payload& frame) {
    // ⚠️ 结构性校验（魔数/长度/类型）在锁外做也可以，但放在锁内更简单：
    //    handler 的调用频率是每查询 3 次/台，锁的开销可忽略。
    RelayFrame f = DecodeRelayFrame(frame);
    std::lock_guard<std::mutex> lock(mu_);
    switch (f.kind) {
        case RelayFrameKind::kInstallSetups: {
            const InstallPayload p = DecodeInstallPayload(f.payload, f.count);
            // 客户端的 session 号每次查询都一样 ⇒ 先清表再装（见文件头 §1 的限制）
            table_.Clear();
            for (size_t i = 0; i < p.sessions.size(); ++i) {
                table_.Install(p.sessions[i], p.setups[i]);
            }
            ++install_frames_;
            install_records_ += static_cast<uint64_t>(p.sessions.size());
            // `count` = 实际安装条数：客户端会拿它与自己发的条数比对
            return EncodeRelayFrame(RelayFrameKind::kInstallAck,
                                    static_cast<uint32_t>(p.sessions.size()), Payload{});
        }
        case RelayFrameKind::kPhase1Batch:
        case RelayFrameKind::kPhase2Batch: {
            // 内层帧的类型必须与封套一致（否则是"用第 2 轮的封套送第 1 轮的帧"这类错配）
            if (f.payload.size() < 2) {
                throw std::invalid_argument("MPA-08 Relay: 相位帧的内层载荷太短");
            }
            const RelayFrameKind inner_kind = ExpectedKindForBatchType(f.payload[1], false);
            if (inner_kind != f.kind) {
                throw std::invalid_argument(
                    std::string("MPA-08 Relay: 封套类型与内层帧类型不符（封套 ") +
                    RelayFrameKindName(f.kind) + "，内层 " + RelayFrameKindName(inner_kind) +
                    "）");
            }
            // **同一份**服务端逻辑（`SecureMulBatchServerTable`）：逐条按 session 分派
            Payload inner = table_.HandleFrame(f.payload);
            const uint32_t processed = InnerCount(inner);
            ++phase_frames_;
            phase_records_ += processed;
            const RelayFrameKind ack = IsPhase1Kind(f.kind) ? RelayFrameKind::kPhase1Ack
                                                            : RelayFrameKind::kPhase2Ack;
            return EncodeRelayFrame(ack, processed, inner);
        }
        case RelayFrameKind::kStatsRequest:
            throw std::logic_error(
                "MPA-08 Relay: kStatsRequest 由 MpraqDemoService 直接处理（需要节点账目）");
        default:
            throw std::invalid_argument(
                std::string("MPA-08 Relay: 服务器不接受该类型的帧（") +
                RelayFrameKindName(f.kind) + "）");
    }
}

uint64_t MpraqSecureMulServer::install_frames() const {
    std::lock_guard<std::mutex> lock(mu_);
    return install_frames_;
}
uint64_t MpraqSecureMulServer::phase_frames() const {
    std::lock_guard<std::mutex> lock(mu_);
    return phase_frames_;
}
uint64_t MpraqSecureMulServer::install_records() const {
    std::lock_guard<std::mutex> lock(mu_);
    return install_records_;
}
uint64_t MpraqSecureMulServer::phase_records() const {
    std::lock_guard<std::mutex> lock(mu_);
    return phase_records_;
}
uint64_t MpraqSecureMulServer::session_states() const {
    std::lock_guard<std::mutex> lock(mu_);
    return static_cast<uint64_t>(table_.size());
}

// ---------------------------------------------------------------------------
// RemoteSecureMulBatchEndpoint
// ---------------------------------------------------------------------------

RemoteSecureMulBatchEndpoint::RemoteSecureMulBatchEndpoint(ITransportClient& client,
                                                           int server_id)
    : client_(&client), server_id_(server_id) {
    if (server_id < 0) {
        throw std::invalid_argument("RemoteSecureMulBatchEndpoint: server_id 必须 >= 0");
    }
}

void RemoteSecureMulBatchEndpoint::BeginSession() {
    // 端点绑在"一台服务器"上、会被**跨查询复用** ⇒ 每次会话开始必须清掉上一次的
    // 计数与缓冲（否则账目会累加：install_frames 变成 2/4/6…）。
    sessions_.clear();
    setups_.clear();
    expected_records_ = 0;
    last_request_kind_ = 0;
    phase_frames_ = 0;
    processed_phase1_ = 0;
    processed_phase2_ = 0;
    install_frames_ = 0;
    install_bytes_ = 0;
}

void RemoteSecureMulBatchEndpoint::Install(uint64_t session,
                                           const SecureMulServerSetup& setup) {
    sessions_.push_back(session);
    setups_.push_back(setup);
}

void RemoteSecureMulBatchEndpoint::FlushInstalls() {
    if (sessions_.empty()) {
        return;
    }
    const Payload payload = EncodeInstallPayload(sessions_, setups_);
    const Payload frame = EncodeRelayFrame(
        RelayFrameKind::kInstallSetups, static_cast<uint32_t>(sessions_.size()), payload);
    const size_t n = sessions_.size();
    ++relay_calls_;
    const Response raw = client_->RoundTrip(server_id_, frame);
    if (!raw.ok) {
        throw std::runtime_error(
            "MPA-08 安装 state 失败（服务器 " + Num(static_cast<uint64_t>(server_id_)) +
            "）: " + raw.error);
    }
    const RelayFrame ack = DecodeRelayFrame(raw.payload);
    if (ack.kind != RelayFrameKind::kInstallAck) {
        throw std::runtime_error(
            std::string("MPA-08 安装回执类型不符：期望 kInstallAck，实际 ") +
            RelayFrameKindName(ack.kind));
    }
    if (ack.count != n) {
        throw std::runtime_error(
            "MPA-08 安装回执条数不符：服务器报 " + Num(ack.count) + "，客户端发了 " +
            Num(n) + "（**不是**静默接受）");
    }
    ++install_frames_;
    install_bytes_ += frame.size();
    expected_records_ = n;
    sessions_.clear();
    setups_.clear();
}

void RemoteSecureMulBatchEndpoint::SubmitFrame(const Payload& frame) {
    if (frame.size() < 2) {
        throw std::invalid_argument("RemoteSecureMulBatchEndpoint::SubmitFrame: 帧太短");
    }
    // 内层批量帧的类型字节（第 2 字节）决定封套 kind：第 1 轮 / 第 2 轮
    const RelayFrameKind kind = ExpectedKindForBatchType(frame[1], /*response=*/false);
    if (kind != RelayFrameKind::kPhase1Batch && kind != RelayFrameKind::kPhase2Batch) {
        throw std::invalid_argument(
            "RemoteSecureMulBatchEndpoint::SubmitFrame: 只接受 Phase1/Phase2 的**请求**帧");
    }
    const Payload wrapped =
        EncodeRelayFrame(kind, static_cast<uint32_t>(InnerCount(frame)), frame);
    last_request_kind_ = static_cast<uint64_t>(kind);
    ++relay_calls_;
    ++phase_frames_;
    client_->Submit(server_id_, wrapped);
}

Response RemoteSecureMulBatchEndpoint::UnwrapResponse(const Response& raw) {
    if (!raw.ok) {
        return raw;  // 传输层失败：原样向上（口径 = kTransportError）
    }
    try {
        const RelayFrame ack = DecodeRelayFrame(raw.payload);
        const RelayFrameKind want = last_request_kind_ ==
                                            static_cast<uint64_t>(RelayFrameKind::kPhase1Batch)
                                        ? RelayFrameKind::kPhase1Ack
                                        : RelayFrameKind::kPhase2Ack;
        if (ack.kind != want) {
            return Response::Err(std::string("MPA-08 相位回执类型不符：期望 ") +
                                 RelayFrameKindName(want) + "，实际 " +
                                 RelayFrameKindName(ack.kind));
        }
        // 服务器**自报**的"本轮实际处理的子消息数"：记账 + 与期望条数比对
        if (want == RelayFrameKind::kPhase1Ack) {
            processed_phase1_ = ack.count;
        } else {
            processed_phase2_ = ack.count;
        }
        if (expected_records_ != 0 && ack.count != expected_records_) {
            return Response::Err("MPA-08 相位回执条数不符：服务器报 " + Num(ack.count) +
                                 "，本轮应有 " + Num(expected_records_) + " 条");
        }
        return Response::Ok(ack.payload);
    } catch (const std::exception& e) {
        // ⚠️ 解封套失败**必须**变成错误（绝不返回空 payload 冒充成功）
        return Response::Err(std::string("MPA-08 相位回执解析失败: ") + e.what());
    }
}

ServerStats QueryServerStats(ITransportClient& client, int server_id) {
    const Payload frame = EncodeRelayFrame(RelayFrameKind::kStatsRequest, 0, Payload{});
    const Response raw = client.RoundTrip(server_id, frame);
    if (!raw.ok) {
        throw std::runtime_error("MPA-08 账目查询失败（服务器 " +
                                 Num(static_cast<uint64_t>(server_id)) + "）: " + raw.error);
    }
    const RelayFrame ack = DecodeRelayFrame(raw.payload);
    if (ack.kind != RelayFrameKind::kStatsAck) {
        throw std::runtime_error(std::string("MPA-08 账目回执类型不符：") +
                                 RelayFrameKindName(ack.kind));
    }
    if (ack.count != kServerStatsFields ||
        ack.payload.size() != 8 * kServerStatsFields) {
        throw std::runtime_error("MPA-08 账目回执长度不符（count=" + Num(ack.count) +
                                 "，payload=" + Num(ack.payload.size()) + " B）");
    }
    uint64_t v[kServerStatsFields];
    for (size_t i = 0; i < kServerStatsFields; ++i) {
        v[i] = ReadU64LE(ack.payload.data() + 8 * i);
    }
    ServerStats s;
    s.initialized = v[0] != 0;
    s.storage_bytes = v[1];
    s.feature_storage_bytes = v[2];
    s.attribute_storage_bytes = v[3];
    s.rpc_count = v[4];
    s.queries_served = v[5];
    s.words_read = v[6];
    s.batch_rpc_count = v[7];
    s.relay_install_frames = v[8];
    s.relay_phase_frames = v[9];
    s.relay_records_processed = v[10];
    s.node_scalar_rpc_count = v[11];
    s.node_batch_rpc_count = v[12];
    s.service_batch_resp_calls = v[13];
    return s;
}

// ---------------------------------------------------------------------------
// MpraqDemoService
// ---------------------------------------------------------------------------

MpraqDemoService::MpraqDemoService(MpraqNode& node) : node_(&node), data_(node) {}

grpc::Status MpraqDemoService::InitTable(grpc::ServerContext* ctx,
                                         const ::mpraqwire::InitTableRequest* req,
                                         ::mpraqwire::InitTableResponse* resp) {
    return data_.InitTable(ctx, req, resp);
}

grpc::Status MpraqDemoService::UploadFeatureWords(
    grpc::ServerContext* ctx, const ::mpraqwire::UploadFeatureWordsRequest* req,
    ::mpraqwire::UploadFeatureWordsResponse* resp) {
    return data_.UploadFeatureWords(ctx, req, resp);
}

grpc::Status MpraqDemoService::SetAttributeShares(
    grpc::ServerContext* ctx, const ::mpraqwire::SetAttributeSharesRequest* req,
    ::mpraqwire::SetAttributeSharesResponse* resp) {
    return data_.SetAttributeShares(ctx, req, resp);
}

grpc::Status MpraqDemoService::ServerResp(grpc::ServerContext* ctx,
                                          const ::mpraqwire::PirQueryRequest* req,
                                          ::mpraqwire::PirQueryResponse* resp) {
    return data_.ServerResp(ctx, req, resp);
}

grpc::Status MpraqDemoService::Relay(grpc::ServerContext*,
                                     const ::mpraqwire::RelayRequest* req,
                                     ::mpraqwire::RelayResponse* resp) {
    relay_calls_.fetch_add(1, std::memory_order_relaxed);
    const Payload in(req->payload().begin(), req->payload().end());
    try {
        // 账目类请求在这里就地处理（它需要节点，而 `MpraqSecureMulServer` 不持有节点）
        const RelayFrame f = DecodeRelayFrame(in);
        if (f.kind == RelayFrameKind::kStatsRequest) {
            const ServerStats s = Stats();
            Payload payload;
            payload.reserve(8 * kServerStatsFields);
            WriteU64LE(s.initialized ? 1 : 0, &payload);
            WriteU64LE(s.storage_bytes, &payload);
            WriteU64LE(s.feature_storage_bytes, &payload);
            WriteU64LE(s.attribute_storage_bytes, &payload);
            WriteU64LE(s.rpc_count, &payload);
            WriteU64LE(s.queries_served, &payload);
            WriteU64LE(s.words_read, &payload);
            WriteU64LE(s.batch_rpc_count, &payload);
            WriteU64LE(s.relay_install_frames, &payload);
            WriteU64LE(s.relay_phase_frames, &payload);
            WriteU64LE(s.relay_records_processed, &payload);
            WriteU64LE(s.node_scalar_rpc_count, &payload);
            WriteU64LE(s.node_batch_rpc_count, &payload);
            WriteU64LE(s.service_batch_resp_calls, &payload);
            const Payload out = EncodeRelayFrame(
                RelayFrameKind::kStatsAck, static_cast<uint32_t>(kServerStatsFields), payload);
            resp->set_ok(true);
            resp->set_payload(std::string(reinterpret_cast<const char*>(out.data()), out.size()));
            return grpc::Status::OK;
        }
        const Payload out = securemul_.Handle(in);
        resp->set_ok(true);
        resp->set_payload(out.empty()
                              ? std::string()
                              : std::string(reinterpret_cast<const char*>(out.data()),
                                            out.size()));
        return grpc::Status::OK;
    } catch (const std::exception& e) {
        // 与 `net/transport.hpp` 的约定一致：handler 抛异常 ⇒ 错误必须**可表达**
        relay_errors_.fetch_add(1, std::memory_order_relaxed);
        resp->set_ok(false);
        resp->set_error(std::string("MPA-08 服务器 Relay 拒绝: ") + e.what());
        return grpc::Status::OK;
    } catch (...) {
        relay_errors_.fetch_add(1, std::memory_order_relaxed);
        resp->set_ok(false);
        resp->set_error("MPA-08 服务器 Relay 抛出未知异常");
        return grpc::Status::OK;
    }
}

ServerStats MpraqDemoService::Stats() const {
    ServerStats s;
    s.initialized = node_->initialized();
    if (s.initialized) {
        s.storage_bytes = node_->StorageBytes();
        s.feature_storage_bytes = node_->FeatureStorageBytes();
        s.attribute_storage_bytes = node_->AttributeStorageBytes();
    }
    s.rpc_count = data_.rpc_count();
    s.queries_served = data_.queries_served();
    s.words_read = node_->words_read();
    s.batch_rpc_count = node_->batch_rpc_count();
    s.node_scalar_rpc_count = node_->rpc_count();
    s.node_batch_rpc_count = node_->batch_rpc_count();
    s.service_batch_resp_calls = data_.batch_rpc_count();
    s.relay_install_frames = securemul_.install_frames();
    s.relay_phase_frames = securemul_.phase_frames();
    s.relay_records_processed = securemul_.phase_records();
    return s;
}

}  // namespace mpraq
}  // namespace tsb
