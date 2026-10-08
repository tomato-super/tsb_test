#include "net/grpc_mpraq.hpp"

#include <cstring>
#include <stdexcept>
#include <vector>

#include "core/field.hpp"
// `MPA-09` 任务 B：客户端收包上限的**唯一权威定义**（两侧必须成对设置）
#include "net/grpc_transport.hpp"

namespace tsb {

namespace {

// ---------------------------------------------------------------------------
// 字节编码约定（**与 `grpc_vmpq.cpp` 的 ToBytes/FromBytes 逐字同约定**）
// ---------------------------------------------------------------------------
// 线上每个 16 字节元素都是 `uint128` 的**小端**定长编码：
//   * 写：`toBytesLE(v, buf)`（低位字节在前）；
//   * 读：`fromBytesLE(buf)`，并且**严格校验长度**（16 字节以外一律抛异常，
//     绝不"取前 16 字节"或补零 —— 那会让长度错误静默变成错值）。
// 属性值的 `ModShare` 用**同一个** 16 字节小端编码（它是 `uint128_t` 的强类型
// 包装，`mod q = 2^127−1` 的加法共享），因此接收侧必须显式检查 `< q`。

std::string ToBytes(uint128_t v) {
    uint8_t buf[kUint128Bytes];
    toBytesLE(v, buf);
    return std::string(reinterpret_cast<const char*>(buf), kUint128Bytes);
}

uint128_t FromBytes(const std::string& s) {
    if (s.size() != kUint128Bytes) {
        throw std::invalid_argument("期望 16 字节的 uint128 编码，实际 " +
                                    std::to_string(s.size()) + " 字节");
    }
    return fromBytesLE(reinterpret_cast<const uint8_t*>(s.data()));
}

std::string ShareToBytes(const ModShare& s) { return ToBytes(s.value); }

// ---- 整条目（一个条目 = 一整列 = entry_words 个字）的编解码 ----
// ⚠️ 串接小端：第 j 个字在 [j*16, (j+1)*16)。长度必须是 16 的整数倍，
//    且调用方按 `entry_words` 校验（不变量 I4：宽度不符即拒绝）。
std::string EntryToBytes(const PlinkoEntry& e) {
    std::string out;
    out.reserve(e.size() * kUint128Bytes);
    for (uint128_t w : e) out += ToBytes(w);
    return out;
}

PlinkoEntry EntryFromBytes(const std::string& s, size_t expect_words) {
    if (s.size() % kUint128Bytes != 0) {
        throw std::invalid_argument("整条目编码长度必须 16 的整数倍，实际 " +
                                    std::to_string(s.size()) + " 字节");
    }
    const size_t words = s.size() / kUint128Bytes;
    if (words != expect_words) {
        throw std::invalid_argument(
            "整条目宽度不符（不变量 I4）：期望 " + std::to_string(expect_words) +
            " 个字，实际 " + std::to_string(words) + " 个字");
    }
    PlinkoEntry e(words, 0);
    for (size_t j = 0; j < words; ++j) {
        e[j] = FromBytes(s.substr(j * kUint128Bytes, kUint128Bytes));
    }
    return e;
}

ModShare ShareFromBytes(const std::string& s, uint32_t attr_id, size_t index) {
    const uint128_t v = FromBytes(s);
    if (v >= mpraq::kMpraqModulus) {
        throw std::out_of_range(
            "SetAttributeShares: 属性 " + std::to_string(attr_id) + " 第 " +
            std::to_string(index) + " 个共享分量 >= q = 2^127−1（加法共享必须已在 mod q 域内，"
            "否则 ReconstructMod 会静默错值）");
    }
    return ModShare{v};
}

// `StoreParamsProto` → `StoreParams`。
// ⚠️ **不在这里做几何推导**：客户端的 `StoreParams` 是权威（服务器按它分配存储），
//    但所有合法性都由 `StoreParams::Validate()` + `PlinkoParams::Validate()` 复核，
//    因此"客户端报错的几何"会在 InitTable 阶段被拒绝，而不是留到查询时静默错值。
mpraq::StoreParams FromProto(const ::mpraqwire::StoreParamsProto& p) {
    mpraq::StoreParams out;
    out.n = static_cast<size_t>(p.n());
    out.entry_words = static_cast<size_t>(p.entry_words());
    out.m = static_cast<size_t>(p.m());
    out.levels = static_cast<size_t>(p.levels());
    out.plinko.m = p.plinko().m();
    out.plinko.entry_words = p.plinko().entry_words();
    out.plinko.w = p.plinko().w();
    out.plinko.lambda = p.plinko().lambda();
    out.plinko.prp_epsilon = p.plinko().prp_epsilon();
    // ⚠️ 线协议版本：**不匹配即拒绝**（D41 前后几何字段语义不同 ⇒ 静默按错口径解析会错值）
    if (p.protocol_version() != kMpraqWireProtocolVersion) {
        throw std::invalid_argument(
            "StoreParamsProto.protocol_version = " + std::to_string(p.protocol_version()) +
            " 与本端期望的 " + std::to_string(kMpraqWireProtocolVersion) +
            " 不符（1 = word 粒度、2 = 列粒度/D41、3 = 列粒度 + xmac tag）"
            "—— 拒绝按错口径解析，请两端一起重编译");
    }
    // ⚠️ 档位编码必须落在已知档位上（`static_cast` 对任意整数都能过 ⇒ 非法值会静默错路）
    out.security_mode = mpraq::MpraqSecurityModeFromRaw(p.security_mode());
    out.attrs.clear();
    out.attrs.reserve(static_cast<size_t>(p.attrs_size()));
    for (const auto& a : p.attrs()) {
        mpraq::StoreAttribute s;
        s.name = a.name();
        s.id = a.id();
        s.lcte.range_min = a.lcte().range_min();
        s.lcte.range_size = a.lcte().range_size();
        s.lcte.window_size = a.lcte().window_size();
        s.domain_min = a.domain_min();
        s.domain_max = a.domain_max();
        out.attrs.push_back(std::move(s));
    }
    return out;
}

// `StoreParams` → `StoreParamsProto`（客户端侧）
void ToProto(const mpraq::StoreParams& in, ::mpraqwire::StoreParamsProto* p) {
    p->Clear();
    p->set_n(in.n);
    p->set_entry_words(in.entry_words);
    p->set_m(in.m);
    p->set_levels(in.levels);
    p->set_security_mode(static_cast<uint32_t>(in.security_mode));
    p->set_protocol_version(kMpraqWireProtocolVersion);
    auto* pl = p->mutable_plinko();
    pl->set_m(in.plinko.m);
    pl->set_entry_words(in.plinko.entry_words);
    pl->set_w(in.plinko.w);
    pl->set_lambda(in.plinko.lambda);
    pl->set_prp_epsilon(in.plinko.prp_epsilon);
    for (const mpraq::StoreAttribute& a : in.attrs) {
        auto* out = p->add_attrs();
        out->set_name(a.name);
        out->set_id(a.id);
        auto* l = out->mutable_lcte();
        l->set_range_min(a.lcte.range_min);
        l->set_range_size(a.lcte.range_size);
        l->set_window_size(a.lcte.window_size);
        out->set_domain_min(a.domain_min);
        out->set_domain_max(a.domain_max);
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// MpraqServiceImpl
// ---------------------------------------------------------------------------

grpc::Status MpraqServiceImpl::InitTable(grpc::ServerContext*,
                                        const ::mpraqwire::InitTableRequest* req,
                                        ::mpraqwire::InitTableResponse* resp) {
    try {
        const mpraq::StoreParams params = FromProto(req->params());
        node_.InitTable(params);
        rpc_count_.fetch_add(1, std::memory_order_relaxed);
        resp->set_ok(true);
        return grpc::Status::OK;
    } catch (const std::exception& e) {
        resp->set_ok(false);
        resp->set_error(e.what());
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
}

grpc::Status MpraqServiceImpl::UploadFeatureWords(
    grpc::ServerContext*, const ::mpraqwire::UploadFeatureWordsRequest* req,
    ::mpraqwire::UploadFeatureWordsResponse* resp) {
    try {
        std::vector<uint128_t> words;
        words.reserve(static_cast<size_t>(req->words_size()));
        for (const auto& w : req->words()) {
            words.push_back(FromBytes(w));
        }
        // count = words.size()：线上请求没有独立的 count 字段（它就是 words 的长度），
        // 因此这里不可能出现"count 与 words 长度不一致"这种客户端算错分块的情形。
        node_.UploadFeatureWords(req->base_index(), words, words.size());
        rpc_count_.fetch_add(1, std::memory_order_relaxed);
        resp->set_ok(true);
        return grpc::Status::OK;
    } catch (const std::exception& e) {
        resp->set_ok(false);
        resp->set_error(e.what());
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
}

grpc::Status MpraqServiceImpl::UploadFeatureTags(
    grpc::ServerContext*, const ::mpraqwire::UploadFeatureTagsRequest* req,
    ::mpraqwire::UploadFeatureTagsResponse* resp) {
    try {
        std::vector<uint128_t> tags;
        tags.reserve(static_cast<size_t>(req->tags_size()));
        for (const auto& t : req->tags()) {
            tags.push_back(FromBytes(t));
        }
        // 与数据侧同规则；服务端会拒绝"半诚实档却上传 tag"（该档没有 tag 表）。
        node_.UploadFeatureTags(req->base_index(), tags, tags.size());
        rpc_count_.fetch_add(1, std::memory_order_relaxed);
        resp->set_ok(true);
        return grpc::Status::OK;
    } catch (const std::exception& e) {
        resp->set_ok(false);
        resp->set_error(e.what());
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
}

grpc::Status MpraqServiceImpl::SetAttributeShares(
    grpc::ServerContext*, const ::mpraqwire::SetAttributeSharesRequest* req,
    ::mpraqwire::SetAttributeSharesResponse* resp) {
    try {
        std::vector<ModShare> shares;
        shares.reserve(static_cast<size_t>(req->shares_size()));
        for (int i = 0; i < req->shares_size(); ++i) {
            shares.push_back(ShareFromBytes(req->shares(i), req->attr_id(),
                                            static_cast<size_t>(i)));
        }
        node_.SetAttributeShares(req->attr_id(), shares);
        rpc_count_.fetch_add(1, std::memory_order_relaxed);
        resp->set_ok(true);
        return grpc::Status::OK;
    } catch (const std::exception& e) {
        resp->set_ok(false);
        resp->set_error(e.what());
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
}

grpc::Status MpraqServiceImpl::ServerResp(grpc::ServerContext*,
                                         const ::mpraqwire::PirQueryRequest* req,
                                         ::mpraqwire::PirQueryResponse* resp) {
    try {
        // ⚠️ 一次请求里的多个查询集**共用同一份几何**（同一批查询来自同一客户端、
        //    同一张表）；`PlinkoQuery` 本身是"单查询 + 几何"，因此这里逐个查询集
        //    构造，再整批交给批量入口。
        //
        // ⚠️ `MPA-08` 裁决 1（2026-09-10）：整批**一次**装进 `std::vector`，
        //    然后**只调一次** `MpraqNode::ServerRespBatch`（此前是逐条调标量
        //    `MpraqNode::ServerResp`）⇒ 服务侧 `batch_rpc_count()` 每 RPC +1，
        //    node 层 `batch_rpc_count()` 也能反映"一次 RPC = 一次批量调用"。
        //    可观测语义不变：`ServerRespBatch` 内部先**整批校验**、再逐条
        //    `AnswerOne`，应答的内容/顺序/条数与标量路径逐位相同
        //    （`test_mpraq_grpc` 的 `OneRpcIsExactlyOneBatchCallOnServerSide` 有对照）。
        if (req->queries_size() <= 0) {
            // 空批次没有语义：旧实现在这里会**静默返回 0 条应答**（看起来"成功"），
            // 而 `MpraqNode::ServerRespBatch` 早已把空批次定义为非法
            // ⇒ 统一拒绝，绝不让"没有查询"冒充"查询成功"。
            throw std::invalid_argument(
                "ServerResp: queries 为空 —— 一次请求至少携带一个查询集"
                "（空批没有语义；合法客户端在本地就会拒绝空批）");
        }
        std::vector<PlinkoQuery> qs;
        qs.reserve(static_cast<size_t>(req->queries_size()));
        for (const auto& set : req->queries()) {
            PlinkoQuery one;
            one.blocks = req->blocks();
            one.block_size = req->block_size();
            one.entry_words = req->entry_words();
            one.offsets.assign(set.offsets().begin(), set.offsets().end());
            one.groups.assign(set.groups().begin(), set.groups().end());
            qs.push_back(std::move(one));
        }
        // 越界/几何不符由 `MpraqNode::ServerRespBatch` 显式校验并抛异常
        // （**整批** abort：绝不静默截断、绝不返回部分结果）
        const std::vector<PlinkoAnswer> answers = node_.ServerRespBatch(qs);
        if (answers.size() != qs.size()) {
            throw std::logic_error("ServerResp: 批量入口的应答条数与请求不一致（" +
                                   std::to_string(answers.size()) + " vs " +
                                   std::to_string(qs.size()) + "）");
        }
        for (const PlinkoAnswer& a : answers) {
            auto* out = resp->add_answers();
            out->set_acc0(EntryToBytes(a.r0));
            out->set_acc1(EntryToBytes(a.r1));
            // xmac 的 tag 累加（**仅恶意档**）。半诚实档 `m0` 为空 ⇒ 这两个字段不设，
            // 客户端按档位判断"该有却没有" ⇒ 拒绝（不变量 I5 / 防静默降级）。
            if (a.has_tags()) {
                out->set_mac_acc0(EntryToBytes(a.m0));
                out->set_mac_acc1(EntryToBytes(a.m1));
            }
        }
        rpc_count_.fetch_add(1, std::memory_order_relaxed);
        batch_rpc_count_.fetch_add(1, std::memory_order_relaxed);  // 本 RPC **恰好**一次批量调用（不变量的落地位置）
        queries_served_.fetch_add(static_cast<uint64_t>(req->queries_size()),
                                std::memory_order_relaxed);
        return grpc::Status::OK;
    } catch (const std::exception& e) {
        resp->set_error(e.what());
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
}

// ---------------------------------------------------------------------------
// GrpcMpraqChannel
// ---------------------------------------------------------------------------

GrpcMpraqChannel::GrpcMpraqChannel(const std::string& target) : target_(target) {
    // 🔴 与 `GrpcTransportClient` 同一纪律（`MPA-09` 任务 B）：**显式**放宽收包上限，
    //    不用 gRPC 默认的 4 MiB。本通道的应答随"一次 `RunBatch` 的查询集数"增长
    //    （每查询集 2×16 B），默认值在超大批次下同样会失败；两侧口径必须一致。
    grpc::ChannelArguments args;
    args.SetMaxReceiveMessageSize(kGrpcClientMaxReceiveBytes);
    channel_ = grpc::CreateCustomChannel(target_, grpc::InsecureChannelCredentials(), args);
    stub_ = ::mpraqwire::MpraqService::NewStub(channel_);
}

bool GrpcMpraqChannel::WaitForConnection(int timeout_ms) {
    if (timeout_ms <= 0) {
        return channel_->GetState(/*try_to_connect=*/true) == GRPC_CHANNEL_READY;
    }
    return channel_->WaitForConnected(
        std::chrono::system_clock::now() + std::chrono::milliseconds(timeout_ms));
}

void GrpcMpraqChannel::Connect() {
    if (!WaitForConnection(5000)) {
        throw std::runtime_error("GrpcMpraqChannel::Connect: 无法连接到 " + target_ +
                                 "（5s 超时；服务器未启动或地址写错）");
    }
}

void GrpcMpraqChannel::InitTable(const mpraq::StoreParams& params) {
    ::mpraqwire::InitTableRequest req;
    ToProto(params, req.mutable_params());
    ::mpraqwire::InitTableResponse resp;
    grpc::ClientContext ctx;
    ++rpc_count_;
    const grpc::Status st = stub_->InitTable(&ctx, req, &resp);
    if (!st.ok()) {
        throw std::runtime_error("InitTable RPC 失败（" + target_ +
                                 "）: " + st.error_message() +
                                 (resp.error().empty() ? "" : " / " + resp.error()));
    }
    if (!resp.ok()) {
        throw std::runtime_error("InitTable 被拒绝（" + target_ + "）: " + resp.error());
    }
}

void GrpcMpraqChannel::UploadFeatureWords(uint64_t base_index,
                                         const std::vector<uint128_t>& words,
                                         size_t count) {
    // 与本地通道同一纪律：本地 `MpraqNode` 会拒绝 count != words.size()，
    // 远程通道必须在**发请求之前**拒绝，否则错误会被网络层掩盖成另一种错误。
    if (count != words.size()) {
        throw std::invalid_argument(
            "GrpcMpraqChannel::UploadFeatureWords: count=" + std::to_string(count) +
            " 与 words.size()=" + std::to_string(words.size()) + " 不一致");
    }
    ::mpraqwire::UploadFeatureWordsRequest req;
    req.set_base_index(base_index);
    for (uint128_t w : words) {
        req.add_words(ToBytes(w));
    }
    ::mpraqwire::UploadFeatureWordsResponse resp;
    grpc::ClientContext ctx;
    ++rpc_count_;
    const grpc::Status st = stub_->UploadFeatureWords(&ctx, req, &resp);
    if (!st.ok()) {
        throw std::runtime_error("UploadFeatureWords RPC 失败（" + target_ +
                                 "）: " + st.error_message() +
                                 (resp.error().empty() ? "" : " / " + resp.error()));
    }
    if (!resp.ok()) {
        throw std::runtime_error("UploadFeatureWords 被拒绝（" + target_ +
                                 "）: " + resp.error());
    }
}

void GrpcMpraqChannel::UploadFeatureTags(uint64_t base_index,
                                        const std::vector<uint128_t>& tags, size_t count) {
    // 与本地通道同一纪律：在**发请求之前**拒绝不一致的长度，
    // 否则错误会被网络层掩盖成另一种错误。
    if (count != tags.size()) {
        throw std::invalid_argument(
            "GrpcMpraqChannel::UploadFeatureTags: count=" + std::to_string(count) +
            " 与 tags.size()=" + std::to_string(tags.size()) + " 不一致");
    }
    ::mpraqwire::UploadFeatureTagsRequest req;
    req.set_base_index(base_index);
    for (uint128_t t : tags) {
        req.add_tags(ToBytes(t));
    }
    ::mpraqwire::UploadFeatureTagsResponse resp;
    grpc::ClientContext ctx;
    ++rpc_count_;
    const grpc::Status st = stub_->UploadFeatureTags(&ctx, req, &resp);
    if (!st.ok()) {
        throw std::runtime_error("UploadFeatureTags RPC 失败（" + target_ +
                                 "）: " + st.error_message() +
                                 (resp.error().empty() ? "" : " / " + resp.error()));
    }
    if (!resp.ok()) {
        throw std::runtime_error("UploadFeatureTags 被拒绝（" + target_ +
                                 "）: " + resp.error());
    }
}

void GrpcMpraqChannel::SetAttributeShares(uint32_t attr_id,
                                         const std::vector<ModShare>& shares) {
    ::mpraqwire::SetAttributeSharesRequest req;
    req.set_attr_id(attr_id);
    for (const ModShare& s : shares) {
        req.add_shares(ShareToBytes(s));
    }
    ::mpraqwire::SetAttributeSharesResponse resp;
    grpc::ClientContext ctx;
    ++rpc_count_;
    const grpc::Status st = stub_->SetAttributeShares(&ctx, req, &resp);
    if (!st.ok()) {
        throw std::runtime_error("SetAttributeShares RPC 失败（" + target_ +
                                 "）: " + st.error_message() +
                                 (resp.error().empty() ? "" : " / " + resp.error()));
    }
    if (!resp.ok()) {
        throw std::runtime_error("SetAttributeShares 被拒绝（" + target_ +
                                 "）: " + resp.error());
    }
}

PlinkoAnswer GrpcMpraqChannel::ServerResp(const PlinkoQuery& q) {
    const std::vector<PlinkoAnswer> answers = SendQuerySets({q}, /*is_batch=*/false);
    if (answers.size() != 1) {
        throw std::runtime_error("ServerResp（" + target_ + "）: 应答数量 " +
                                 std::to_string(answers.size()) + " != 1");
    }
    return answers[0];
}

std::vector<PlinkoAnswer> GrpcMpraqChannel::ServerRespBatch(
    const std::vector<PlinkoQuery>& qs) {
    if (qs.empty()) {
        throw std::invalid_argument(
            "GrpcMpraqChannel::ServerRespBatch: 查询集不能为空（空批没有语义）");
    }
    // ⚠️ 一次调用 = **一次** RPC（Q5 / `MPRAQ_IMPL.md` §3）。逐条发会让
    //    N = 2^14 的一列（128 个 word）退化成 128 次回环往返，正是本方法要避免的。
    return SendQuerySets(qs, /*is_batch=*/true);
}

std::vector<PlinkoAnswer> GrpcMpraqChannel::SendQuerySets(
    const std::vector<PlinkoQuery>& qs, bool is_batch) {
    if (qs.size() > 1) {
        // 一批里的所有查询集**必须共用同一份几何**：proto 的 `blocks`/`block_size`
        // 是请求级的（一次 RPC 只有一份几何）。不一致 ⇒ 说明上层把不同表/不同几何
        // 的查询混进了一批，当场报错，而不是发一个自相矛盾的请求出去。
        const uint64_t c = qs[0].blocks;
        const uint64_t w = qs[0].block_size;
        for (const PlinkoQuery& q : qs) {
            if (q.blocks != c || q.block_size != w) {
                throw std::invalid_argument(
                    "GrpcMpraqChannel::ServerRespBatch: 同一批里的查询集几何不一致"
                    "（c 与 w 必须相同；一次 RPC 只有一份请求级几何）");
            }
        }
    }
    ::mpraqwire::PirQueryRequest req;
    req.set_blocks(qs[0].blocks);
    req.set_block_size(qs[0].block_size);
    // ⚠️ 不变量 I4：条目宽度必须上线，服务端据此校验应答宽度（不符即拒绝）。
    req.set_entry_words(qs[0].entry_words);
    for (const PlinkoQuery& q : qs) {
        auto* set = req.add_queries();
        set->mutable_offsets()->Reserve(static_cast<int>(q.offsets.size()));
        for (uint64_t o : q.offsets) {
            set->add_offsets(static_cast<uint32_t>(o));
        }
        set->mutable_groups()->Reserve(static_cast<int>(q.groups.size()));
        for (uint8_t g : q.groups) {
            set->add_groups(g);
        }
    }
    ::mpraqwire::PirQueryResponse resp;
    grpc::ClientContext ctx;  // 每次 RPC 一个**新建的** ClientContext
    ++rpc_count_;
    // ⚠️ 口径由**入口**决定，不由批次大小决定（D28/Q5）：批量里 1 个查询集也是 1 次
    //    批量 RPC。曾经按 `qs.size() == 1` 反推 ⇒ "每批 1 个 word"的调用被记成标量，
    //    通道的 `server_resp_batch_calls()` 恒为 0（`test_mpraq_grpc` 抓到）。
    if (is_batch) {
        ++server_resp_batch_calls_;
    } else {
        ++server_resp_calls_;
    }
    const grpc::Status st = stub_->ServerResp(&ctx, req, &resp);
    if (!st.ok()) {
        throw std::runtime_error("ServerResp RPC 失败（" + target_ +
                                 "）: " + st.error_message() +
                                 (resp.error().empty() ? "" : " / " + resp.error()));
    }
    if (!resp.error().empty()) {
        throw std::runtime_error("ServerResp 被拒绝（" + target_ + "）: " + resp.error());
    }
    if (static_cast<size_t>(resp.answers_size()) != qs.size()) {
        throw std::runtime_error(
            "ServerResp 被拒绝（" + target_ + "）: 应答数量 " +
            std::to_string(resp.answers_size()) + " 与查询集数量 " +
            std::to_string(qs.size()) + " 不一致");
    }
    std::vector<PlinkoAnswer> out;
    out.reserve(qs.size());
    for (size_t i = 0; i < static_cast<size_t>(resp.answers_size()); ++i) {
        const auto& a = resp.answers(static_cast<int>(i));
        // ⚠️ 不变量 I4：按该查询集声明的 entry_words 校验应答宽度（不符即抛）
        const size_t ew = static_cast<size_t>(qs[i].entry_words);
        PlinkoAnswer one;
        one.r0 = EntryFromBytes(a.acc0(), ew);
        one.r1 = EntryFromBytes(a.acc1(), ew);
        // xmac 的 tag（**仅恶意档**存在）。两个字段**要么都有、要么都没有** ——
        // 只出现一个是"实现不一致"，直接拒绝，不在通道层做任何修补。
        const bool has0 = !a.mac_acc0().empty();
        const bool has1 = !a.mac_acc1().empty();
        if (has0 != has1) {
            throw std::runtime_error(
                "ServerRespBatch: 应答的 tag 字段只有一侧存在（mac_acc0/mac_acc1 不成对）"
                "—— 实现不一致，拒绝");
        }
        if (has0) {
            one.m0 = EntryFromBytes(a.mac_acc0(), ew);
            one.m1 = EntryFromBytes(a.mac_acc1(), ew);
        }
        out.push_back(std::move(one));
    }
    queries_served_ += static_cast<uint64_t>(qs.size());
    return out;
}

// ---------------------------------------------------------------------------
// InProcessMpraqNode
// ---------------------------------------------------------------------------

InProcessMpraqNode::InProcessMpraqNode(const std::string& address) : impl_(node_) {
    grpc::ServerBuilder builder;
    int bound = 0;
    builder.AddListeningPort(address, grpc::InsecureServerCredentials(), &bound);
    builder.RegisterService(&impl_);
    server_ = builder.BuildAndStart();
    if (server_ && bound != 0) {
        started_ = true;
        bound_port_ = std::to_string(bound);
    }
}

InProcessMpraqNode::~InProcessMpraqNode() {
    if (server_) {
        server_->Shutdown();
        server_->Wait();
    }
}

}  // namespace tsb
