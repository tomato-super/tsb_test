#include "net/grpc_vmpq.hpp"

#include <cstring>
#include <stdexcept>

namespace tsb {

namespace {

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

// ---- 向量条目编解码（决策 D38）----
//
// 一个条目 = entry_words 个 128 位分量；`PirAnswer.acc0/acc1` 与
// `UploadEntriesRequest.entries` 都按**串接小端**承载（每分量 16 字节）。

std::string ToBytesVec(const std::vector<uint128_t>& v) {
    std::string out;
    out.resize(v.size() * kUint128Bytes);
    for (size_t i = 0; i < v.size(); ++i) {
        uint8_t buf[kUint128Bytes];
        toBytesLE(v[i], buf);
        std::memcpy(&out[i * kUint128Bytes], buf, kUint128Bytes);
    }
    return out;
}

std::vector<uint128_t> FromBytesVec(const std::string& s, uint64_t words) {
    if (s.size() != words * kUint128Bytes) {
        throw std::invalid_argument(
            "期望 " + std::to_string(words * kUint128Bytes) +
            " 字节的向量条目编码（entry_words=" + std::to_string(words) +
            "），实际 " + std::to_string(s.size()) + " 字节");
    }
    std::vector<uint128_t> v(static_cast<size_t>(words));
    for (uint64_t i = 0; i < words; ++i) {
        v[i] = fromBytesLE(reinterpret_cast<const uint8_t*>(s.data()) +
                           i * kUint128Bytes);
    }
    return v;
}

}  // namespace

// ---------------------------------------------------------------------------
// VmpqServiceImpl
// ---------------------------------------------------------------------------

grpc::Status VmpqServiceImpl::InitTable(grpc::ServerContext*,
                                        const vmpq::InitTableRequest* req,
                                        vmpq::InitTableResponse* resp) {
    ++rpc_count_;
    try {
        std::vector<uint32_t> sizes(req->attr_sizes().begin(),
                                    req->attr_sizes().end());
        node_.InitTable(req->window_size(), sizes);
        resp->set_ok(true);
        return grpc::Status::OK;
    } catch (const std::exception& e) {
        resp->set_ok(false);
        resp->set_error(e.what());
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
}

grpc::Status VmpqServiceImpl::UploadEntries(
    grpc::ServerContext*, const vmpq::UploadEntriesRequest* req,
    vmpq::UploadEntriesResponse* resp) {
    ++rpc_count_;
    try {
        std::vector<uint128_t> entries;
        entries.reserve(req->entries_size());
        for (const auto& e : req->entries()) {
            entries.push_back(FromBytes(e));
        }
        node_.UploadEntries(req->base_index(), entries);
        resp->set_ok(true);
        return grpc::Status::OK;
    } catch (const std::exception& e) {
        resp->set_ok(false);
        resp->set_error(e.what());
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
}

grpc::Status VmpqServiceImpl::PirQuery(grpc::ServerContext*,
                                       const vmpq::PirQueryRequest* req,
                                       vmpq::PirQueryResponse* resp) {
    ++rpc_count_;
    try {
        // ⚠️ 决策 D38：服务端按 entry_words 校验条目宽度（必须等于本节点
        //    登记窗口大小 N），否则"每个查询集 = 一个条目"的口径就不成立。
        const uint64_t words = req->entry_words();
        const uint64_t n = node_.params().window_size;
        if (words != n) {
            throw std::invalid_argument(
                "PirQuery 被拒绝: entry_words=" + std::to_string(words) +
                " 与本服务器登记的 window_size=" + std::to_string(n) +
                " 不一致（决策 D38：一个条目 = 一整列 = N 个分量）");
        }
        std::vector<PirQuerySetData> queries;
        queries.reserve(req->queries_size());
        for (const auto& q : req->queries()) {
            PirQuerySetData d;
            d.offsets.assign(q.offsets().begin(), q.offsets().end());
            d.groups.assign(q.groups().begin(), q.groups().end());
            queries.push_back(std::move(d));
        }
        const std::vector<PirAnswerData> answers = node_.PirQuery(queries);
        queries_served_ += queries.size();
        for (const auto& a : answers) {
            auto* out = resp->add_answers();
            out->set_acc0(ToBytesVec(a.acc0));
            out->set_acc1(ToBytesVec(a.acc1));
        }
        return grpc::Status::OK;
    } catch (const std::exception& e) {
        resp->set_error(e.what());
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
}

// ---------------------------------------------------------------------------
// GrpcChannel
// ---------------------------------------------------------------------------

GrpcChannel::GrpcChannel(const std::string& target) {
    channel_ = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
    stub_ = vmpq::VmpqService::NewStub(channel_);
}

bool GrpcChannel::WaitForConnection(int timeout_ms) {
    return channel_->WaitForConnected(
        std::chrono::system_clock::now() + std::chrono::milliseconds(timeout_ms));
}

void GrpcChannel::InitTable(uint32_t window_size,
                            const std::vector<uint32_t>& attr_sizes) {
    vmpq::InitTableRequest req;
    req.set_window_size(window_size);
    for (uint32_t s : attr_sizes) {
        req.add_attr_sizes(s);
    }
    vmpq::InitTableResponse resp;
    grpc::ClientContext ctx;
    ++rpc_count_;
    const grpc::Status st = stub_->InitTable(&ctx, req, &resp);
    if (!st.ok()) {
        throw std::runtime_error("InitTable RPC 失败: " + st.error_message());
    }
    if (!resp.ok()) {
        throw std::runtime_error("InitTable 被拒绝: " + resp.error());
    }
    // 决策 D38：N 同时是条目宽度 entry_words，后续 PirQuery 用它填字段/解码
    window_size_ = window_size;
}

void GrpcChannel::UploadEntries(uint64_t base_entry,
                                const std::vector<uint128_t>& cells) {
    vmpq::UploadEntriesRequest req;
    req.set_base_index(base_entry);  // 条目号（决策 D38）
    for (uint128_t v : cells) {
        req.add_entries(ToBytes(v));
    }
    vmpq::UploadEntriesResponse resp;
    grpc::ClientContext ctx;
    ++rpc_count_;
    const grpc::Status st = stub_->UploadEntries(&ctx, req, &resp);
    if (!st.ok()) {
        throw std::runtime_error("UploadEntries RPC 失败: " + st.error_message());
    }
    if (!resp.ok()) {
        throw std::runtime_error("UploadEntries 被拒绝: " + resp.error());
    }
}

std::vector<PirAnswerData> GrpcChannel::PirQuery(
    const std::vector<PirQuerySetData>& queries) {
    vmpq::PirQueryRequest req;
    for (const auto& q : queries) {
        auto* set = req.add_queries();
        for (uint32_t o : q.offsets) set->add_offsets(o);
        for (uint32_t g : q.groups) set->add_groups(g);
    }
    // 每个条目的分量数（决策 D38：= InitTable 登记的 N）
    req.set_entry_words(window_size_);
    vmpq::PirQueryResponse resp;
    grpc::ClientContext ctx;
    ++rpc_count_;
    const grpc::Status st = stub_->PirQuery(&ctx, req, &resp);
    if (!st.ok()) {
        throw std::runtime_error("PirQuery RPC 失败: " + st.error_message());
    }
    if (!resp.error().empty()) {
        throw std::runtime_error("PirQuery 被拒绝: " + resp.error());
    }
    std::vector<PirAnswerData> out;
    out.reserve(resp.answers_size());
    for (const auto& a : resp.answers()) {
        PirAnswerData d;
        d.acc0 = FromBytesVec(a.acc0(), window_size_);
        d.acc1 = FromBytesVec(a.acc1(), window_size_);
        out.push_back(std::move(d));
    }
    return out;
}

// ---------------------------------------------------------------------------
// InProcessNode
// ---------------------------------------------------------------------------

InProcessNode::InProcessNode(const std::string& address) : impl_(node_) {
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

InProcessNode::~InProcessNode() {
    if (server_) {
        server_->Shutdown();
        server_->Wait();
    }
}

}  // namespace tsb
