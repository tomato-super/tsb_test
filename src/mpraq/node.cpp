#include "mpraq/node.hpp"

#include <algorithm>
#include <cstdio>
#include <sstream>

namespace tsb {
namespace mpraq {

namespace {

std::string Num(uint64_t v) { return std::to_string(v); }

// 属性在错误信息里的可读标签
std::string AttrLabel(const StoreAttribute& a) {
    return "属性 " + std::to_string(a.id) + "(\"" + a.name + "\")";
}

}  // namespace

// ---------------------------------------------------------------------------
// StoreParams
// ---------------------------------------------------------------------------

void StoreParams::Validate() const {
    if (num_records == 0) {
        throw std::invalid_argument(
            "StoreParams: num_records (N) 必须 >= 1（N=0 时特征表为空，"
            "LCTE 表与 PIR 数据库都没有意义）");
    }
    if (words_per_column != (num_records + 127) / 128) {
        throw std::invalid_argument(
            "StoreParams: words_per_column 必须等于 ⌈N/128⌉ = " +
            Num((num_records + 127) / 128) + "（实际 " + Num(words_per_column) + "）");
    }
    if (column_count == 0) {
        throw std::invalid_argument("StoreParams: column_count 必须 >= 1");
    }
    if (real_column_count == 0 || real_column_count > column_count) {
        throw std::invalid_argument(
            "StoreParams: 必须满足 0 < real_column_count <= column_count（实际 " +
            Num(real_column_count) + " / " + Num(column_count) + "）");
    }
    if (attrs.empty()) {
        throw std::invalid_argument("StoreParams: 至少要有一个属性");
    }
    if (attrs.size() > static_cast<size_t>(UINT32_MAX)) {
        throw std::invalid_argument("StoreParams: 属性数过多");
    }
    size_t base = 0;
    for (size_t a = 0; a < attrs.size(); ++a) {
        const StoreAttribute& s = attrs[a];
        if (s.id != a) {
            throw std::invalid_argument(
                "StoreParams: 属性必须按 id = 0,1,2,... 连续编号（第 " + Num(a) +
                " 个属性的 id 是 " + Num(s.id) + "）");
        }
        if (s.lcte.range_size == 0) {
            throw std::invalid_argument("StoreParams: " + AttrLabel(s) +
                                        " 的 lcte.range_size 必须 >= 1");
        }
        if (s.domain_min > s.domain_max) {
            throw std::invalid_argument("StoreParams: " + AttrLabel(s) +
                                        " 的取值域倒置（domain_min > domain_max）");
        }
        base += s.lcte.range_size;
    }
    if (base != real_column_count) {
        throw std::invalid_argument(
            "StoreParams: real_column_count 必须等于 Σ_a lcte.range_size = " +
            Num(base) + "（实际 " + Num(real_column_count) + "）");
    }
    // PIR 几何：n 必须是本表真实的 word 数（D24④），且几何合法（D21/D15(a)）
    if (plinko.n != entry_count()) {
        throw std::invalid_argument(
            "StoreParams: plinko.n 必须等于条目数 column_count·⌈N/128⌉ = " +
            Num(entry_count()) + "（实际 " + Num(plinko.n) +
            "）。⚠️ PIR 的 n 是 **word 数**（D24④），不是记录数 N = " + Num(num_records) + "。");
    }
    plinko.Validate();
}

size_t StoreParams::column_base(uint32_t attr_id) const {
    if (attr_id >= attrs.size()) {
        throw std::out_of_range("StoreParams::column_base: 属性号越界 " + Num(attr_id) +
                                "（共 " + Num(attrs.size()) + " 个属性）");
    }
    size_t base = 0;
    for (uint32_t a = 0; a < attr_id; ++a) base += attrs[a].lcte.range_size;
    return base;
}

size_t StoreParams::global_column(uint32_t attr_id, uint32_t column) const {
    if (attr_id >= attrs.size()) {
        throw std::out_of_range("StoreParams::global_column: 属性号越界 " + Num(attr_id) +
                                "（共 " + Num(attrs.size()) + " 个属性）");
    }
    const StoreAttribute& s = attrs[attr_id];
    if (column >= s.lcte.range_size) {
        throw std::out_of_range(
            "StoreParams::global_column: " + AttrLabel(s) + " 的列号越界 " + Num(column) +
            "（该属性的 lcte.range_size = " + Num(s.lcte.range_size) + "）");
    }
    return column_base(attr_id) + column;
}

uint64_t StoreParams::ColWordIndex(uint32_t attr_id, uint32_t column, size_t word) const {
    return ColWordIndex(global_column(attr_id, column), word);
}

uint64_t StoreParams::ColWordIndex(size_t global_column, size_t word) const {
    if (global_column >= column_count) {
        throw std::out_of_range("StoreParams::ColWordIndex: 全局列号越界 " +
                                Num(global_column) + "（共 " + Num(column_count) + " 列）");
    }
    if (word >= words_per_column) {
        throw std::out_of_range("StoreParams::ColWordIndex: word 序号越界 " + Num(word) +
                                "（每列 " + Num(words_per_column) + " 个 word）");
    }
    // ⚠️ **列主序**：条目号 = 全局列号 · ⌈N/128⌉ + word 序号（MPRAQ_IMPL.md §1）。
    //    写成行主序（word · columns + column）会静默取错条目："取一整列"不再是连续段。
    return static_cast<uint64_t>(global_column) * words_per_column + word;
}

// ---------------------------------------------------------------------------
// MpraqNode
// ---------------------------------------------------------------------------

void MpraqNode::InitTable(const StoreParams& params) {
    params.Validate();
    params_ = params;

    words_.assign(static_cast<size_t>(params_.entry_count()), 0);
    attr_shares_.assign(params_.attrs.size(),
                        std::vector<ModShare>(params_.num_records, ModShare{0}));

    rpc_count_ = 0;
    batch_rpc_count_ = 0;
    queries_served_ = 0;
    words_read_ = 0;
    inited_ = true;
}

void MpraqNode::UploadFeatureWords(uint64_t base_index,
                                   const std::vector<uint128_t>& words, size_t count) {
    if (!inited_) {
        throw std::logic_error("MpraqNode::UploadFeatureWords: 尚未 InitTable");
    }
    if (count != words.size()) {
        throw std::invalid_argument(
            "MpraqNode::UploadFeatureWords: count=" + Num(count) + " 与 words.size()=" +
            Num(words.size()) + " 不一致（调用方算错了分块长度）");
    }
    if (count == 0) {
        throw std::invalid_argument("MpraqNode::UploadFeatureWords: 分块长度不能为 0");
    }
    // ⚠️ 先算上界再校验：早先的实现直接 `words_[base + i] = ...`，base+count 越界时
    //    是**堆越界写**（静默破坏内存），而不是异常。
    if (base_index >= words_.size() || count > words_.size() - base_index) {
        throw std::out_of_range(
            "MpraqNode::UploadFeatureWords: 上传区间越界 [base=" + Num(base_index) +
            ", count=" + Num(count) + ") vs 条目数 " + Num(words_.size()) +
            "（条目数 = columns·⌈N/128⌉ = " + Num(params_.column_count) + "·" +
            Num(params_.words_per_column) + "）");
    }
    std::copy(words.begin(), words.begin() + static_cast<ptrdiff_t>(count),
              words_.begin() + static_cast<ptrdiff_t>(base_index));
}

void MpraqNode::SetAttributeShares(uint32_t attr_id,
                                   const std::vector<ModShare>& shares) {
    if (!inited_) {
        throw std::logic_error("MpraqNode::SetAttributeShares: 尚未 InitTable");
    }
    if (attr_id >= attr_shares_.size()) {
        throw std::out_of_range("MpraqNode::SetAttributeShares: 属性号越界 " +
                                Num(attr_id) + "（共 " + Num(attr_shares_.size()) +
                                " 个属性）");
    }
    if (shares.size() != params_.num_records) {
        throw std::invalid_argument(
            "MpraqNode::SetAttributeShares: 共享向量长度必须等于 N = " +
            Num(params_.num_records) + "（实际 " + Num(shares.size()) + "）");
    }
    // mod q 加法共享的分量必须落在 [0, q) —— 越界分量会让 ReconstructMod 静默错值
    for (size_t i = 0; i < shares.size(); ++i) {
        if (shares[i].value >= kMpraqModulus) {
            throw std::out_of_range(
                "MpraqNode::SetAttributeShares: 属性 " + Num(attr_id) + " 第 " + Num(i) +
                " 个共享分量 >= q = 2^127−1（共享必须已在 mod q 域内）");
        }
    }
    attr_shares_[attr_id] = shares;  // ⚠️ 长度已校验：绝不隐式创建/扩容空 vector
}

void MpraqNode::ValidateQuery(const PlinkoQuery& q) const {
    if (!inited_) {
        throw std::logic_error("MpraqNode: 尚未 InitTable");
    }
    if (params_.plinko.block_count() != q.blocks ||
        params_.plinko.w != q.block_size) {
        throw std::invalid_argument(
            "MpraqNode: 查询几何与数据库不符（查询 c=" + Num(q.blocks) +
            ", w=" + Num(q.block_size) + "；数据库 c=" +
            Num(params_.plinko.block_count()) + ", w=" + Num(params_.plinko.w) + "）");
    }
    if (!q.well_formed()) {
        throw std::invalid_argument(
            "MpraqNode: 查询格式非法（offsets/groups 长度须为 c，"
            "偏移须 < w，分组比特须为 0/1）");
    }
}

PlinkoAnswer MpraqNode::AnswerOne(const PlinkoQuery& q) const {
    // 在**本方 XOR 共享**上做分组累加（`PlinkoClient::ServerRespShared`）。
    // 服务器看不到 hint、看不到 parity，也看不到目标索引。
    return PlinkoClient::ServerRespShared(
        q, [this](uint64_t i) -> uint128_t { return words_[static_cast<size_t>(i)]; });
}

PlinkoAnswer MpraqNode::ServerResp(const PlinkoQuery& q) const {
    ValidateQuery(q);
    ++rpc_count_;  // ⚠️ 只统计**标量**路径；批量路径走 batch_rpc_count_
    // D31：`queries_served` 数的是**查询集个数**（与 `grpc_mpraq` 通道、`node.hpp` 注释、
    //      `MpraqClient::channel_rpc_stats().queries` 同口径）；区块/word 访问量归 `words_read`。
    queries_served_ += 1;
    // 每个区块读 1 个 word ⇒ 读到的条目数 = c = blocks（与 w 无关，因为 w 是
    // "每区块的 **word** 数"这一几何量，不是记录数 —— D24④ 的静默错 128 倍陷阱）。
    words_read_ += q.blocks;
    return AnswerOne(q);
}

std::vector<PlinkoAnswer> MpraqNode::ServerRespBatch(
    const std::vector<PlinkoQuery>& qs) const {
    if (qs.empty()) {
        throw std::invalid_argument(
            "MpraqNode::ServerRespBatch: 批次不能为空（一次「整批」调用至少要有一个查询集）");
    }
    if (!inited_) {
        throw std::logic_error("MpraqNode::ServerRespBatch: 尚未 InitTable");
    }
    // ① **先整批校验**：非法批次要么整批 abort、要么整批成功，绝不返回部分结果
    for (const PlinkoQuery& q : qs) ValidateQuery(q);
    // ② 计数：一次批量调用 = 一次"往返"；`queries_served` 按 D31 记**查询集个数**
    ++batch_rpc_count_;
    for (const PlinkoQuery& q : qs) {
        queries_served_ += 1;      // D31：查询集个数（不是区块数）
        words_read_ += q.blocks;   // 区块/word 访问量
    }
    std::vector<PlinkoAnswer> out;
    out.reserve(qs.size());
    for (const PlinkoQuery& q : qs) out.push_back(AnswerOne(q));
    return out;
}

uint128_t MpraqNode::FeatureWord(uint64_t i) const {
    if (i >= words_.size()) {
        throw std::out_of_range("MpraqNode::FeatureWord: 条目号越界 " + Num(i) +
                                "（共 " + Num(words_.size()) + " 个 word）");
    }
    return words_[static_cast<size_t>(i)];
}

ModShare MpraqNode::AttributeShare(uint32_t attr_id, size_t record) const {
    if (attr_id >= attr_shares_.size()) {
        throw std::out_of_range("MpraqNode::AttributeShare: 属性号越界 " + Num(attr_id));
    }
    if (record >= params_.num_records) {
        throw std::out_of_range("MpraqNode::AttributeShare: 记录号越界 " + Num(record));
    }
    return attr_shares_[attr_id][record];
}

uint64_t MpraqNode::FeatureStorageBytes() const {
    // 16 B/word × columns × ⌈N/128⌉（**含补齐列**）
    return static_cast<uint64_t>(kUint128Bytes) * words_.size();
}

uint64_t MpraqNode::AttributeStorageBytes() const {
    return static_cast<uint64_t>(kUint128Bytes) * params_.num_records *
           attr_shares_.size();
}

uint64_t MpraqNode::StorageBytes() const {
    return FeatureStorageBytes() + AttributeStorageBytes();
}

void MpraqNode::Clear() {
    inited_ = false;
    params_ = StoreParams{};
    words_.clear();
    words_.shrink_to_fit();
    attr_shares_.clear();
    attr_shares_.shrink_to_fit();
    rpc_count_ = 0;
    batch_rpc_count_ = 0;
    queries_served_ = 0;
    words_read_ = 0;
}

// ---------------------------------------------------------------------------
// 远程占位通道
// ---------------------------------------------------------------------------
//
// ⚠️ 这里原本有一个 `WarnUnbatchedServerResp()`（"`ServerRespBatch` 走了退化默认实现"
//    的一次性告警）。`MPA-08` 裁决 2（2026-09-10）把 `ServerRespBatch` 改成**纯虚**后
//    "默认实现被触发"这一状态在类型层面已不可能存在 ⇒ 该函数**删除**（不再有调用点；
//    留着会让人误以为仍有退化路径）。详见 `node.hpp` 的接口注释。

void PlaceholderRemoteMpraqChannel::Unsupported(const char* what) const {
    std::ostringstream oss;
    oss << "PlaceholderRemoteMpraqChannel: 远程 MPRAQ 通道尚未实现（" << what
        << "）。真正的 gRPC 通道是 MPA-08（需要 proto/mpraq.proto + 语义为 MPRAQ 的"
           "一次 RPC 携带全部列的全部查询集）。endpoint=\"" << endpoint_ << "\"。"
           "⚠️ 本占位**绝不**静默退化成本地调用 —— 请使用 LocalMpraqChannel。";
    throw RemoteMpraqChannelNotImplemented(oss.str());
}

void PlaceholderRemoteMpraqChannel::Connect() { Unsupported("Connect"); }
void PlaceholderRemoteMpraqChannel::InitTable(const StoreParams&) {
    Unsupported("InitTable");
}
void PlaceholderRemoteMpraqChannel::UploadFeatureWords(uint64_t,
                                                       const std::vector<uint128_t>&,
                                                       size_t) {
    Unsupported("UploadFeatureWords");
}
void PlaceholderRemoteMpraqChannel::SetAttributeShares(uint32_t,
                                                       const std::vector<ModShare>&) {
    Unsupported("SetAttributeShares");
}
PlinkoAnswer PlaceholderRemoteMpraqChannel::ServerResp(const PlinkoQuery&) {
    Unsupported("ServerResp");
}
std::vector<PlinkoAnswer> PlaceholderRemoteMpraqChannel::ServerRespBatch(
    const std::vector<PlinkoQuery>&) {
    Unsupported("ServerRespBatch");
}

}  // namespace mpraq
}  // namespace tsb
