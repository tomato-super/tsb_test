#include "vmpq/vmpq.hpp"

#include "core/random.hpp"
#include "shared/secret_sharing.hpp"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace tsb {

// ---------------------------------------------------------------------------
// 打包辅助
// ---------------------------------------------------------------------------

std::vector<uint128_t> PackColumn(const std::vector<uint8_t>& bits) {
    const size_t words = (bits.size() + 127) / 128;
    std::vector<uint128_t> out(words, 0);
    for (size_t i = 0; i < bits.size(); ++i) {
        if ((bits[i] & 1u) != 0) {
            out[i / 128] |= static_cast<uint128_t>(1) << (i % 128);
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// VmpqParams
// ---------------------------------------------------------------------------

uint64_t VmpqParams::TotalEntries() const {
    uint64_t total = 0;
    const uint32_t w = words_per_column();
    for (uint32_t size : attr_sizes) {
        total += static_cast<uint64_t>(size) * w;
    }
    return total;
}

uint64_t VmpqParams::PaddedEntries() const {
    const uint64_t n = TotalEntries();
    if (n == 0) return 0;
    uint64_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

void VmpqParams::Validate() const {
    if (window_size == 0) {
        throw std::invalid_argument("VmpqParams: window_size 必须 > 0");
    }
    if (attr_sizes.empty()) {
        throw std::invalid_argument("VmpqParams: 至少要有一个属性");
    }
    for (size_t i = 0; i < attr_sizes.size(); ++i) {
        const uint32_t s = attr_sizes[i];
        if (s < 2) {
            throw std::invalid_argument("VmpqParams: 属性 " + std::to_string(i) +
                                        " 的取值域必须 >= 2");
        }
        if ((s & (s - 1)) != 0) {
            throw std::invalid_argument("VmpqParams: 属性 " + std::to_string(i) +
                                        " 的取值域必须是 2 的幂");
        }
    }
    if (lambda == 0) {
        throw std::invalid_argument("VmpqParams: lambda 必须 > 0");
    }
}

VooPirParams VmpqParams::DerivePirParams() const {
    Validate();
    // ⚠️ V-OO-PIR 要求 part_num × part_size == n 且两者都是 2 的幂
    // ⇒ n 必须是 2 的幂。真实条目数一般不是，因此向上补齐。
    const uint64_t n = PaddedEntries();

    VooPirParams p;
    p.n = n;
    p.lambda = lambda;

    // 取 √n 附近的 2 的幂作为 part_size，其余归 part_num
    uint32_t log2n = 0;
    while ((static_cast<uint64_t>(1) << log2n) < n) ++log2n;
    const uint32_t half = log2n / 2;
    uint32_t part_size = static_cast<uint32_t>(1) << half;
    uint32_t part_num = static_cast<uint32_t>(n / part_size);
    if (part_num < 2) {
        part_num = 2;
        part_size = static_cast<uint32_t>(n / 2);
    }

    // ⚠️ part_num 太小会让 FindCutoff 的过滤区间法几乎失效
    // （区间只占 1/8 的值域，P 太小时区间内元素数常常不足 P/2）。
    // 实测 P=6 时有效率仅 ~8%。这里要求 P >= 16，否则明确报错而不是
    // 静默产生一堆无效 hint。
    if (part_num < 16) {
        throw std::invalid_argument(
            "VmpqParams::DerivePirParams: 分区数 P=" + std::to_string(part_num) +
            " 太小，FindCutoff 会大量失效（需要 P >= 16）。"
            "请增大 window_size 或属性取值域，使 PIR 数据库条目数 >= 256。"
            "当前真实条目数 = " + std::to_string(TotalEntries()));
    }

    p.part_num = part_num;
    p.part_size = part_size;
    p.Validate();
    return p;
}

// ---------------------------------------------------------------------------
// VmpqServerStore
// ---------------------------------------------------------------------------

void VmpqServerStore::Init(const VmpqParams& params) {
    params.Validate();
    params_ = params;
    attr_base_.assign(params.num_attributes(), 0);

    uint64_t offset = 0;
    const uint32_t w = params.words_per_column();
    for (uint32_t a = 0; a < params.num_attributes(); ++a) {
        attr_base_[a] = offset;
        offset += static_cast<uint64_t>(params.attr_sizes[a]) * w;
    }
    // 按补齐到 2 的幂的大小分配（V-OO-PIR 的几何约束）
    entries_.assign(static_cast<size_t>(params.PaddedEntries()), 0);
    attr_values_.assign(params.window_size, RingShare{0});
}

void VmpqServerStore::SetColumn(uint32_t attr_id, uint32_t attr_value,
                                const std::vector<uint128_t>& packed_words) {
    if (attr_id >= params_.num_attributes()) {
        throw std::out_of_range("VmpqServerStore::SetColumn: attr_id 越界");
    }
    if (attr_value >= params_.attr_sizes[attr_id]) {
        throw std::out_of_range("VmpqServerStore::SetColumn: attr_value 越界");
    }
    const uint32_t w = params_.words_per_column();
    if (packed_words.size() != w) {
        throw std::invalid_argument(
            "VmpqServerStore::SetColumn: word 数应为 " + std::to_string(w) +
            "，实际 " + std::to_string(packed_words.size()));
    }
    const uint64_t base = attr_base_[attr_id] +
                          static_cast<uint64_t>(attr_value) * w;
    for (uint32_t i = 0; i < w; ++i) {
        entries_[base + i] = packed_words[i];
    }
}

const std::vector<uint128_t>& VmpqServerStore::Column(uint32_t attr_id,
                                                      uint32_t attr_value) const {
    if (attr_id >= params_.num_attributes()) {
        throw std::out_of_range("VmpqServerStore::Column: attr_id 越界");
    }
    if (attr_value >= params_.attr_sizes[attr_id]) {
        throw std::out_of_range("VmpqServerStore::Column: attr_value 越界");
    }
    const uint32_t w = params_.words_per_column();
    const uint64_t base = attr_base_[attr_id] +
                          static_cast<uint64_t>(attr_value) * w;
    static thread_local std::vector<uint128_t> scratch;
    scratch.assign(entries_.begin() + base, entries_.begin() + base + w);
    return scratch;
}

uint128_t VmpqServerStore::Entry(uint64_t flat_index) const {
    if (flat_index >= entries_.size()) {
        throw std::out_of_range("VmpqServerStore::Entry: 索引越界");
    }
    return entries_[flat_index];
}

void VmpqServerStore::SetEntry(uint64_t flat_index, uint128_t v) {
    if (flat_index >= entries_.size()) {
        throw std::out_of_range("VmpqServerStore::SetEntry: 索引越界");
    }
    entries_[flat_index] = v;
}

void VmpqServerStore::SetAttributeValues(const std::vector<RingShare>& shared_values) {
    if (shared_values.size() != params_.window_size) {
        throw std::invalid_argument(
            "VmpqServerStore::SetAttributeValues: 长度应等于 window_size");
    }
    attr_values_ = shared_values;
}

uint64_t VmpqServerStore::StorageBytes() const {
    // 按论文 Table I 的口径：|κ|·N（属性值） + |κ|·N·2^l（one-hot 索引）。
    // 本实现把 one-hot 按位打包，故 one-hot 部分实际为 entries_ 的大小。
    const uint64_t kappa = kUint128Bytes;
    return kappa * params_.window_size + kappa * entries_.size();
}

// ---------------------------------------------------------------------------
// VmpqClient
// ---------------------------------------------------------------------------

namespace {
// 计算每个属性在扁平条目表里的基址：attr_base[a] = Σ_{b<a} 2^{l_b} · words
void ComputeAttrBase(const VmpqParams& params, std::vector<uint64_t>& attr_base) {
    attr_base.assign(params.num_attributes(), 0);
    uint64_t offset = 0;
    const uint32_t w = params.words_per_column();
    for (uint32_t a = 0; a < params.num_attributes(); ++a) {
        attr_base[a] = offset;
        offset += static_cast<uint64_t>(params.attr_sizes[a]) * w;
    }
}
}  // namespace

VmpqClient::VmpqClient(const VmpqParams& params, const AesPrf& prf)
    : params_(params),
      pir_(params.DerivePirParams(), prf) {  // 半诚实：不启用证明
    params_.Validate();

    // 单进程模式：自建两个节点与两条本地通道
    owned_nodes_.reserve(2);
    owned_channels_.reserve(2);
    for (int i = 0; i < 2; ++i) {
        owned_nodes_.push_back(std::make_unique<VmpqNode>());
        owned_channels_.push_back(
            std::make_unique<LocalChannel>(*owned_nodes_.back()));
        channels_[i] = owned_channels_.back().get();
    }
    for (int i = 0; i < 2; ++i) {
        channels_[i]->InitTable(params_.window_size, params_.attr_sizes);
    }
    ComputeAttrBase(params_, attr_base_);
    // 明文表同样补齐到 2 的幂，与 PIR 数据库一一对应
    plain_entries_.assign(static_cast<size_t>(params_.PaddedEntries()), 0);
}

VmpqClient::VmpqClient(const VmpqParams& params, const AesPrf& prf,
                       IVmpqChannel& channel0, IVmpqChannel& channel1)
    : params_(params), pir_(params.DerivePirParams(), prf) {
    params_.Validate();
    channels_[0] = &channel0;
    channels_[1] = &channel1;
    ComputeAttrBase(params_, attr_base_);
    plain_entries_.assign(static_cast<size_t>(params_.PaddedEntries()), 0);
}

uint64_t VmpqClient::FlatIndex(uint32_t attr_id, uint32_t attr_value,
                               uint32_t word_index) const {
    return attr_base_[attr_id] +
           static_cast<uint64_t>(attr_value) * params_.words_per_column() +
           word_index;
}

void VmpqClient::EncodeAndDistribute(uint32_t record_index,
                                     const std::vector<uint64_t>& record) {
    if (record.size() != params_.num_attributes()) {
        throw std::invalid_argument(
            "VmpqClient::EncodeAndDistribute: 记录属性数与 schema 不符");
    }
    for (uint32_t a = 0; a < params_.num_attributes(); ++a) {
        if (record[a] >= params_.attr_sizes[a]) {
            throw std::out_of_range(
                "VmpqClient::EncodeAndDistribute: 属性 " + std::to_string(a) +
                " 的取值超出域大小");
        }
        // one-hot：只有 record_index 这一位为 1（若该取值恰为 record[a]）
        const uint32_t word_index = record_index / 128;
        const uint32_t bit_index = record_index % 128;
        // 注意：客户端的明文表按"列"组织，因此每写一条记录要更新
        // record[a] 对应的那一列的对应位。
        const uint64_t fi = FlatIndex(a, static_cast<uint32_t>(record[a]), word_index);
        plain_entries_[fi] |= static_cast<uint128_t>(1) << bit_index;
    }
}

void VmpqClient::Init(const std::vector<std::vector<uint64_t>>& records) {
    if (records.size() != params_.window_size) {
        throw std::invalid_argument(
            "VmpqClient::Init: 记录数应等于 window_size (" +
            std::to_string(params_.window_size) + ")，实际 " +
            std::to_string(records.size()));
    }
    if (records_loaded_ != 0) {
        throw std::logic_error("VmpqClient::Init: 已经初始化过（决策 D8 只允许一次性装载）");
    }

    // 1) 清空明文表
    std::fill(plain_entries_.begin(), plain_entries_.end(),
              static_cast<uint128_t>(0));

    // 2) 逐记录写入明文 one-hot（按列组织）
    for (uint32_t j = 0; j < params_.window_size; ++j) {
        EncodeAndDistribute(j, records[j]);
    }

    // 3) XOR 共享每一个 word 并分发给两台服务器。
    //    决策 D12：parity 语义是 ⊕，因此必须是 XOR 共享（不是加法共享）。
    static constexpr size_t kChunk = 4096;  // 分块上传，避免单条消息过大
    for (size_t base = 0; base < plain_entries_.size(); base += kChunk) {
        const size_t end = std::min(base + kChunk, plain_entries_.size());
        std::vector<uint128_t> sh0, sh1;
        sh0.reserve(end - base);
        sh1.reserve(end - base);
        for (size_t i = base; i < end; ++i) {
            const uint128_t mask = random::Uint128();
            sh0.push_back(mask);
            sh1.push_back(static_cast<uint128_t>(plain_entries_[i] ^ mask));
        }
        channels_[0]->UploadEntries(base, sh0);
        channels_[1]->UploadEntries(base, sh1);
    }

    // 4) 属性值：本版本尚未实现 SUM，先留空（VMP-04 补齐）

    // 5) 离线阶段：对客户端本地明文表生成 V-OO-PIR hint
    pir_.HintInit(plain_entries_);

    records_loaded_ = params_.window_size;
}

void VmpqClient::Append(const std::vector<std::vector<uint64_t>>& records) {
    if (records.empty()) {
        return;
    }
    if (records.size() + records_loaded_ > params_.window_size) {
        throw std::out_of_range("VmpqClient::Append: 超出窗口容量（决策 D8 不支持扩容）");
    }
    for (const auto& rec : records) {
        EncodeAndDistribute(records_loaded_, rec);
        // 同步更新两台服务器的共享：新的比特位需要重新共享
        for (uint32_t a = 0; a < params_.num_attributes(); ++a) {
            const uint32_t word_index = records_loaded_ / 128;
            const uint32_t bit_index = records_loaded_ % 128;
            const uint64_t fi =
                FlatIndex(a, static_cast<uint32_t>(rec[a]), word_index);
            // 该 word 的明文发生了变化，重新生成掩码并分发
            const uint128_t mask = random::Uint128();
            channels_[0]->UploadEntries(fi, {mask});
            channels_[1]->UploadEntries(
                fi, {static_cast<uint128_t>(plain_entries_[fi] ^ mask)});
        }
        ++records_loaded_;
    }
    // Append 会改变明文表，因此 hint 必须在装载完成后重新生成
    pir_.HintInit(plain_entries_);
}

const VmpqNode& VmpqClient::node(int server_id) const {
    if (server_id < 0 || server_id > 1) {
        throw std::out_of_range("VmpqClient::node: server_id 必须是 0 或 1");
    }
    if (owned_nodes_.empty()) {
        throw std::logic_error(
            "VmpqClient::node: 远程模式下没有本地节点（请改用通道访问）");
    }
    return *owned_nodes_[static_cast<size_t>(server_id)];
}

VmpqNode& VmpqClient::node(int server_id) {
    if (server_id < 0 || server_id > 1) {
        throw std::out_of_range("VmpqClient::node: server_id 必须是 0 或 1");
    }
    if (owned_nodes_.empty()) {
        throw std::logic_error(
            "VmpqClient::node: 远程模式下没有本地节点（请改用通道访问）");
    }
    return *owned_nodes_[static_cast<size_t>(server_id)];
}

bool VmpqClient::BitIsSet(const std::vector<uint128_t>& packed_words,
                          uint32_t record) {
    const uint32_t w = record / 128;
    if (w >= packed_words.size()) return false;
    return ((packed_words[w] >> (record % 128)) & 1u) != 0;
}

// ---------------------------------------------------------------------------
// 单谓词 Count（VMP-02）
// ---------------------------------------------------------------------------

std::vector<std::vector<uint8_t>> VmpqClient::RetrieveColumns(
    const std::vector<std::pair<uint32_t, uint64_t>>& targets) {
    if (targets.empty()) {
        throw std::invalid_argument("VmpqClient::RetrieveColumns: 目标不能为空");
    }
    if (records_loaded_ == 0) {
        throw std::logic_error("VmpqClient::RetrieveColumns: 尚未 Init");
    }
    for (const auto& [a, v] : targets) {
        if (a >= params_.num_attributes()) {
            throw std::out_of_range("VmpqClient::RetrieveColumns: attr_id 越界");
        }
        if (v >= params_.attr_sizes[a]) {
            throw std::out_of_range("VmpqClient::RetrieveColumns: 取值越界");
        }
    }

    const uint32_t words = params_.words_per_column();

    // 1) 为**全部目标的全部 word** 生成查询集
    //
    // ⚠️ 这正是决策 Q5 的口径：VMPQ 的 PIR 一次查询产生一个查询集，
    //    无法避免"把所有谓词发过去"，因此这里一次性构造并在**单次 RPC**
    //    中发送所有查询集，而不是逐谓词、逐 word 往返。
    struct Pending {
        uint32_t target_index;
        uint32_t word_index;
        VooPirQuery q;
    };
    std::vector<Pending> pending;
    pending.reserve(targets.size() * words);
    for (uint32_t t = 0; t < targets.size(); ++t) {
        for (uint32_t w = 0; w < words; ++w) {
            const uint64_t fi =
                FlatIndex(targets[t].first, static_cast<uint32_t>(targets[t].second), w);
            pending.push_back(Pending{t, w, pir_.Query(fi)});
        }
    }

    // 2) 一次性发往两台服务器
    std::vector<PirQuerySetData> wire;
    wire.reserve(pending.size());
    for (const auto& p : pending) {
        wire.push_back(ToWireQuery(p.q));
    }
    const std::vector<PirAnswerData> ans0 = channels_[0]->PirQuery(wire);
    const std::vector<PirAnswerData> ans1 = channels_[1]->PirQuery(wire);
    if (ans0.size() != wire.size() || ans1.size() != wire.size()) {
        throw std::runtime_error("VmpqClient::RetrieveColumns: 服务器应答数量不符");
    }

    // 3) 本地重建每一列
    std::vector<std::vector<uint8_t>> out(
        targets.size(), std::vector<uint8_t>(params_.window_size, 0));
    for (size_t j = 0; j < pending.size(); ++j) {
        const VooPirAnswer a0{ans0[j].acc0, ans0[j].acc1};
        const VooPirAnswer a1{ans1[j].acc0, ans1[j].acc1};
        const auto rec = pir_.Reconstruct(pending[j].q, a0, a1);

        const uint32_t lo = pending[j].word_index * 128;
        const uint32_t hi =
            std::min<uint32_t>(lo + 128, params_.window_size);
        for (uint32_t b = lo; b < hi; ++b) {
            out[pending[j].target_index][b] =
                GetPackedBit(rec.value, b - lo) ? 1 : 0;
        }
    }
    return out;
}

std::vector<uint8_t> VmpqClient::RetrieveColumn(uint32_t attr_id,
                                                uint64_t attr_value) {
    auto cols = RetrieveColumns({{attr_id, attr_value}});
    return std::move(cols[0]);
}

uint64_t VmpqClient::CountMultiPredicate(const std::vector<Predicate>& predicates) {
    if (predicates.empty()) {
        throw std::invalid_argument("VmpqClient::CountMultiPredicate: 谓词不能为空");
    }
    // 把所有谓词的列**一次性**取回，再在客户端本地做组合
    std::vector<std::pair<uint32_t, uint64_t>> targets;
    targets.reserve(predicates.size());
    for (const auto& p : predicates) {
        targets.emplace_back(p.attr_id, p.attr_value);
    }
    const auto cols = RetrieveColumns(targets);

    std::vector<uint8_t> filter = cols[0];
    for (size_t i = 1; i < cols.size(); ++i) {
        for (size_t j = 0; j < filter.size(); ++j) {
            filter[j] = static_cast<uint8_t>(filter[j] & cols[i][j]);
        }
    }
    uint64_t count = 0;
    for (uint8_t b : filter) {
        if (b) ++count;
    }
    return count;
}

uint64_t VmpqClient::SumWithFilter(const std::vector<Predicate>& filter,
                                   uint32_t sum_attr) {
    if (sum_attr >= params_.num_attributes()) {
        throw std::out_of_range("VmpqClient::SumWithFilter: sum_attr 越界");
    }
    uint64_t total = 0;
    for (uint32_t v = 0; v < params_.attr_sizes[sum_attr]; ++v) {
        auto preds = filter;
        preds.push_back(Predicate{sum_attr, v});
        const uint64_t c = CountMultiPredicate(preds);
        total += static_cast<uint64_t>(v) * c;
    }
    return total;
}

VmpqClient::AggregateResult VmpqClient::Aggregate(
    const std::vector<Predicate>& filter, uint32_t sum_attr) {
    if (sum_attr >= params_.num_attributes()) {
        throw std::out_of_range("VmpqClient::Aggregate: sum_attr 越界");
    }
    AggregateResult r;
    for (uint32_t v = 0; v < params_.attr_sizes[sum_attr]; ++v) {
        auto preds = filter;
        preds.push_back(Predicate{sum_attr, v});
        const uint64_t c = CountMultiPredicate(preds);
        r.count += c;
        r.sum += static_cast<uint64_t>(v) * c;
        r.sum_sq += static_cast<uint64_t>(v) * static_cast<uint64_t>(v) * c;
    }
    return r;
}

uint64_t VmpqClient::AvgWithFilter(const std::vector<Predicate>& filter,
                                   uint32_t sum_attr) {
    const uint64_t c = CountMultiPredicate(filter);
    if (c == 0) return 0;
    return SumWithFilter(filter, sum_attr) / c;
}

uint64_t VmpqClient::CountSinglePredicate(uint32_t attr_id, uint64_t attr_value) {
    const std::vector<uint8_t> col = RetrieveColumn(attr_id, attr_value);
    uint64_t count = 0;
    for (uint8_t b : col) {
        if (b) ++count;
    }
    return count;
}

}  // namespace tsb
