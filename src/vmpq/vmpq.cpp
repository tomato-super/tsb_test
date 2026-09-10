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

uint64_t VmpqParams::OneHotEntries() const {
    uint64_t total = 0;
    const uint32_t w = words_per_column();
    for (uint32_t size : attr_sizes) {
        total += static_cast<uint64_t>(size) * w;
    }
    return total;
}

uint64_t VmpqParams::PlaneEntries() const {
    uint64_t total = 0;
    const uint32_t w = words_per_column();
    for (uint32_t a = 0; a < num_attributes(); ++a) {
        total += static_cast<uint64_t>(bits_per_attr(a)) * w;
    }
    return total;
}

uint32_t VmpqParams::num_planes() const {
    uint32_t total = 0;
    for (uint32_t a = 0; a < num_attributes(); ++a) {
        total += bits_per_attr(a);
    }
    return total;
}

uint64_t VmpqParams::TotalEntries() const {
    return OneHotEntries() + PlaneEntries();
}

void ComputeEntryLayout(const VmpqParams& params, std::vector<uint64_t>& attr_base,
                        std::vector<uint64_t>& plane_base) {
    const uint32_t w = params.words_per_column();
    attr_base.assign(params.num_attributes(), 0);
    plane_base.assign(params.num_attributes(), 0);

    uint64_t offset = 0;
    for (uint32_t a = 0; a < params.num_attributes(); ++a) {
        attr_base[a] = offset;
        offset += static_cast<uint64_t>(params.attr_sizes[a]) * w;
    }
    // value plane 区紧跟在 one-hot 区之后
    for (uint32_t a = 0; a < params.num_attributes(); ++a) {
        plane_base[a] = offset;
        offset += static_cast<uint64_t>(params.bits_per_attr(a)) * w;
    }
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
    // 客户端与服务器共用同一套布局推导（含 value plane 区）
    ComputeEntryLayout(params_, attr_base_, plane_base_);
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

std::vector<uint128_t> VmpqServerStore::Column(uint32_t attr_id,
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
    // ⚠️ 按值返回。早先这里返回的是 `static thread_local` scratch 缓冲区的引用：
    // 连续两次调用会让前一个引用指向被覆盖的数据（静默错误），且调用方写
    // `const auto& c = store.Column(...)` 时毫无察觉。
    return std::vector<uint128_t>(entries_.begin() + base,
                                  entries_.begin() + base + w);
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

VmpqClient::VmpqClient(const VmpqParams& params, const AesPrf& prf)
    : params_(params),
      pir_(params.DerivePirParams(), prf) {  // 半诚实：不启用证明
    params_.Validate();
    if (params_.unsafe_disable_hint_refresh) {
        // ⚠️ 显式不安全的基准测量路径：允许复用未刷新的 hint（决策 D17）
        pir_.SetHintReusePolicy(HintReusePolicy::kAllowUnsafeForTesting);
    }

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
    ComputeEntryLayout(params_, attr_base_, plane_base_);
    // 明文表同样补齐到 2 的幂，与 PIR 数据库一一对应
    plain_entries_.assign(static_cast<size_t>(params_.PaddedEntries()), 0);
}

VmpqClient::VmpqClient(const VmpqParams& params, const AesPrf& prf,
                       IVmpqChannel& channel0, IVmpqChannel& channel1)
    : params_(params), pir_(params.DerivePirParams(), prf) {
    params_.Validate();
    channels_[0] = &channel0;
    channels_[1] = &channel1;
    if (params_.unsafe_disable_hint_refresh) {
        pir_.SetHintReusePolicy(HintReusePolicy::kAllowUnsafeForTesting);
    }
    ComputeEntryLayout(params_, attr_base_, plane_base_);
    plain_entries_.assign(static_cast<size_t>(params_.PaddedEntries()), 0);
}

uint64_t VmpqClient::FlatIndex(uint32_t attr_id, uint32_t attr_value,
                               uint32_t word_index) const {
    return attr_base_[attr_id] +
           static_cast<uint64_t>(attr_value) * params_.words_per_column() +
           word_index;
}

uint64_t VmpqClient::PlaneFlatIndex(uint32_t attr_id, uint32_t bit) const {
    if (bit >= params_.bits_per_attr(attr_id)) {
        throw std::out_of_range("VmpqClient::PlaneFlatIndex: 比特面序号越界");
    }
    return plane_base_[attr_id] +
           static_cast<uint64_t>(bit) * params_.words_per_column();
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

        // value plane：第 b 面的第 record_index 位 = 取值的第 b 个二进制位。
        // 有了它，SUM/矩 只需取回 l_a 个面即可在本地还原每条记录的取值。
        const uint32_t bits = params_.bits_per_attr(a);
        for (uint32_t b = 0; b < bits; ++b) {
            if (((record[a] >> b) & 1u) == 0) continue;
            const uint64_t pi = plane_base_[a] +
                                static_cast<uint64_t>(b) * params_.words_per_column() +
                                word_index;
            plain_entries_[pi] |= static_cast<uint128_t>(1) << bit_index;
        }
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

    // 4) 属性值 E 的**加法共享**不在此上传。
    //    SUM/矩 目前走 value plane（PIR-02/决策 D18）：取回 l_a 个比特面即可在
    //    客户端还原每条记录的取值，结果与明文一致、且 PIR 次数比旧归约少 18.3 倍。
    //    ⚠️ 论文口径的「属性值加法共享 + SecureMul」链路**仍未接入**（见 §7.9 G2）：
    //    那条路需要服务器参与乘法，只有在要与论文逐字对齐做对照实验时才需要补。

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
    // 一条记录会改动：该记录在各属性上的 one-hot 列各 1 个 word，
    // 以及各属性的 value plane 各 1 个 word。逐个重算掩码并分发。
    const auto reshare = [this](uint64_t flat_index) {
        const uint128_t mask = random::Uint128();
        channels_[0]->UploadEntries(flat_index, {mask});
        channels_[1]->UploadEntries(
            flat_index, {static_cast<uint128_t>(plain_entries_[flat_index] ^ mask)});
    };
    for (const auto& rec : records) {
        EncodeAndDistribute(records_loaded_, rec);
        const uint32_t word_index = records_loaded_ / 128;
        for (uint32_t a = 0; a < params_.num_attributes(); ++a) {
            reshare(FlatIndex(a, static_cast<uint32_t>(rec[a]), word_index));
            const uint32_t bits = params_.bits_per_attr(a);
            for (uint32_t b = 0; b < bits; ++b) {
                reshare(PlaneFlatIndex(a, b) + word_index);
            }
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
    std::vector<std::pair<uint64_t, uint32_t>> segments;
    segments.reserve(targets.size());
    const uint32_t words = params_.words_per_column();
    for (const auto& [a, v] : targets) {
        if (a >= params_.num_attributes()) {
            throw std::out_of_range("VmpqClient::RetrieveColumns: attr_id 越界");
        }
        if (v >= params_.attr_sizes[a]) {
            throw std::out_of_range("VmpqClient::RetrieveColumns: 取值越界");
        }
        segments.emplace_back(FlatIndex(a, static_cast<uint32_t>(v), 0), words);
    }
    return RetrieveSegments(segments);
}

std::vector<uint8_t> VmpqClient::RetrieveColumn(uint32_t attr_id,
                                                uint64_t attr_value) {
    auto cols = RetrieveColumns({{attr_id, attr_value}});
    return std::move(cols[0]);
}

std::vector<std::vector<uint8_t>> VmpqClient::RetrieveValuePlanes(uint32_t attr_id) {
    if (attr_id >= params_.num_attributes()) {
        throw std::out_of_range("VmpqClient::RetrieveValuePlanes: attr_id 越界");
    }
    const uint32_t bits = params_.bits_per_attr(attr_id);
    const uint32_t words = params_.words_per_column();
    std::vector<std::pair<uint64_t, uint32_t>> segments;
    segments.reserve(bits);
    for (uint32_t b = 0; b < bits; ++b) {
        segments.emplace_back(PlaneFlatIndex(attr_id, b), words);
    }
    return RetrieveSegments(segments);
}

std::vector<uint64_t> VmpqClient::RetrieveAttributeValues(uint32_t attr_id) {
    const auto planes = RetrieveValuePlanes(attr_id);
    std::vector<uint64_t> values(params_.window_size, 0);
    for (uint32_t b = 0; b < planes.size(); ++b) {
        for (uint32_t j = 0; j < params_.window_size; ++j) {
            if (planes[b][j]) values[j] |= (static_cast<uint64_t>(1) << b);
        }
    }
    return values;
}

void VmpqClient::RefreshSlot(const VooPirQuery& q, uint128_t value) {
    if (params_.unsafe_disable_hint_refresh) return;
    if (q.hint_slot == std::numeric_limits<size_t>::max()) return;
    // 刷新材料由 offline server 生成（单进程仿真里客户端自己算）。
    // FindCutoff 会丢弃一部分材料（c == 0 ⇒ 无效），换新的 hint_id 重试。
    for (int attempt = 0; attempt < 64; ++attempt) {
        const VooPirClient::RefreshMaterial mat =
            pir_.GenerateRefreshMaterial(plain_entries_, q.target_index);
        if (mat.select_cutoff == 0) continue;
        pir_.Refresh(q.hint_slot, q, mat, value);
        return;
    }
    throw std::runtime_error(
        "VmpqClient::RefreshSlot: 连续 64 次都拿不到有效的 hint 补充材料");
}

std::vector<std::vector<uint8_t>> VmpqClient::RetrieveSegments(
    const std::vector<std::pair<uint64_t, uint32_t>>& segments) {
    if (segments.empty()) {
        throw std::invalid_argument("VmpqClient::RetrieveSegments: 段不能为空");
    }
    if (records_loaded_ == 0) {
        throw std::logic_error("VmpqClient::RetrieveSegments: 尚未 Init");
    }
    for (const auto& [base, words] : segments) {
        if (words == 0) {
            throw std::invalid_argument("VmpqClient::RetrieveSegments: 段长度不能为 0");
        }
        if (base + words > plain_entries_.size()) {
            throw std::out_of_range("VmpqClient::RetrieveSegments: 段越界");
        }
    }

    // 展开成"逐个 word 的 PIR 查询"
    struct Pending {
        size_t seg;
        uint32_t word;
        uint64_t flat_index;
        VooPirQuery q;
    };
    std::vector<Pending> all;
    for (size_t s = 0; s < segments.size(); ++s) {
        for (uint32_t w = 0; w < segments[s].second; ++w) {
            all.push_back(Pending{s, w, segments[s].first + w, VooPirQuery{}});
        }
    }

    std::vector<std::vector<uint8_t>> out(
        segments.size(), std::vector<uint8_t>(params_.window_size, 0));

    // ⚠️ 决策 Q5：一次查询把所有 word 的查询集**放在同一次 RPC** 里发过去。
    // ⚠️ 决策 D17：每轮查询都会**消费**一条 hint，而补充 hint 必须拿到该轮的
    //    重建值 ⇒ 只能在收到应答后刷新。因此按"当前空闲 hint 数"分批：
    //    每批一次 RPC，重建后立刻刷新本批用掉的槽位。常规规模（|filter| + l_a
    //    个面，各 w 个 word）下一批就够，往返次数与优化前完全一致。
    std::vector<Pending> batch;
    size_t next = 0;
    int stalls = 0;

    const auto flush = [&]() {
        if (batch.empty()) return;
        std::vector<PirQuerySetData> wire;
        wire.reserve(batch.size());
        for (const auto& p : batch) wire.push_back(ToWireQuery(p.q));
        const std::vector<PirAnswerData> ans0 = channels_[0]->PirQuery(wire);
        const std::vector<PirAnswerData> ans1 = channels_[1]->PirQuery(wire);
        if (ans0.size() != wire.size() || ans1.size() != wire.size()) {
            throw std::runtime_error(
                "VmpqClient::RetrieveSegments: 服务器应答数量不符");
        }
        for (size_t j = 0; j < batch.size(); ++j) {
            const Pending& p = batch[j];
            const VooPirAnswer a0{ans0[j].acc0, ans0[j].acc1};
            const VooPirAnswer a1{ans1[j].acc0, ans1[j].acc1};
            const auto rec = pir_.Reconstruct(p.q, a0, a1);
            const uint32_t lo = p.word * 128;
            const uint32_t hi = std::min<uint32_t>(lo + 128, params_.window_size);
            for (uint32_t b = lo; b < hi; ++b) {
                out[p.seg][b] = GetPackedBit(rec.value, b - lo) ? 1 : 0;
            }
            // 立刻把被消费的槽位换成一条全新的 hint（决策 D17）
            RefreshSlot(p.q, rec.value);
        }
        batch.clear();
    };

    while (next < all.size()) {
        if (batch.size() >= pir_.FreeHintCount()) {
            flush();
        }
        try {
            all[next].q = pir_.Query(all[next].flat_index);
            batch.push_back(all[next]);
            ++next;
        } catch (const HintsExhausted&) {
            // 该索引的候选 hint 恰好都已在本批里被消费：先结算本批
            // （重建 + 刷新）再重试，避免死等。
            if (batch.empty()) throw;
            flush();
            if (++stalls > 64) {
                throw std::runtime_error(
                    "VmpqClient::RetrieveSegments: 反复出现 hint 耗尽，无法推进");
            }
        }
    }
    flush();
    return out;
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

VmpqClient::AggregateResult VmpqClient::Aggregate(
    const std::vector<Predicate>& filter, uint32_t sum_attr) {
    if (sum_attr >= params_.num_attributes()) {
        throw std::out_of_range("VmpqClient::Aggregate: sum_attr 越界");
    }
    for (const auto& p : filter) {
        if (p.attr_id >= params_.num_attributes()) {
            throw std::out_of_range("VmpqClient::Aggregate: filter 属性号越界");
        }
        if (p.attr_value >= params_.attr_sizes[p.attr_id]) {
            throw std::out_of_range("VmpqClient::Aggregate: filter 取值越界");
        }
    }

    // 一次性取回：filter 的每一列 + sum_attr 的 l_a 个 value plane。
    //
    // ⚠️ 优化（PIR-02）：早先的 SUM 走 `SUM = Σ_v v·Count(filter ∧ attr==v)`，
    //    需要 |domain(sum_attr)| 次 Count，实测开销 = |domain| × 2 × Count
    //    （见 TASK_PLAN §7.10）。现在只取回 l_a 个比特面即可在本地还原**每条
    //    记录的取值**，PIR 次数从 2^{l_a}·(|filter|+1) 个列降到
    //    (|filter| + l_a) 个列 —— l_a = 6 时约 20 倍。而且 count / sum /
    //    sum_sq 同一次往返全部拿到。
    const uint32_t words = params_.words_per_column();
    const uint32_t sum_bits = params_.bits_per_attr(sum_attr);
    std::vector<std::pair<uint64_t, uint32_t>> segments;
    segments.reserve(filter.size() + sum_bits);
    for (const auto& p : filter) {
        segments.emplace_back(
            FlatIndex(p.attr_id, static_cast<uint32_t>(p.attr_value), 0), words);
    }
    for (uint32_t b = 0; b < sum_bits; ++b) {
        segments.emplace_back(PlaneFlatIndex(sum_attr, b), words);
    }
    const auto cols = RetrieveSegments(segments);

    // 本地布尔组合（Q5 裁决：服务器不参与谓词组合）
    std::vector<uint8_t> mask(params_.window_size, 1);
    for (size_t i = 0; i < filter.size(); ++i) {
        for (uint32_t j = 0; j < params_.window_size; ++j) {
            mask[j] = static_cast<uint8_t>(mask[j] & cols[i][j]);
        }
    }

    AggregateResult r;
    for (uint32_t j = 0; j < params_.window_size; ++j) {
        if (!mask[j]) continue;
        uint64_t v = 0;
        for (uint32_t b = 0; b < sum_bits; ++b) {
            if (cols[filter.size() + b][j]) v |= (static_cast<uint64_t>(1) << b);
        }
        ++r.count;
        r.sum += v;
        r.sum_sq += v * v;
    }
    return r;
}

uint64_t VmpqClient::SumWithFilter(const std::vector<Predicate>& filter,
                                   uint32_t sum_attr) {
    return Aggregate(filter, sum_attr).sum;
}

uint64_t VmpqClient::AvgWithFilter(const std::vector<Predicate>& filter,
                                   uint32_t sum_attr) {
    const AggregateResult r = Aggregate(filter, sum_attr);
    if (r.count == 0) return 0;
    return r.sum / r.count;
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
