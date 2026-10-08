#include "vmpq/vmpq.hpp"

#include "core/random.hpp"

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

uint64_t VmpqParams::TotalEntries() const {
    return OneHotEntries() + PlaneEntries();
}

// ---------------------------------------------------------------------------
// 基于列的布局（决策 D38）
// ---------------------------------------------------------------------------

uint64_t VmpqParams::one_hot_columns() const {
    uint64_t total = 0;
    for (uint32_t size : attr_sizes) total += size;
    return total;
}

uint64_t VmpqParams::plane_columns() const {
    uint64_t total = 0;
    for (uint32_t a = 0; a < num_attributes(); ++a) {
        total += bits_per_attr(a);
    }
    return total;
}

uint64_t VmpqParams::total_columns() const {
    return one_hot_columns() + plane_columns();
}

uint64_t VmpqParams::padded_columns() const {
    const uint64_t n = total_columns();
    if (n == 0) return 0;
    uint64_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

uint64_t VmpqParams::one_hot_column_base(uint32_t a) const {
    if (a >= num_attributes()) {
        throw std::out_of_range("VmpqParams::one_hot_column_base: 属性号越界");
    }
    uint64_t base = 0;
    for (uint32_t i = 0; i < a; ++i) base += attr_sizes[i];
    return base;
}

uint64_t VmpqParams::plane_column_base(uint32_t a) const {
    if (a >= num_attributes()) {
        throw std::out_of_range("VmpqParams::plane_column_base: 属性号越界");
    }
    uint64_t base = one_hot_columns();
    for (uint32_t i = 0; i < a; ++i) base += bits_per_attr(i);
    return base;
}

void ComputeEntryLayout(const VmpqParams& params, std::vector<uint64_t>& attr_base,
                        std::vector<uint64_t>& plane_base) {
    attr_base.assign(params.num_attributes(), 0);
    plane_base.assign(params.num_attributes(), 0);

    // one-hot 区：属性 0 的 2^{l_0} 列，随后属性 1 …（决策 D38）
    uint64_t offset = 0;
    for (uint32_t a = 0; a < params.num_attributes(); ++a) {
        attr_base[a] = offset;
        offset += params.attr_sizes[a];
    }
    // bit 面区紧跟在全部 one-hot 列之后
    for (uint32_t a = 0; a < params.num_attributes(); ++a) {
        plane_base[a] = offset;
        offset += params.bits_per_attr(a);
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
    // ⚠️ 决策 D38：DB 条目 = 一整列 ⇒ PIR 的 n = 补齐后的**列数**，
    // entry_words = N（每列的 cell 数）。这正是论文 §V-C 的复杂度口径。
    // V-OO-PIR 要求 part_num × part_size == n 且两者都是 2 的幂
    // ⇒ 列数必须是 2 的幂。真实列数一般不是，因此向上补齐。
    const uint64_t n = padded_columns();

    VooPirParams p;
    p.n = n;
    p.lambda = lambda;
    p.entry_words = window_size;  // 一条目 = 一整列 = N 个 128 位分量

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
            "当前真实列数 = " + std::to_string(total_columns()));
    }

    p.part_num = part_num;
    p.part_size = part_size;
    p.Validate();
    return p;
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
    // 明文条目表（决策 D38）：padded_columns() 个条目，每条目 N 个 128 位分量
    plain_entries_.assign(static_cast<size_t>(params_.padded_columns()),
                          std::vector<uint128_t>(params_.window_size, 0));
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
    plain_entries_.assign(static_cast<size_t>(params_.padded_columns()),
                          std::vector<uint128_t>(params_.window_size, 0));
}

uint64_t VmpqClient::OneHotColumn(uint32_t attr_id, uint32_t attr_value) const {
    if (attr_id >= params_.num_attributes()) {
        throw std::out_of_range("VmpqClient::OneHotColumn: attr_id 越界");
    }
    if (attr_value >= params_.attr_sizes[attr_id]) {
        throw std::out_of_range("VmpqClient::OneHotColumn: 取值越界");
    }
    return attr_base_[attr_id] + attr_value;
}

uint64_t VmpqClient::PlaneColumn(uint32_t attr_id, uint32_t bit) const {
    if (bit >= params_.bits_per_attr(attr_id)) {
        throw std::out_of_range("VmpqClient::PlaneColumn: bit 面序号越界");
    }
    return plane_base_[attr_id] + bit;
}

void VmpqClient::EncodeAndDistribute(uint32_t record_index,
                                     const std::vector<uint64_t>& record) {
    if (record_index >= params_.window_size) {
        throw std::out_of_range("VmpqClient::EncodeAndDistribute: 记录号越界");
    }
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
        // 决策 D38：一条目 = 一整列 ⇒ 第 record_index 条记录只点亮
        // (属性 a, 取值 record[a]) 那一列的**第 record_index 个 cell**。
        // 同属性其它列的该 cell 保持 0（one-hot 列互斥）。
        plain_entries_[OneHotColumn(a, static_cast<uint32_t>(record[a]))]
                      [record_index] = 1;

        // bit 面列：第 b 列的第 record_index 个 cell = 取值的第 b 个二进制位。
        // 有了它，SUM/矩 只需取回 l_a 个面即可在本地还原每条记录的取值。
        const uint32_t bits = params_.bits_per_attr(a);
        for (uint32_t b = 0; b < bits; ++b) {
            const uint64_t pc = PlaneColumn(a, b);
            plain_entries_[pc][record_index] =
                ((record[a] >> b) & 1u) ? 1 : 0;
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

    // 1) 清空明文条目表（padded_columns 个条目，每条目 N 个 cell）
    for (auto& entry : plain_entries_) {
        std::fill(entry.begin(), entry.end(), static_cast<uint128_t>(0));
    }

    // 2) 逐记录写入明文 one-hot / bit 面（按列组织，决策 D38）
    for (uint32_t j = 0; j < params_.window_size; ++j) {
        EncodeAndDistribute(j, records[j]);
    }

    // 3) **逐 cell 加法共享**（RSS over Z_{2^128}）每一个条目并分发给两台服务器。
    //    决策 D37：parity/answer 的群是 Z_{2^128} 加法 ⇒ 共享也必须是加法
    //    （这正是论文 §IV-B 的口径："x = [x]₁ + [x]₂，shares from a 128-bit ring"）。
    //    ⚠️ 与累加运算必须同群：配 XOR 共享会静默错值（D12 的反例；实测见
    //    `doc/design/vmpq_parity_alignment.md` §5）。
    const uint64_t n = params_.window_size;  // N：每条目的分量数
    const uint64_t total_entries = params_.padded_columns();
    // 分块上传：每条约 16k 个 cell，避免单条消息过大
    const uint64_t per_chunk = std::max<uint64_t>(1, 16384 / n);
    for (uint64_t e0 = 0; e0 < total_entries; e0 += per_chunk) {
        const uint64_t e1 = std::min(e0 + per_chunk, total_entries);
        std::vector<uint128_t> sh0, sh1;
        sh0.reserve(static_cast<size_t>((e1 - e0) * n));
        sh1.reserve(static_cast<size_t>((e1 - e0) * n));
        for (uint64_t e = e0; e < e1; ++e) {
            for (uint64_t r = 0; r < n; ++r) {
                const uint128_t mask = random::Uint128();
                sh0.push_back(mask);
                sh1.push_back(sub(plain_entries_[e][r], mask));  // plain = sh0 + sh1
            }
        }
        channels_[0]->UploadEntries(e0, sh0);
        channels_[1]->UploadEntries(e0, sh1);
    }

    // 4) 属性值 E 的**加法共享**不在此上传。
    //    SUM/矩 目前走 bit 面列（决策 D18）：取回 l_a 个面即可在客户端还原
    //    每条记录的取值，结果与明文一致。⚠️ 论文口径的「属性值加法共享 +
    //    SecureMul」链路**仍未接入**（见 §7.9 G2）。

    // 5) 离线阶段：对客户端本地明文条目表生成 V-OO-PIR hint
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
    const uint64_t n = params_.window_size;
    // 一条记录只改动每个受影响列的一个 cell；但按决策 D38 的接口
    // （条目 = 一整列），这里重新共享并上传**整条目**。
    // ⚠️ 与 Init 同口径：**逐 cell 加法共享**（决策 D37）。
    const auto reshare_entry = [this, n](uint64_t e) {
        std::vector<uint128_t> sh0, sh1;
        sh0.reserve(static_cast<size_t>(n));
        sh1.reserve(static_cast<size_t>(n));
        for (uint64_t r = 0; r < n; ++r) {
            const uint128_t mask = random::Uint128();
            sh0.push_back(mask);
            sh1.push_back(sub(plain_entries_[e][r], mask));
        }
        channels_[0]->UploadEntries(e, sh0);
        channels_[1]->UploadEntries(e, sh1);
    };
    for (const auto& rec : records) {
        EncodeAndDistribute(records_loaded_, rec);
        for (uint32_t a = 0; a < params_.num_attributes(); ++a) {
            reshare_entry(OneHotColumn(a, static_cast<uint32_t>(rec[a])));
            const uint32_t bits = params_.bits_per_attr(a);
            for (uint32_t b = 0; b < bits; ++b) {
                reshare_entry(PlaneColumn(a, b));
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
    // 决策 D38：每个目标 = 1 个条目（一整列）= 1 个查询集
    std::vector<uint64_t> entries;
    entries.reserve(targets.size());
    for (const auto& [a, v] : targets) {
        if (a >= params_.num_attributes()) {
            throw std::out_of_range("VmpqClient::RetrieveColumns: attr_id 越界");
        }
        if (v >= params_.attr_sizes[a]) {
            throw std::out_of_range("VmpqClient::RetrieveColumns: 取值越界");
        }
        entries.push_back(OneHotColumn(a, static_cast<uint32_t>(v)));
    }
    const auto rebuilt = RetrieveEntries(entries);
    std::vector<std::vector<uint8_t>> out;
    out.reserve(rebuilt.size());
    for (const auto& e : rebuilt) out.push_back(EntryToBits(e));
    return out;
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
    // 决策 D38：每个 bit 面 = 1 个条目 = 1 次 PIR
    std::vector<uint64_t> entries;
    entries.reserve(bits);
    for (uint32_t b = 0; b < bits; ++b) {
        entries.push_back(PlaneColumn(attr_id, b));
    }
    const auto rebuilt = RetrieveEntries(entries);
    std::vector<std::vector<uint8_t>> out;
    out.reserve(rebuilt.size());
    for (const auto& e : rebuilt) out.push_back(EntryToBits(e));
    return out;
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

void VmpqClient::RefreshSlot(const VooPirQuery& q,
                             const std::vector<uint128_t>& value) {
    if (params_.unsafe_disable_hint_refresh) return;
    if (q.hint_slot == std::numeric_limits<size_t>::max()) return;
    // 刷新材料由 offline server 生成（单进程仿真里客户端自己算），
    // 在**明文条目表**上计算（决策 D38：material 也是逐分量的向量）。
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

std::vector<uint8_t> VmpqClient::EntryToBits(
    const std::vector<uint128_t>& entry) const {
    // 决策 D38：重建出的条目是 N 个 128 位 cell；cell != 0 ⇒ 该记录命中该列
    std::vector<uint8_t> bits(static_cast<size_t>(params_.window_size), 0);
    for (uint32_t r = 0; r < params_.window_size; ++r) {
        bits[r] = (r < entry.size() && entry[r] != 0) ? 1 : 0;
    }
    return bits;
}

std::vector<std::vector<uint128_t>> VmpqClient::RetrieveEntries(
    const std::vector<uint64_t>& entry_ids) {
    if (entry_ids.empty()) {
        throw std::invalid_argument("VmpqClient::RetrieveEntries: 条目不能为空");
    }
    if (records_loaded_ == 0) {
        throw std::logic_error("VmpqClient::RetrieveEntries: 尚未 Init");
    }
    for (uint64_t e : entry_ids) {
        if (e >= plain_entries_.size()) {
            throw std::out_of_range("VmpqClient::RetrieveEntries: 条目号越界");
        }
    }

    // ⚠️ 决策 Q5：一次查询把所有条目的查询集**放在同一次 RPC** 里发过去。
    // ⚠️ 决策 D17：每个条目查询都会**消费**一条 hint，而补充 hint 必须拿到
    //    该轮的重建值 ⇒ 只能在收到应答后刷新。因此按"当前空闲 hint 数"分批：
    //    每批一次 RPC，重建后立刻刷新本批用掉的槽位。常规规模
    //    （|filter| + l_a 个条目）下一批就够，往返次数与旧口径一致。
    struct Pending {
        size_t out;        // 在 out[] 中的位置
        uint64_t entry;    // PIR 条目号（= 列号）
        VooPirQuery q;
    };
    std::vector<Pending> all;
    all.reserve(entry_ids.size());
    for (size_t i = 0; i < entry_ids.size(); ++i) {
        all.push_back(Pending{i, entry_ids[i], VooPirQuery{}});
    }

    std::vector<std::vector<uint128_t>> out(
        entry_ids.size(),
        std::vector<uint128_t>(static_cast<size_t>(params_.window_size), 0));

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
                "VmpqClient::RetrieveEntries: 服务器应答数量不符");
        }
        for (size_t j = 0; j < batch.size(); ++j) {
            const Pending& p = batch[j];
            const VooPirAnswer a0{ans0[j].acc0, ans0[j].acc1};
            const VooPirAnswer a1{ans1[j].acc0, ans1[j].acc1};
            const auto rec = pir_.Reconstruct(p.q, a0, a1);
            // 重建出的就是该条目的**全部分量**（决策 D38）
            out[p.out] = rec.value;
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
            all[next].q = pir_.Query(all[next].entry);
            batch.push_back(all[next]);
            ++next;
        } catch (const HintsExhausted&) {
            // 该条目的候选 hint 恰好都已在本批里被消费：先结算本批
            // （重建 + 刷新）再重试，避免死等。
            if (batch.empty()) throw;
            flush();
            if (++stalls > 64) {
                throw std::runtime_error(
                    "VmpqClient::RetrieveEntries: 反复出现 hint 耗尽，无法推进");
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

    // 一次性取回：filter 的每一列 + sum_attr 的 l_a 个 bit 面列。
    // 决策 D38：每列 = 1 个条目 = 1 次 PIR ⇒ 总 PIR 次数 = |filter| + l_a。
    //
    // ⚠️ 优化（决策 D18）：早先的 SUM 走 `SUM = Σ_v v·Count(filter ∧ attr==v)`，
    //    需要 |domain(sum_attr)| 次 Count。现在只取回 l_a 个 bit 面即可在本地
    //    还原**每条记录的取值**。count / sum / sum_sq 同一次往返全部拿到。
    const uint32_t sum_bits = params_.bits_per_attr(sum_attr);
    std::vector<uint64_t> entries;
    entries.reserve(filter.size() + sum_bits);
    for (const auto& p : filter) {
        entries.push_back(
            OneHotColumn(p.attr_id, static_cast<uint32_t>(p.attr_value)));
    }
    for (uint32_t b = 0; b < sum_bits; ++b) {
        entries.push_back(PlaneColumn(sum_attr, b));
    }
    const auto rebuilt = RetrieveEntries(entries);
    std::vector<std::vector<uint8_t>> cols;
    cols.reserve(rebuilt.size());
    for (const auto& e : rebuilt) cols.push_back(EntryToBits(e));

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
