#include "vmpq/node.hpp"

#include <algorithm>

namespace tsb {

// ---------------------------------------------------------------------------
// VmpqNode
// ---------------------------------------------------------------------------

void VmpqNode::InitTable(uint32_t window_size,
                         const std::vector<uint32_t>& attr_sizes) {
    VmpqParams p;
    p.window_size = window_size;
    p.attr_sizes = attr_sizes;
    p.lambda = 24;  // 服务器侧不使用 lambda，占位以通过 Validate
    p.Validate();

    params_ = p;
    // ⚠️ 按补齐到 2 的幂的大小分配：V-OO-PIR 要求 part_num × part_size == n
    //    且两者都是 2 的幂（决策 D15 (1)）。
    entries_.assign(static_cast<size_t>(p.PaddedEntries()), 0);
    inited_ = true;
}

void VmpqNode::UploadEntries(uint64_t base_index,
                             const std::vector<uint128_t>& entries) {
    if (!inited_) {
        throw std::logic_error("VmpqNode::UploadEntries: 尚未 InitTable");
    }
    if (base_index + entries.size() > entries_.size()) {
        throw std::out_of_range("VmpqNode::UploadEntries: 超出已分配的存储范围");
    }
    std::copy(entries.begin(), entries.end(), entries_.begin() + base_index);
}

std::vector<PirAnswerData> VmpqNode::PirQuery(
    const std::vector<PirQuerySetData>& queries) const {
    if (!inited_) {
        throw std::logic_error("VmpqNode::PirQuery: 尚未 InitTable");
    }
    ++rpc_count_;
    queries_served_ += queries.size();
    const uint32_t P = params_.DerivePirParams().part_num;
    const uint32_t sigma = params_.DerivePirParams().part_size;

    std::vector<PirAnswerData> out;
    out.reserve(queries.size());

    for (const auto& q : queries) {
        if (q.offsets.size() != P || q.groups.size() != P) {
            throw std::invalid_argument(
                "VmpqNode::PirQuery: 查询集的长度必须等于分区数 P=" +
                std::to_string(P));
        }
        PirAnswerData ans;
        for (uint32_t k = 0; k < P; ++k) {
            if (q.offsets[k] >= sigma) {
                throw std::invalid_argument("VmpqNode::PirQuery: 偏移超出分区大小");
            }
            const uint64_t idx = static_cast<uint64_t>(k) * sigma + q.offsets[k];
            if (idx >= entries_.size()) {
                throw std::out_of_range("VmpqNode::PirQuery: 索引越界");
            }
            const uint128_t v = entries_[idx];
            if (q.groups[k]) {
                ans.acc1 = static_cast<uint128_t>(ans.acc1 ^ v);
            } else {
                ans.acc0 = static_cast<uint128_t>(ans.acc0 ^ v);
            }
        }
        out.push_back(ans);
    }
    return out;
}

uint128_t VmpqNode::Entry(uint64_t i) const {
    if (i >= entries_.size()) {
        throw std::out_of_range("VmpqNode::Entry: 索引越界");
    }
    return entries_[i];
}

void VmpqNode::Clear() {
    inited_ = false;
    params_ = VmpqParams{};
    entries_.clear();
}

// ---------------------------------------------------------------------------
// 查询集转换
// ---------------------------------------------------------------------------

PirQuerySetData ToWireQuery(const VooPirQuery& q) {
    PirQuerySetData w;
    w.offsets.assign(q.offsets.begin(), q.offsets.end());
    w.groups.assign(q.groups.begin(), q.groups.end());
    return w;
}

}  // namespace tsb
