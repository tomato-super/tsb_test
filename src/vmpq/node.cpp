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
    // ⚠️ 决策 D38：DB 条目 = 一整列 = N 个 128 位分量。
    // 存储 = padded_columns() × N 个 cell（条目 e 的第 r 个分量在 e*N + r）。
    entries_.assign(static_cast<size_t>(p.padded_columns()) * window_size, 0);
    inited_ = true;
}

void VmpqNode::UploadEntries(uint64_t base_entry,
                             const std::vector<uint128_t>& cells) {
    if (!inited_) {
        throw std::logic_error("VmpqNode::UploadEntries: 尚未 InitTable");
    }
    const uint64_t n = params_.window_size;
    if (cells.size() % n != 0) {
        throw std::invalid_argument(
            "VmpqNode::UploadEntries: cells 数量必须是 N 的整数倍（决策 D38："
            "条目 = 一整列）");
    }
    const uint64_t count = cells.size() / n;
    if ((base_entry + count) * n > entries_.size()) {
        throw std::out_of_range("VmpqNode::UploadEntries: 超出已分配的存储范围");
    }
    std::copy(cells.begin(), cells.end(),
              entries_.begin() + static_cast<size_t>(base_entry * n));
}

std::vector<PirAnswerData> VmpqNode::PirQuery(
    const std::vector<PirQuerySetData>& queries) const {
    if (!inited_) {
        throw std::logic_error("VmpqNode::PirQuery: 尚未 InitTable");
    }
    ++rpc_count_;
    queries_served_ += queries.size();
    const VooPirParams pir = params_.DerivePirParams();
    const uint32_t P = pir.part_num;
    const uint32_t sigma = pir.part_size;
    // 决策 D38：一个查询集 = 一个条目 = 一整列（N 个分量）
    const uint64_t words = params_.window_size;

    std::vector<PirAnswerData> out;
    out.reserve(queries.size());

    for (const auto& q : queries) {
        if (q.offsets.size() != P || q.groups.size() != P) {
            throw std::invalid_argument(
                "VmpqNode::PirQuery: 查询集的长度必须等于分区数 P=" +
                std::to_string(P));
        }
        PirAnswerData ans;
        ans.acc0.assign(static_cast<size_t>(words), 0);
        ans.acc1.assign(static_cast<size_t>(words), 0);
        for (uint32_t k = 0; k < P; ++k) {
            if (q.offsets[k] >= sigma) {
                throw std::invalid_argument("VmpqNode::PirQuery: 偏移超出分区大小");
            }
            // 条目号 = k*sigma + offset（每个分区恰好 1 个条目）
            const uint64_t e = static_cast<uint64_t>(k) * sigma + q.offsets[k];
            if ((e + 1) * words > entries_.size()) {
                throw std::out_of_range("VmpqNode::PirQuery: 条目号越界");
            }
            const uint128_t* col = entries_.data() + e * words;
            // ⚠️ 决策 D37：群是 Z_{2^128} 加法（服务器在**本方加法共享**上累加）；
            // D38：逐分量。这是 `VooPirClient::Answer` 的同一语义的另一份实现，
            // 改动必须同步。
            if (q.groups[k]) {
                for (uint64_t r = 0; r < words; ++r) {
                    ans.acc1[r] = add(ans.acc1[r], col[r]);
                }
            } else {
                for (uint64_t r = 0; r < words; ++r) {
                    ans.acc0[r] = add(ans.acc0[r], col[r]);
                }
            }
        }
        out.push_back(std::move(ans));
    }
    return out;
}

uint128_t VmpqNode::Entry(uint64_t flat_index) const {
    if (flat_index >= entries_.size()) {
        throw std::out_of_range("VmpqNode::Entry: 索引越界");
    }
    return entries_[flat_index];
}

std::vector<uint128_t> VmpqNode::EntryVector(uint64_t entry) const {
    const uint64_t n = params_.window_size;
    if (n == 0 || (entry + 1) * n > entries_.size()) {
        throw std::out_of_range("VmpqNode::EntryVector: 条目号越界");
    }
    return std::vector<uint128_t>(entries_.begin() + entry * n,
                                  entries_.begin() + (entry + 1) * n);
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
