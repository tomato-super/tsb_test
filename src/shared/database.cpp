#include "shared/database.hpp"

#include <algorithm>

namespace tsb {

// ---------------------------------------------------------------------------
// PlainTable
// ---------------------------------------------------------------------------

PlainTable::PlainTable(size_t num_columns, size_t num_rows)
    : num_columns_(num_columns), num_rows_(num_rows) {
    data_.assign(num_columns_ * num_rows_, 0);
}

size_t PlainTable::Index(size_t row, size_t col) const {
    if (row >= num_rows_ || col >= num_columns_) {
        throw std::out_of_range("PlainTable: (row, col) 越界");
    }
    return row * num_columns_ + col;
}

void PlainTable::AppendRow(const std::vector<uint128_t>& row) {
    if (row.size() != num_columns_) {
        throw std::invalid_argument("PlainTable::AppendRow: 行长度与列数不符");
    }
    data_.insert(data_.end(), row.begin(), row.end());
    ++num_rows_;
}

void PlainTable::Set(size_t row, size_t col, uint128_t v) {
    data_[Index(row, col)] = v;
}

uint128_t PlainTable::At(size_t row, size_t col) const {
    return data_[Index(row, col)];
}

std::vector<uint128_t> PlainTable::Column(size_t col) const {
    if (col >= num_columns_) {
        throw std::out_of_range("PlainTable::Column: 列号越界");
    }
    std::vector<uint128_t> out(num_rows_);
    for (size_t r = 0; r < num_rows_; ++r) {
        out[r] = data_[r * num_columns_ + col];
    }
    return out;
}

uint128_t PlainTable::ColumnXor(size_t col) const {
    if (col >= num_columns_) {
        throw std::out_of_range("PlainTable::ColumnXor: 列号越界");
    }
    uint128_t acc = 0;
    for (size_t r = 0; r < num_rows_; ++r) {
        acc = static_cast<uint128_t>(acc ^ data_[r * num_columns_ + col]);
    }
    return acc;
}

void PlainTable::ClearRows() {
    data_.clear();
    num_rows_ = 0;
}

// ---------------------------------------------------------------------------
// ShareTable
// ---------------------------------------------------------------------------

ShareTable::ShareTable(size_t num_columns, size_t num_rows)
    : num_columns_(num_columns), num_rows_(num_rows) {
    data_.resize(num_columns_ * num_rows_);
}

size_t ShareTable::Index(size_t row, size_t col) const {
    if (row >= num_rows_ || col >= num_columns_) {
        throw std::out_of_range("ShareTable: (row, col) 越界");
    }
    return row * num_columns_ + col;
}

void ShareTable::AppendRow(const std::vector<RingShare>& row) {
    if (row.size() != num_columns_) {
        throw std::invalid_argument("ShareTable::AppendRow: 行长度与列数不符");
    }
    data_.insert(data_.end(), row.begin(), row.end());
    ++num_rows_;
}

void ShareTable::Set(size_t row, size_t col, const RingShare& v) {
    data_[Index(row, col)] = v;
}

const RingShare& ShareTable::At(size_t row, size_t col) const {
    return data_[Index(row, col)];
}

std::vector<RingShare> ShareTable::Column(size_t col) const {
    if (col >= num_columns_) {
        throw std::out_of_range("ShareTable::Column: 列号越界");
    }
    std::vector<RingShare> out(num_rows_);
    for (size_t r = 0; r < num_rows_; ++r) {
        out[r] = data_[r * num_columns_ + col];
    }
    return out;
}

RingShare ShareTable::ColumnXor(size_t col) const {
    if (col >= num_columns_) {
        throw std::out_of_range("ShareTable::ColumnXor: 列号越界");
    }
    RingShare acc{0};
    for (size_t r = 0; r < num_rows_; ++r) {
        acc.value = static_cast<uint128_t>(acc.value ^ data_[r * num_columns_ + col].value);
    }
    return acc;
}

void ShareTable::ClearRows() {
    data_.clear();
    num_rows_ = 0;
}

std::pair<ShareTable, ShareTable> ShareTableSplit(const PlainTable& plain) {
    ShareTable a(plain.num_columns()), b(plain.num_columns());
    // 逐行共享，保证每行的掩码独立
    for (size_t r = 0; r < plain.num_rows(); ++r) {
        std::vector<uint128_t> row(plain.num_columns());
        for (size_t c = 0; c < plain.num_columns(); ++c) {
            row[c] = plain.At(r, c);
        }
        auto [sa, sb] = ShareRingBatch(row);
        a.AppendRow(sa);
        b.AppendRow(sb);
    }
    return {std::move(a), std::move(b)};
}

PlainTable ReconstructTable(const ShareTable& a, const ShareTable& b) {
    if (a.num_columns() != b.num_columns() || a.num_rows() != b.num_rows()) {
        throw std::invalid_argument("ReconstructTable: 两个共享表的形状不一致");
    }
    PlainTable out(a.num_columns());
    for (size_t r = 0; r < a.num_rows(); ++r) {
        std::vector<uint128_t> row(a.num_columns());
        for (size_t c = 0; c < a.num_columns(); ++c) {
            row[c] = ReconstructRing(a.At(r, c), b.At(r, c));
        }
        out.AppendRow(row);
    }
    return out;
}

// ---------------------------------------------------------------------------
// ShareDatabase
// ---------------------------------------------------------------------------

void ShareDatabase::CreateTable(const std::string& table_id, size_t num_columns,
                                size_t num_rows) {
    tables_[table_id] = ShareTable(num_columns, num_rows);
}

bool ShareDatabase::HasTable(const std::string& table_id) const {
    return tables_.find(table_id) != tables_.end();
}

ShareTable& ShareDatabase::Table(const std::string& table_id) {
    const auto it = tables_.find(table_id);
    if (it == tables_.end()) {
        throw std::out_of_range("ShareDatabase: 表不存在: " + table_id);
    }
    return it->second;
}

const ShareTable& ShareDatabase::Table(const std::string& table_id) const {
    const auto it = tables_.find(table_id);
    if (it == tables_.end()) {
        throw std::out_of_range("ShareDatabase: 表不存在: " + table_id);
    }
    return it->second;
}

std::vector<std::string> ShareDatabase::TableIds() const {
    std::vector<std::string> ids;
    ids.reserve(tables_.size());
    for (const auto& [id, _] : tables_) {
        ids.push_back(id);
    }
    // unordered_map 的遍历顺序不稳定，排序保证可复现
    std::sort(ids.begin(), ids.end());
    return ids;
}

void ShareDatabase::Clear() { tables_.clear(); }

size_t ShareDatabase::TotalElements() const {
    size_t total = 0;
    for (const auto& [_, t] : tables_) {
        total += t.num_elements();
    }
    return total;
}

// ---------------------------------------------------------------------------
// 编码辅助
// ---------------------------------------------------------------------------

std::vector<uint128_t> MakeOneHotRow(uint64_t onehot_index, uint32_t num_bucket) {
    if (onehot_index >= num_bucket) {
        throw std::out_of_range("MakeOneHotRow: 取值超出 num_bucket");
    }
    std::vector<uint128_t> row(num_bucket, 0);
    row[onehot_index] = 1;
    return row;
}

std::vector<uint128_t> EncodeOneHotRows(const std::vector<uint64_t>& values,
                                        uint32_t num_bucket) {
    std::vector<uint128_t> flat;
    flat.reserve(values.size() * num_bucket);
    for (uint64_t v : values) {
        const auto row = MakeOneHotRow(v, num_bucket);
        flat.insert(flat.end(), row.begin(), row.end());
    }
    return flat;
}

std::vector<uint128_t> LcteEncode(int64_t x, const LcteParams& params) {
    // 论文 §Left-Threshold Cumulative Encoding：
    //   R = {r_1, ..., r_m}，本文取 R = {r_min, r_min+1, ..., r_min+m-1}，
    //   LCTE(x) = ([x < r_1], ..., [x < r_m])。
    // 1-based 的 r_i = range_min + i - 1，等价于 **0-based 列索引 i 的阈值为
    // range_min + i**（此前实现误用 range_min + i + 1，整体偏移了 1）。
    std::vector<uint128_t> row(params.range_size, 0);
    for (uint32_t i = 0; i < params.range_size; ++i) {
        const int64_t threshold = params.range_min + static_cast<int64_t>(i);
        row[i] = (x < threshold) ? static_cast<uint128_t>(1) : static_cast<uint128_t>(0);
    }
    return row;
}

std::vector<uint128_t> EncodeLcteRows(const std::vector<int64_t>& values,
                                      const LcteParams& params) {
    std::vector<uint128_t> flat;
    flat.reserve(values.size() * params.range_size);
    for (int64_t v : values) {
        const auto row = LcteEncode(v, params);
        flat.insert(flat.end(), row.begin(), row.end());
    }
    return flat;
}

std::vector<uint128_t> PackBitsToRing(const std::vector<uint8_t>& bits) {
    const size_t words = (bits.size() + 127) / 128;
    std::vector<uint128_t> out(words, 0);
    for (size_t i = 0; i < bits.size(); ++i) {
        if ((bits[i] & 1u) != 0) {
            out[i / 128] |= static_cast<uint128_t>(1) << (i % 128);
        }
    }
    return out;
}

std::vector<uint8_t> UnpackRingToBits(const std::vector<uint128_t>& words,
                                      size_t num_bits) {
    std::vector<uint8_t> bits(num_bits, 0);
    for (size_t i = 0; i < num_bits; ++i) {
        bits[i] = static_cast<uint8_t>((words[i / 128] >> (i % 128)) & 1u);
    }
    return bits;
}

}  // namespace tsb
