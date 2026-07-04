#pragma once

#include "common.hpp"
#include <string>
#include <vector> 
#include <unordered_map>
#include <stdexcept>

using std::vector;
using std::string;
using std::unordered_map;

class OneHotTable 
{
public:
    OneHotTable() : window_size_(0), num_bucket_(0) {}

    explicit OneHotTable(uint32_t window_size, uint32_t num_bucket)
        : window_size_(window_size), num_bucket_(num_bucket) {}

    uint128_t& at(uint32_t row, uint32_t col) {
        return data_[row * num_bucket_ + col];
    }

    const uint128_t& at(uint32_t row, uint32_t col) const {
        return data_[row * num_bucket_ + col];
    }

    void add_row(const vector<uint128_t>& shares) {
        if (num_bucket_ > 0 && shares.size() != num_bucket_) {
            throw std::invalid_argument(
                "column count mismatch: expected " + std::to_string(num_bucket_) +
                ", got " + std::to_string(shares.size()));
        }
        data_.insert(data_.end(), shares.begin(), shares.end());
    }

    void reset(uint32_t window_size, uint32_t num_bucket) {
        window_size_ = window_size;
        num_bucket_ = num_bucket;
        data_.clear();
    }

    bool match(uint32_t window_size, uint32_t num_bucket) const {
        return window_size_ == window_size && num_bucket_ == num_bucket;
    }

    uint32_t window_size() const { return window_size_; }
    uint32_t num_bucket() const { return num_bucket_; }
    uint32_t row_count() const { return num_bucket_ > 0 ? data_.size() / num_bucket_ : 0; }

private:
    uint32_t num_bucket_;
    uint32_t window_size_;
    vector<uint128_t> data_;
};


class VMPQServer 
{
public:
    explicit VMPQServer(int server_id);

    void initTable(const string& table_id, uint32_t window_size, uint32_t num_bucket);
    void updateBatchVarList(const string& var_list_id, const vector<std::pair<uint32_t, uint128_t>>& shares);
    void updateBatchTable(const string& table_id, const vector<vector<uint128_t>>& rows);

private:
    int server_id_;

    unordered_map<string, vector<uint128_t>> var_list_;
    unordered_map<string, OneHotTable> table_;

};