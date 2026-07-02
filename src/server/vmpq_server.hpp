#pragma once

#include "config.hpp"
#include <string>
#include <vector> 
#include <unordered_map>

using std::vector;
using std::string;
using std::unordered_map;

class OneHotTable 
{
public:
    explicit OneHotTable(uint128_t window_size, uint128_t num_bucket)
        : window_size_(window_size), num_bucket_(num_bucket) {}

    // 非 const 版本：可读可写
    uint128_t& at(uint32_t row, uint32_t col) {
        return data_[row * num_bucket_ + col];
    }

    // const 版本：只读，const 对象调用
    const uint128_t& at(uint32_t row, uint32_t col) const {
        return data_[row * num_bucket_ + col];
    }

    void add_row(const vector<uint128_t>& shares) {
        data_.insert(data_.end(), shares.begin(), shares.end());
    }

    void reset(uint32_t window_size, uint32_t num_bucket) {
        window_size_ = window_size;
        num_bucket_ = num_bucket;
        data_.clear();
    }

    uint32_t window_size() const { return window_size_; }
    uint32_t num_bucket() const { return num_bucket_; }

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

private:
    int server_id_;
    uint32_t window_size_;
    uint32_t num_bucket_;

    unordered_map<string, vector<uint128_t>> var_list_;
    unordered_map<string, OneHotTable> table_;

};

