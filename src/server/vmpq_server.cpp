#include "vmpq_server.hpp"
#include <stdexcept>


VMPQServer::VMPQServer(int server_id) : server_id_(server_id) {}

void VMPQServer::initTable(
    const string &table_id, uint32_t window_size, uint32_t num_bucket
)
{
    if (table_id.empty()) {
        throw std::invalid_argument("table_id is empty");
    }

    auto& list = var_list_[table_id];
    list.clear();
    list.resize(window_size);

    auto it = table_.find(table_id);
    if (it != table_.end() && it->second.match(window_size, num_bucket)) {
        it->second.reset(window_size, num_bucket);
    } else {
        table_.erase(table_id);
        table_.emplace(table_id, OneHotTable(window_size, num_bucket));
    }
}

void VMPQServer::updateBatchVarList(
    const string& var_list_id, const vector<std::pair<uint32_t, uint128_t>>& shares
)
{
    auto& vl = var_list_[var_list_id];
    for (const auto& [idx, share] : shares) {
        vl[idx] = share;
    }
}

void VMPQServer::updateBatchTable(
    const string& table_id, const vector<vector<uint128_t>>& rows
)
{
    auto it = table_.find(table_id);
    if (it == table_.end()) {
        throw std::invalid_argument("table not found: " + table_id);
    }
    for (const auto& row : rows) {
        it->second.add_row(row);
    }
}