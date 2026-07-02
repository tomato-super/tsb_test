#include "vmpq_server.hpp"


VMPQServer::VMPQServer(int server_id) : server_id_(server_id) {}

void VMPQServer::initTable(
    const string &table_id, uint32_t window_size, uint32_t num_bucket
)
{
    this->window_size_ = window_size;
    this->num_bucket_ = num_bucket;

    auto& list = var_list_[table_id];
    list.clear();
    list.reserve(window_size_);

    table_.erase(table_id);
    table_.emplace(table_id, OneHotTable(window_size_, num_bucket_));
}


