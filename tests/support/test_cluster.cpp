#include "test_cluster.hpp"

#include <stdexcept>

using namespace tsb;

TestCluster::TestCluster() : dbs_(2) {
    transport_ = std::make_unique<LocalTransport>(2);
}

ServerDatabase& TestCluster::server_db(int server_id) {
    if (server_id < 0 || server_id > 1) {
        throw std::out_of_range("TestCluster: server_id 必须是 0 或 1");
    }
    return dbs_[static_cast<size_t>(server_id)];
}

const ServerDatabase& TestCluster::server_db(int server_id) const {
    if (server_id < 0 || server_id > 1) {
        throw std::out_of_range("TestCluster: server_id 必须是 0 或 1");
    }
    return dbs_[static_cast<size_t>(server_id)];
}

void TestCluster::DistributeVarList(const std::string& id,
                                    const std::vector<uint128_t>& plain) {
    (void)id;
    auto [a, b] = ShareRingBatch(plain);
    dbs_[0].var_list = a;
    dbs_[1].var_list = b;
}

std::vector<uint128_t> TestCluster::ReconstructVarList(const std::string& id) const {
    (void)id;
    return ReconstructRingBatch(dbs_[0].var_list, dbs_[1].var_list);
}

void TestCluster::DistributeOneHotTable(const std::string& table_id,
                                        uint32_t num_bucket,
                                        const std::vector<uint128_t>& rows_flat) {
    if (num_bucket == 0) {
        throw std::invalid_argument("DistributeOneHotTable: num_bucket 不能为 0");
    }
    if (rows_flat.size() % num_bucket != 0) {
        throw std::invalid_argument(
            "DistributeOneHotTable: rows_flat 长度不是 num_bucket 的整数倍");
    }
    const size_t num_rows = rows_flat.size() / num_bucket;

    // 借助 PlainTable + ShareTableSplit 复用既有的共享/重建路径
    PlainTable plain(num_bucket);
    for (size_t r = 0; r < num_rows; ++r) {
        std::vector<uint128_t> row(num_bucket);
        for (uint32_t c = 0; c < num_bucket; ++c) {
            row[c] = rows_flat[r * num_bucket + c];
        }
        plain.AppendRow(row);
    }
    auto [a, b] = ShareTableSplit(plain);

    for (int sid = 0; sid < 2; ++sid) {
        ServerDatabase& db = dbs_[static_cast<size_t>(sid)];
        db.tables.CreateTable(table_id, num_bucket, 0);
        ShareTable& t = db.tables.Table(table_id);
        const ShareTable& src = sid == 0 ? a : b;
        for (size_t r = 0; r < num_rows; ++r) {
            std::vector<RingShare> row(num_bucket);
            for (uint32_t c = 0; c < num_bucket; ++c) {
                row[c] = src.At(r, c);
            }
            t.AppendRow(row);
        }
    }
}

void TestCluster::SetHandler(int server_id, ServerHandler handler) {
    transport_->SetHandler(server_id, std::move(handler));
}

void TestCluster::SetDbHandler(int server_id, DbHandler handler) {
    const ServerDatabase* db = &server_db(server_id);
    transport_->SetHandler(server_id, [db, handler](const Payload& req) {
        return handler(*db, req);
    });
}

void TestCluster::MakeMalicious(int server_id) {
    auto hook = transport_->options().tamper_hook;
    transport_->options().tamper_hook = [server_id, hook](int sid, Payload& resp) {
        if (hook) {
            hook(sid, resp);
        }
        if (sid == server_id) {
            // 简单但确定的篡改：翻转最后一个字节
            if (!resp.empty()) {
                resp.back() = static_cast<uint8_t>(resp.back() ^ 0x01);
            } else {
                resp.push_back(0xFF);
            }
        }
    };
}

void TestCluster::MakeUnresponsive(int server_id) {
    auto hook = transport_->options().drop_hook;
    transport_->options().drop_hook = [server_id, hook](int sid) {
        if (hook && hook(sid)) {
            return true;
        }
        return sid == server_id;
    };
}

void TestCluster::RestoreAll() {
    transport_->options().tamper_hook = nullptr;
    transport_->options().drop_hook = nullptr;
}

bool TestCluster::VarListMatches(const std::string& id,
                                 const std::vector<uint128_t>& expected) const {
    const auto got = ReconstructVarList(id);
    if (got.size() != expected.size()) {
        return false;
    }
    for (size_t i = 0; i < got.size(); ++i) {
        if (got[i] != expected[i]) {
            return false;
        }
    }
    return true;
}
