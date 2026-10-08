// VMPQ 客户端进程（VMP-08）。
//
// 用法：./vmpq_client <config.json> [--rows N]
//
// 流程：连接两台服务器 → 生成合成时序数据 → Init（编码+加法共享+上传+离线 hint）
//       → 执行若干聚合查询 → 与本地明文基准对照
//
// ⚠️ 半诚实版本（决策 D16）：不做任何 proof/验证；服务器默认不篡改应答。
//    查询口径（Q5）：一次查询把所有谓词的全部查询集放进**一次** RPC。

#include "core/config.hpp"
#include "core/random.hpp"
#include "net/grpc_vmpq.hpp"
#include "vmpq/vmpq.hpp"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

using namespace tsb;

namespace {

double MsSince(const std::chrono::steady_clock::time_point& t0) {
    return std::chrono::duration<double, std::milli>(
               std::chrono::steady_clock::now() - t0)
        .count();
}

// 合成一份确定性的时序数据：两个属性，取值域同 config
std::vector<std::vector<uint64_t>> MakeRecords(uint32_t rows,
                                               const std::vector<uint32_t>& sizes,
                                               uint64_t seed) {
    const auto key = AesPrf::GenerateKey();
    random::DeterministicPrng prng(key, seed);
    std::vector<std::vector<uint64_t>> recs(rows,
                                            std::vector<uint64_t>(sizes.size()));
    for (auto& r : recs) {
        for (size_t a = 0; a < sizes.size(); ++a) {
            r[a] = prng.Below(sizes[a]);
        }
    }
    return recs;
}

uint64_t PlainCount(const std::vector<std::vector<uint64_t>>& recs, uint32_t attr,
                    uint64_t value) {
    uint64_t c = 0;
    for (const auto& r : recs) {
        if (r[attr] == value) ++c;
    }
    return c;
}

uint64_t PlainCountBoth(const std::vector<std::vector<uint64_t>>& recs, uint64_t v0,
                        uint64_t v1) {
    uint64_t c = 0;
    for (const auto& r : recs) {
        if (r[0] == v0 && r[1] == v1) ++c;
    }
    return c;
}

uint64_t PlainSum(const std::vector<std::vector<uint64_t>>& recs, uint32_t sum_attr,
                  uint64_t filter_v) {
    uint64_t s = 0;
    for (const auto& r : recs) {
        if (r[0] == filter_v) s += r[sum_attr];
    }
    return s;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "用法: ./vmpq_client <config.json> [--rows N]\n";
        return EXIT_FAILURE;
    }

    try {
        const VmpqConfig cfg = VmpqConfig::FromFile(argv[1]);
        if (cfg.servers.size() != 2) {
            std::cerr << "VMPQ 需要恰好 2 台服务器\n";
            return EXIT_FAILURE;
        }

        uint32_t rows = cfg.params.window_size;
        for (int i = 2; i + 1 < argc; ++i) {
            if (std::string(argv[i]) == "--rows") {
                rows = static_cast<uint32_t>(std::stoul(argv[i + 1]));
            }
        }

        std::vector<uint32_t> sizes = cfg.params.attr_sizes;
        if (sizes.empty()) {
            sizes = {cfg.params.num_bucket};
        }

        VmpqParams params;
        params.window_size = rows;
        params.attr_sizes = sizes;
        params.lambda = cfg.params.lambda;
        params.Validate();

        // 配置摘要（原中文标题「=== 配置 ===」）；取值域 = attr_sizes 列表。
        std::cout << "config\n";
        for (const auto& s : cfg.servers) {
            std::cout << "  server " << (int)s.id << ": " << s.address << "\n";
        }
        std::cout << "  window=" << rows << " attrs=" << sizes.size() << " domain=[";
        for (size_t i = 0; i < sizes.size(); ++i) {
            std::cout << (i ? "," : "") << sizes[i];
        }
        // 半诚实模式（决策 D16）：无 proof、无 MAC 密钥。
        std::cout << "] lambda=" << params.lambda << " proof=none mac_key=none\n";

        // ---- 连接两台服务器 ----
        GrpcChannel ch0(cfg.servers[0].address);
        GrpcChannel ch1(cfg.servers[1].address);
        if (!ch0.WaitForConnection(5000) || !ch1.WaitForConnection(5000)) {
            std::cerr << "无法连接到服务器，请先启动 ./vmpq_server\n";
            return EXIT_FAILURE;
        }
        std::cout << "[1/4] connected servers=2\n";

        // ---- Init：分配存储 + 上传共享 ----
        ch0.InitTable(params.window_size, params.attr_sizes);
        ch1.InitTable(params.window_size, params.attr_sizes);

        const auto recs = MakeRecords(rows, sizes, 20260910);
        std::vector<uint8_t> prf_key(16);
        for (int i = 0; i < 16; ++i) prf_key[i] = static_cast<uint8_t>(i + 1);
        AesPrf prf(prf_key);

        VmpqClient client(params, prf, ch0, ch1);
        auto t0 = std::chrono::steady_clock::now();
        client.Init(recs);
        // Init 阶段（原中文说明）：编码 + 加法共享 + 上传 + 离线 hint；打印总耗时。
        std::cout << "[2/4] init_ms="
                  << std::fixed << std::setprecision(1) << MsSince(t0) << "\n";

        // ---- 单谓词 Count ----
        t0 = std::chrono::steady_clock::now();
        int checked = 0, mismatch = 0;
        for (uint32_t v = 0; v < sizes[0] && v < 8; ++v) {
            const uint64_t got = client.CountSinglePredicate(0, v);
            const uint64_t want = PlainCount(recs, 0, v);
            ++checked;
            if (got != want) ++mismatch;
        }
        // 单谓词 Count：逐一与明文基准对照（checked 组，mismatch 组不一致）。
        std::cout << "[3/4] single_count checked=" << checked << " rpc_per_channel=" << ch0.rpc_count()
                  << " ms=" << MsSince(t0) << " mismatch=" << mismatch << "\n";

        // ---- 多谓词 Count（Q5：一次 RPC 发全部谓词）----
        const uint64_t rpc_before = ch0.rpc_count();
        t0 = std::chrono::steady_clock::now();
        const uint64_t both = client.CountMultiPredicate({{0, 3}, {1, 5}});
        const double both_ms = MsSince(t0);
        const uint64_t rpc_used = ch0.rpc_count() - rpc_before;
        const uint64_t want_both = PlainCountBoth(recs, 3, 5);
        // 多谓词 Count（Q5：一次 RPC 发全部谓词 ⇒ 2 个谓词仍只 1 次 PirQuery RPC）。
        std::cout << "[4/4] multi_count p0=3 p1=5 result=" << both
                  << " plain=" << want_both
                  << (both == want_both ? " ok=1" : " ok=0")
                  << " ms=" << std::fixed << std::setprecision(2) << both_ms
                  << " pir_query_rpc=" << rpc_used << "\n";

        // ---- SUM ----
        t0 = std::chrono::steady_clock::now();
        const uint64_t sum = client.SumWithFilter({{0, 2}}, 1);
        const uint64_t want_sum = PlainSum(recs, 1, 2);
        // SUM：filter p0=2，对 p1 求和；与明文基准对照。
        std::cout << "      sum filter_p0=2 sum_attr=1 result=" << sum
                  << " plain=" << want_sum << (sum == want_sum ? " ok=1" : " ok=0")
                  << " ms=" << MsSince(t0) << "\n";

        // 远程模式下客户端**不持有**服务器存储，只能报告自己这一侧的规模。
        // （这本身就是隐私性的体现：服务端状态对客户端不可见。）
        //
        // 口径（决策 D38）：一个 DB 条目 = 一整列 = N 个 128 位 cell，
        // 一次列查询 = 1 次 PIR（1 个查询集）。
        const uint64_t one_hot_cols = params.one_hot_columns();
        const uint64_t plane_cols = params.plane_columns();
        const uint64_t total_cols = params.total_columns();
        const uint64_t padded_cols = params.padded_columns();
        const uint64_t per_server_kb =
            padded_cols * params.window_size * 16 / 1024;
        // 客户端侧账目（原中文说明）：远程模式下客户端**不持有**服务器存储，只能报告自己
        // 这一侧的规模（服务端状态对客户端不可见）。口径（决策 D38）：一个 DB 条目 = 一整列
        // = N 个 128 位 cell，一次列查询 = 1 次 PIR（1 个查询集）；PIR 数据库补齐到
        // padded_cols 个条目。
        std::cout << "\nclient_accounts total_columns=" << total_cols << " one_hot_columns="
                  << one_hot_cols << " plane_columns=" << plane_cols
                  << " entries_per_column=" << params.window_size
                  << " server_storage_kb_per_server=" << per_server_kb
                  << " padded_entries=" << padded_cols << " pir_per_column_query=1\n";
        std::cout << "rpc server0=" << ch0.rpc_count()
                  << " server1=" << ch1.rpc_count() << "\n";

        const int bad = mismatch + (both == want_both ? 0 : 1) + (sum == want_sum ? 0 : 1);
        // 原中文结论行「=== 全部一致 / 存在不一致 ===」精简为裸键值；退出码不变。
        std::cout << "result all_match=" << (bad == 0 ? 1 : 0) << " mismatch=" << bad << "\n";
        return bad == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    } catch (const std::exception& e) {
        std::cerr << "客户端失败: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
}
