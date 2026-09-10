// VMPQ 客户端进程（VMP-08）。
//
// 用法：./vmpq_client <config.json> [--rows N]
//
// 流程：连接两台服务器 → 生成合成时序数据 → Init（编码+XOR 共享+上传+离线 hint）
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

        std::cout << "=== 配置 ===\n";
        for (const auto& s : cfg.servers) {
            std::cout << "  server " << (int)s.id << ": " << s.address << "\n";
        }
        std::cout << "  window=" << rows << " 属性数=" << sizes.size() << " 取值域=[";
        for (size_t i = 0; i < sizes.size(); ++i) {
            std::cout << (i ? "," : "") << sizes[i];
        }
        std::cout << "] lambda=" << params.lambda << "\n";
        std::cout << "  半诚实模式：无 proof、无 MAC 密钥（决策 D16）\n\n";

        // ---- 连接两台服务器 ----
        GrpcChannel ch0(cfg.servers[0].address);
        GrpcChannel ch1(cfg.servers[1].address);
        if (!ch0.WaitForConnection(5000) || !ch1.WaitForConnection(5000)) {
            std::cerr << "无法连接到服务器，请先启动 ./vmpq_server\n";
            return EXIT_FAILURE;
        }
        std::cout << "[1/4] 已连接两台服务器\n";

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
        std::cout << "[2/4] Init（编码 + XOR 共享 + 上传 + 离线 hint）: "
                  << std::fixed << std::setprecision(1) << MsSince(t0) << " ms\n";

        // ---- 单谓词 Count ----
        t0 = std::chrono::steady_clock::now();
        int checked = 0, mismatch = 0;
        for (uint32_t v = 0; v < sizes[0] && v < 8; ++v) {
            const uint64_t got = client.CountSinglePredicate(0, v);
            const uint64_t want = PlainCount(recs, 0, v);
            ++checked;
            if (got != want) ++mismatch;
        }
        std::cout << "[3/4] 单谓词 Count ×" << checked << " (RPC/ch=" << ch0.rpc_count()
                  << ")  " << MsSince(t0) << " ms  不一致=" << mismatch << "\n";

        // ---- 多谓词 Count（Q5：一次 RPC 发全部谓词）----
        const uint64_t rpc_before = ch0.rpc_count();
        t0 = std::chrono::steady_clock::now();
        const uint64_t both = client.CountMultiPredicate({{0, 3}, {1, 5}});
        const double both_ms = MsSince(t0);
        const uint64_t rpc_used = ch0.rpc_count() - rpc_before;
        const uint64_t want_both = PlainCountBoth(recs, 3, 5);
        std::cout << "[4/4] 多谓词 Count(p0=3 ∧ p1=5) = " << both
                  << "  明文=" << want_both
                  << (both == want_both ? "  ✓" : "  ✗")
                  << "  用时 " << std::fixed << std::setprecision(2) << both_ms
                  << " ms，PirQuery RPC 次数=" << rpc_used
                  << "（Q5：2 个谓词仍只发 1 次）\n";

        // ---- SUM ----
        t0 = std::chrono::steady_clock::now();
        const uint64_t sum = client.SumWithFilter({{0, 2}}, 1);
        const uint64_t want_sum = PlainSum(recs, 1, 2);
        std::cout << "      SUM(filter p0=2, 求和 p1) = " << sum
                  << "  明文=" << want_sum << (sum == want_sum ? "  ✓" : "  ✗")
                  << "  用时 " << MsSince(t0) << " ms\n";

        // 远程模式下客户端**不持有**服务器存储，只能报告自己这一侧的规模。
        // （这本身就是隐私性的体现：服务端状态对客户端不可见。）
        const uint64_t words = params.words_per_column();
        uint64_t total_columns = 0;
        for (uint32_t s : sizes) total_columns += s;
        // 服务器存的条目表 = one-hot 区（每取值一列） + value plane 区
        //（每属性 l_a 个比特面，供 SUM/矩 还原每条记录的取值）。
        const uint64_t one_hot_entries = total_columns * words;
        const uint64_t plane_entries =
            static_cast<uint64_t>(params.num_planes()) * words;
        std::cout << "\n客户端侧账目：每列 " << words << " 个 word，共 "
                  << total_columns << " 列 ⇒ one-hot 区 "
                  << one_hot_entries << " 个共享条目 + value plane 区 "
                  << params.num_planes() << " 个面 × " << words << " words = "
                  << plane_entries << " 个 ⇒ 合计 "
                  << (one_hot_entries + plane_entries) << " 个（"
                  << ((one_hot_entries + plane_entries) * 16 / 1024)
                  << " KB，按位打包；PIR 数据库补齐到 2 的幂后为 "
                  << params.PaddedEntries() << " 个）\n";
        std::cout << "本通道 RPC 统计：server0=" << ch0.rpc_count()
                  << "，server1=" << ch1.rpc_count() << "\n";

        const int bad = mismatch + (both == want_both ? 0 : 1) + (sum == want_sum ? 0 : 1);
        std::cout << "\n=== " << (bad == 0 ? "全部一致" : "存在不一致") << " ===\n";
        return bad == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    } catch (const std::exception& e) {
        std::cerr << "客户端失败: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
}
