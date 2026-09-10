// VMP-07：VMPQ 基准测试。
//
// 报告论文 Table I / Table III 关心的量，便于对照：
//   * 离线 Init 耗时与 hint 存储（客户端侧）
//   * 在线查询延迟：单谓词 Count / 多谓词 Count / SUM
//   * 服务端存储（论文口径 |κ|·(N + N·2^l)）
//   * 查询通信量（按"每个 word 一次 PIR 请求"计入）
//   * **实测** PIR 请求次数（由服务器侧计数器量出，不再靠公式估算）
//
// ⚠️ 与论文的可比性说明（见 TASK_PLAN §7.9）：
//   论文把整列作为一次 PIR 的 entry（hint parity 可压到 1 比特）；
//   本实现把列按 128 位打包、每个 word 一次 PIR，因此**请求次数**是
//   ⌈N/128⌉ 倍，但每次请求的规模也小得多。绝对延迟不可直接对比，
//   但量级与伸缩趋势可以。
//
// 运行：./build/bin/bench_vmpq [--quick]

#include "vmpq/vmpq.hpp"
#include "core/random.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace tsb;
using Clock = std::chrono::steady_clock;

namespace {

double MsSince(const Clock::time_point& t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

struct Row {
    uint32_t window = 0;
    uint32_t attr_bits = 0;   // l
    uint32_t part_num = 0;
    uint32_t part_size = 0;
    uint64_t hints = 0;
    uint64_t real_entries = 0;    // 真实条目数（one-hot 区 + value plane 区）
    uint64_t pir_entries = 0;     // 补齐到 2 的幂后的 PIR 数据库大小
    double init_ms = 0;
    double count1_ms = 0;
    double count2_ms = 0;
    double sum_ms = 0;
    uint64_t server_kb = 0;
    uint64_t hint_kb = 0;
    uint64_t query_bytes = 0;  // 一次单谓词查询的请求字节数
    // 实测 PIR 次数（服务器侧计数器增量）
    uint64_t pir_count1 = 0;
    uint64_t pir_sum = 0;
    bool no_refresh = false;
    uint64_t answer = 0;
};

// 确定性记录生成。
// ⚠️ 用**固定密钥**（早期版本用 AesPrf::GenerateKey() 取真随机密钥，导致
// 每次运行的数据库都不同、基准数字不可复现；数据内容虽不影响复杂度，
// 但复现性对出表很重要）。
std::vector<std::vector<uint64_t>> MakeRecords(uint32_t n, uint32_t domain,
                                               uint64_t seed) {
    std::array<uint8_t, 16> key{};
    key.fill(0x2B);
    random::DeterministicPrng prng(key, seed);
    std::vector<std::vector<uint64_t>> recs(n, std::vector<uint64_t>(2));
    for (auto& r : recs) {
        r[0] = prng.Below(domain);
        r[1] = prng.Below(domain);
    }
    return recs;
}

// unsafe_no_refresh=true 时关闭"查询后刷新 hint"（决策 D17），
// 用来量化刷新带来的额外开销；**该模式不保证隐私**，只用于基准对比。
Row RunCase(uint32_t window, uint32_t attr_bits, uint32_t lambda, uint64_t seed,
            bool unsafe_no_refresh = false) {
    Row row;
    row.window = window;
    row.attr_bits = attr_bits;
    row.no_refresh = unsafe_no_refresh;

    VmpqParams p;
    p.window_size = window;
    const uint32_t domain = 1u << attr_bits;
    p.attr_sizes = {domain, domain};
    p.lambda = lambda;
    p.unsafe_disable_hint_refresh = unsafe_no_refresh;

    const auto recs = MakeRecords(window, domain, seed);

    std::vector<uint8_t> key(16);
    for (int i = 0; i < 16; ++i) key[i] = static_cast<uint8_t>(i + 1);
    AesPrf prf(key);

    VmpqClient client(p, prf);

    auto t0 = Clock::now();
    client.Init(recs);
    row.init_ms = MsSince(t0);

    const VooPirParams pp = p.DerivePirParams();
    row.part_num = pp.part_num;
    row.part_size = pp.part_size;
    row.hints = client.pir().ValidHintCount();
    row.real_entries = p.TotalEntries();
    row.pir_entries = pp.n;

    // 在线：单谓词 Count（实测消耗的查询集个数）
    const uint64_t served_before = client.node(0).queries_served();
    t0 = Clock::now();
    row.answer = client.CountSinglePredicate(0, 3 % domain);
    row.count1_ms = MsSince(t0);
    row.pir_count1 = client.node(0).queries_served() - served_before;

    // 在线：双谓词 Count
    t0 = Clock::now();
    (void)client.CountMultiPredicate({{0, 3 % domain}, {1, 5 % domain}});
    row.count2_ms = MsSince(t0);

    // 在线：SUM（对属性 1 求和，filter 是一个谓词）
    const uint64_t served_before_sum = client.node(0).queries_served();
    t0 = Clock::now();
    (void)client.SumWithFilter({{0, 3 % domain}}, 1);
    row.sum_ms = MsSince(t0);
    row.pir_sum = client.node(0).queries_served() - served_before_sum;

    // 存储：服务端（两台合计）
    row.server_kb = client.node(0).storage_bytes() * 2 / 1024;
    // 存储：客户端 hint（每条：hint_id 8 + cutoff 4 + 指示位 1 + extra 8 + parity 16）
    const uint64_t per_hint = 8 + 4 + 1 + 8 + 16;
    row.hint_kb = row.hints * per_hint / 1024;
    // 通信：单谓词查询 = ⌈N/128⌉ 次 PIR 请求，每次 = P×(2 字节偏移 + 1 比特分组)
    const uint64_t words = (window + 127) / 128;
    row.query_bytes = words * (pp.part_num * 2 + pp.part_num / 8);
    return row;
}

}  // namespace

int main(int argc, char** argv) {
    const bool quick = (argc > 1 && std::strcmp(argv[1], "--quick") == 0);

    std::printf("VMPQ benchmark (VMP-07)\n");
    std::printf("半诚实版本：无 proof、无 MAC 密钥（决策 D16）；"
                "查询时全部谓词列一次取回、客户端本地组合（Q5）；\n"
                "每轮查询后刷新被消费的 hint（决策 D17）\n\n");

    const uint32_t l = 6;  // 64 个取值
    std::vector<uint32_t> windows = quick
        ? std::vector<uint32_t>{512, 1024}
        : std::vector<uint32_t>{512, 1024, 2048, 4096};

    std::vector<Row> rows;
    std::printf("%8s %4s %8s %8s %5s %6s %7s %9s %8s %8s %9s %8s %8s %8s %8s %8s\n",
                "N", "l", "entries", "PIR n", "P", "sigma", "M", "Init ms",
                "Cnt1 ms", "Cnt2 ms", "Sum ms", "PIR/Cnt1", "PIR/Sum", "Srv KB",
                "Hint KB", "Qry B");
    std::printf("%s\n", std::string(140, '-').c_str());

    for (uint32_t n : windows) {
        try {
            const Row r = RunCase(n, l, 24, 7);
            rows.push_back(r);
            std::printf("%8u %4u %8llu %8llu %5u %6u %7llu %9.1f %8.2f %8.2f "
                        "%9.2f %8llu %8llu %8llu %8llu %8llu\n",
                        r.window, r.attr_bits,
                        (unsigned long long)r.real_entries,
                        (unsigned long long)r.pir_entries,
                        r.part_num, r.part_size,
                        (unsigned long long)r.hints, r.init_ms, r.count1_ms,
                        r.count2_ms, r.sum_ms,
                        (unsigned long long)r.pir_count1,
                        (unsigned long long)r.pir_sum,
                        (unsigned long long)r.server_kb,
                        (unsigned long long)r.hint_kb,
                        (unsigned long long)r.query_bytes);
        } catch (const std::exception& e) {
            std::printf("%8u %5u  -- 跳过：%s\n", n, l, e.what());
        }
    }

    // SUM 的 PIR 次数：本实现（value plane） vs 旧归约（Σ_v v·Count）
    std::printf("\nSUM 的 PIR 次数对比（filter 1 个谓词，求和属性 l=%u）：\n", l);
    std::printf("%8s %12s %22s %10s\n", "N", "本实现(实测)",
                "旧归约(2^l·(|f|+1)·w)", "加速比");
    for (const Row& r : rows) {
        const uint64_t words = (r.window + 127) / 128;
        const uint64_t legacy =
            static_cast<uint64_t>(1u << r.attr_bits) * 2 * words;
        std::printf("%8u %12llu %22llu %9.1fx\n", r.window,
                    (unsigned long long)r.pir_sum, (unsigned long long)legacy,
                    static_cast<double>(legacy) /
                        static_cast<double>(r.pir_sum == 0 ? 1 : r.pir_sum));
    }

    // 决策 D17 的开销：查询后刷新 hint（换新的 hint_id/cutoff/半区）
    std::printf("\n刷新 hint 的开销（决策 D17；不刷新会泄露查询分区，仅供对比）：\n");
    std::printf("%8s %14s %16s %12s %14s\n", "N", "Cnt1(刷新) ms",
                "Cnt1(不刷新) ms", "SUM(刷新) ms", "SUM(不刷新) ms");
    for (uint32_t n : windows) {
        try {
            const Row safe = RunCase(n, l, 24, 7, false);
            const Row fast = RunCase(n, l, 24, 7, true);
            std::printf("%8u %14.2f %16.2f %12.2f %14.2f\n", n, safe.count1_ms,
                        fast.count1_ms, safe.sum_ms, fast.sum_ms);
        } catch (const std::exception& e) {
            std::printf("%8u  -- 跳过：%s\n", n, e.what());
        }
    }

    // 论文取值 λ=80 的规模验证（hint 数放大 3.3 倍）
    std::printf("\n论文取值 lambda=80（N=1024, l=6）：\n");
    try {
        const Row r = RunCase(1024, l, 80, 11);
        std::printf("  P=%u sigma=%u M=%llu  Init=%.1f ms  Hint=%.0f KB  "
                    "Srv=%.0f KB\n",
                    r.part_num, r.part_size, (unsigned long long)r.hints,
                    r.init_ms, static_cast<double>(r.hint_kb),
                    static_cast<double>(r.server_kb));
    } catch (const std::exception& e) {
        std::printf("  跳过：%s\n", e.what());
    }

    std::printf("\n说明：\n");
    std::printf("  * entries = 真实条目数（one-hot 区 + value plane 区）；PIR n = 向上补齐\n");
    std::printf("    到 2 的幂后的 PIR 数据库大小（决策 D15(1)：V-OO-PIR 要求 n 是 2 的幂）。\n");
    std::printf("    ⚠️ value plane 区会把条目数推过 2 的幂边界，使本表的 PIR n / P / M\n");
    std::printf("    相对 §7.10 的旧数字翻倍（旧口径下 N=1024 的真实条目恰好是 1024）。\n");
    std::printf("    因此**延迟不能跨版本直接比较**，可比较的是 PIR 次数与伸缩规律。\n");
    std::printf("  * Srv(KB) 是**两台服务器合计**的条目表存储（按位打包后），\n");
    std::printf("    含 one-hot 区与 value plane 区（后者仅占 ~l/2^l）。\n");
    std::printf("    论文口径为 |κ|·(N + N·2^l)；本实现按位打包，故 one-hot 部分\n");
    std::printf("    为 |κ|·(N·2^l/128)，比论文小 128 倍（见 §7.9 G1）。\n");
    std::printf("  * PIR/xxx 是**服务器侧计数器实测**的查询集个数：\n");
    std::printf("    单谓词 Count = ⌈N/128⌉（每 word 一次）；\n");
    std::printf("    SUM = (|filter| + l)·⌈N/128⌉（PIR-02：取回 value plane 后\n");
    std::printf("    本地还原每条记录的取值，见 §7.9 G5）。\n");
    std::printf("    多谓词 Count 按谓词数线性叠加。\n");
    std::printf("  * Qry(B) 按论文的请求编码 P×(2 字节偏移 + 1 比特分组) 估算。\n");
    return 0;
}
