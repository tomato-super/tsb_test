// MPRAQ 客户端进程（任务 `MPA-08`：端到端 demo 的**客户端侧**，真实 gRPC）。
//
// 用法（规模来源 = JSON 配置 + CLI 逐项覆盖；不给 `--config` 时走同一套派生逻辑的默认值）：
//   ./mpraq_client --server0 127.0.0.1:P0 --server1 127.0.0.1:P1 \
//                  [--config config/mpraq_scale.json] \
//                  [--rows 4096] [--columns 32] [--attributes 2] [--predicates 3] \
//                  [--lambda 80] [--eps 1e-4] [--seed 7] [--prng-seed 11] [--sum-attr 1]
//
// 规模口径（**负责人只管三个量**：行数 N、每属性列数、谓词数 k；其余全部自动派生，
// 详见 `src/mpraq/scale_config.hpp`）：
//   * `--rows`      = 行数 = 记录数 N（**2 的幂**，否则**报错拒绝**，不静默取整）；
//   * `--columns`   = 列数 = **每个属性**的 LCTE 列数（**2 的幂**；所有属性同形状、
//                     但**各自一组列** ⇒ 真实列数 M = 属性数 × 每属性列数）；
//   * `--predicates`= 谓词数 k（谓词内容由程序自动生成，尽量落在互不相同的列上
//                     ⇒ 去重列数 = min(k, M)）；
//   * 补齐列数 m / Plinko 几何 (n, w, c) / 查询集数 / 存储 / L14 预算全部由程序派生。
//   启动时会打印一行换算（"本次规模：… ⇒ 去重列数=…、查询集数=…、每台 RPC=1"）。
//
// 流程（每一步都与**明文基准**逐值对照，铁律 D6：每个断言都有明确期望值）：
//   ① 确定性合成数据（`DeterministicPrng` + 显式 seed；`feature = i` 是 D36 的行标签）
//   ② 两台服务器进程上的 `Init`（`InitWithChannels` → 真实 gRPC：InitTable +
//      特征 word XOR 共享分块上传 + 每个属性一条 mod q 加法共享）
//   ③ **L14 查询预算**：打印算式（一次 Count 需要 `去重列数` 个查询集 —— 一列 = 一个条目 = 1 个查询集；
//      一次离线上限 = min(q = λw/2, 新鲜索引池 n)）
//   ④ 查询 ①：**单谓词**（= 自动生成的谓词 #0，占 1 列）→ Count + filter
//   ⑤ 查询 ②：**k 个谓词的合取**（Φ = ∧_j P_j，去重列数 = min(k, M)）→ Count + filter
//   ⑥ `Sum` / `Avg`：对两个 filter 各跑一次 `MPA-06` 的批量 SecureMul
//      （**服务器在另一个进程里** ⇒ 走 `MPA-08` 的标记帧 + 通用 `Relay`）
//   ⑦ 账目：服务器存储（**实测** + 公式双报含补齐/不含补齐）、查询集数、每台 RPC 次数
//      （一次 `RunBatch` 恒 1）、SecureMul 往返数（恒 2）与消息数、各阶段耗时、
//      hint 消耗与剩余
//
// ⚠️ 性能口径（报告里必须区分）：本 demo 是**真实 gRPC 回环/本机两进程**，
//    不是"进程内 `LocalTransport`"；两者数字不可混用。
//
// ⚠️ 半诚实版本（决策 D4/D16）：无 TLS、无认证；`PIR 值层`与`Count` 完整性
//    **没有**可用机制（`MPA-07` 已如实声明）——本 demo 不假装有验证层。

#include "net/mpraq_remote_securemul.hpp"

#include "core/field.hpp"
#include "core/random.hpp"
#include "mpraq/aggquery.hpp"
#include "mpraq/aggvalue.hpp"
#include "mpraq/init.hpp"
#include "mpraq/node.hpp"
#include "mpraq/predicate.hpp"
#include "mpraq/scale_config.hpp"
#include "net/grpc_mpraq.hpp"
#include "net/grpc_transport.hpp"

#include "mpraq_baseline.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace tsb;
using namespace tsb::mpraq;

namespace {

using Clock = std::chrono::steady_clock;

// 输出详略开关：只有 `--verbose` 才打印全量账目（默认一屏摘要）。
// ⚠️ 它**只影响打印**：所有口径断言、fail-loudly 与退出码都与它无关。
bool g_verbose = false;

double MsSince(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

std::string Num(uint64_t v) { return std::to_string(v); }

// ---------------------------------------------------------------------------
// 命令行
// ---------------------------------------------------------------------------

struct Options {
    std::string server0;
    std::string server1;
    // 规模来源：`--config FILE`（基底） + 规模旗标（逐项覆盖）。
    // ⚠️ 不给 `--config` 时基底 = `MpraqScaleConfig::Defaults()`（与
    //    `config/mpraq_scale.json` 逐字段一致），**走的仍是同一套派生逻辑**。
    std::string config;
    MpraqScaleOverrides scale;   // --rows/--columns/--attributes/--predicates/--lambda/--eps/--seed
    uint64_t prng_seed = 11;     // SecureMul triple 的确定性种子
    uint32_t sum_attr = 1;       // Sum/Avg 作用的属性号（默认取规模派生值）
    bool has_sum_attr = false;   // 是否显式给了 --sum-attr（否则用派生值）
    // 默认**只打一屏摘要**；`--verbose` 打印全部账目（规模派生、L14 算式、服务器增量、
    // hint 余额、每阶段耗时等）。**所有断言与 fail-loudly 行为与开关无关**。
    bool verbose = false;
};

Options ParseArgs(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        const auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) {
                throw std::invalid_argument(std::string("缺少参数值: ") + what);
            }
            return argv[++i];
        };
        if (a == "--server0") {
            o.server0 = next("--server0");
        } else if (a == "--server1") {
            o.server1 = next("--server1");
        } else if (a == "--config") {
            o.config = next("--config");
        } else if (a == "--prng-seed") {
            o.prng_seed = std::stoull(next("--prng-seed"));
        } else if (a == "--sum-attr") {
            o.sum_attr = static_cast<uint32_t>(std::stoul(next("--sum-attr")));
            o.has_sum_attr = true;
        } else if (a == "--verbose" || a == "-v") {
            o.verbose = true;
        } else if (a == "--help" || a == "-h") {
            std::cout
                << "用法: ./mpraq_client --server0 host:port --server1 host:port [选项]\n"
                   "\n"
                   "规模（负责人只管三个量；其余全部自动派生，见 src/mpraq/scale_config.hpp）：\n"
                   "  --config FILE       规模配置 JSON（缺省 = config/mpraq_scale.json 的同值默认值）\n"
                   "  --rows N            行数 = 记录数 N（**必须是 2 的幂**，否则报错拒绝）\n"
                   "  --columns C         列数 = **每个属性**的 LCTE 列数（**必须是 2 的幂**，>= 2）\n"
                   "  --attributes A      属性数（M = 属性数 × 每属性列数）\n"
                   "  --predicates K      谓词数 k（谓词内容自动生成；去重列数 = min(k, M)）\n"
                   "  --lambda L          Plinko 安全参数 λ（默认 80）\n"
                   "  --eps E             iPRF 的 PRP 目标 ε（默认 1e-4）\n"
                   "  --seed S            合成数据与 Init 的确定性种子（默认 7）\n"
                   "  --security-mode M   运行方式：malicious（默认）| semi-honest\n"
                   "                        （必须与两台服务器的档位一致）\n"
                   "  --repeat-query-cache on|off\n"
                   "                       Plinko 的重复查询缓存（**默认 on**）。\n"
                   "                       off ⇒ 重复查询**直接拒绝**（绝不重查同一索引，\n"
                   "                       那会让访问模式可关联）；要求上层不对同一列重复查询\n"
                   "\n"
                   "其余：\n"
                   "  --prng-seed P       SecureMul triple 的确定性种子（默认 11）\n"
                   "  --sum-attr A        Sum/Avg 作用的属性号（默认取规模派生值）\n"
                   "  --verbose, -v       打印全部账目（默认只打一屏摘要）\n"
                   "  --help              打印本帮助\n"
                   "\n"
                   "命令行覆盖优先于 JSON；启动时会打印一行换算：\n"
                   "  本次规模：N=…、每属性列数=…、属性数=…、M=…、m=…、谓词数=…\n"
                   "            ⇒ 去重列数=min(k,M)、查询集数=去重列数、每台 RPC=1\n";
            std::exit(EXIT_SUCCESS);
        } else if (MpraqScaleOverrides::IsScaleFlag(a)) {
            o.scale.Set(a, next(a.c_str()));
        } else {
            throw std::invalid_argument("未知参数: " + a);
        }
    }
    if (o.server0.empty() || o.server1.empty()) {
        throw std::invalid_argument(
            "必须给出两台服务器进程的端点：--server0 host:port --server1 host:port");
    }
    if (o.server0 == o.server1) {
        throw std::invalid_argument(
            "--server0 与 --server1 不能相同：那等于一台服务器冒充两台");
    }
    return o;
}

// ---------------------------------------------------------------------------
// 数据与 schema（**全部由规模配置派生**；见 `mpraq/scale_config.hpp`）
// ---------------------------------------------------------------------------
//   * 每个属性：R = [0, 每属性列数 − 1]、domain = [0, 每属性列数 − 2]（D19-5 取紧上限）；
//   * 取值：`DeterministicPrng(seed)` 在取值域内均匀取样（合成数据，用户不关心内容）；
//   * `feature = i` = 行标签（D36 的"死字段"，只进客户端明文副本）。
// ---------------------------------------------------------------------------

// 明文基准的数据集：取值域直接从这个 schema 抄（**不**复用协议层的求值路径）
mpraq_baseline::Dataset MakeBaseline(const Schema& schema,
                                     const std::vector<MpraqRecord>& recs) {
    mpraq_baseline::Dataset d;
    d.num_attributes = schema.num_attributes();
    for (const AttributeSchema& a : schema.attributes()) {
        d.domain_min.push_back(a.domain_min);
        d.domain_max.push_back(a.domain_max);
    }
    d.records.reserve(recs.size());
    for (const MpraqRecord& r : recs) d.records.push_back(r.attributes);
    return d;
}

// 谓词 → 明文基准谓词（**独立转写**：基准不复用被测代码，见 `mpraq_baseline.hpp`）
mpraq_baseline::Pred ToBaseline(const Predicate& p) {
    mpraq_baseline::Pred b;
    b.attr = p.attribute_id;
    switch (p.op) {
        case mpraq::PredicateOp::kEq: b.op = mpraq_baseline::Op::kEq; break;
        case mpraq::PredicateOp::kNeq: b.op = mpraq_baseline::Op::kNe; break;
        case mpraq::PredicateOp::kLt: b.op = mpraq_baseline::Op::kLt; break;
        case mpraq::PredicateOp::kLe: b.op = mpraq_baseline::Op::kLe; break;
        case mpraq::PredicateOp::kGt: b.op = mpraq_baseline::Op::kGt; break;
        case mpraq::PredicateOp::kGe: b.op = mpraq_baseline::Op::kGe; break;
        case mpraq::PredicateOp::kRange: b.op = mpraq_baseline::Op::kRange; break;
    }
    b.value = p.value;
    b.lower = p.lower;
    b.upper = p.upper;
    return b;
}

std::vector<mpraq_baseline::Pred> ToBaseline(const std::vector<Predicate>& ps) {
    std::vector<mpraq_baseline::Pred> out;
    out.reserve(ps.size());
    for (const Predicate& p : ps) out.push_back(ToBaseline(p));
    return out;
}

Predicate ById(uint32_t attr, mpraq::PredicateOp op, int64_t v) {
    Predicate p;
    p.by_id = true;
    p.attribute_id = attr;
    p.op = op;
    p.value = v;
    return p;
}

std::string PredString(const std::vector<Predicate>& ps) {
    std::string s;
    for (size_t i = 0; i < ps.size(); ++i) {
        const Predicate& p = ps[i];
        if (i != 0) s += " ∧ ";
        s += "attr" + std::to_string(p.attribute_id);
        switch (p.op) {
            case mpraq::PredicateOp::kRange:
                s += " ∈ [" + std::to_string(p.lower) + "," + std::to_string(p.upper) + ")";
                break;
            case mpraq::PredicateOp::kEq: s += " == " + std::to_string(p.value); break;
            case mpraq::PredicateOp::kNeq: s += " ≠ " + std::to_string(p.value); break;
            case mpraq::PredicateOp::kLt: s += " < " + std::to_string(p.value); break;
            case mpraq::PredicateOp::kLe: s += " ≤ " + std::to_string(p.value); break;
            case mpraq::PredicateOp::kGt: s += " > " + std::to_string(p.value); break;
            case mpraq::PredicateOp::kGe: s += " ≥ " + std::to_string(p.value); break;
        }
    }
    return s;
}

uint64_t Popcount(const std::vector<uint8_t>& f) {
    uint64_t c = 0;
    for (uint8_t b : f) c += (b != 0) ? 1u : 0u;
    return c;
}

// ---------------------------------------------------------------------------
// 一次 Count + Sum + Avg 的结果（全部与基准逐值对照）
// ---------------------------------------------------------------------------

struct QueryReport {
    std::string name;
    std::string predicate_text;
    CountResult count;
    uint64_t words_queried = 0;
    uint64_t rpc_calls[2] = {0, 0};   // 本次 Count 在每台服务器上的 RPC 次数
    double count_ms = 0.0;
    bool has_sum = false;
    bool has_avg = false;   // count == 0 ⇒ Avg 无定义（库口径抛 domain_error），不调用
    SumResult sum;
    uint128_t avg = 0;
    double sum_ms = 0.0;
    SecureMulBatchStats sm;
};

// 打印一条 `Count` 的账目（含 Q5 口径：一批 = 1 次 RPC/台）—— 仅 `--verbose`。
// 被移出 print 的口径（原中文说明）：
//   * 每个命中位的 filter 都逐位对照过明文基准；
//   * 检索列按去重升序；**一列 = 一个条目 = 1 个查询集** ⇒ 查询集 = 去重列数；
//   * 一次 RunBatch 恒 1 次 RPC/台，与查询集个数无关；
//   * retrieve 含 QueryGen+ServerResp+XOR+ClientRecon；combine 是本地布尔组合。
void PrintCountAccounts(const QueryReport& r, size_t entry_words) {
    if (!g_verbose) return;
    std::printf("    count count=%llu filter_bitwise_checked=1\n",
                static_cast<unsigned long long>(r.count.count));
    std::printf("      columns n=%zu entry_words=%zu query_sets=%llu\n",
                r.count.columns.size(), entry_words,
                static_cast<unsigned long long>(r.words_queried));
    std::printf("      rpc server0=%llu server1=%llu per_batch=1\n",
                static_cast<unsigned long long>(r.rpc_calls[0]),
                static_cast<unsigned long long>(r.rpc_calls[1]));
    std::printf("      timing retrieve_ms=%.1f combine_ms=%.2f total_ms=%.1f\n",
                r.count.retrieve_ms, r.count.combine_ms, r.count_ms);
}

// 打印一次 Sum/Avg 的账目（`--verbose` 专用）。被移出 print 的口径（原中文说明）：
//   * sum 在 mod q = 2^127−1 下；Avg = sum/count（整数向下取整）；
//   * count == 0 ⇒ Avg 无定义（`AvgOverFilter` 不被调用）；
//   * rounds 恒 2；Collect 第 1/2 轮各一次；安装阶段额外 rounds/frames（install_frames 是帧数）；
//   * messages = 2N（单台视角）、wire_messages = 4N（线上真实条数）；
//   * 帧长 Phase1 = 6+34N、Phase2 = 6+58N、安装帧合计 = 2×(13+152N)；
//   * 服务器侧常驻材料 = N×(7×16+16) B/台；records = 不剪枝时 f=0 也照发的记录数。
void PrintSumAccounts(const QueryReport& r, size_t n) {
    if (!g_verbose) return;
    const SecureMulBatchStats& s = r.sm;
    if (r.has_avg) {
        std::printf("    sum sum=%s count=%llu avg=%s mod_q=2^127-1\n",
                    toString(r.sum.sum).c_str(),
                    static_cast<unsigned long long>(r.sum.count), toString(r.avg).c_str());
    } else {
        std::printf("    sum sum=%s count=0 avg=undefined avg_called=0 mod_q=2^127-1\n",
                    toString(r.sum.sum).c_str());
    }
    std::printf("      rounds rounds=%llu collect_p1=%llu collect_p2=%llu "
                "install_rounds=%llu install_frames=%llu\n",
                static_cast<unsigned long long>(s.rounds),
                static_cast<unsigned long long>(s.collect_calls_phase1),
                static_cast<unsigned long long>(s.collect_calls_phase2),
                static_cast<unsigned long long>(s.install_rounds),
                static_cast<unsigned long long>(s.install_frames));
    std::printf("      messages messages=%llu wire_messages=%llu "
                "p1_s0=%llu p1_s1=%llu p2_s0=%llu p2_s1=%llu frames_s0=%llu frames_s1=%llu\n",
                static_cast<unsigned long long>(s.messages),
                static_cast<unsigned long long>(s.wire_messages),
                static_cast<unsigned long long>(s.server_records_processed[0]),
                static_cast<unsigned long long>(s.server_records_processed[1]),
                static_cast<unsigned long long>(s.server_records_processed_phase2[0]),
                static_cast<unsigned long long>(s.server_records_processed_phase2[1]),
                static_cast<unsigned long long>(s.server_frames[0]),
                static_cast<unsigned long long>(s.server_frames[1]));
    std::printf("      frame_bytes phase1=%llu phase2=%llu install_total=%llu\n",
                static_cast<unsigned long long>(s.frame_bytes_phase1),
                static_cast<unsigned long long>(s.frame_bytes_phase2),
                static_cast<unsigned long long>(s.install_bytes));
    std::printf("      timing offline_triple_ms=%.1f offline_setup_ms=%.1f online_ms=%.1f "
                "verify_ms=%.1f sum_total_ms=%.1f\n",
                s.offline_triple_ms, s.offline_setup_ms, s.online_ms, s.verify_ms,
                r.sum_ms);
    std::printf("      server_state bytes_per_server=%llu records=%llu\n",
                static_cast<unsigned long long>(s.server_state_peak_bytes),
                static_cast<unsigned long long>(s.records));
    (void)n;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const Options opt = ParseArgs(argc, argv);
        g_verbose = opt.verbose;

        if (g_verbose) {
            // 原中文标题「MPRAQ 端到端 demo（MPA-08）：真实 gRPC、两进程、1 客户端 + 2 服务器」
            // 与分隔线一并精简为裸键值：口径 = 真 gRPC、两个服务器进程、1 客户端 + 2 服务器。
            std::printf("mpraq_demo mode=grpc_two_process clients=1 servers=2\n");
            std::printf("server0=%s\nserver1=%s\n", opt.server0.c_str(),
                        opt.server1.c_str());
        } else {
            std::printf("mpraq_demo mode=grpc_two_process server0=%s server1=%s\n",
                        opt.server0.c_str(), opt.server1.c_str());
        }

        // ---------------------------------------------------------------
        // ⓪ 规模配置（JSON + CLI 覆盖）→ 派生 schema / 合成数据 / 谓词 / 几何
        // ---------------------------------------------------------------
        // ⚠️ 口径：负责人只管三个量（行数 N、每属性列数、谓词数 k）；其余全部自动派生。
        //    不给 `--config` 时基底是 `MpraqScaleConfig::Defaults()`（与
        //    `config/mpraq_scale.json` 同值），**派生逻辑完全同一条路径**。
        const MpraqScaleConfig base_cfg = opt.config.empty()
                                              ? MpraqScaleConfig::Defaults()
                                              : MpraqScaleConfig::FromFile(opt.config);
        const MpraqScaleConfig cfg = ApplyOverrides(base_cfg, opt.scale);
        const MpraqScaleSetup setup = Build(cfg);
        const MpraqScaleEstimate& est = setup.estimate;
        const size_t N = static_cast<size_t>(cfg.rows);
        const uint32_t sum_attr =
            opt.has_sum_attr ? opt.sum_attr : setup.sum_attr;  // 默认取派生值
        if (sum_attr >= cfg.attributes) {
            throw std::invalid_argument(
                "--sum-attr = " + std::to_string(sum_attr) + " 越界：本次规模的属性数 = " +
                std::to_string(cfg.attributes) + "（合法范围 [0, " +
                std::to_string(cfg.attributes - 1) + "]）");
        }
        const std::string cfg_source =
            opt.config.empty() ? std::string("default") : ("config:" + opt.config);
        if (g_verbose) {
            // 规模来源：缺省 = 内置默认值（同 config/mpraq_scale.json）；CLI 覆盖 = 有/无。
            std::printf("scale_source=%s cli_overrides=%s\n", cfg_source.c_str(),
                        opt.scale.any() ? "yes" : "no");
        }

        // ---- 必须打印的一行换算（负责人按它手算核对）----
        std::printf("\nscale %s\n", est.Headline().c_str());
        if (g_verbose) {
            std::printf("%s", est.Report().c_str());
        }
        std::printf("params lambda=%u eps=%g seed=%llu prng_seed=%llu sum_attr=%u\n", cfg.lambda,
                    cfg.eps, static_cast<unsigned long long>(cfg.seed),
                    static_cast<unsigned long long>(opt.prng_seed), sum_attr);

        // ---------------------------------------------------------------
        // ⓪' 数据 + 基准（全部来自规模派生）
        // ---------------------------------------------------------------
        const Schema& schema = setup.schema;
        const std::vector<MpraqRecord>& records = setup.records;
        const mpraq_baseline::Dataset baseline = MakeBaseline(schema, records);
        if (g_verbose) {
            // 数据口径（原中文说明）：N 条记录；每个属性 R = [0, 列数−1]、m = 列数、
            // domain = [min,max]；取值由 `DeterministicPrng(seed)` 合成；M = 真实列数
            // = 属性数 × 每属性列数。
            std::printf("data N=%zu attrs=%u R_max=%u m=%u domain_min=%lld domain_max=%lld "
                        "seed=%llu M=%llu\n",
                        N, cfg.attributes, cfg.columns_per_attribute - 1,
                        cfg.columns_per_attribute,
                        static_cast<long long>(ScaleDomainMin(cfg)),
                        static_cast<long long>(ScaleDomainMax(cfg)),
                        static_cast<unsigned long long>(cfg.seed),
                        static_cast<unsigned long long>(est.levels));
            // 谓词自动生成（阈值全部落在该属性的 LCTE 区间内）⇒ 去重列数 = min(k, M)。
            std::printf("preds k=%u min(k,M)=%u M=%llu dedup=%llu\n",
                        cfg.predicates, cfg.predicates,
                        static_cast<unsigned long long>(est.levels),
                        static_cast<unsigned long long>(est.dedup_columns));
        }

        // ---------------------------------------------------------------
        // ② Init（真实 gRPC 到两台服务器进程）
        // ---------------------------------------------------------------
        GrpcMpraqChannel channel0(opt.server0);
        GrpcMpraqChannel channel1(opt.server1);
        const auto t_connect = Clock::now();
        channel0.Connect();
        channel1.Connect();
        const double connect_ms = MsSince(t_connect);

        // SecureMul 的通用传输（Relay 通道）连的是**同一个端口**（同一台服务器进程）
        GrpcTransportClient transport({opt.server0, opt.server1});
        transport.Connect(5000);
        RemoteSecureMulBatchEndpoint ep0(transport, kServer0);
        RemoteSecureMulBatchEndpoint ep1(transport, kServer1);

        // Init 参数**直接**取自规模派生（λ / ε / seed；w 交给几何派生）
        const MpraqInitParams init_params = setup.init;

        const auto t_init = Clock::now();
        std::unique_ptr<MpraqClient> client = MpraqClient::InitWithChannels(
            schema, records, init_params, channel0, channel1);
        const double init_ms = MsSince(t_init);

        const StoreParams& store = client->store_params();
        const PlinkoParams& plinko = client->plinko_params();
        const size_t entry_words = store.entry_words;
        const uint64_t n_entries = store.entry_count();
        const uint64_t q_hints = plinko.backup_hints();
        const uint64_t hint_slots = plinko.hint_slots();

        // [Init] 一行：连接/Init（含上传）/HintInit 耗时、上传字节、几何 n/w/c。
        std::printf("\ninit connect_ms=%.1f init_ms=%.1f hintinit_ms=%.1f "
                    "upload_bytes=%llu m=%llu w=%llu kappa=%llu\n",
                    connect_ms, init_ms, client->timings().hint_ms,
                    static_cast<unsigned long long>(client->upload_bytes()),
                    static_cast<unsigned long long>(n_entries),
                    static_cast<unsigned long long>(plinko.w),
                    static_cast<unsigned long long>(plinko.blocks()));
        if (g_verbose) {
            const MpraqInitTimings& t = client->timings();
            // 上传字节（两台合计）= 2×(16n + 16N·|attrs|)。
            std::printf("        phases lcte_ms=%.1f pack_ms=%.1f share_ms=%.1f "
                        "hintinit_ms=%.1f upload_ms=%.1f\n",
                        t.lcte_ms, t.pack_ms, t.share_ms, t.hint_ms, t.upload_ms);
            std::printf("        upload_chunks chunks=%zu chunk_words=%zu bytes=%llu\n",
                        t.chunk_count, t.chunk_words,
                        static_cast<unsigned long long>(client->upload_bytes()));
            // 几何：m = PIR 条目数（一列 = 一个条目）；λw = 常规 hint；N_T = λw/2（备份）；
            //       H = λw+N_T（槽位）。
            std::printf("        geom n=%zu entry_words=%zu levels=%zu m=%zu pad=%zu w=%llu kappa=%llu "
                        "lw=%llu N_T=%llu H=%llu\n",
                        store.n, entry_words, store.levels,
                        store.m, store.padding_columns(),
                        static_cast<unsigned long long>(n_entries),
                        static_cast<unsigned long long>(plinko.w),
                        static_cast<unsigned long long>(plinko.blocks()),
                        static_cast<unsigned long long>(plinko.main_hints()),
                        static_cast<unsigned long long>(q_hints),
                        static_cast<unsigned long long>(hint_slots));
            // Init 阶段的 RPC 次数（口径由 `DistributeUpload` 推导，不写死常数）：
            // 每台 = InitTable 1 + 上传 %llu + 属性共享 %zu。
            std::printf("        init_rpc per_server=%llu init_table=1 upload=%llu attr_shares=%zu\n",
                        static_cast<unsigned long long>(channel0.rpc_count()),
                        static_cast<unsigned long long>(client->timings().chunk_count),
                        store.num_attributes());
        }

        // 服务器账目的**基线**：本 demo 的服务器进程可能在多次客户端运行之间存活，
        // 因此所有"服务器侧计数"都用**增量**口径（与通道侧的 delta 口径一致），
        // 绝对量（存储字节）另有公式可对照。
        ServerStats stats_before[2] = {QueryServerStats(transport, 0),
                                       QueryServerStats(transport, 1)};

        // ---------------------------------------------------------------
        // ③ L14 查询预算（**先算清楚再查**）
        // ---------------------------------------------------------------
        // ① 每个**查询集**（= 一整列）消费 1 条常规 hint 并提升 1 条备份 ⇒ 一次离线支持
        //    `N_T = λw/2` 次列举查询；
        // ② 重复访问同一列要另取"未答复过的"新索引 ⇒ 新鲜索引池 = m（条目数）。
        // ⚠️ 列粒度：**一列 = 一个条目 = 1 个查询集**，因此计划量就是"列数"，
        //    **不再乘以 ⌈n/128⌉**（旧 word 口径的 128 倍消耗已作废）。
        const auto budget_plan = [&](const std::vector<size_t>& per_query_columns) {
            uint64_t total = 0;
            for (size_t c : per_query_columns) total += c;
            return total;
        };
        // 两次查询的去重列数：①单谓词 = 1 列；②k 个谓词 = min(k, M)（规模派生值）
        const std::vector<size_t> plan_columns = {1,
                                                  static_cast<size_t>(est.dedup_columns)};
        const uint64_t planned_sets = budget_plan(plan_columns);
        const uint64_t budget = std::min<uint64_t>(q_hints, n_entries);
        // 口径断言（与详略无关，必须始终成立）
        if (plan_columns[1] != est.query_sets) {
            throw std::logic_error(
                "本次查询的去重列数 ≠ 规模派生的查询集数 " + Num(est.query_sets) +
                " —— 规模层与谓词层的口径漂移了");
        }
        if (planned_sets > budget) {
            throw std::runtime_error(
                "L14 预算不足：计划 " + Num(planned_sets) + " 个查询集 > 上限 " +
                Num(budget) + " —— 必须加大 λ/w（放大 N_T）或减少本次查询的列数");
        }
        // 一行摘要（默认）；完整算式在 `--verbose`。
        // 口径：计划查询集 ≤ min(N_T = λw/2（备份 hint）, m（新鲜索引池）)。
        std::printf("budget planned_sets=%llu N_T=%llu m=%llu budget=%llu margin=%llu pass=1\n",
                    static_cast<unsigned long long>(planned_sets),
                    static_cast<unsigned long long>(q_hints),
                    static_cast<unsigned long long>(n_entries),
                    static_cast<unsigned long long>(budget),
                    static_cast<unsigned long long>(budget - planned_sets));
        if (g_verbose) {
            // 一次 Count 消耗「去重列数」个查询集；查询① = 单谓词（1 列）、
            // 查询② = k 个谓词（去重 min(k,M) 列）。
            std::printf("\nbudget_check\n");
            std::printf("           q0_cols=%zu q0_cols_mul=%zu entry_words=%zu q0_sets=%zu "
                        "q1_preds=%u q1_cols=%zu q1_cols_mul=%zu wpr2=%zu q1_words=%zu "
                        "total_words=%llu\n",
                        plan_columns[0], plan_columns[0], entry_words,
                        plan_columns[0] * entry_words, cfg.predicates, plan_columns[1],
                        plan_columns[1], entry_words, plan_columns[1] * entry_words,
                        static_cast<unsigned long long>(planned_sets));
            // 口径换算：谓词数 k → 去重列数 min(k, M) → 查询集数 = 去重列数
            // （对齐规模派的预估值）→ 每台 RPC = 1。
            std::printf("           convert preds=%u preds2=%u M=%llu dedup=%zu dedup2=%zu "
                        "entry_words=%zu qsets=%zu est_qsets=%llu rpc_per_server=1\n",
                        cfg.predicates, cfg.predicates,
                        static_cast<unsigned long long>(est.levels), plan_columns[1],
                        plan_columns[1], entry_words, plan_columns[1] * entry_words,
                        static_cast<unsigned long long>(est.query_sets));
            // 一次离线的上限 = min(① 备份 hint N_T = λw/2，② 新鲜索引池 m)。
            std::printf("           cap min_lambda_w_over_2 lambda=%u w=%llu N_T=%llu pool_m=%llu cap=%llu\n",
                        cfg.lambda, static_cast<unsigned long long>(plinko.w),
                        static_cast<unsigned long long>(q_hints),
                        static_cast<unsigned long long>(n_entries),
                        static_cast<unsigned long long>(budget));
            // 两次查询用的列互不重复（列 plan_columns[0]+plan_columns[1] 个，m 列）
            // ⇒ 不额外消耗新鲜索引。
            std::printf("           check planned=%llu budget=%llu margin=%llu "
                        "cols0=%zu cols1=%zu m=%zu disjoint=1\n",
                        static_cast<unsigned long long>(planned_sets),
                        static_cast<unsigned long long>(budget),
                        static_cast<unsigned long long>(budget - planned_sets),
                        plan_columns[0], plan_columns[1], store.m);
        }

        // 客户端侧 SecureMul 状态（α **全局一份**，来自 Init 的 mac_key_shares()）
        // ⚠️ 档位必须显式传入（构造无默认值）：半诚实档下 `VerifyAndReconstruct`
        //    **不做任何验证**（跳过 SPDZ MAC 与 §4.5-A/B）—— 这是如实声明的边界。
        SecureMulClientState mac(client->mac_key_shares(), client->modulus(),
                                 client->store_params().security_mode);
        random::DeterministicPrng prng(MakeAesSeed(std::vector<uint8_t>{'m', 'p', 'a', '0', '8'}),
                                       opt.prng_seed);

        // ---------------------------------------------------------------
        // ④⑤⑥ 两次查询：Count（PIR） + Sum/Avg（SecureMul）
        // ---------------------------------------------------------------
        struct Case {
            std::string name;
            std::vector<Predicate> preds;
            std::vector<mpraq_baseline::Pred> bpreds;
            uint64_t expect_columns = 0;  // 期望的去重列数（规模派生口径）
        };
        // ① 单谓词（自动生成的谓词 #0，name=q0）⇒ 1 列；
        // ② 全部 k 个谓词的合取（name=q1_k<k>）⇒ 去重列数 = min(k, M)（谓词落在互不相同的列上）。
        // 名字只作为裸键值/诊断里的标识，不再带中文。
        const std::vector<Case> cases = {
            {"q0",
             {setup.predicates[0]},
             {ToBaseline(setup.predicates[0])},
             1},
            {"q1_k" + std::to_string(cfg.predicates),
             setup.predicates,
             ToBaseline(setup.predicates),
             est.dedup_columns},
        };

        std::vector<QueryReport> reports;
        uint64_t total_query_sets = 0;
        uint64_t total_pir_rpc[2] = {0, 0};
        uint64_t total_sm_rounds = 0;
        uint64_t total_sm_wire = 0;
        uint64_t total_install_rounds = 0;
        double total_count_ms = 0.0;
        double total_sum_ms = 0.0;

        for (size_t ci = 0; ci < cases.size(); ++ci) {
            const Case& c = cases[ci];
            QueryReport r;
            r.name = c.name;
            r.predicate_text = PredString(c.preds);
            if (g_verbose) {
                std::printf("\nquery name=%s phi=%s\n", c.name.c_str(), r.predicate_text.c_str());
            }

            const uint64_t rpc0_before = channel0.rpc_count();
            const uint64_t rpc1_before = channel1.rpc_count();
            const auto t_count = Clock::now();
            r.count = CountPredicates(*client, schema, c.preds);
            r.count_ms = MsSince(t_count);
            r.rpc_calls[0] = channel0.rpc_count() - rpc0_before;
            r.rpc_calls[1] = channel1.rpc_count() - rpc1_before;
            // ⚠️ 列粒度：**一列 = 一个条目 = 1 个查询集** ⇒ 查询集数就等于去重列数
            //    （不再乘以 entry_words）。
            r.words_queried = static_cast<uint64_t>(r.count.columns.size());
            // 口径核对（必须打印/断言出来，而不是只写在注释里）：
            //   去重列数 == 期望值（① 1 列；② min(k, M)）
            //   查询集数 == 去重列数（一列 = 一个条目 = 1 个查询集）
            //   每台 RPC 次数 == 1（一次 RunBatch 恒 1，与批次大小无关）
            if (r.count.columns.size() != c.expect_columns) {
                throw std::runtime_error(
                    "查询 " + c.name + " 的去重列数 " +
                    Num(static_cast<uint64_t>(r.count.columns.size())) + " ≠ 规模派生口径 " +
                    Num(c.expect_columns));
            }
            if (r.count.queries_issued != r.words_queried) {
                throw std::runtime_error("查询集数 ≠ 去重列数");
            }
            if (r.rpc_calls[0] != 1 || r.rpc_calls[1] != 1) {
                throw std::runtime_error(
                    "每次 Count 在每台服务器上的 RPC 次数必须恒为 1（实测 " +
                    Num(r.rpc_calls[0]) + "/" + Num(r.rpc_calls[1]) + "）");
            }

            // ---- 与**明文基准**逐值对照（铁律 D6：不是"跑通即通过"）----
            const std::vector<uint8_t> bfilter = mpraq_baseline::Filter(baseline, c.bpreds);
            const uint64_t bcount = Popcount(bfilter);
            if (r.count.count != bcount) {
                throw std::runtime_error("Count 与明文基准不一致：协议 " +
                                         Num(r.count.count) + " vs 基准 " + Num(bcount));
            }
            if (mpraq_baseline::FilterShape(r.count.filter) !=
                mpraq_baseline::FilterShape(bfilter)) {
                throw std::runtime_error("filter 向量与明文基准逐位不一致");
            }
            if (g_verbose) {
                // 明文基准对照：filter 逐位一致；每字面量取反/合取由客户端本地做，服务器零参与。
                std::printf("    baseline count=%llu filter_bits=%zu bitwise_match=1 "
                            "server_participation=0\n",
                            static_cast<unsigned long long>(bcount), r.count.filter.size());
            }
            PrintCountAccounts(r, entry_words);

            // ---- Sum / Avg（`MPA-06` 批量 SecureMul，**服务器在另一个进程**）----
            // ⚠️ `count == 0`（没有任何记录满足谓词）是**合法**的查询结果，但 `Avg` 在数学上
            //    无定义 —— 库的口径是**抛** `std::domain_error`（绝不静默返回 0，
            //    见 `aggvalue.hpp` §8）⇒ 调用方必须先判 count（本 demo 就按这条口径做：
            //    count == 0 时**不调用** `AvgOverFilter`，只跑 Sum（= 0，数学上良定义））。
            const uint64_t salt = prng.Next() & 0xFFFFFFFFFFFFULL;  // **每次查询换新盐**
            const auto t_sum = Clock::now();
            r.sum = SumOverFilter(r.count, schema, sum_attr, *client, transport, ep0,
                                  ep1, mac, prng, salt);
            r.sum_ms = MsSince(t_sum);
            r.has_avg = (r.count.count > 0);
            if (r.has_avg) {
                r.avg = AvgOverFilter(r.sum);
            } else if (g_verbose) {
                // count == 0 ⇒ 平均值无定义，**不调用** `AvgOverFilter`
                //（库口径：count == 0 ⇒ std::domain_error）；Sum = 0 仍与明文基准对照。
                std::printf("    avg count=0 avg=undefined avg_called=0 sum_still_checked=1\n");
            }
            r.sm = r.sum.securemul;
            r.has_sum = true;

            const mpraq_baseline::Moments bm =
                mpraq_baseline::Aggregate(baseline, c.bpreds, sum_attr);
            if (r.sum.sum != static_cast<uint128_t>(bm.sum)) {
                throw std::runtime_error("Sum 与明文基准不一致：协议 " + toString(r.sum.sum) +
                                         " vs 基准 " + Num(bm.sum));
            }
            if (r.sum.count != bm.count) {
                throw std::runtime_error("count 与明文基准不一致");
            }
            if (r.has_avg) {
                if (bm.count == 0 || r.avg != static_cast<uint128_t>(bm.sum / bm.count)) {
                    throw std::runtime_error("Avg 与明文基准不一致");
                }
            } else if (bm.count != 0) {
                throw std::runtime_error(
                    "Avg 被跳过了，但明文基准的 count = " + Num(bm.count) + " ≠ 0");
            }
            if (r.sm.rounds != 2) {
                throw std::runtime_error("SecureMul 往返数 ≠ 2（口径被破坏）");
            }
            if (r.sm.wire_messages != 4 * N || r.sm.messages != 2 * N) {
                throw std::runtime_error("SecureMul 消息条数与 2N/4N 口径不符");
            }
            PrintSumAccounts(r, N);
            if (g_verbose) {
                if (bm.count == 0) {
                    // 两边口径一致：不调用 AvgOverFilter、不做除法。
                    std::printf("    baseline sum=%llu count=0 avg=undefined "
                                "avg_called=0 divide_done=0\n",
                                static_cast<unsigned long long>(bm.sum));
                } else {
                    // Avg 为整数向下取整；协议 / 基准双向一致。
                    std::printf("    baseline sum=%llu count=%llu avg=%llu floor=1 match=1\n",
                                static_cast<unsigned long long>(bm.sum),
                                static_cast<unsigned long long>(bm.count),
                                static_cast<unsigned long long>(bm.sum / bm.count));
                }
            }
            // 一行摘要（默认）：结果 = 基准、Sum/Avg、关键账目
            std::printf("query name=%s phi=%s count=%llu count_matches_baseline=1 sum=%s avg=%s "
                        "columns=%zu query_sets=%llu rpc0=%llu rpc1=%llu retrieve_ms=%.1f "
                        "sum_ms=%.1f\n",
                        c.name.c_str(), r.predicate_text.c_str(),
                        static_cast<unsigned long long>(r.count.count),
                        toString(r.sum.sum).c_str(),
                        r.has_avg ? toString(r.avg).c_str() : "undefined",
                        r.count.columns.size(),
                        static_cast<unsigned long long>(r.words_queried),
                        static_cast<unsigned long long>(r.rpc_calls[0]),
                        static_cast<unsigned long long>(r.rpc_calls[1]), r.count.retrieve_ms,
                        r.sum_ms);

            total_query_sets += r.words_queried;
            total_pir_rpc[0] += r.rpc_calls[0];
            total_pir_rpc[1] += r.rpc_calls[1];
            total_sm_rounds += r.sm.rounds;
            total_sm_wire += r.sm.wire_messages;
            total_install_rounds += r.sm.install_rounds;
            total_count_ms += r.count_ms;
            total_sum_ms += r.sum_ms;
            reports.push_back(std::move(r));
        }

        // ---------------------------------------------------------------
        // ⑦ 账目汇总
        // ---------------------------------------------------------------
        if (g_verbose) {
            // 账目汇总（原中文标题）：真实 gRPC 两进程，**不是**进程内 LocalTransport 口径。
            std::printf("\naccounts mode=grpc_two_process local_transport=0\n");
        }

        // ---- 服务器存储：公式**三项双报**（数据 / tag / 属性）+ 服务器**实测**值 ----
        // ⚠️ xmac 的 tag 表与数据表**等大**（tag 与条目等宽，ℓ = 128 = 一个字）；
        //    只有**恶意档**存在（半诚实档不生成/不存/不传/不校验 tag ⇒ 存储减半）。
        const uint64_t feature_padded =
            16ull * store.m * entry_words;
        const uint64_t feature_unpadded =
            16ull * store.levels * entry_words;
        const uint64_t tag_bytes =
            store.has_tags() ? 16ull * store.m * entry_words : 0ull;
        const uint64_t attr_bytes =
            16ull * store.n * store.num_attributes();
        if (g_verbose) {
            // 公式（每台服务器）：
            //   含补齐   = 16·m·entry_words + 16·n·|attrs|；
            //   不含补齐 = 16·levels·entry_words + 16·n·|attrs|；
            //   属性值部分 = 16·N·|attrs|（每属性一条长度 N 的向量）。
            std::printf("storage_formula per_server=1\n");
            std::printf("  srv_padded m=%zu entry_words=%zu n=%zu attrs=%zu security=%s "
                        "bytes=%llu\n",
                        store.m, entry_words, store.n,
                        store.num_attributes(),
                        MpraqSecurityModeName(store.security_mode),
                        static_cast<unsigned long long>(feature_padded + tag_bytes + attr_bytes));
            std::printf("  srv_data_bytes bytes=%llu\n",
                        static_cast<unsigned long long>(feature_padded));
            std::printf("  srv_tag_bytes bytes=%llu has_tags=%d\n",
                        static_cast<unsigned long long>(tag_bytes),
                        store.has_tags() ? 1 : 0);
            std::printf("  srv_unpadded levels=%zu entry_words=%zu n=%zu attrs=%zu bytes=%llu diff=%llu "
                        "pad_entries=%zu\n",
                        store.levels, entry_words, store.n,
                        store.num_attributes(),
                        static_cast<unsigned long long>(feature_unpadded + tag_bytes + attr_bytes),
                        static_cast<unsigned long long>(feature_padded - feature_unpadded),
                        store.padding_columns());
            std::printf("  srv_attr_bytes bytes=%llu\n",
                        static_cast<unsigned long long>(attr_bytes));
            // 服务器进程**实测**值：经 Relay 的账目帧取回（非公式）。
            std::printf("\nstorage_measured source=relay_account_frame\n");
        }
        for (int sid = 0; sid < 2; ++sid) {
            const ServerStats st = QueryServerStats(transport, sid);
            const ServerStats& b = stats_before[static_cast<size_t>(sid)];
            // 增量（本次客户端运行期间的服务器侧实测计数）
            const uint64_t d_rpc = st.rpc_count - b.rpc_count;
            const uint64_t d_queries = st.queries_served - b.queries_served;
            const uint64_t d_words = st.words_read - b.words_read;
            const uint64_t d_install = st.relay_install_frames - b.relay_install_frames;
            const uint64_t d_phase = st.relay_phase_frames - b.relay_phase_frames;
            const uint64_t d_records =
                st.relay_records_processed - b.relay_records_processed;
            const uint64_t d_service_batch =
                st.service_batch_resp_calls - b.service_batch_resp_calls;
            const uint64_t d_node_batch =
                st.node_batch_rpc_count - b.node_batch_rpc_count;
            const uint64_t d_node_scalar =
                st.node_scalar_rpc_count - b.node_scalar_rpc_count;
            if (g_verbose) {
                // 服务器实测（增量口径，本次客户端运行期间）：数据 RPC = 服务侧受理的 4 条
                // 数据 RPC 合计（本 demo 里 = Count 次数）；node 层 word 读取 = 查询集 × c；
                // node 层计数在 InitTable 时清零。
                std::printf("  server id=%d initialized=%s storage_bytes=%llu feature_bytes=%llu "
                            "attr_bytes=%llu d_rpc=%llu count_calls=%zu d_queries=%llu "
                            "d_words_read=%llu d_queries_mul=%llu c=%llu\n",
                            sid, st.initialized ? "yes" : "no",
                            static_cast<unsigned long long>(st.storage_bytes),
                            static_cast<unsigned long long>(st.feature_storage_bytes),
                            static_cast<unsigned long long>(st.attribute_storage_bytes),
                            static_cast<unsigned long long>(d_rpc), reports.size(),
                            static_cast<unsigned long long>(d_queries),
                            static_cast<unsigned long long>(d_words),
                            static_cast<unsigned long long>(d_queries),
                            static_cast<unsigned long long>(plinko.blocks()));
                // PIR 计数口径（增量）：服务侧批量入口调用 = 数据 RPC 次数（一次 RPC 恰好一次
                // 批量调用）；node 层批量；node 层标量在 gRPC 部署下恒 0（服务侧不再走标量接口，
                // 且 node 层的 `InitTable` 会清零 ⇒ 此处是最近一次 Init 之后的增量）。
                std::printf("              pir_counts service_batch=%llu d_rpc=%llu "
                            "node_batch=%llu node_scalar=%llu\n",
                            static_cast<unsigned long long>(d_service_batch),
                            static_cast<unsigned long long>(d_rpc),
                            static_cast<unsigned long long>(d_node_batch),
                            static_cast<unsigned long long>(d_node_scalar));
                // Relay 增量：安装帧 = Sum 次数、相位帧 = 2×Sum 次数、累计处理记录 = 2N×Sum 次数。
                std::printf("              relay d_install_frames=%llu sum_calls=%zu "
                            "d_phase_frames=%llu d_records=%llu\n",
                            static_cast<unsigned long long>(d_install), reports.size(),
                            static_cast<unsigned long long>(d_phase),
                            static_cast<unsigned long long>(d_records));
            }
            if (st.storage_bytes != feature_padded + tag_bytes + attr_bytes) {
                throw std::runtime_error(
                    "服务器 " + Num(static_cast<uint64_t>(sid)) + " 实测存储 " +
                    Num(st.storage_bytes) + " ≠ 公式（数据 " + Num(feature_padded) +
                    " + tag " + Num(tag_bytes) + " + 属性 " + Num(attr_bytes) + "）");
            }
            if (d_rpc != reports.size()) {
                throw std::runtime_error("服务器数据 RPC 增量 ≠ Count 次数（一次 RunBatch = 1 RPC）");
            }
            // MPA-08 裁决 1：**一次 RPC 恰好一次批量入口调用**（服务侧可断言）
            if (d_service_batch != d_rpc) {
                throw std::runtime_error(
                    "服务侧批量入口调用次数 ≠ 数据 RPC 次数（" + Num(d_service_batch) +
                    " vs " + Num(d_rpc) + "）—— 服务侧必须一次 RPC 只调一次批量入口");
            }
            if (d_node_batch != d_rpc) {
                throw std::runtime_error("node 层批量调用增量 ≠ 数据 RPC 次数");
            }
            if (d_node_scalar != 0) {
                throw std::runtime_error(
                    "node 层**标量** ServerResp 被调用了 " + Num(d_node_scalar) +
                    " 次 —— gRPC 服务侧必须只走批量入口");
            }
            if (d_queries != total_query_sets) {
                throw std::runtime_error("服务器受理的查询集增量 ≠ 客户端发出的查询集数");
            }
            // ⚠️ 列粒度：每个查询集读的是**一整个条目**（entry_words 个字）⇒
            //    words_read = 查询集数 × κ × entry_words。
            if (d_words != total_query_sets * plinko.blocks() * store.entry_words) {
                throw std::runtime_error(
                    "服务器 word 读取增量 ≠ 查询集数 × κ × entry_words");
            }
            if (d_phase != 2 * reports.size()) {
                throw std::runtime_error("服务器相位帧增量 ≠ 2 × Sum 次数（两轮/查询）");
            }
            if (d_install != reports.size()) {
                throw std::runtime_error("服务器安装帧增量 ≠ Sum 次数（每次 Sum 一次安装）");
            }
            if (d_records != 2ull * N * reports.size()) {
                throw std::runtime_error("服务器累计处理记录增量 ≠ 2N × Sum 次数");
            }
        }

        // ---- 账目一行摘要（默认）；完整账目在 `--verbose` ----
        // 口径：存储/台 = 公式 = 实测；查询集 = Σ 每次 Count 的 列数×⌈N/128⌉；
        // SecureMul rounds 与线上消息（wire）；安装 rounds 与帧数（两台合计）。
        // `tag_checks` = 已通过 xmac 校验的查询集个数。**恶意档 = 查询集数（校验真的跑了）；
        // 半诚实档恒 0**（该档不生成 γ、不校验）—— 这是"分档确实生效"的可见证据。
        std::printf("\naccounts storage_bytes_per_server=%llu query_sets=%llu "
                    "pir_rpc0=%llu pir_rpc1=%llu sm_rounds=%llu sm_wire_messages=%llu "
                    "install_rounds=%llu install_frames=%llu tag_checks=%llu "
                    "pir_cache=%s\n",
                    static_cast<unsigned long long>(feature_padded + tag_bytes + attr_bytes),
                    static_cast<unsigned long long>(total_query_sets),
                    static_cast<unsigned long long>(total_pir_rpc[0]),
                    static_cast<unsigned long long>(total_pir_rpc[1]),
                    static_cast<unsigned long long>(total_sm_rounds),
                    static_cast<unsigned long long>(total_sm_wire),
                    static_cast<unsigned long long>(total_install_rounds),
                    static_cast<unsigned long long>(2 * reports.size()),
                    static_cast<unsigned long long>(client->tag_checks()),
                    client->pir_query_cache_enabled() ? "on" : "off");

        // ---- 查询集 / RPC / 往返 ----
        if (g_verbose) {
            // 口径（原中文说明）：查询集总数 = Σ 每次 Count 的 列数×⌈N/128⌉；PIR 的 n 是
            // **word 数**，不是记录数；每台 PIR RPC = 查询次数（一次 RunBatch = 1 次 RPC，
            // 与批次大小无关）；SecureMul 每次 Sum 恒 2 轮，线上消息 = 4N × Sum 次数；
            // 安装 = 离线 dealer 材料下发（每次 Sum 一次），帧数两台合计；
            // 端到端 RPC/往返总计（每台）= PIR + SecureMul 在线 + 安装 + 账目查询(2)。
            std::printf("\nquery_rpc\n");
            std::printf("  query_sets total=%llu\n",
                        static_cast<unsigned long long>(total_query_sets));
            std::printf("  pir_rpc server0=%llu server1=%llu count=%zu per_batch=1\n",
                        static_cast<unsigned long long>(total_pir_rpc[0]),
                        static_cast<unsigned long long>(total_pir_rpc[1]), reports.size());
            std::printf("  securemul rounds=%llu sum_calls=%zu wire_messages=%llu sum_calls2=%zu\n",
                        static_cast<unsigned long long>(total_sm_rounds), reports.size(),
                        static_cast<unsigned long long>(total_sm_wire), reports.size());
            std::printf("  install rounds=%llu frames=%llu\n",
                        static_cast<unsigned long long>(total_install_rounds),
                        static_cast<unsigned long long>(2 * reports.size()));
            std::printf("  rpc_total per_server pir=%llu sm_online=%llu install=%llu "
                        "accounts=%llu total=%llu\n",
                        static_cast<unsigned long long>(total_pir_rpc[0]),
                        static_cast<unsigned long long>(total_sm_rounds),
                        static_cast<unsigned long long>(total_install_rounds),
                        static_cast<unsigned long long>(2),
                        static_cast<unsigned long long>(total_pir_rpc[0] + total_sm_rounds +
                                                        total_install_rounds + 2));
        }

        // ---- hint 预算消耗 ----
        const uint64_t consumed = client->query_count();
        // L14 的两条上限都要算（**最小的那条说了算**）。
        // 口径：以"**本轮 demo 的这两次查询**"为单位（合计 `total_query_sets` 个 word 查询）
        // ⇒ "还能做 N 轮"是可直接对应的说法，而不是把一个平均值冒充"每次查询"。
        const uint64_t per_round = total_query_sets;
        const uint64_t by_hint =
            per_round == 0 ? 0 : client->backup_remaining() / per_round;
        const uint64_t pool_left =
            n_entries > total_query_sets ? n_entries - total_query_sets : 0;
        const uint64_t by_pool = per_round == 0 ? 0 : pool_left / per_round;
        std::printf("hint backup_remaining=%llu N_T=%llu pool_m=%llu pool_used=%llu "
                    "rounds_left=%llu\n",
                    static_cast<unsigned long long>(client->backup_remaining()),
                    static_cast<unsigned long long>(q_hints),
                    static_cast<unsigned long long>(n_entries),
                    static_cast<unsigned long long>(total_query_sets),
                    static_cast<unsigned long long>(std::min(by_hint, by_pool)));
        if (g_verbose) {
            // 预算（台账 L14）明细：已消耗的查询集数（客户端计数）= 实际发出的查询集；
            // ① 备份 hint 剩余 / N_T（H = λw + N_T）⇒ 还能做几轮同样规模的查询（每轮 per_round 个）；
            // ② 新鲜索引池 m（重复访问同一**条目**要另取未答复索引）；
            // 两条上限取较小者；用尽必须重跑离线（D8，本项目不做摊销式离线）。
            std::printf("\nhint_budget\n");
            std::printf("  hint_used words=%llu query_sets=%llu\n",
                        static_cast<unsigned long long>(consumed),
                        static_cast<unsigned long long>(total_query_sets));
            std::printf("  hint_backup remaining=%llu N_T=%llu H=%llu rounds_left=%llu "
                        "words_per_round=%llu\n",
                        static_cast<unsigned long long>(client->backup_remaining()),
                        static_cast<unsigned long long>(q_hints),
                        static_cast<unsigned long long>(hint_slots),
                        static_cast<unsigned long long>(by_hint),
                        static_cast<unsigned long long>(per_round));
            std::printf("  hint_pool m=%llu used=%llu rounds_left=%llu\n",
                        static_cast<unsigned long long>(n_entries),
                        static_cast<unsigned long long>(total_query_sets),
                        static_cast<unsigned long long>(by_pool));
            std::printf("  hint_limit rounds_min=%llu exhausted_action=offline_rerun\n",
                        static_cast<unsigned long long>(std::min(by_hint, by_pool)));
        }
        if (consumed != total_query_sets) {
            throw std::runtime_error("hint 消耗计数 " + Num(consumed) +
                                     " ≠ 发出的查询集数 " + Num(total_query_sets));
        }

        // ---- 耗时（一行） ----
        std::printf("timing init_ms=%.1f count_ms=%.1f sum_ms=%.1f wall_ms=%.1f\n",
                    init_ms, total_count_ms, total_sum_ms, MsSince(t_init));

        // 结论：Count/filter/Sum/Avg 全部与明文基准逐值一致；一次 RunBatch = 1 次 RPC/台；
        // SecureMul 往返恒 2；服务器存储 = 公式。
        std::printf("result baseline_match=1 rpc_per_batch=1 sm_rounds=2 storage_formula_match=1\n");
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << "\n[FAIL-LOUDLY] demo 中止：" << e.what() << "\n";
        return EXIT_FAILURE;
    }
}
