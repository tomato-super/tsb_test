// `MPA-09`：MPRAQ 的**参数与复杂度验证**基准/实验驱动（实测曲线 + 参数选择）。
//
// ===========================================================================
// 0. 这个程序回答什么（以及**不**回答什么）
// ===========================================================================
// 实验（`--exp`）：
//   * `online`    在线查询成本 vs 规模：`Count` 延迟、查询集数、每台 RPC 次数、
//                 去重列数 ⇒ 精确对照 "查询集数 = 列数 × ⌈N/128⌉"；
//   * `sum`       `Sum`/`Avg` 在线成本 vs 规模：`rounds`/`messages`/`wire`/
//                 帧长/`online_ms`/`verify_ms`，**两进程口径另含 D34 的安装段**；
//   * `init-w`    离线 `Init` 成本 vs `(n, w)`：验证 `HintInit ≈ n × IF⁻¹`
//                 （与 `w` 无关、与 `n` 成正比，`TASK_PLAN.md` D22-1）；
//   * `storage`   服务器存储（§1 公式，**双报**含/不含补齐）+ 客户端存储
//                 （hint 的"理想口径 / 每条口径 / 实际分配"三个口径都给）；
//   * `tradeoff`  `λ` 与 `ε` 的权衡：失败概率参数 ↔ 离线成本 / 客户端存储 /
//                 L14 查询预算；
//   * `all`       依次跑上面全部（每张表独立打印）。
//
// **不做**（如实声明，见 `TASK_PLAN.md` D8 与 Q9 报告 D6）：
//   ① 数据库更新 ⇒ 论文的 `O(log n)` 更新**这一条曲线本程序不产出**（本项目 D8
//      明确不做更新；要报只能报"不支持 + 依据"）；
//   ② 论文的 `Õ(n/r)` 是**渐近**口径：本程序实测的是 `c = n/w` 次**区块访问**
//      （以及 `word` 查询数、RPC 次数三个**不同**的量），**不把 `c` 与 `n/r` 等同**；
//   ③ `N ≥ 2^16` 不支持（两进程安装帧会到 ~80 MB，需分块安装，未实现）。
//
// ===========================================================================
// 1. 口径（每个数字都必须能回答"这是进程内还是两进程？是区块访问还是查询集还是 RPC？"）
// ===========================================================================
//   | 量 | 口径 |
//   |---|---|
//   | `mode=local` | 进程内 `LocalTransport` + 进程内 `MpraqNode`（无序列化/无回环） |
//   | `mode=grpc-two-process` | 真实 gRPC、**两个服务器进程**（`mpraq_server`），
//   |              | 客户端通过 `GrpcMpraqChannel`（数据 RPC）+ `Relay`（SecureMul）接入 |
//   | 查询集数 | = **一个条目**的一次 PIR 检索 = `列数`（一个条目 = 一整列；**不是** RPC） |
//   | RPC 次数 | = `ServerRespBatch` 调用次数；**一次 `RunBatch` 恒 1**（与批次大小无关） |
//   | 区块访问量 | = 查询集数 × `kappa`（`kappa = m/w`；论文 `Õ(n/r)` 的实数化口径） |
//   | 条目宽度 | `entry_words = ⌈n/128⌉` 个字；应答与缓存都按**整条目**搬运 |
//   | 安装段（D34） | 两进程下每次 `Sum` 把 `N` 条 `SecureMulServerSetup` 下发给**每台**
//   |              | ⇒ `install_bytes = 2×(13+152N)`，**单列**、不并入 `wire_messages` |
//   | 服务器存储 | `16·m·entry_words + 16·n·|attrs|`（`m` = **补齐后**条目数）；双报"不含补齐" |
//
// ===========================================================================
// 2. 查询预算（台账 L14；**先算清楚再跑**，绝不跑到一半抛异常）
// ===========================================================================
// 两条硬上限（`TASK_PLAN.md` 台账 L14）：
//   ① 每次查询消费 1 条常规 hint 并提升 1 条备份 ⇒ 一次离线支持 `N_T = λw/2` 次；
//   ② 重复访问同一**条目**要另取"未答复过"的新索引 ⇒ 新鲜索引池 = `m`。
// ⇒ 本程序在**任何** Init/查询之前先算 `planned_sets = 列数 × 重复次数`
//   （**一列 = 一个条目 = 1 个查询集**），与 `min(N_T, m)` 比较；
//   超预算就**拒绝运行**（退出码 **3**），绝不把失败推迟到 `PlinkoBackupsExhausted`。
//
// ===========================================================================
// 3. 机器可读输出（`MPA-10` / 自动汇总用）
// ===========================================================================
//   * `--json`     ：**每行一条 JSON**（JSONL），形如
//                    `{"config":{...},"point":{...}}`；人读文本同时打到 **stderr**
//                    （终端上照样能看到表格，stdout 保持干净可解析）。
//   * `--json-out F`：把完整文档（`config` + 全部 `points` + `summary`）写到文件 F，
//                    人读文本仍走 stdout。
//   * 字段名稳定（`snake_case`），几何/账目/耗时的键在任何实验里都存在。
//
// ⚠️ 性能口径：`local` 与 `grpc-two-process` 的数字**不可直接比较**（`MPA-08` 的
//    性能口径声明）；所有输出都带 `mode` 字段。

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
#include "net/transport.hpp"

#include "mpraq_baseline.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace tsb;
using namespace tsb::mpraq;

namespace {

using Clock = std::chrono::steady_clock;

// 人读文本的出口：默认 stdout；`--json` 时改道 **stderr**（stdout 只留 JSONL，便于管道/解析）
FILE* g_human = stdout;
#define HPRINT(...) std::fprintf(g_human, __VA_ARGS__)

double MsSince(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

std::string Num(uint64_t v) { return std::to_string(v); }

// 与 `mpraq/init.cpp` 的 `NextPow2` 同义（那份在匿名命名空间里 ⇒ 这里只用于**报告**
// "升级前的最小补齐列数 m0"，与几何推导本身无关）
std::string NumD(double v, int prec = 2) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(prec) << v;
    return oss.str();
}

// ===========================================================================
// 极简 JSON 输出（不引入依赖；字段顺序 = 插入顺序 ⇒ 输出可 diff）
// ===========================================================================

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

std::string JsonStr(const std::string& s) { return "\"" + JsonEscape(s) + "\""; }

class Json {
public:
    Json() = default;

    Json& Str(const std::string& k, const std::string& v) {
        kv_.emplace_back(k, JsonStr(v));
        return *this;
    }
    Json& U64(const std::string& k, uint64_t v) {
        kv_.emplace_back(k, std::to_string(v));
        return *this;
    }
    Json& I64(const std::string& k, int64_t v) {
        kv_.emplace_back(k, std::to_string(v));
        return *this;
    }
    Json& Bool(const std::string& k, bool v) {
        kv_.emplace_back(k, v ? "true" : "false");
        return *this;
    }
    // 浮点：默认 6 位有效数字（够用且可读）；`json_double_precision` 可调
    Json& Dbl(const std::string& k, double v, int prec = 6) {
        std::ostringstream oss;
        if (!std::isfinite(v)) {
            kv_.emplace_back(k, "null");
            return *this;
        }
        oss << std::setprecision(prec) << v;
        kv_.emplace_back(k, oss.str());
        return *this;
    }
    Json& Raw(const std::string& k, const std::string& raw_json) {
        kv_.emplace_back(k, raw_json);
        return *this;
    }
    Json& Field(const std::string& k, const Json& o) { return Raw(k, o.Dump()); }

    std::string Dump() const {
        std::string out = "{";
        for (size_t i = 0; i < kv_.size(); ++i) {
            if (i) out += ",";
            out += JsonStr(kv_[i].first) + ":" + kv_[i].second;
        }
        out += "}";
        return out;
    }

private:
    std::vector<std::pair<std::string, std::string>> kv_;
};

// ===========================================================================
// 数据集 / schema（**确定性**：显式公式，不用 PRNG 造数据 ⇒ 期望值可独立手算）
// ===========================================================================
//   属性 0：R = [0,5]、m = 6、domain = [0,4]；取值 = i % 5
//   属性 1：R = [0,3]、m = 4、domain = [0,2]；取值 = (i / 2) % 3   ← Sum/Avg 的属性
constexpr uint32_t kAttrCount = 2;
constexpr uint32_t kAttr0M = 6;
constexpr uint32_t kAttr1M = 4;
constexpr int64_t kAttr0DomainMax = 4;
constexpr int64_t kAttr1DomainMax = 2;
constexpr size_t kRealColumns = kAttr0M + kAttr1M;  // M = 10

AttributeSchema MakeAttr(uint32_t id, uint32_t m, int64_t dmin, int64_t dmax, size_t n) {
    AttributeSchema a;
    a.name = "attr" + std::to_string(id);
    a.id = id;
    a.lcte.window_size = static_cast<uint32_t>(n);
    a.lcte.range_min = dmin;
    a.lcte.range_size = m;
    a.domain_min = dmin;
    a.domain_max = dmax;
    return a;
}

Schema MakeSchema(size_t n) {
    Schema s;
    s.AddAttribute(MakeAttr(0, kAttr0M, 0, kAttr0DomainMax, n));
    s.AddAttribute(MakeAttr(1, kAttr1M, 0, kAttr1DomainMax, n));
    return s;
}

std::vector<MpraqRecord> MakeRecords(size_t n) {
    std::vector<MpraqRecord> recs(n);
    for (size_t i = 0; i < n; ++i) {
        recs[i].attributes = {static_cast<int64_t>(i % 5),
                              static_cast<int64_t>((i / 2) % 3)};
        recs[i].feature = static_cast<int64_t>(i);
    }
    return recs;
}

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

// ===========================================================================
// 规模配置层（负责人只管三个量：行数 N、每属性列数、谓词数 k）
// ===========================================================================
// ★ 兼容性铁律：**只有**给出 `--config` 或 `--columns-per-attribute/--attributes/
//   --predicates` 之一时才走规模层；否则逐位保持旧行为（属性 0/1 = 6/4 列、M = 10、
//   谓词由 `--predicate range|conj` 决定）——`test_mpraq_scaling` 的历史断言因此不受影响。
//   规模层里 schema / 合成数据 / 自动谓词**全部由 `mpraq::Build` 生成**（与两个 app
//   共用同一份派生逻辑，绝不在这里再写第二套）。
struct BenchScaleState {
    bool enabled = false;
    MpraqScaleConfig cfg;             // JSON + CLI 覆盖之后（每个点的 N 再逐点覆盖）
    bool have_config_file = false;
    std::string config_path;

    // 真实列数 M（旧行为 = 10；规模层 = 属性数 × 每属性列数）
    size_t real_columns() const {
        if (!enabled) return kRealColumns;
        return static_cast<size_t>(cfg.attributes) *
               static_cast<size_t>(cfg.columns_per_attribute);
    }
    // 谓词路径下去重列数（每个自动谓词恰好 1 列 ⇒ min(k, M)）
    size_t dedup_columns() const {
        if (!enabled) return kRealColumns;  // 旧口径：按上界 M 计划（见 Point::PlannedColumns）
        return std::min<size_t>(cfg.predicates, real_columns());
    }
};

BenchScaleState g_scale;

Predicate ById(uint32_t attr, mpraq::PredicateOp op, int64_t v) {
    Predicate p;
    p.by_id = true;
    p.attribute_id = attr;
    p.op = op;
    p.value = v;
    return p;
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

Predicate Range(uint32_t attr, int64_t lo, int64_t hi) {
    Predicate p;
    p.by_id = true;
    p.attribute_id = attr;
    p.op = mpraq::PredicateOp::kRange;
    p.lower = lo;
    p.upper = hi;
    return p;
}

uint64_t Popcount(const std::vector<uint8_t>& f) {
    uint64_t c = 0;
    for (uint8_t b : f) c += (b != 0) ? 1u : 0u;
    return c;
}

// ===========================================================================
// 命令行
// ===========================================================================

enum class Mode { kLocal, kGrpcTwoProcess };

const char* ModeName(Mode m) {
    return m == Mode::kLocal ? "local" : "grpc-two-process";
}

struct Options {
    std::string exp = "online";    // online|sum|init-w|storage|tradeoff|all
    Mode mode = Mode::kLocal;
    std::vector<size_t> rows = {1024, 2048, 4096, 8192, 16384};
    uint32_t lambda = 80;
    double eps = 1e-4;
    uint64_t seed = 7;
    // 运行方式（安全档位）——**接口预留**（`src/mpraq/security_mode.hpp`）。
    // 默认恶意档；`--security-mode semi-honest` 显式 opt-in（严格解析，非法值拒绝启动）。
    MpraqSecurityMode security_mode = kDefaultMpraqSecurityMode;
    uint64_t prng_seed = 11;
    uint64_t w = 0;                  // 0 = 自动派生；否则显式 w（必须 2 的幂）
    std::vector<uint64_t> w_list;    // init-w / storage 用的显式 w 网格
    std::vector<uint32_t> lambda_list = {32, 64, 80, 128};
    std::vector<double> eps_list = {1e-2, 1e-4, 1e-6, 1e-10};
    std::string predicate = "range";  // range | conj
    size_t columns = 0;               // >0：绕过谓词层，直接取前 K 个真实列（**精确列数**）
    uint32_t repeat = 1;              // 同一批查询重复次数（L14 预算按 列数×L×repeat 计）
    bool with_sum = true;             // online 实验里是否附带一次 Sum
    bool json = false;                // JSONL → stdout，人读文本 → stderr
    std::string json_out;             // 完整 JSON 文档 → 文件
    std::string server0;              // grpc 模式的服务器端点
    std::string server1;
    std::string spawn_servers;        // grpc 模式：自动 fork/exec 服务器进程的路径
    bool keep_servers = false;        // 调试：跑完不杀自己起的服务器
    int sum_attr = 1;
    bool quick = false;
    // 默认只打一行 `[规模]` 摘要（连同表格已给出的几何）；`--verbose` 追加 `est.Report()`
    // 的完整派生明细。**只影响人读输出**：`--json` 契约与 L14 拒绝路径不受影响。
    bool verbose = false;
    // ---- 规模配置层（行数 / 每属性列数 / 谓词数 ⇒ 其余自动派生）----
    // `--config FILE` + `--columns-per-attribute C`（= 每属性列数，JSON 的
    // `columns_per_attribute`）、`--attributes A`、`--predicates K`；`--rows/--lambda/--eps/
    // --seed` 也逐项覆盖配置。⚠️ 本程序原有的 `--columns K` 语义**保持不变**
    // （绕过谓词层、精确取前 K 个**真实列**），因此每属性列数用 `--columns-per-attribute`。
    std::string config;
    bool has_cpa = false;
    uint32_t columns_per_attribute = 0;
    bool has_attributes = false;
    uint32_t attributes = 0;
    bool has_predicates = false;
    uint32_t predicates = 0;
    // 规模层只有在**显式**给出 `--config` 或上面三个规模旗标之一时启用（其余情况逐位保持旧行为）
    bool scale_enabled = false;
    // 既有旗标是否被显式给出（显式 ⇒ 覆盖配置里的对应项）
    bool has_rows = false;
    bool has_lambda = false;
    bool has_eps = false;
    bool has_seed = false;
    // ⚠️ 默认**拒绝** N > 2^15（D34：两进程下每次 Sum 要下发 2×(13+152N) 字节的安装帧）。
    // 加这个开关只是让"越界探测"成为**显式**动作（默认仍按文档的限制跳过）。
    bool allow_large_n = false;
};

std::vector<size_t> ParseSizeList(const std::string& s) {
    std::vector<size_t> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (!item.empty()) out.push_back(static_cast<size_t>(std::stoull(item)));
    }
    return out;
}

std::vector<uint64_t> ParseU64List(const std::string& s) {
    std::vector<uint64_t> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (!item.empty()) out.push_back(std::stoull(item));
    }
    return out;
}

std::vector<uint32_t> ParseU32List(const std::string& s) {
    std::vector<uint32_t> out;
    for (uint64_t v : ParseU64List(s)) out.push_back(static_cast<uint32_t>(v));
    return out;
}

std::vector<double> ParseDoubleList(const std::string& s) {
    std::vector<double> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (!item.empty()) out.push_back(std::stod(item));
    }
    return out;
}

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
        if (a == "--exp") {
            o.exp = next("--exp");
        } else if (a == "--mode") {
            const std::string m = next("--mode");
            if (m == "local") {
                o.mode = Mode::kLocal;
            } else if (m == "grpc" || m == "grpc-two-process") {
                o.mode = Mode::kGrpcTwoProcess;
            } else {
                throw std::invalid_argument("--mode 只能是 local 或 grpc（实际 " + m + "）");
            }
        } else if (a == "--rows") {
            o.rows = ParseSizeList(next("--rows"));
            o.has_rows = true;
        } else if (a == "--lambda") {
            o.lambda = static_cast<uint32_t>(std::stoul(next("--lambda")));
            o.has_lambda = true;
        } else if (a == "--eps") {
            o.eps = std::stod(next("--eps"));
            o.has_eps = true;
        } else if (a == "--seed") {
            o.seed = std::stoull(next("--seed"));
            o.has_seed = true;
        } else if (a == "--security-mode") {
            o.security_mode = ParseMpraqSecurityMode(next("--security-mode"));
        } else if (a == "--prng-seed") {
            o.prng_seed = std::stoull(next("--prng-seed"));
        } else if (a == "--w") {
            o.w = std::stoull(next("--w"));
        } else if (a == "--w-list") {
            o.w_list = ParseU64List(next("--w-list"));
        } else if (a == "--lambda-list") {
            o.lambda_list = ParseU32List(next("--lambda-list"));
        } else if (a == "--eps-list") {
            o.eps_list = ParseDoubleList(next("--eps-list"));
        } else if (a == "--predicate") {
            o.predicate = next("--predicate");
        } else if (a == "--columns") {
            o.columns = static_cast<size_t>(std::stoull(next("--columns")));
        } else if (a == "--config") {
            o.config = next("--config");
            o.scale_enabled = true;
        } else if (a == "--columns-per-attribute") {
            o.columns_per_attribute =
                static_cast<uint32_t>(std::stoul(next("--columns-per-attribute")));
            o.has_cpa = true;
            o.scale_enabled = true;
        } else if (a == "--attributes") {
            o.attributes = static_cast<uint32_t>(std::stoul(next("--attributes")));
            o.has_attributes = true;
            o.scale_enabled = true;
        } else if (a == "--predicates") {
            o.predicates = static_cast<uint32_t>(std::stoul(next("--predicates")));
            o.has_predicates = true;
            o.scale_enabled = true;
        } else if (a == "--repeat") {
            o.repeat = static_cast<uint32_t>(std::stoul(next("--repeat")));
        } else if (a == "--no-sum") {
            o.with_sum = false;
        } else if (a == "--json") {
            o.json = true;
        } else if (a == "--json-out") {
            o.json_out = next("--json-out");
        } else if (a == "--server0") {
            o.server0 = next("--server0");
        } else if (a == "--server1") {
            o.server1 = next("--server1");
        } else if (a == "--spawn-servers") {
            o.spawn_servers = next("--spawn-servers");
        } else if (a == "--keep-servers") {
            o.keep_servers = true;
        } else if (a == "--sum-attr") {
            o.sum_attr = std::stoi(next("--sum-attr"));
        } else if (a == "--allow-large-n") {
            o.allow_large_n = true;
        } else if (a == "--quick") {
            o.quick = true;
        } else if (a == "--verbose" || a == "-v") {
            o.verbose = true;
        } else if (a == "--help" || a == "-h") {
            std::cout
                << "用法: mpraq_bench [--exp online|sum|init-w|storage|tradeoff|all]\n"
                   "                   [--mode local|grpc] [--rows 1024,2048,...]\n"
                   "                   [--lambda 80] [--eps 1e-4] [--w 0|2^k]\n"
                   "                   [--predicate range|conj] [--columns K] [--repeat R]\n"
                   "                   [--security-mode malicious|semi-honest] [--no-sum] [--json] [--json-out FILE]\n"
                   "                   [--server0 host:port --server1 host:port]\n"
                   "                   [--spawn-servers PATH_TO_mpraq_server] [--quick]\n"
                   "                   [--verbose]  # 额外打印规模派生明细（默认只打一行 [规模]）\n"
                   "                   [--allow-large-n]  # 越过 N > 2^15 的默认保护（探测用）\n"
                   "\n"
                   "规模配置层（负责人只管三个量；其余全部自动派生）：\n"
                   "  --config FILE              规模配置 JSON（默认值同 config/mpraq_scale.json）\n"
                   "  --columns-per-attribute C  列数 = **每个属性**的 LCTE 列数（**必须是 2 的幂**）\n"
                   "  --attributes A             属性数（M = 属性数 × 每属性列数）\n"
                   "  --predicates K             谓词数 k（谓词内容自动生成；去重列数 = min(k, M)）\n"
                   "  （--rows / --lambda / --eps / --seed 既有的旗标同样逐项覆盖配置）\n"
                   "  ⚠️ 只有给出 --config 或上面三个规模旗标之一时才启用规模层；\n"
                   "     否则逐位保持旧行为（属性 0/1 = 6/4 列、M = 10、谓词 = --predicate）。\n"
                   "\n"
                   "  --json        每行一条 JSON（{\"config\":{...},\"point\":{...}}）打到 stdout；\n"
                   "                人读表格同时打到 stderr\n"
                   "  --json-out F  完整文档（config+points+summary）写到 F\n"
                   "  --columns K   绕过谓词层直接取前 K 个**真实列**（查询集数 = K×⌈N/128⌉，**精确**）；\n"
                   "                ⚠️ 与 client app 的 `--columns`（= 每属性列数）语义不同，别混用\n"
                   "  --repeat R    同一批查询重复 R 次（L14 预算按 列数×⌈N/128⌉×R 计）\n"
                   "  --mode grpc   真实 gRPC 两进程；未给端点时自动用可执行文件同目录的\n"
                   "                mpraq_server（也可用 --spawn-servers 指定）\n";
            std::exit(EXIT_SUCCESS);
        } else {
            throw std::invalid_argument("未知参数: " + a);
        }
    }
    if (o.repeat == 0) throw std::invalid_argument("--repeat 必须 >= 1");
    if (o.rows.empty()) throw std::invalid_argument("--rows 不能为空");
    return o;
}

// ===========================================================================
// 几何 + L14 预算（**在任何重活之前**完成；超预算 ⇒ 拒绝运行，退出码 3）
// ===========================================================================

// 几何（符号向论文看齐，D41）：`n` = 记录数、`entry_words` = ⌈n/128⌉、`levels` = 真实层数、
// `m` = PIR 条目数（含列级补齐）、`w` = 块大小（条目/块）、`kappa` = 块数 = m/w、
// `main_hints` = λw、`backup_hints` = N_T = λw/2、`hint_slots` = H = λw + N_T。
struct Geometry {
    size_t n = 0;                  // 记录数 = 列长（bit）
    size_t entry_words = 0;        // ⌈n/128⌉：条目宽度（字）
    size_t levels = 0;             // 真实 LCTE 层数
    size_t m = 0;                  // PIR 条目数（含补齐列）
    size_t padding_columns = 0;    // m − levels
    uint64_t w = 0;                // 块大小（条目/块）
    uint64_t kappa = 0;            // 块数 = m / w（偶数）
    uint32_t lambda = 0;
    double eps = 0.0;
    uint64_t main_hints = 0;       // λw
    uint64_t backup_hints = 0;     // N_T = λw/2
    uint64_t hint_slots = 0;       // H = λw + N_T
};

// 退出码 3 = **参数/L14 预算被拒**（与运行期失败 1 区分）；测试按这个码断言。
constexpr int kExitBudgetRejected = 3;

class L14Rejected : public std::runtime_error {
public:
    explicit L14Rejected(const std::string& what) : std::runtime_error(what) {}
};

Geometry DeriveGeometry(size_t N, const Options& o, uint64_t w_explicit) {
    const MpraqPaddedGeometry g = DerivePaddedGeometry(
        g_scale.real_columns(), N, o.lambda, o.eps, w_explicit != 0, w_explicit);
    Geometry G;
    G.n = N;
    G.entry_words = (N + 127) / 128;
    G.levels = g.levels;
    G.m = static_cast<uint64_t>(g.m);   // PIR 条目数 = m（一个条目 = 一整列）
    G.padding_columns = g.padding_columns;
    G.w = g.plinko.w;
    G.kappa = g.plinko.blocks();
    G.lambda = g.plinko.lambda;
    G.eps = g.plinko.prp_epsilon;
    G.main_hints = g.plinko.main_hints();
    G.backup_hints = g.plinko.backup_hints();
    G.hint_slots = g.plinko.hint_slots();
    return G;
}

struct Budget {
    Geometry g;
    uint64_t columns = 0;       // 本次实验计划的列数
    uint64_t repeat = 1;
    // ⚠️ 列粒度：**一列 = 一个条目 = 1 个查询集** ⇒ 计划量就是「列数 × repeat」，
    //    **不再乘以 ⌈N/128⌉**（旧 word 口径的 128 倍消耗已作废）。
    uint64_t planned_sets = 0;
    uint64_t hint_cap = 0;       // N_T = λw/2
    uint64_t pool_cap = 0;       // m（新鲜索引池 = 条目数）
    uint64_t budget = 0;         // min(N_T, m)
    std::string binding;         // 较紧的那条
    double used_ratio = 0.0;
};

// 预算校验：**只看参数**，不碰任何查询（所以失败发生在"跑之前"）
Budget PlanBudget(const Geometry& g, uint64_t planned_columns, uint64_t repeat) {
    Budget b;
    b.g = g;
    b.columns = planned_columns;
    b.repeat = repeat;
    b.planned_sets = planned_columns * repeat;
    b.hint_cap = g.backup_hints;
    b.pool_cap = g.m;
    b.budget = std::min(b.hint_cap, b.pool_cap);
    b.binding = (b.pool_cap <= b.hint_cap) ? "pool(m)" : "hint(N_T)";
    b.used_ratio = b.budget == 0 ? 1.0
                                 : static_cast<double>(b.planned_sets) /
                                       static_cast<double>(b.budget);
    if (b.planned_sets > b.budget) {
        std::ostringstream oss;
        oss << "[mpraq_bench][budget_rejected] planned_sets=" << b.planned_sets
            << " > 上限 min(N_T, m) = " << b.budget << "（N_T = λw/2 = " << b.hint_cap
            << "、m = " << b.pool_cap << "；较紧的是 " << b.binding << "）。"
            << " plan columns=" << planned_columns << " repeat=" << repeat
            << " limit=" << b.budget;
        throw L14Rejected(oss.str());
    }
    return b;
}

Json BudgetJson(const Budget& b) {
    Json j;
    j.U64("planned_columns", b.columns)
        .U64("repeat", b.repeat)
        .U64("planned_sets", b.planned_sets)
        .U64("backup_hints", b.hint_cap)
        .U64("pool_m", b.pool_cap)
        .U64("budget", b.budget)
        .Str("binding_constraint", b.binding)
        .Dbl("budget_used_ratio", b.used_ratio)
        .U64("budget_headroom", b.budget - b.planned_sets);
    return j;
}

Json GeometryJson(const Geometry& g) {
    // ⚠️ 列粒度下**没有"补齐到 2 的幂"**（D41 取代 D35）⇒ 不再有 m0 / "是否升级" 这类字段；
    //    补齐只补到 `2w` 的倍数，用 `levels` / `m` / `padding_columns` 三个量就描述完整。
    Json j;
    j.U64("n", g.n)
        .U64("entry_words", g.entry_words)
        .U64("levels", g.levels)
        .U64("m", g.m)
        .U64("padding_columns", g.padding_columns)
        .U64("w", g.w)
        .U64("kappa", g.kappa)
        .U64("lambda", g.lambda)
        .Dbl("prp_epsilon", g.eps, 3)
        .U64("main_hints_lambda_w", g.main_hints)
        .U64("backup_hints_N_T", g.backup_hints)
        .U64("hint_slots_H", g.hint_slots)
        .U64("block_accesses_per_query_set", g.kappa);
    return j;
}

// ===========================================================================
// 服务器进程管理（grpc 模式）：fork/exec 两个 `mpraq_server`，跑完杀掉
// ===========================================================================

std::string DirNameOf(const std::string& path) {
    const size_t p = path.find_last_of('/');
    return p == std::string::npos ? std::string(".") : path.substr(0, p);
}

bool FileIsExecutable(const std::string& path) {
    return !path.empty() && ::access(path.c_str(), X_OK) == 0;
}

class ServerProcesses {
public:
    ~ServerProcesses() { Stop(); }

    // 自己起两个服务器进程（路径为空 ⇒ 用 bench 可执行文件同目录的 mpraq_server）
    void Spawn(const std::string& explicit_path, const std::string& argv0) {
        std::string bin = explicit_path;
        if (bin.empty()) bin = DirNameOf(argv0) + "/mpraq_server";
        if (!FileIsExecutable(bin)) {
            throw std::runtime_error(
                "--mode grpc 需要两台服务器进程：既没给 --server0/--server1，也没找到可执行的 "
                "mpraq_server（试过 '" + bin + "'）。请用 --spawn-servers PATH 指定，"
                "或先手动起两个 mpraq_server 并把端点传给 --server0/--server1。");
        }
        bin_ = bin;
        for (int id = 0; id < 2; ++id) {
            port_file_[static_cast<size_t>(id)] =
                "/tmp/mpraq_bench_" + std::to_string(::getpid()) + "_" +
                std::to_string(id) + ".port";
            ::unlink(port_file_[static_cast<size_t>(id)].c_str());
            const pid_t pid = ::fork();
            if (pid < 0) {
                throw std::runtime_error("fork 失败：无法启动服务器进程");
            }
            if (pid == 0) {
                // 子进程：立刻 exec（fork 后不调用任何非 async-signal-safe 的复杂逻辑）
                // ⚠️ 必须把服务器进程的 **stdout 重定向到 /dev/null**：否则它的启动横幅会
                //    混进本程序的 stdout，把 `--json` 的 JSONL 流污染成不可解析的文本。
                const int devnull = ::open("/dev/null", O_WRONLY);
                if (devnull >= 0) {
                    ::dup2(devnull, STDOUT_FILENO);
                    ::close(devnull);
                }
                const std::string id_s = std::to_string(id);
                ::execl(bin.c_str(), bin.c_str(), "--listen", "127.0.0.1:0", "--id",
                        id_s.c_str(), "--port-file",
                        port_file_[static_cast<size_t>(id)].c_str(),
                        static_cast<char*>(nullptr));
                std::perror("execl(mpraq_server) 失败");
                ::_exit(127);
            }
            pids_[static_cast<size_t>(id)] = pid;
        }
        // 等端口文件（最多 20 s）
        for (int id = 0; id < 2; ++id) {
            const std::string& pf = port_file_[static_cast<size_t>(id)];
            const auto t0 = Clock::now();
            int port = 0;
            while (MsSince(t0) < 20000.0) {
                std::ifstream in(pf);
                if (in && (in >> port) && port > 0) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
            if (port <= 0) {
                throw std::runtime_error("服务器进程 " + std::to_string(id) +
                                         " 在 20 s 内没有就绪（未写出端口文件 " + pf + "）");
            }
            addr_[static_cast<size_t>(id)] = "127.0.0.1:" + std::to_string(port);
        }
        spawned_ = true;
    }

    void UseEndpoints(const std::string& a0, const std::string& a1) {
        addr_[0] = a0;
        addr_[1] = a1;
    }

    bool spawned() const { return spawned_; }
    std::string addr(int i) const { return addr_[static_cast<size_t>(i)]; }
    pid_t pid(int i) const { return pids_[static_cast<size_t>(i)]; }

    void Stop() {
        if (!spawned_ || killed_) return;
        killed_ = true;
        for (int id = 0; id < 2; ++id) {
            const pid_t pid = pids_[static_cast<size_t>(id)];
            if (pid > 0) {
                ::kill(pid, SIGTERM);
            }
        }
        for (int id = 0; id < 2; ++id) {
            const pid_t pid = pids_[static_cast<size_t>(id)];
            if (pid > 0) {
                int status = 0;
                ::waitpid(pid, &status, 0);
            }
            const std::string& pf = port_file_[static_cast<size_t>(id)];
            if (!pf.empty()) ::unlink(pf.c_str());
        }
    }

    void Keep() { keep_ = true; }
    bool keep() const { return keep_; }

private:
    std::string bin_;
    std::string addr_[2];
    std::string port_file_[2];
    pid_t pids_[2] = {-1, -1};
    bool spawned_ = false;
    bool killed_ = false;
    bool keep_ = false;
};

// ===========================================================================
// 一次 (N, λ, ε, w) 的实验装置
// ===========================================================================

struct Row {
    std::string experiment;
    std::string mode;
    Geometry geom;
    Budget budget;
    bool has_budget = false;

    // 离线
    double init_ms = 0.0, lcte_ms = 0.0, pack_ms = 0.0, share_ms = 0.0, hint_ms = 0.0,
           upload_ms = 0.0;
    uint64_t upload_bytes = 0;
    size_t chunk_count = 0, chunk_words = 0;

    // 客户端存储
    uint64_t hint_slots_measured = 0;
    double hint_logical_bytes = 0.0;   // 实现口径（每条 hint 的字段口径）
    uint64_t hint_state_bytes = 0;     // 实际分配
    uint64_t block_key_bytes = 0;      // c 把 iPRF 密钥
    uint64_t cache_bytes = 0;          // Plinko 的重复查询缓存 Q（n 条）
    double hint_formula_task_bytes = 0.0;   // H × 16.125
    double hint_formula_spec_bytes = 0.0;   // H × 32.125（= entry(16) + 16.125）

    // Count
    bool has_count = false;
    uint64_t count = 0, baseline_count = 0;
    uint64_t queries_issued = 0, columns_used = 0;
    uint64_t rpc_delta[2] = {0, 0};
    uint64_t scalar_delta[2] = {0, 0};
    uint64_t node_queries_delta[2] = {0, 0};
    uint64_t node_words_delta[2] = {0, 0};
    double count_ms = 0.0, count_ms_max = 0.0, retrieve_ms = 0.0, combine_ms = 0.0;
    std::vector<double> per_round_ms;
    bool filter_matches_baseline = false;
    bool columns_identity_ok = false;

    // Sum
    bool has_sum = false;
    uint128_t sum = 0, avg = 0;
    uint64_t baseline_sum = 0, baseline_sum_count = 0;
    double sum_ms = 0.0;
    SecureMulBatchStats sm;

    // 服务器存储（公式 + 实测）
    uint64_t feature_bytes_padded = 0, feature_bytes_unpadded = 0, attr_bytes = 0;
    uint64_t tag_bytes = 0;   // xmac 的 tag 表（恶意档 = 与数据表等大；半诚实档 = 0）
    uint64_t server_storage_formula_padded = 0, server_storage_formula_unpadded = 0;
    uint64_t server_storage_measured[2] = {0, 0};
    uint64_t server_state_peak_bytes[2] = {0, 0};
    uint64_t relay_install_frames_delta[2] = {0, 0};
    uint64_t relay_phase_frames_delta[2] = {0, 0};

    // hint 生命周期
    uint64_t hint_consumed = 0, backup_remaining = 0;
    double hint_ms_per_entry = 0.0;   // hint_ms / n  ⇒ 隐含的 IF⁻¹
    double online_ms_per_query_set = 0.0;
    double online_ms_per_block_access = 0.0;
};

// ---------------------------------------------------------------------------
// Point：一次 (N, λ, ε, w) 的装置（**每个点一份**，避免预算/状态跨界）
// ---------------------------------------------------------------------------
class Point {
public:
    Point(const Options& o, size_t N, uint32_t lambda, double eps, uint64_t w_explicit,
          ServerProcesses* servers)
        : o_(o), N_(N), lambda_(lambda), eps_(eps), w_explicit_(w_explicit),
          servers_(servers) {
        geom_ = DeriveGeometry(N, o_, w_explicit_);
        if (g_scale.enabled) {
            // 规模层：schema / 合成数据 / 自动谓词**全部**来自 `mpraq::Build`
            // （逐点覆盖 N/λ/ε/seed；M = 属性数 × 每属性列数）
            MpraqScaleConfig c = g_scale.cfg;
            c.rows = N;
            c.lambda = lambda;
            c.eps = eps;
            c.seed = o.seed;
            scale_setup_ = Build(c);
            has_scale_ = true;
            schema_ = scale_setup_.schema;
            records_ = scale_setup_.records;
            baseline_ = MakeBaseline(schema_, records_);
        } else {
            schema_ = MakeSchema(N);
            records_ = MakeRecords(N);
            baseline_ = MakeBaseline(schema_, records_);
        }
    }

    // 规模层是否启用（决定谓词从哪来）
    bool scaled() const { return has_scale_; }
    // 本次点的谓词（规模层 = 自动生成的 k 个；旧行为 = `--predicate range|conj`）
    std::vector<Predicate> Predicates() const {
        if (has_scale_) return scale_setup_.predicates;
        if (o_.predicate == "range") return {Range(0, 1, 4)};
        if (o_.predicate == "conj") {
            return {Range(0, 2, 5), ById(1, mpraq::PredicateOp::kGe, 1)};
        }
        throw std::invalid_argument("--predicate 只能是 range 或 conj（实际 " + o_.predicate +
                                    "）");
    }

    // 明文基准谓词（公开包装：实验函数里造 filter 用）
    std::vector<mpraq_baseline::Pred> BaselinePredicates() const {
        return MakeBaselinePreds();
    }

    const Geometry& geom() const { return geom_; }
    const Schema& schema() const { return schema_; }
    const mpraq_baseline::Dataset& baseline() const { return baseline_; }
    MpraqClient& client() {
        if (!client_) throw std::logic_error("Point: Init 之前不能访问 client");
        return *client_;
    }
    bool remote() const { return o_.mode == Mode::kGrpcTwoProcess; }

    // 计划的列数（**在 Init 之前**就能算）：
    //   --columns K ⇒ 精确 K；
    //   规模层 ⇒ 谓词路径的**精确**去重列数 min(k, M)（每个自动谓词恰好 1 列）；
    //   旧行为 ⇒ 按谓词路径取**上界 M**（最坏情形，保证不会中途超预算）
    uint64_t PlannedColumns() const {
        if (o_.columns > 0) return o_.columns;
        if (has_scale_) return g_scale.dedup_columns();
        return geom_.levels;
    }

    Budget Plan() const { return PlanBudget(geom_, PlannedColumns(), o_.repeat); }

    void Init() {
        MpraqInitParams p;
        p.lambda = lambda_;
        p.prp_epsilon = eps_;
        p.seed = o_.seed;
        p.security_mode = o_.security_mode;   // 接口预留；服务端据此做一致性校验
        p.has_explicit_w = (w_explicit_ != 0);
        p.w = w_explicit_;
        const auto t0 = Clock::now();
        if (remote()) {
            if (!servers_) throw std::logic_error("Point: grpc 模式缺少服务器端点");
            ch0_ = std::make_unique<GrpcMpraqChannel>(servers_->addr(0));
            ch1_ = std::make_unique<GrpcMpraqChannel>(servers_->addr(1));
            ch0_->Connect();
            ch1_->Connect();
            client_ = MpraqClient::InitWithChannels(schema_, records_, p, *ch0_, *ch1_);
            transport_ = std::make_unique<GrpcTransportClient>(
                std::vector<std::string>{servers_->addr(0), servers_->addr(1)});
            transport_->Connect(10000);
            ep0_ = std::make_unique<RemoteSecureMulBatchEndpoint>(*transport_, kServer0);
            ep1_ = std::make_unique<RemoteSecureMulBatchEndpoint>(*transport_, kServer1);
        } else {
            client_ = MpraqClient::Init(schema_, records_, p);
        }
        init_ms_ = MsSince(t0);
        server_stats_before_[0] = QueryServerStatsOrZero(0);
        server_stats_before_[1] = QueryServerStatsOrZero(1);
    }

    void SetMac() {
        mac_ = std::make_unique<SecureMulClientState>(client_->mac_key_shares(),
                                                      client_->modulus());
        prng_ = std::make_unique<random::DeterministicPrng>(
            MakeAesSeed(std::vector<uint8_t>{'m', 'p', 'a', '0', '9', 'b', 'e', 'n'}),
            o_.prng_seed);
    }
    SecureMulClientState& mac() { return *mac_; }
    random::DeterministicPrng& prng() { return *prng_; }

    // 一次 Count（重复 `repeat` 次）
    Row RunCount() {
        Row r;
        r.experiment = o_.exp;
        r.mode = ModeName(o_.mode);
        r.geom = geom_;
        r.budget = Plan();
        r.has_budget = true;
        FillInitRow(r);

        // 谓词来源：规模层 = 自动生成的 k 个（去重列数 = min(k, M)）；
        //           旧行为 = `--predicate range|conj` 的固定谓词
        const std::vector<Predicate> preds = Predicates();

        r.has_count = true;
        for (uint32_t rep = 0; rep < o_.repeat; ++rep) {
            const auto t0 = Clock::now();
            CountResult c;
            uint64_t rpc0 = 0, rpc1 = 0, s0 = 0, s1 = 0;
            uint64_t nq0 = 0, nq1 = 0, nw0 = 0, nw1 = 0;
            if (o_.columns > 0) {
                // ---- 裸列路径：精确 K 列的查询集（不经过谓词层）----
                if (o_.columns > geom_.levels) {
                    throw std::invalid_argument(
                        "--columns 不能超过真实列数 M = " + Num(geom_.levels));
                }
                rpc0 = ChannelU64(RpcSnapshot(0));
                rpc1 = ChannelU64(RpcSnapshot(1));
                NodeSnapshot(0, &nq0, &nw0);
                NodeSnapshot(1, &nq1, &nw1);
                // 用**裸条目号**构造（一列 = 一个条目，条目号 = 全局列号）
                std::vector<uint64_t> flat_indices;
                flat_indices.reserve(o_.columns);
                for (size_t col = 0; col < o_.columns; ++col) {
                    flat_indices.push_back(client_->GlobalEntryIndex(col));
                }
                MpraqQueryBatch batch = client_->CreateQueriesForIndices(flat_indices);
                const std::vector<PlinkoEntry> cols = client_->RunBatch(batch);
                c.count = 0;
                uint64_t plain_popcount = 0;
                // 逐**整列**与明文副本对照（确定性 oracle：同一次 Init 的明文副本）；
                // ⚠️ 只数恰好 n 个有效 bit（不变量 I3：尾部填充位不计入）
                const std::vector<uint128_t>& plain_words = client_->plain_feature_words();
                for (size_t i = 0; i < cols.size(); ++i) {
                    const size_t base = i * geom_.entry_words;
                    for (size_t w = 0; w < cols[i].size(); ++w) {
                        if (cols[i][w] != plain_words[base + w]) {
                            throw std::runtime_error("裸列查询：重建整列与明文不一致");
                        }
                    }
                    for (size_t j = 0; j < geom_.n; ++j) {
                        const bool bit =
                            ((cols[i][j / 128] >> (j % 128)) & static_cast<uint128_t>(1)) != 0;
                        const bool pbit =
                            ((plain_words[base + j / 128] >> (j % 128)) &
                             static_cast<uint128_t>(1)) != 0;
                        if (bit) ++c.count;
                        if (pbit) ++plain_popcount;
                    }
                }
                if (c.count != plain_popcount) {
                    throw std::runtime_error("裸列查询：重建比特数与明文不一致");
                }
                c.queries_issued = flat_indices.size();
                c.columns.clear();
                for (size_t col = 0; col < o_.columns; ++col) {
                    c.columns.emplace_back(0u, static_cast<uint32_t>(col));
                }
                // 裸列路径的"基准"= 明文副本的 popcount（上面已逐 word 对照过）
                r.filter_matches_baseline = true;
                r.baseline_count = plain_popcount;
            } else {
                rpc0 = ChannelU64(RpcSnapshot(0));
                rpc1 = ChannelU64(RpcSnapshot(1));
                s0 = ScalarSnapshot(0);
                s1 = ScalarSnapshot(1);
                NodeSnapshot(0, &nq0, &nw0);
                NodeSnapshot(1, &nq1, &nw1);
                c = CountPredicates(*client_, schema_, preds);
                const std::vector<uint8_t> bfilter =
                    mpraq_baseline::Filter(baseline_, MakeBaselinePreds());
                const uint64_t bcount = Popcount(bfilter);
                r.baseline_count = bcount;
                r.filter_matches_baseline =
                    (c.count == bcount) &&
                    (mpraq_baseline::FilterShape(c.filter) ==
                     mpraq_baseline::FilterShape(bfilter));
                if (!r.filter_matches_baseline) {
                    throw std::runtime_error("Count/filter 与明文基准不一致（协议 " +
                                             Num(c.count) + " vs 基准 " + Num(bcount) + "）");
                }
            }
            const double ms = MsSince(t0);
            r.per_round_ms.push_back(ms);
            r.count_ms += ms;
            r.count_ms_max = std::max(r.count_ms_max, ms);
            r.count = c.count;
            r.queries_issued += c.queries_issued;
            r.columns_used = c.columns.size();
            r.rpc_delta[0] += ChannelU64(RpcSnapshot(0)) - rpc0;
            r.rpc_delta[1] += ChannelU64(RpcSnapshot(1)) - rpc1;
            r.scalar_delta[0] += ScalarSnapshot(0) - s0;
            r.scalar_delta[1] += ScalarSnapshot(1) - s1;
            uint64_t aq0 = 0, aw0 = 0, aq1 = 0, aw1 = 0;
            NodeSnapshot(0, &aq0, &aw0);
            NodeSnapshot(1, &aq1, &aw1);
            r.node_queries_delta[0] += aq0 - nq0;
            r.node_queries_delta[1] += aq1 - nq1;
            r.node_words_delta[0] += aw0 - nw0;
            r.node_words_delta[1] += aw1 - nw1;
        }
        // 平均口径（进程内/两进程都报"平均每次"）
        r.count_ms /= o_.repeat;

        // **精确对照**：查询集数 == 列数 × repeat（一列 = 一个条目 = 1 个查询集）
        const uint64_t expected =
            static_cast<uint64_t>(r.columns_used) * o_.repeat;
        r.columns_identity_ok = (r.queries_issued == expected);
        if (!r.columns_identity_ok) {
            throw std::runtime_error("查询集数 " + Num(r.queries_issued) +
                                     " ≠ 列数×repeat = " + Num(expected));
        }
        // 每台 RPC 次数 == 查询（Count）次数；标量路径恒 0
        for (int i = 0; i < 2; ++i) {
            if (r.rpc_delta[static_cast<size_t>(i)] != o_.repeat) {
                throw std::runtime_error(
                    "服务器 " + Num(static_cast<uint64_t>(i)) + " 的 PIR RPC 次数 " +
                    Num(r.rpc_delta[static_cast<size_t>(i)]) + " ≠ 查询次数 " +
                    Num(o_.repeat) + "（一次 RunBatch 必须恒 1 次 RPC）");
            }
            if (r.scalar_delta[static_cast<size_t>(i)] != 0) {
                throw std::runtime_error("标量 ServerResp 被调用了（批量路径不应走标量接口）");
            }
        }
        // 实际消耗必须在预算内（**实测复核**，不只是事前计划）
        r.hint_consumed = client_->query_count();
        r.backup_remaining = client_->backup_remaining();
        if (r.hint_consumed > r.budget.budget) {
            throw std::runtime_error("实测 hint 消耗 " + Num(r.hint_consumed) +
                                     " 超出预算 " + Num(r.budget.budget));
        }
        r.online_ms_per_query_set =
            r.queries_issued == 0 ? 0.0 : r.count_ms / static_cast<double>(r.queries_issued);
        r.online_ms_per_block_access =
            (r.queries_issued == 0 || geom_.kappa == 0)
                ? 0.0
                : r.count_ms /
                      (static_cast<double>(r.queries_issued) * static_cast<double>(geom_.kappa));
        return r;
    }

    // 一次 Sum/Avg（取当前的 filter）
    void RunSum(Row* r, const std::vector<uint8_t>& filter, uint64_t salt) {
        if (!mac_) SetMac();
        const auto t0 = Clock::now();
        SumResult s;
        if (remote()) {
            s = SumOverFilter(CountResultFromFilter(filter, r->baseline_count), schema_,
                              static_cast<uint32_t>(o_.sum_attr), *client_, *transport_,
                              *ep0_, *ep1_, *mac_, *prng_, salt);
        } else {
            local_net_ = std::make_unique<LocalTransport>(2);
            s = SumOverFilter(CountResultFromFilter(filter, r->baseline_count), schema_,
                              static_cast<uint32_t>(o_.sum_attr), *client_, *local_net_,
                              *mac_, *prng_, salt);
        }
        const double ms = MsSince(t0);
        r->has_sum = true;
        r->sum = s.sum;
        r->sum_ms = ms;
        r->sm = s.securemul;
        // ⚠️ `count == 0` ⇒ Avg 在数学上无定义：库口径抛 `std::domain_error`（不静默返回 0）
        // ⇒ 先判 count（规模层里"谓词数很大"时合取可能为空，这是合法的查询结果）
        if (s.count > 0) {
            r->avg = AvgOverFilter(s);
        } else {
            r->avg = 0;
            // count = 0 ⇒ Avg 在数学上无定义（未调用 `AvgOverFilter`）；Sum = 0 与明文基准
            // 仍逐值对照。此处只打裸键值。
            HPRINT("        avg count=0 avg=undefined avg_called=0 sum_checked=1\n");
        }
        // 裸列模式的 filter 是"全命中"⇒ 基准取**空谓词**（`Filter(d, {})` = 全 1）
        const std::vector<mpraq_baseline::Pred> bpreds =
            (o_.columns > 0) ? std::vector<mpraq_baseline::Pred>{} : MakeBaselinePreds();
        const mpraq_baseline::Moments bm =
            mpraq_baseline::Aggregate(baseline_, bpreds, o_.sum_attr);
        r->baseline_sum = bm.sum;
        r->baseline_sum_count = bm.count;
        if (s.sum != static_cast<uint128_t>(bm.sum) || s.count != bm.count) {
            throw std::runtime_error("Sum/count 与明文基准不一致（协议 " + toString(s.sum) +
                                     " vs 基准 " + Num(bm.sum) + "）");
        }
        // 账目口径断言（**确定性**）
        const SecureMulBatchStats& st = s.securemul;
        if (st.rounds != 2 || st.messages != 2 * N_ || st.wire_messages != 4 * N_ ||
            st.frame_bytes_phase1 != 6 + 34 * N_ || st.frame_bytes_phase2 != 6 + 58 * N_) {
            throw std::runtime_error("Sum 账目口径被破坏（rounds/messages/wire/帧长）");
        }
        if (remote()) {
            // D34：两进程下的安装段
            if (st.install_frames != 2 || st.install_rounds != 2 ||
                st.install_bytes != 2ull * (13 + 152 * N_)) {
                throw std::runtime_error(
                    "两进程安装段账目 ≠ D34 口径 2×(13+152N)（实测 " +
                    Num(st.install_bytes) + "）");
            }
        } else if (st.install_bytes != 0 || st.install_frames != 0) {
            throw std::runtime_error("进程内模式的 install_* 必须为 0（实测 " +
                                     Num(st.install_bytes) + "）");
        }
        for (int i = 0; i < 2; ++i) {
            const ServerStats now = QueryServerStatsOrZero(i);
            const ServerStats& before = server_stats_before_[static_cast<size_t>(i)];
            r->relay_install_frames_delta[static_cast<size_t>(i)] =
                now.relay_install_frames - before.relay_install_frames;
            r->relay_phase_frames_delta[static_cast<size_t>(i)] =
                now.relay_phase_frames - before.relay_phase_frames;
            if (remote()) {
                r->server_state_peak_bytes[static_cast<size_t>(i)] =
                    st.server_state_peak_bytes;
            }
        }
    }

    // 服务器存储：公式（双报）+ 实测
    void FillStorage(Row* r) {
        const StoreParams& sp = client_->store_params();
        r->feature_bytes_padded = 16ull * sp.m * sp.entry_words;
        r->feature_bytes_unpadded = 16ull * sp.levels * sp.entry_words;
        // xmac 的 tag 表：与数据表**等大**，且**只有恶意档**存在
        // （半诚实档不生成/不存/不传/不校验 tag ⇒ 存储减半）。
        r->tag_bytes = sp.has_tags() ? 16ull * sp.m * sp.entry_words : 0ull;
        r->attr_bytes = 16ull * sp.n * sp.num_attributes();
        r->server_storage_formula_padded =
            r->feature_bytes_padded + r->tag_bytes + r->attr_bytes;
        r->server_storage_formula_unpadded =
            r->feature_bytes_unpadded + r->tag_bytes + r->attr_bytes;
        for (int i = 0; i < 2; ++i) {
            if (remote()) {
                r->server_storage_measured[static_cast<size_t>(i)] =
                    QueryServerStatsOrZero(i).storage_bytes;
            } else {
                r->server_storage_measured[static_cast<size_t>(i)] =
                    client_->node(i).StorageBytes();
            }
            if (r->server_storage_measured[static_cast<size_t>(i)] !=
                r->server_storage_formula_padded) {
                throw std::runtime_error(
                    "服务器 " + Num(static_cast<uint64_t>(i)) + " 实测存储 " +
                    Num(r->server_storage_measured[static_cast<size_t>(i)]) +
                    " ≠ §1 公式（含补齐）" + Num(r->server_storage_formula_padded));
            }
        }
    }

    void FillInitRow(Row& r) {
        const MpraqInitTimings& t = client_->timings();
        r.init_ms = init_ms_;
        r.lcte_ms = t.lcte_ms;
        r.pack_ms = t.pack_ms;
        r.share_ms = t.share_ms;
        r.hint_ms = t.hint_ms;
        r.upload_ms = t.upload_ms;
        r.upload_bytes = client_->upload_bytes();
        r.chunk_count = t.chunk_count;
        r.chunk_words = t.chunk_words;
        r.hint_ms_per_entry =
            geom_.m == 0 ? 0.0 : r.hint_ms / static_cast<double>(geom_.m);
        r.hint_slots_measured = client_->hint_slot_count();
        r.hint_logical_bytes = client_->logical_hint_bytes();
        r.hint_state_bytes = client_->hint_state_bytes();
        r.block_key_bytes = geom_.kappa * 32ull;  // IprfKey = 2 × AES-128 密钥
        r.cache_bytes = geom_.m * (16ull + 1ull + 8ull);
        r.hint_formula_task_bytes =
            static_cast<double>(geom_.hint_slots) * 16.125;               // 任务书的写法（不含 parity）
        r.hint_formula_spec_bytes =
            static_cast<double>(geom_.hint_slots) * (16.0 + 16.125);      // MPRAQ_IMPL §1 / PLINKO_SPEC §6
        r.backup_remaining = client_->backup_remaining();
        FillStorage(&r);
    }

private:
    std::vector<mpraq_baseline::Pred> MakeBaselinePreds() const {
        // 规模层：把自动谓词**独立转写**成明文基准谓词（基准不复用被测代码）
        if (has_scale_) {
            std::vector<mpraq_baseline::Pred> out;
            for (const Predicate& p : scale_setup_.predicates) out.push_back(ToBaseline(p));
            return out;
        }
        if (o_.predicate == "conj") {
            return {mpraq_baseline::Pred{0, mpraq_baseline::Op::kRange, 0, 2, 5},
                    mpraq_baseline::Pred{1, mpraq_baseline::Op::kGe, 1, 0, 0}};
        }
        return {mpraq_baseline::Pred{0, mpraq_baseline::Op::kRange, 0, 1, 4}};
    }

    // CountResult 的最小重建：`SumOverFilter` 只用 filter/count（MPA-06 的口径）
    CountResult CountResultFromFilter(const std::vector<uint8_t>& filter,
                                      uint64_t count) const {
        CountResult c;
        c.filter = filter;
        c.count = count;
        return c;
    }

    uint64_t RpcSnapshot(int i) const {
        if (remote()) {
            return i == 0 ? ch0_->rpc_count() : ch1_->rpc_count();
        }
        return client_->channel_rpc_stats(i).server_resp_batch_calls;
    }
    static uint64_t ChannelU64(uint64_t v) { return v; }
    uint64_t ScalarSnapshot(int i) const {
        if (remote()) {
            return i == 0 ? ch0_->server_resp_calls() : ch1_->server_resp_calls();
        }
        return client_->channel_rpc_stats(i).server_resp_single_calls;
    }
    void NodeSnapshot(int i, uint64_t* queries, uint64_t* words) const {
        if (remote()) {
            const ServerStats s = QueryServerStatsOrZero(i);
            *queries = s.queries_served;
            *words = s.words_read;
        } else {
            *queries = client_->node(i).queries_served();
            *words = client_->node(i).words_read();
        }
    }
    ServerStats QueryServerStatsOrZero(int i) const {
        if (!remote() || !transport_) return ServerStats{};
        return QueryServerStats(*transport_, i);
    }

    const Options& o_;
    size_t N_;
    uint32_t lambda_;
    double eps_;
    uint64_t w_explicit_;
    ServerProcesses* servers_ = nullptr;
    Geometry geom_;
    // 规模层（启用时由 `mpraq::Build` 生成 schema/数据/谓词）
    MpraqScaleSetup scale_setup_;
    bool has_scale_ = false;

    Schema schema_;
    std::vector<MpraqRecord> records_;
    mpraq_baseline::Dataset baseline_;
    std::unique_ptr<GrpcMpraqChannel> ch0_, ch1_;
    std::unique_ptr<GrpcTransportClient> transport_;
    std::unique_ptr<RemoteSecureMulBatchEndpoint> ep0_, ep1_;
    std::unique_ptr<MpraqClient> client_;
    std::unique_ptr<SecureMulClientState> mac_;
    std::unique_ptr<random::DeterministicPrng> prng_;
    std::unique_ptr<LocalTransport> local_net_;
    mutable ServerStats server_stats_before_[2];
    double init_ms_ = 0.0;
};

// ===========================================================================
// 行 → JSON / 表格
// ===========================================================================

Json RowJson(const Row& r) {
    Json g = GeometryJson(r.geom);
    // "不含补齐"对照：直接用真实层数 levels（D41 取代了 D35 的"×2 升级"口径）
    const uint64_t feature_no_upgrade = 16ull * r.geom.levels * r.geom.entry_words;
    const uint64_t total_no_upgrade = feature_no_upgrade + r.attr_bytes;
    Json b = r.has_budget ? BudgetJson(r.budget) : Json();

    Json init;
    init.Dbl("init_ms", r.init_ms, 4)
        .Dbl("lcte_ms", r.lcte_ms, 4)
        .Dbl("pack_ms", r.pack_ms, 4)
        .Dbl("share_ms", r.share_ms, 4)
        .Dbl("hint_init_ms", r.hint_ms, 4)
        .Dbl("upload_ms", r.upload_ms, 4)
        .Dbl("hint_init_ms_per_entry", r.hint_ms_per_entry, 6)
        .U64("upload_bytes", r.upload_bytes)
        .U64("upload_chunks", r.chunk_count)
        .U64("upload_chunk_words", r.chunk_words);

    Json client;
    client.U64("hint_slots_measured", r.hint_slots_measured)
        .Dbl("hint_logical_bytes", r.hint_logical_bytes, 2)
        .U64("hint_state_bytes", r.hint_state_bytes)
        .Dbl("hint_formula_16_125_bytes", r.hint_formula_task_bytes, 2)
        .Dbl("hint_formula_entry_plus_16_125_bytes", r.hint_formula_spec_bytes, 2)
        .U64("block_key_bytes", r.block_key_bytes)
        .U64("repeat_query_cache_bytes", r.cache_bytes)
        .U64("hint_consumed", r.hint_consumed)
        .U64("backup_remaining", r.backup_remaining);

    Json count;
    count.Bool("available", r.has_count)
        .U64("count", r.count)
        .U64("baseline_count", r.baseline_count)
        .U64("queries_issued", r.queries_issued)
        .U64("columns_used", r.columns_used)
        .U64("queries_per_column", r.geom.entry_words)
        .Bool("queries_identity_ok", r.columns_identity_ok)
        .U64("pir_rpc_server0", r.rpc_delta[0])
        .U64("pir_rpc_server1", r.rpc_delta[1])
        .U64("scalar_server_resp_server0", r.scalar_delta[0])
        .U64("scalar_server_resp_server1", r.scalar_delta[1])
        .U64("node_queries_served_server0", r.node_queries_delta[0])
        .U64("node_words_read_server0", r.node_words_delta[0])
        .U64("node_words_read_server1", r.node_words_delta[1])
        .Dbl("count_ms_total", r.count_ms, 4)
        .Dbl("count_ms_max_round", r.count_ms_max, 4)
        .Dbl("online_ms_per_query_set", r.online_ms_per_query_set, 6)
        .Dbl("online_ms_per_block_access", r.online_ms_per_block_access, 6)
        .Bool("filter_matches_baseline", r.filter_matches_baseline);

    Json sum;
    sum.Bool("available", r.has_sum)
        .Str("sum", r.has_sum ? toString(r.sum) : std::string(""))
        .Str("avg", r.has_sum ? toString(r.avg) : std::string(""))
        .U64("baseline_sum", r.baseline_sum)
        .U64("baseline_count", r.baseline_sum_count)
        .Dbl("sum_ms", r.sum_ms, 4)
        .U64("rounds", r.sm.rounds)
        .U64("messages", r.sm.messages)
        .U64("wire_messages", r.sm.wire_messages)
        .U64("server_frames_server0", r.sm.server_frames[0])
        .U64("server_frames_server1", r.sm.server_frames[1])
        .U64("records", r.sm.records)
        .U64("frame_bytes_phase1", r.sm.frame_bytes_phase1)
        .U64("frame_bytes_phase2", r.sm.frame_bytes_phase2)
        .U64("frame_formula_6_plus_34N", 6 + 34ull * r.geom.n)
        .U64("frame_formula_6_plus_58N", 6 + 58ull * r.geom.n)
        .Dbl("offline_triple_ms", r.sm.offline_triple_ms, 4)
        .Dbl("offline_setup_ms", r.sm.offline_setup_ms, 4)
        .Dbl("securemul_online_ms", r.sm.online_ms, 4)
        .Dbl("verify_ms", r.sm.verify_ms, 4)
        .U64("install_frames", r.sm.install_frames)
        .U64("install_rounds", r.sm.install_rounds)
        .U64("install_bytes", r.sm.install_bytes)
        .U64("install_formula_bytes", 2ull * (13 + 152ull * r.geom.n))
        .U64("server_state_peak_bytes", r.sm.server_state_peak_bytes)
        .U64("server_state_allocated_bytes", r.sm.server_state_allocated_bytes);

    Json srv;
    // ⚠️ D41 取代 D35：不再有"×2 升级"口径，`*_no_upgrade` / `upgrade_extra_bytes` 三个
    //    字段随之删除；"补齐代价"由 `padded` 与 `unpadded` 两个字段之差表达。
    srv.U64("feature_bytes_padded", r.feature_bytes_padded)
        .U64("feature_bytes_unpadded", r.feature_bytes_unpadded)
        .U64("tag_bytes", r.tag_bytes)
        .U64("attribute_bytes", r.attr_bytes)
        .U64("total_bytes_formula_padded", r.server_storage_formula_padded)
        .U64("total_bytes_formula_unpadded", r.server_storage_formula_unpadded)
        .U64("total_bytes_measured_server0", r.server_storage_measured[0])
        .U64("total_bytes_measured_server1", r.server_storage_measured[1])
        .U64("relay_install_frames_server0", r.relay_install_frames_delta[0])
        .U64("relay_install_frames_server1", r.relay_install_frames_delta[1])
        .U64("relay_phase_frames_server0", r.relay_phase_frames_delta[0])
        .U64("relay_phase_frames_server1", r.relay_phase_frames_delta[1]);

    Json out;
    out.Str("experiment", r.experiment)
        .Str("mode", r.mode)
        .Raw("geometry", g.Dump())
        .Raw("budget", b.Dump())
        .Raw("init", init.Dump())
        .Raw("client_storage", client.Dump())
        .Raw("count", count.Dump())
        .Raw("sum", sum.Dump())
        .Raw("server_storage", srv.Dump())
        // JSON `notes`：字段名与结构不变，值改为纯 ASCII（原中文说明移到本注释）——
        // mode=local 为进程内 LocalTransport；mode=grpc-two-process 为真实 gRPC 两进程。
        // 一列 = 一个条目 = 1 个查询集；RPC 次数 = ServerRespBatch 调用数；
        // 区块访问量 = 查询集数×kappa；install_* = D34 的离线材料下发（仅两进程）。
        .Str("notes",
             "mode=local:in-process LocalTransport; mode=grpc-two-process:real gRPC. "
             "query_sets=columns (one entry = one entire column); rpc=ServerRespBatch calls; "
             "block_accesses=query_sets*kappa; install_*=D34 offline setup (two-process only).");
    return out;
}

Json ConfigJson(const Options& o, const char* bench_build) {
    Json rows_json;
    std::string rows_str;
    for (size_t i = 0; i < o.rows.size(); ++i) {
        if (i) rows_str += ",";
        rows_str += std::to_string(o.rows[i]);
    }
    Json j;
    j.Str("experiment", o.exp)
        .Str("mode", ModeName(o.mode))
        .Raw("rows", "[" + rows_str + "]")
        .U64("lambda", o.lambda)
        .Dbl("eps", o.eps, 3)
        .U64("seed", o.seed)
        .U64("prng_seed", o.prng_seed)
        .U64("explicit_w", o.w)
        .Str("predicate", o.predicate)
        .U64("raw_columns", o.columns)
        .Bool("scale_enabled", o.scale_enabled)
        .U64("columns_per_attribute", o.has_cpa ? o.columns_per_attribute : 0)
        .U64("attributes", o.has_attributes ? o.attributes : 0)
        .U64("predicates", o.has_predicates ? o.predicates : 0)
        .Str("config", o.config)
        .U64("repeat", o.repeat)
        .Bool("with_sum", o.with_sum)
        .Str("build_type", bench_build)
        .Str("query_set_unit", "one PIR entry retrieval (= one entire column, entry_words*16 B)")
        .Str("rpc_unit", "IMpraqChannel::ServerRespBatch call (= 1 network round trip)")
        .Str("block_access_unit", "one (block, offset) read on one server")
        .Str("install_unit", "SecureMulServerSetup delivery, D34 (two-process only)")
        // `MPA-09` 任务 B：**客户端**显式设置的 gRPC 收包上限（gRPC 默认只有 4 MiB）
        .U64("client_max_receive_bytes",
             static_cast<uint64_t>(kGrpcClientMaxReceiveBytes))
        .Str("client_max_receive_note",
             "client max receive bytes; SecureMul response frames = 19+43N / 19+58N bytes "
             "=> hard ceiling for two-process N (server side must widen too, see mpraq_server)");
    return j;
}

// PrintHeader：只打裸 `key=value`。以下口径**保留在注释里**（print 精简纪律）：
//   * mode=grpc  = 真实 gRPC、两个服务器进程、回环 socket；
//     mode=local = 进程内 LocalTransport + 进程内 MpraqNode。两者**不可互相引用**。
//   * scale_layer=1 表示走规模配置层（--config / --columns-per-attribute / --attributes /
//     --predicates）⇒ schema、合成数据、谓词全部自动派生；=0 表示沿用旧口径
//     （属性 0/1 = 6/4 列、M = 10、谓词 = --predicate）。
//   * grpc_max_recv 是客户端显式设置的收包上限；gRPC 默认仅 4 MiB ⇒ `N > 72 315` 时
//     Phase2 应答帧（19+58N）会被拒。
//   * 复杂度口径（D41）：PIR 条目数 = `m`（LCTE 层数），一次列查询实测为
//     `kappa = m/w` 次**区块访问**；论文的 Õ(n/r) 是渐近口径，本表**不**把 kappa 与 n/r
//     等同（Q9 报告 D6）。更新（O(log n)）D8 不做 ⇒ 不产出该曲线。
void PrintHeader(const Options& o) {
    HPRINT("exp=%s mode=%s\n", o.exp.c_str(), ModeName(o.mode));
    HPRINT("lambda=%u eps=%g seed=%llu prng_seed=%llu predicate=%s raw_columns=%zu repeat=%u\n",
           o.lambda, o.eps, static_cast<unsigned long long>(o.seed),
           static_cast<unsigned long long>(o.prng_seed), o.predicate.c_str(), o.columns, o.repeat);
    HPRINT("grpc_max_recv=%d scale_layer=%d\n", kGrpcClientMaxReceiveBytes,
           o.scale_enabled ? 1 : 0);
}

// PrintGeometry：只打裸 `key=value`。
//   * wpr  = ⌈N/128⌉（每列 word 数）；M = 真实列数；m = 补齐后列数；pad = 补齐列数。
//   * n = m·wpr（PIR 条目数 = word 数，不是记录数）；c = n/w（块数，偶数）。
//   * lw = λw（常规 hint）；N_T = λw/2（备份）；H = λw + N_T（槽位）。
//   * 若 m > NextPow2(M)，说明触发了 D35 的列数 ×2 升级；此时服务器存储
//     16·m·wpr 同比放大，升级前后各打一次（upgrade 行）。
void PrintGeometry(const Geometry& g, bool planned_only) {
    // ⚠️ 标签向论文看齐（D41）：`n` = 记录数、`entry_words` = ⌈n/128⌉、`levels` = 真实层数、
    //    `m` = PIR 条目数、`w` = 块大小（条目/块）、`kappa` = 块数、`lw` = λw、
    //    `N_T` = 备份 hint 数（λw/2）、`H` = 槽位（λw + N_T）。
    HPRINT("geom n=%zu entry_words=%zu levels=%zu m=%zu pad=%zu w=%llu kappa=%llu "
           "lambda=%u lw=%llu N_T=%llu H=%llu\n",
           g.n, g.entry_words, g.levels, g.m, g.padding_columns,
           static_cast<unsigned long long>(g.w), static_cast<unsigned long long>(g.kappa),
           g.lambda, static_cast<unsigned long long>(g.main_hints),
           static_cast<unsigned long long>(g.backup_hints), static_cast<unsigned long long>(g.hint_slots));
    // ⚠️ 列粒度下**不再有"补齐到 2 的幂"**（D41 取代 D35）：`m` 只需是 `2w` 的倍数，
    //    所以这里只报补齐了多少列与它带来的存储增量，不再报"×N 升级倍数"。
    if (g.padding_columns > 0) {
        HPRINT("padding levels=%zu m=%zu pad=%zu srv_delta=%llu\n", g.levels,
               g.m, g.padding_columns,
               static_cast<unsigned long long>(16ull * g.padding_columns * g.entry_words));
    }
    if (planned_only) return;
}

// PrintBudget：只打裸 `key=value`。
//   * planned_sets = 列数 × repeat；上限 = min(N_T=λw/2, m)；
//   * binding 是较紧的那条上限的名字；used_ratio 是 planned/budget；margin = budget − planned。
void PrintBudget(const Budget& b) {
    // ⚠️ 标签向论文看齐（D41）：`N_T` = λw/2（备份 hint）、`m` = PIR 条目数（新鲜索引池）。
    HPRINT("budget planned_sets=%llu columns=%llu entry_words=%zu repeat=%llu N_T=%llu m=%llu "
           "cap=%llu binding=%s used_pct=%.1f margin=%llu\n",
           static_cast<unsigned long long>(b.planned_sets),
           static_cast<unsigned long long>(b.columns), b.g.entry_words,
           static_cast<unsigned long long>(b.repeat),
           static_cast<unsigned long long>(b.hint_cap),
           static_cast<unsigned long long>(b.pool_cap),
           static_cast<unsigned long long>(b.budget), b.binding.c_str(),
           b.used_ratio * 100.0,
           static_cast<unsigned long long>(b.budget - b.planned_sets));
}

// ===========================================================================
// 实验 1：在线查询成本 vs 规模（Count）
// ===========================================================================

std::vector<Row> ExpOnline(const Options& o, ServerProcesses* servers) {
    std::vector<Row> rows;
    HPRINT("exp=online mode=%s\n", ModeName(o.mode));
    HPRINT("%8s %6s %6s %6s %6s %6s %9s %9s %8s %8s %8s %10s %12s\n", "n", "levels",
                "m", "e_words", "w", "kappa", "sets", "cols", "rpc0", "rpc1", "blocks",
                "count_ms", "ms/set");
    for (size_t N : o.rows) {
        if (N > (1u << 15)) {
            if (!o.allow_large_n) {
                // 默认跳过 N > 2^15：两进程安装帧 = 2×(13+152N)；D34 的限制（N ≥ 2^16 需
                // 分块安装，未实现）。加 `--allow-large-n` 可探测。
                HPRINT("  skip N=%zu reason=n_gt_2^15 install_frames_mb=%.1f allow_large_n=0\n",
                       N, 2.0 * (13 + 152.0 * static_cast<double>(N)) / 1048576.0);
                continue;
            }
            HPRINT("  large_n N=%zu allow_large_n=1 install_frames_mb=%.1f\n",
                   N, 2.0 * (13 + 152.0 * static_cast<double>(N)) / 1048576.0);
        }
        Point p(o, N, o.lambda, o.eps, o.w, servers);
        const Geometry& g = p.geom();
        const Budget b = p.Plan();
        PrintGeometry(g, false);
        PrintBudget(b);
        p.Init();
        Row r = p.RunCount();
        r.experiment = "online";  // `--exp all` 下也必须能分辨是哪张表的点
        if (o.with_sum) {
            // 重新造一份 filter 给 Sum 用（同一谓词；**不动** L14 预算：Sum 不额外消耗 word 查询）
            std::vector<uint8_t> filter;
            uint64_t bcount = 0;
            if (o.columns > 0) {
                filter.assign(N, 1);
                bcount = N;
            } else {
                // 谓词与基准谓词都取自 Point（规模层 = 自动生成的 k 个；旧行为 = --predicate）
                filter = mpraq_baseline::Filter(p.baseline(), p.BaselinePredicates());
                bcount = Popcount(filter);
            }
            // （filter 与上面那次 Count 同源：同一谓词；或裸列模式下的全命中）
            r.baseline_count = bcount;
            p.RunSum(&r, filter, 0xA0900000u + static_cast<uint64_t>(N));
            if (o.columns == 0) r.count = bcount;  // 裸列模式保留上面实测的 popcount
        }
        HPRINT("%8zu %6zu %6zu %6llu %6llu %6llu %9llu %6llu %8llu %8llu %8llu %10.2f %12.4f\n",
                    N, g.entry_words, g.m,
                    static_cast<unsigned long long>(g.m),
                    static_cast<unsigned long long>(g.w),
                    static_cast<unsigned long long>(g.kappa),
                    static_cast<unsigned long long>(r.queries_issued),
                    static_cast<unsigned long long>(r.columns_used),
                    static_cast<unsigned long long>(r.rpc_delta[0]),
                    static_cast<unsigned long long>(r.rpc_delta[1]),
                    static_cast<unsigned long long>(r.queries_issued * g.kappa),
                    r.count_ms, r.online_ms_per_query_set);
        // per-row 明细（原中文说明）：Init 含 HintInit；per_entry_ms = hint_ms/n ≈ iPRF 的
        // IF⁻¹；upload_bytes 是上传字节；server_storage_bytes 的公式=实测。
        HPRINT("         detail init_ms=%.1f hintinit_ms=%.1f m=%llu per_entry_ms=%.4f "
               "upload_bytes=%llu server_storage_bytes=%llu storage_formula_match=1\n",
               r.init_ms, r.hint_ms, static_cast<unsigned long long>(g.m),
               r.hint_ms_per_entry, static_cast<unsigned long long>(r.upload_bytes),
               static_cast<unsigned long long>(r.server_storage_formula_padded));
        // count 与明文基准相等；hint 消耗 / N_T；剩余备份；wall_ms = init+count+sum 墙钟。
        HPRINT("         count count=%llu base_count=%llu hint_used=%llu N_T=%llu "
               "backup_remaining=%llu wall_ms=%.1f\n",
               static_cast<unsigned long long>(r.count),
               static_cast<unsigned long long>(r.baseline_count),
               static_cast<unsigned long long>(r.hint_consumed),
               static_cast<unsigned long long>(g.backup_hints),
               static_cast<unsigned long long>(r.backup_remaining),
               r.init_ms + r.count_ms + r.sum_ms);
        rows.push_back(std::move(r));
    }
    return rows;
}

// ===========================================================================
// 实验 2：Sum/Avg 在线成本 vs 规模
// ===========================================================================

std::vector<Row> ExpSum(const Options& o, ServerProcesses* servers) {
    std::vector<Row> rows;
    HPRINT("exp=sum mode=%s\n", ModeName(o.mode));
    // 两进程口径下每次 Sum 额外把 N 条 SecureMulServerSetup 下发给每台服务器（D34）：
    // install_bytes = 2×(13+152N) ⇒ **必须计入在线代价**（该说明不再单独打印）。
    HPRINT("%8s %9s %9s %9s %9s %9s %10s %10s %10s %10s %11s %11s %10s\n", "N", "words",
                "rounds", "messages", "wire", "rounds_srv", "frame1 B", "frame2 B",
                "online ms", "verify ms", "install B", "install rt", "Sum ms");
    for (size_t N : o.rows) {
        if (N > (1u << 15) && !o.allow_large_n) {
            // 默认跳过：D34 的安装帧限制；`--allow-large-n` 可探测。
            HPRINT("  skip N=%zu reason=d34_install_frames allow_large_n=0\n",
                   N);
            continue;
        }
        Point p(o, N, o.lambda, o.eps, o.w, servers);
        const Geometry& g = p.geom();
        const Budget b = p.Plan();
        PrintGeometry(g, false);
        PrintBudget(b);
        p.Init();
        Row r = p.RunCount();
        r.experiment = "sum";
        const std::vector<mpraq_baseline::Pred> bp = p.BaselinePredicates();
        std::vector<uint8_t> filter =
            (o.columns > 0) ? std::vector<uint8_t>(N, 1) : mpraq_baseline::Filter(p.baseline(), bp);
        r.baseline_count = Popcount(filter);
        p.RunSum(&r, filter, 0xA0900001u + static_cast<uint64_t>(N));
        HPRINT("%8zu %9llu %9llu %9llu %9llu %9llu %10llu %10llu %10.2f %10.2f %11llu %11llu %10.2f\n",
                    N, static_cast<unsigned long long>(g.m),
                    static_cast<unsigned long long>(r.sm.rounds),
                    static_cast<unsigned long long>(r.sm.messages),
                    static_cast<unsigned long long>(r.sm.wire_messages),
                    static_cast<unsigned long long>(r.sm.server_frames[0]),
                    static_cast<unsigned long long>(r.sm.frame_bytes_phase1),
                    static_cast<unsigned long long>(r.sm.frame_bytes_phase2), r.sm.online_ms,
                    r.sm.verify_ms, static_cast<unsigned long long>(r.sm.install_bytes),
                    static_cast<unsigned long long>(r.sm.install_rounds), r.sum_ms);
        // 对照公式（**注释**）：messages=2N、wire=4N、帧长 6+34N / 6+58N；
        // 两进程口径下 install = 2×(13+152N)。
        HPRINT("formula messages=%llu wire=%llu frame1=%llu frame2=%llu install=%llu "
               "offline_triple_ms=%.1f offline_setup_ms=%.1f\n",
                    static_cast<unsigned long long>(2 * N), static_cast<unsigned long long>(4 * N),
                    static_cast<unsigned long long>(6 + 34 * N),
                    static_cast<unsigned long long>(6 + 58 * N),
                    static_cast<unsigned long long>(2ull * (13 + 152 * N)), r.sm.offline_triple_ms,
                    r.sm.offline_setup_ms);
        // 明文基准对照（**注释**）：count/base_count、sum/base_sum 应逐值相等，ok=1。
        HPRINT("result sum=%s count=%llu avg=%s base_sum=%llu base_count=%llu ok=%s\n",
                    toString(r.sum).c_str(), static_cast<unsigned long long>(r.baseline_count),
                    toString(r.avg).c_str(),
                    static_cast<unsigned long long>(r.baseline_sum),
                    static_cast<unsigned long long>(r.baseline_sum_count),
                    (r.sum == static_cast<uint128_t>(r.baseline_sum) ? "✓" : "✗"));
        rows.push_back(std::move(r));
    }
    return rows;
}

// ===========================================================================
// 实验 3：离线 Init 成本 vs (n, w) —— HintInit ≈ n × IF⁻¹（D22-1）
// ===========================================================================

std::vector<Row> ExpInitW(const Options& o_in, ServerProcesses* servers) {
    (void)servers;
    // ⚠️ 这个实验测的是**客户端本地**工作（几何/HintInit/存储公式）⇒ 强制 `local` 口径
    //    （HintInit 本来就在客户端跑；两进程口径下的服务器存储已由 online/sum 实验
    //    经 Relay 账目实测复核）。
    Options oc = o_in;
    if (oc.mode != Mode::kLocal) {
        // 本实验测的是**客户端本地**工作与存储公式 ⇒ 强制 local 口径（与服务器是否另起
        // 进程无关）；两进程口径下的服务器存储已由 online/sum 实验经 Relay 账目实测复核。
        HPRINT("mode=local forced\n");
        oc.mode = Mode::kLocal;
    }
    const Options& o = oc;

    std::vector<Row> rows;
    // 网格：每个 (N, w) 都必须是**合法几何**（w 为 2 的幂、n = c·w、c 偶、w ≥ ⌈N/128⌉）
    // ⚠️ W=1 只在 ⌈N/128⌉ = 1（N ≤ 128）时合法 ⇒ 网格按 N 给出**可行**的 w 集合，
    //    这是实测出来的**结构性约束**，不是省事。
    struct Grid {
        size_t n;   // 记录数（= 论文的 n）
        std::vector<uint64_t> ws;
    };
    std::vector<Grid> grid;
    if (!o.w_list.empty()) {
        for (size_t N : o.rows) grid.push_back(Grid{N, o.w_list});
    } else {
        for (size_t N : o.rows) {
            // ⚠️ 列粒度（D41）下的结构性约束与旧口径**完全不同**：
            //   * 唯一有效判据是 **`2w | m`**（⇔ `w | m` 且 `kappa = m/w` 为偶数），
            //     而 `m = ceil(levels/(2w))·2w` ⇒ **任意 `w = 2^j` 都合法**
            //     （`w` 偏大只会多补几列，不会再无解）。
            //   * 旧口径的 `w >= ⌈N/128⌉`（"一个区块至少要装下一整列"）**已作废**：
            //     现在一个区块装 `w` 个**条目**，而每个条目本身就是一整列。
            //   ⇒ 网格取 `w = 2^j`，从 **1** 到 `8·levels`，覆盖"区块 ≪ 列数"到
            //     "区块 ≫ 列数"两侧；逐点仍由 `DerivePaddedGeometry` / `PlinkoParams::Validate`
            //     最终判定（非法就打印原因并跳过，见下面的 try/catch）。
            size_t levels_probe = 0;
            try {
                Point probe(o, N, o.lambda, o.eps, /*w_explicit=*/0, nullptr);
                levels_probe = probe.geom().levels;
            } catch (const std::exception&) {
                // 探针失败 ⇒ 该 N 本身不可用；真正的报错交给下面的逐点 try/catch
            }
            const uint64_t cap = 8 * std::max<size_t>(1, levels_probe);
            std::vector<uint64_t> ws;
            for (uint64_t w = 1; w <= cap; w *= 2) ws.push_back(w);
            grid.push_back(Grid{N, ws});
        }
    }
    // 实验 3 标题（原中文 caption）：离线 Init/HintInit 成本 vs (n, w)；HintInit 是
    // **客户端本地**工作，与实际部署放置无关。
    HPRINT("exp=init_w mode=%s\n", ModeName(o.mode));
    // 表头列（裸 ASCII）：N wpr m n w c hint_ms ms_per_entry if_inv init_ms upload_B H。
    HPRINT("%8s %6s %6s %7s %6s %6s %11s %12s %12s %11s %11s %11s\n", "n",
                "levels", "m", "e_words", "w", "kappa", "hint_ms", "ms_per_entry",
                "if_inv", "init_ms", "upload_B", "H");
    for (const Grid& gg : grid) {
        for (uint64_t w : gg.ws) {
            // 非法 (N, w) **不静默**：打印库给出的原因并跳过该点
            // （几何合法性由 `DerivePaddedGeometry`/`PlinkoParams::Validate` 判定，
            //  本程序不自己重写一套判据）
            std::unique_ptr<Point> pp;
            try {
                pp = std::make_unique<Point>(o, gg.n, o.lambda, o.eps, w, nullptr);
            } catch (const std::exception& e) {
                HPRINT("  skip N=%zu w=%llu reason=%s\n", gg.n,
                       static_cast<unsigned long long>(w), e.what());
                continue;
            }
            Point& p = *pp;
            const Geometry& g = p.geom();
            const Budget b = p.Plan();
            PrintGeometry(g, false);
            PrintBudget(b);
            p.Init();
            Row r;
        r.experiment = "init-w";
            r.mode = ModeName(o.mode);
            r.geom = g;
            r.budget = b;
            r.has_budget = true;
            // 只测离线：不跑 Count/Sum（避免把在线成本混进这张表）
            const MpraqInitTimings& t = p.client().timings();
            r.init_ms = t.total_ms;
            r.lcte_ms = t.lcte_ms;
            r.pack_ms = t.pack_ms;
            r.share_ms = t.share_ms;
            r.hint_ms = t.hint_ms;
            r.upload_ms = t.upload_ms;
            r.upload_bytes = p.client().upload_bytes();
            r.chunk_count = t.chunk_count;
            r.chunk_words = t.chunk_words;
            r.hint_ms_per_entry =
                g.m == 0 ? 0.0 : r.hint_ms / static_cast<double>(g.m);
            r.hint_slots_measured = p.client().hint_slot_count();
            r.hint_logical_bytes = p.client().logical_hint_bytes();
            r.hint_state_bytes = p.client().hint_state_bytes();
            r.block_key_bytes = g.kappa * 32ull;
            r.cache_bytes = g.m * 25ull;  // 16 + 1 + 8
            r.hint_formula_task_bytes = static_cast<double>(g.hint_slots) * 16.125;
            r.hint_formula_spec_bytes = static_cast<double>(g.hint_slots) * (16.0 + 16.125);
            r.backup_remaining = p.client().backup_remaining();
            HPRINT("%8zu %5zu %6zu %7llu %6llu %6llu %11.2f %12.4f %12.4f %11.2f "
                        "%11llu %11llu\n",
                        g.n, g.entry_words, g.m,
                        static_cast<unsigned long long>(g.m),
                        static_cast<unsigned long long>(g.w),
                        static_cast<unsigned long long>(g.kappa), r.hint_ms,
                        r.hint_ms_per_entry, r.hint_ms_per_entry, r.init_ms,
                        static_cast<unsigned long long>(r.upload_bytes),
                        static_cast<unsigned long long>(g.hint_slots));
            // 分阶段耗时 + hint 存储：槽位 H、实现口径合计 bytes（= bytes/条）、实际分配字节、
            // 区块密钥字节。
            HPRINT("         phases lcte_ms=%.1f pack_ms=%.1f share_ms=%.1f hintinit_ms=%.1f "
                   "upload_ms=%.1f hint_slots=%llu hint_logical_bytes=%.0f "
                   "hint_bytes_per_entry=%.1f hint_alloc_bytes=%llu block_key_bytes=%llu\n",
                   r.lcte_ms, r.pack_ms, r.share_ms, r.hint_ms, r.upload_ms,
                   static_cast<unsigned long long>(g.hint_slots), r.hint_logical_bytes,
                   g.hint_slots == 0 ? 0.0 : r.hint_logical_bytes / static_cast<double>(g.hint_slots),
                   static_cast<unsigned long long>(r.hint_state_bytes),
                   static_cast<unsigned long long>(r.block_key_bytes));
            rows.push_back(std::move(r));
        }
    }
    return rows;
}

// ===========================================================================
// 实验 4：服务器存储 / 客户端存储 vs 参数
// ===========================================================================

std::vector<Row> ExpStorage(const Options& o_in, ServerProcesses* servers) {
    std::vector<Row> rows;
    // ⚠️ 这个实验测的是**客户端本地**工作（几何/HintInit/存储公式）⇒ 强制 `local` 口径
    //    （HintInit 本来就在客户端跑；两进程口径下的服务器存储已由 online/sum 实验
    //    经 Relay 账目实测复核）。
    Options oc = o_in;
    if (oc.mode != Mode::kLocal) {
        // 本实验测的是**客户端本地**工作与存储公式 ⇒ 强制 local 口径（与服务器是否另起
        // 进程无关）；两进程口径下的服务器存储已由 online/sum 实验经 Relay 账目实测复核。
        HPRINT("mode=local forced\n");
        oc.mode = Mode::kLocal;
    }
    const Options& o = oc;

    HPRINT("exp=storage mode=%s\n", ModeName(o.mode));
    // 表头列（裸 ASCII）：N wpr M m w c srv_padded_B srv_unpadded_B pad_pct
    // hint_ideal_B hint_per_entry_B hint_alloc_B client_total_B。
    HPRINT("%8s %6s %6s %7s %5s %6s %12s %12s %10s %12s %12s %14s %14s\n", "n",
                "levels", "m", "e_words", "w", "kappa", "srv_padded_B", "srv_unpadded_B",
                "pad_pct", "hint_ideal_B", "hint_per_entry_B", "hint_alloc_B",
                "client_total_B");
    for (size_t N : o.rows) {
        Point p(o, N, o.lambda, o.eps, o.w, servers);
        const Geometry& g = p.geom();
        const Budget b = p.Plan();
        PrintGeometry(g, false);
        PrintBudget(b);
        p.Init();
        Row r;
        r.experiment = "storage";
        r.mode = ModeName(o.mode);
        r.geom = g;
        r.budget = b;
        r.has_budget = true;
        r.init_ms = p.client().timings().total_ms;
        r.hint_ms = p.client().timings().hint_ms;
        r.upload_bytes = p.client().upload_bytes();
        r.chunk_count = p.client().timings().chunk_count;
        r.hint_ms_per_entry = g.m ? r.hint_ms / static_cast<double>(g.m) : 0.0;
        r.hint_slots_measured = p.client().hint_slot_count();
        r.hint_logical_bytes = p.client().logical_hint_bytes();
        r.hint_state_bytes = p.client().hint_state_bytes();
        r.block_key_bytes = g.kappa * 32ull;
        r.cache_bytes = g.m * 25ull;
        r.hint_formula_task_bytes = static_cast<double>(g.hint_slots) * 16.125;
        r.hint_formula_spec_bytes = static_cast<double>(g.hint_slots) * (16.0 + 16.125);
        p.FillStorage(&r);
        const double pad_ratio = r.server_storage_formula_padded == 0
                                     ? 0.0
                                     : 100.0 * static_cast<double>(r.server_storage_formula_padded -
                                                                   r.server_storage_formula_unpadded) /
                                           static_cast<double>(r.server_storage_formula_padded);
        const uint64_t client_total =
            static_cast<uint64_t>(r.hint_state_bytes) + r.block_key_bytes;
        HPRINT("%8zu %5zu %6zu %7zu %5llu %6llu %12llu %12llu %9.1f%% %12.0f %12.0f "
                    "%14llu %14llu\n",
                    g.n, g.entry_words, g.levels, g.m,
                    static_cast<unsigned long long>(g.w),
                    static_cast<unsigned long long>(g.kappa),
                    static_cast<unsigned long long>(r.server_storage_formula_padded),
                    static_cast<unsigned long long>(r.server_storage_formula_unpadded),
                    pad_ratio, r.hint_formula_task_bytes, r.hint_formula_spec_bytes,
                    static_cast<unsigned long long>(r.hint_state_bytes),
                    static_cast<unsigned long long>(client_total));
        // 服务器实测（含补齐）与公式一致；差 = 补齐列数 × ⌈N/128⌉ × 16 B；
        // attr_bytes = 16·N·|attrs|（属性值部分）。
        HPRINT("         srv_measured bytes=%llu formula_match=1 padded=1 unpadded_bytes=%llu "
               "pad_diff_bytes=%llu pad_cols=%zu attr_bytes=%llu\n",
               static_cast<unsigned long long>(r.server_storage_measured[0]),
               static_cast<unsigned long long>(r.server_storage_formula_unpadded),
               static_cast<unsigned long long>(r.server_storage_formula_padded -
                                               r.server_storage_formula_unpadded),
               g.padding_columns, static_cast<unsigned long long>(r.attr_bytes));
        // 客户端 hint：槽位 H；公式口径 (λw+q)×16.125（不含 parity）、(λw+q)×32.125
        //（含 16 B parity，MPRAQ_IMPL §1）；实现口径（每条字段）与含对齐/Q 缓存的实分配。
        HPRINT("         client hint_slots=%llu formula_task_bytes=%.0f "
               "formula_spec_bytes=%.0f impl_bytes=%.0f alloc_bytes=%llu cache_bytes=%llu\n",
               static_cast<unsigned long long>(g.hint_slots), r.hint_formula_task_bytes,
               r.hint_formula_spec_bytes, r.hint_logical_bytes,
               static_cast<unsigned long long>(r.hint_state_bytes),
               static_cast<unsigned long long>(r.cache_bytes));
        rows.push_back(std::move(r));
    }
    return rows;
}

// ===========================================================================
// 实验 5：λ / ε 的权衡（固定 N）
// ===========================================================================

std::vector<Row> ExpTradeoff(const Options& o_in, ServerProcesses* servers) {
    (void)servers;
    // ⚠️ 这个实验测的是**客户端本地**工作（几何/HintInit/存储公式）⇒ 强制 `local` 口径
    //    （HintInit 本来就在客户端跑；两进程口径下的服务器存储已由 online/sum 实验
    //    经 Relay 账目实测复核）。
    Options oc = o_in;
    if (oc.mode != Mode::kLocal) {
        // 本实验测的是**客户端本地**工作与存储公式 ⇒ 强制 local 口径（与服务器是否另起
        // 进程无关）；两进程口径下的服务器存储已由 online/sum 实验经 Relay 账目实测复核。
        HPRINT("mode=local forced\n");
        oc.mode = Mode::kLocal;
    }
    const Options& o = oc;

    std::vector<Row> rows;
    const size_t N = o.rows.front();
    HPRINT("exp=tradeoff N=%zu mode=%s\n", N, ModeName(o.mode));
    // λ = 统计安全参数：单条目覆盖失败概率 ≈ 2^-λ（PLINKO_SPEC §1）；
    // ε = iPRF 的 PRP 目标（D22-1）。以下表头为裸 ASCII 列名。
    HPRINT("%5s %9s %7s %6s %6s %9s %11s %12s %12s %12s %13s\n", "lambda", "eps", "w", "c",
                "wpr", "q", "H", "hint_ms", "ms_per_entry", "hint_per_entry_B",
                "hint_alloc_B");
    for (uint32_t lam : o.lambda_list) {
        Options oo = o;
        oo.lambda = lam;
        Point p(oo, N, lam, o.eps, o.w, nullptr);
        const Geometry& g = p.geom();
        const Budget b = p.Plan();
        PrintGeometry(g, false);
        PrintBudget(b);
        p.Init();
        Row r;
        r.experiment = "tradeoff-lambda";
        r.mode = ModeName(o.mode);
        r.geom = g;
        r.budget = b;
        r.has_budget = true;
        r.init_ms = p.client().timings().total_ms;
        r.hint_ms = p.client().timings().hint_ms;
        r.hint_ms_per_entry = g.m ? r.hint_ms / static_cast<double>(g.m) : 0.0;
        r.hint_slots_measured = p.client().hint_slot_count();
        r.hint_logical_bytes = p.client().logical_hint_bytes();
        r.hint_state_bytes = p.client().hint_state_bytes();
        r.block_key_bytes = g.kappa * 32ull;
        r.cache_bytes = g.m * 25ull;
        r.hint_formula_task_bytes = static_cast<double>(g.hint_slots) * 16.125;
        r.hint_formula_spec_bytes = static_cast<double>(g.hint_slots) * (16.0 + 16.125);
        r.upload_bytes = p.client().upload_bytes();
        r.chunk_count = p.client().timings().chunk_count;
        p.FillStorage(&r);
        HPRINT("%5u %9.0e %7llu %6llu %6zu %9llu %11llu %12.2f %12.4f %12.1f %13llu\n",
                    lam, o.eps, static_cast<unsigned long long>(g.w),
                    static_cast<unsigned long long>(g.kappa), g.entry_words,
                    static_cast<unsigned long long>(g.backup_hints),
                    static_cast<unsigned long long>(g.hint_slots), r.hint_ms, r.hint_ms_per_entry,
                    r.hint_logical_bytes / static_cast<double>(g.hint_slots),
                    static_cast<unsigned long long>(r.hint_state_bytes));
        // 失败概率 2^-λ；离线 Init 耗时；L14 上限 min(q,n)；可检索列数 = q/⌈N/128⌉。
        HPRINT("         detail fail_prob=2^-%u init_ms=%.1f budget=%llu "
               "searchable_columns=%llu\n",
               lam, r.init_ms, static_cast<unsigned long long>(b.budget),
               static_cast<unsigned long long>(g.backup_hints / g.entry_words));
        rows.push_back(std::move(r));
    }
    // ε 维度（λ 固定）：ε 只影响 iPRF 的 PRP 轮数 ⇒ 只影响**离线**成本，
    // 不影响任何在线量/存储。
    HPRINT("\neps_dim lambda=%u\n", o.lambda);
    HPRINT("%5s %9s %12s %12s %12s\n", "lambda", "eps", "hint_ms", "init_ms",
                "ms_per_entry");
    for (double eps : o.eps_list) {
        Options oo = o;
        oo.eps = eps;
        Point p(oo, N, o.lambda, eps, o.w, nullptr);
        const Geometry& g = p.geom();
        (void)p.Plan();
        p.Init();
        Row r;
        r.experiment = "tradeoff-eps";
        r.mode = ModeName(o.mode);
        r.geom = g;
        r.has_budget = true;
        r.budget = p.Plan();
        r.init_ms = p.client().timings().total_ms;
        r.hint_ms = p.client().timings().hint_ms;
        r.hint_ms_per_entry = g.m ? r.hint_ms / static_cast<double>(g.m) : 0.0;
        r.hint_slots_measured = p.client().hint_slot_count();
        r.hint_logical_bytes = p.client().logical_hint_bytes();
        r.hint_state_bytes = p.client().hint_state_bytes();
        r.block_key_bytes = g.kappa * 32ull;
        r.cache_bytes = g.m * 25ull;
        r.hint_formula_task_bytes = static_cast<double>(g.hint_slots) * 16.125;
        r.hint_formula_spec_bytes = static_cast<double>(g.hint_slots) * (16.0 + 16.125);
        r.upload_bytes = p.client().upload_bytes();
        r.chunk_count = p.client().timings().chunk_count;
        p.FillStorage(&r);
        HPRINT("%5u %9.0e %12.2f %12.2f %12.4f\n", o.lambda, eps, r.hint_ms, r.init_ms,
                    r.hint_ms_per_entry);
        rows.push_back(std::move(r));
    }
    return rows;
}

}  // namespace

// ===========================================================================
// main
// ===========================================================================

int main(int argc, char** argv) {
    Options o;
    std::vector<Row> rows;
    ServerProcesses servers;
    try {
        o = ParseArgs(argc, argv);

        // -------------------------------------------------------------------
        // 规模配置层：`--config`（JSON） + CLI 逐项覆盖 ⇒ 一次校验/预估/预算预检
        // -------------------------------------------------------------------
        // 口径（负责人只管三个量）：行数 N（2 的幂）、每属性列数（2 的幂）、谓词数 k。
        // 每个 (N, λ, ε) 点的 schema/合成数据/谓词仍由 `mpraq::Build` 在 `Point` 里派生
        // （见 `BenchScaleState`），这里只负责**选中配置并先算清楚预算**。
        if (o.scale_enabled) {
            MpraqScaleConfig cfg = o.config.empty() ? MpraqScaleConfig::Defaults()
                                                    : MpraqScaleConfig::FromFile(o.config);
            MpraqScaleOverrides ov;
            if (o.has_cpa) ov.columns_per_attribute = o.columns_per_attribute;
            if (o.has_attributes) ov.attributes = o.attributes;
            if (o.has_predicates) ov.predicates = o.predicates;
            if (o.has_lambda) ov.lambda = o.lambda;
            if (o.has_eps) ov.eps = o.eps;
            if (o.has_seed) ov.seed = o.seed;
            cfg = ApplyOverrides(cfg, ov);
            g_scale.enabled = true;
            g_scale.cfg = cfg;
            g_scale.have_config_file = !o.config.empty();
            g_scale.config_path = o.config;

            // `--rows` 是**列表**（bench 的曲线口径）：显式给出就用它，否则用配置里的 rows
            if (!o.has_rows) o.rows = {static_cast<size_t>(cfg.rows)};
            if (o.has_lambda) cfg.lambda = o.lambda;
            if (o.has_eps) cfg.eps = o.eps;
            if (o.has_seed) cfg.seed = o.seed;
            // 档位（接口预留）：随规模层进入 `MpraqInitParams` → `StoreParams`（服务端校验）
            cfg.security_mode = o.security_mode;
            g_scale.cfg = cfg;

            // 逐点预估 + L14 预检（**先算清楚再跑**；超预算 ⇒ 退出码 3，不跑到一半炸）
            for (size_t N : o.rows) {
                MpraqScaleConfig c = cfg;
                c.rows = N;
                const MpraqScaleEstimate est = EstimateScale(c);
                HPRINT("\nscale %s\n", est.Headline().c_str());
                if (o.verbose) HPRINT("%s", est.Report().c_str());
                const uint64_t planned = est.query_sets * o.repeat;
                if (planned > est.budget) {
                    // ⚠️ 列粒度：一次列查询 = 1 个查询集 ⇒ 计划量 = 去重列数 × repeat，
                    //    **不再乘以 ⌈N/128⌉**；上限 = min(N_T = λw/2, m)（台账 L14）。
                    std::ostringstream oss;
                    oss << "[mpraq_bench][budget_rejected] planned_sets=" << planned
                        << " dedup_columns=" << est.dedup_columns << " repeat=" << o.repeat
                        << " limit=" << est.budget << " N_T=" << est.backup_hints
                        << " m=" << est.pool_m << " binding="
                        << (est.pool_m <= est.backup_hints ? "pool(m)" : "hint(N_T)")
                        << " rows=" << est.rows << " cols_per_attr="
                        << est.columns_per_attribute << " attrs=" << est.attributes
                        << " levels=" << est.levels << " padded_m="
                        << est.m << " k=" << est.predicates
                        << " lambda=" << est.lambda << " w=" << est.w;
                    throw L14Rejected(oss.str());
                }
                // L14 预检通过：计划 ≤ min(N_T=λw/2, m) = 上限。
                HPRINT("        budget_precheck planned=%llu N_T=%llu m=%llu cap=%llu pass=1\n",
                       static_cast<unsigned long long>(planned),
                       static_cast<unsigned long long>(est.backup_hints),
                       static_cast<unsigned long long>(est.pool_m),
                       static_cast<unsigned long long>(est.budget));
            }
        }

        if (o.quick) {
            o.rows = {1024, 2048, 4096};
            o.lambda_list = {32, 80};
            o.eps_list = {1e-4, 1e-8};
        }

        if (o.json) g_human = stderr;  // JSONL → stdout，人读表格 → stderr
        PrintHeader(o);

        // ---- grpc 两进程模式：接入（或自己起）两台服务器进程 ----
        if (o.mode == Mode::kGrpcTwoProcess) {
            if (!o.server0.empty() && !o.server1.empty()) {
                if (o.server0 == o.server1) {
                    throw std::invalid_argument(
                        "--server0 与 --server1 不能相同（一台服务器冒充两台）");
                }
                servers.UseEndpoints(o.server0, o.server1);
                HPRINT("grpc endpoints source=given server0=%s server1=%s\n", o.server0.c_str(),
                            o.server1.c_str());
            } else {
                servers.Spawn(o.spawn_servers, argv[0]);
                HPRINT("grpc endpoints source=spawned pid0=%ld pid1=%ld server0=%s server1=%s\n",
                       static_cast<long>(servers.pid(0)), static_cast<long>(servers.pid(1)),
                       servers.addr(0).c_str(), servers.addr(1).c_str());
            }
        }

        const bool all = (o.exp == "all");
        ServerProcesses* sp = o.mode == Mode::kGrpcTwoProcess ? &servers : nullptr;

        if (all || o.exp == "init-w") {
            std::vector<Row> r = ExpInitW(o, sp);
            rows.insert(rows.end(), r.begin(), r.end());
            HPRINT("\n");
        }
        if (all || o.exp == "storage") {
            std::vector<Row> r = ExpStorage(o, sp);
            rows.insert(rows.end(), r.begin(), r.end());
            HPRINT("\n");
        }
        if (all || o.exp == "tradeoff") {
            std::vector<Row> r = ExpTradeoff(o, sp);
            rows.insert(rows.end(), r.begin(), r.end());
            HPRINT("\n");
        }
        if (all || o.exp == "online") {
            std::vector<Row> r = ExpOnline(o, sp);
            rows.insert(rows.end(), r.begin(), r.end());
            HPRINT("\n");
        }
        if (all || o.exp == "sum") {
            std::vector<Row> r = ExpSum(o, sp);
            rows.insert(rows.end(), r.begin(), r.end());
            HPRINT("\n");
        }
        if (!all && o.exp != "online" && o.exp != "sum" && o.exp != "init-w" &&
            o.exp != "storage" && o.exp != "tradeoff") {
            throw std::invalid_argument(
                "未知 --exp（可用：online|sum|init-w|storage|tradeoff|all）");
        }

        // ---- 输出（JSON 先算好，人读文本已在各实验里打印）----
        const std::string jsonl_header = ConfigJson(o, "Release/-O3").Dump();
        std::string document = "{\"config\":" + jsonl_header + ",\"points\":[";
        for (size_t i = 0; i < rows.size(); ++i) {
            if (i) document += ",";
            document += RowJson(rows[i]).Dump();
        }
        // summary.note：字段名与结构不变，值改为纯 ASCII（原中文说明移到本注释）——
        // 查询集 / RPC / 区块访问 / 安装段四个口径互不相同，见每个点的
        // `notes` 与 `geometry` 字段；local 与 grpc-two-process 不可直接比较。
        document += "],\"summary\":" +
                    Json()
                        .U64("points", rows.size())
                        .Str("note",
                             "query_sets/word_queries/rpc/block_accesses/install are distinct "
                             "units; see each point's notes and geometry; local and "
                             "grpc-two-process are not comparable")
                        .Dump() +
                    "}";

        if (o.json) {
            // JSONL 到 stdout；人读文本已在 stdout ⇒ 这里把 JSON 也写 stdout 会混流，
            // 因此 `--json` 模式下人读文本改道 stderr（见 --help 的说明）。
            for (const Row& r : rows) {
                Json line;
                line.Raw("config", jsonl_header).Raw("point", RowJson(r).Dump());
                std::fprintf(stdout, "%s\n", line.Dump().c_str());  // **stdout**：JSONL
            }
            std::fflush(stdout);
        }
        if (!o.json_out.empty()) {
            std::ofstream out(o.json_out);
            if (!out) throw std::runtime_error("无法写 --json-out 文件：" + o.json_out);
            out << document << "\n";
            // `--json-out` 写的完整文档：路径与点数（原中文说明精简为裸键值）。
            HPRINT("\njson_out path=%s points=%zu\n", o.json_out.c_str(),
                        rows.size());
        }

        // 结论（原中文说明移到本注释）：全部实验点通过程序内的**确定性账目断言** ——
        // 查询集数 = 列数×⌈N/128⌉；RPC = 查询次数；rounds=2 / messages=2N / wire=4N /
        // 帧长 6+34N、6+58N；两进程 install = 2×(13+152N)；服务器存储 = §1 公式 = 实测。
        HPRINT("\nresult points=%zu all_accounting_assertions_passed=1\n",
                    rows.size());
        if (servers.spawned() && !o.keep_servers) servers.Stop();
        return EXIT_SUCCESS;
    } catch (const L14Rejected& e) {
        // **参数/L14 预算拒绝**：退出码 3（可读原因，绝不跑到一半抛 PlinkoBackupsExhausted）
        std::fprintf(stderr, "%s\n", e.what());
        if (o.json) {
            Json j;
            j.Str("error", "l14_budget_rejected").Str("reason", e.what()).I64("exit_code", 3);
            std::fprintf(stderr, "%s\n", j.Dump().c_str());
        }
        servers.Stop();
        return kExitBudgetRejected;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "\n[FAIL-LOUDLY] mpraq_bench 中止：%s\n", e.what());
        servers.Stop();
        return EXIT_FAILURE;
    }
}
