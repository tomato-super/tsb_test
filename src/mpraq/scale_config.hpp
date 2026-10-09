#pragma once

// MPRAQ 的**规模配置层**（面向规模测试）—— 负责人只管三个量，其余全部自动派生。
//
// ===========================================================================
// 0. 负责人口径（实现严格照此；本层是**唯一**的规模入口）
// ===========================================================================
//   ① **行数 = 记录数 `N`**，必须是 **2 的幂**。非 2 的幂 ⇒ 抛 `std::invalid_argument`
//      并指出字段名与实际值（**绝不**静默取整到最近的 2 的幂）。
//   ② **列数 = 每个属性的 LCTE 区间长度（列数）`columns_per_attribute`**，必须是
//      **2 的幂**（且 >= 2，否则取值域为空）。**所有属性共用同一套特征表参数**
//      （同 `range_size`、同 `window_size`、同取值域风格），但**每个属性各自拥有一组列**
//      （否则跨属性谓词会互相串列）⇒
//          **真实层数 `levels` = 属性数 × `columns_per_attribute`**。
//      PIR 条目数 `m`（>= levels）与 Plinko 几何 `(m, w, kappa)` 由
//      `DerivePaddedGeometry` 自动派生。
//      ⚠️ 列粒度下（D41）**不再"补齐到 2 的幂"**：只需 `2w | m`（等价于 `w | m` 且
//      `kappa = m/w` 为偶数）⇒ `m = ceil(levels / (2w)) · 2w`，**D35 的 ×2 升级搜索已删除**。
//      服务器存储**双报** `levels` 与 `m` 两种口径。
//   ③ **谓词数量 `k`**：用户不写谓词内容，由 `Build()` 自动生成 `k` 个**合法**谓词，
//      且**尽量落在互不相同的列**上 ⇒ **去重列数 = min(k, M)**。
//      实现上只用**单列**操作符（lt/le/gt/ge 各占 1 列，见 `scale_config.cpp`）：
//        * 偶属性 = 下界 `x >= c`（列号 c 即下界）、奇属性 = 上界 `x < c` ——
//          **同一属性上的谓词同向**，因此合取恒可满足（反向相乘会被夹成空集）；
//        * 列号是 [0, C−1] 上的置换（下界从 1 起、上界从 C−2 起）⇒ k ≤ M 时两两不同，
//          且谓词**非退化**（不是恒真/恒假），demo 的 Count / Sum / Avg 才有可对照的非零结果。
//      ⚠️ 单个属性上的谓词数 >= 每属性列数 − 1 时，最紧的那个界会贴着取值域边界，
//         合取**可能为空**（Count = 0）—— 这是合法的查询结果，不是错误：
//         `AvgOverFilter` 在 `count == 0` 时按设计抛 `std::domain_error`，调用方须先判 count。
//      ⇒ 换算（负责人按这个手算核对；**只写在这里，不打印**）：
//          `k → 去重列数 = min(k, levels) → 查询集数 = 去重列数（一列 = 一个条目）→ 每台 RPC = 1`
//      `MpraqScaleEstimate::Headline()` 只打印该换算的**结果值**（裸 `key=value`），
//      `Report()` 打印逐项数值；两者的解释文字一律留在注释里（print 精简纪律）。
//   ④ 数据集**合成生成**：`DeterministicPrng` + 显式 `seed`（铁律 D6 的确定性）；
//      `MpraqRecord::feature = i`（行号，D36 定义的"死字段"/客户端明文标签，正好当行标签）；
//      属性值落在该属性的取值域内（D19-5 的 `m >= 跨度+2` 取到无损上限）。
//   ⑤ 其余量给合理默认值：λ=80、ε=1e-4、seed=7、属性数=2、谓词数=3、N=4096、
//      每属性列数=32（与 `config/mpraq_scale.json` 逐字段一致），同样可被覆盖。
//
// ===========================================================================
// 1. 派生公式（每条都给出出处；**数值全部由公式算，程序里没有第二份口径**）
// ===========================================================================
//   * 条目宽度          `entry_words = ⌈n/128⌉`
//                       （`node.hpp` §1：一个 PIR 条目 = 一整列 = entry_words 个 128 位字）
//   * 真实层数          `levels = attributes · columns_per_attribute`
//                       （任务口径 ②；每个属性各自一组列）
//   * PIR 条目数        `m`（>= levels 且 `2w | m`）← `DerivePaddedGeometry(levels, n, λ, ε)`
//                       （决策 D15(a) 只补列不补记录；D41 取代了 D35 的 ×2 升级）
//   * 去重列数          `min(k, levels)`（任务口径 ③；每个谓词恰好归约到 1 列，见 §3）
//   * 查询集数          `min(k, levels)`（**一列 = 一个条目 = 1 个查询集**；Q5）
//   * 每台 RPC 次数     **恒 1**（一次 `RunBatch` 把所有查询集放进一次
//                       `IMpraqChannel::ServerRespBatch`；Q5 / D24④）
//   * 服务器存储（每台）`16 · m · entry_words + 16 · n · attributes`（**含补齐**，`node.hpp` §1）
//                       不含补齐：`16 · levels · entry_words + 16 · n · attributes`（双报）
//   * hint 上限         `N_T = λw/2`（`PlinkoParams::backup_hints()`；D8：每个查询集消费 1 条）
//   * 新鲜索引池        `m`（台账 L14 第②条）
//   * 查询预算          `min(k, levels) <= min(N_T, m)`，超预算 ⇒ **拒绝并给出可读原因**
//                       （`TASK_PLAN.md` 台账 L14 / bench 的 `budget_rejected` 口径）
//
// ===========================================================================
// 2. fail-loudly（铁律）
// ===========================================================================
//   * 非 2 的幂 / `attributes == 0` / `predicates == 0` / `λ == 0` / `ε ∉ (0,1)` /
//     未知 JSON 字段 ⇒ `std::invalid_argument`，消息里**指明字段名、实际值与期望**；
//   * 几何无解（列数补不出合法的 `(n, w, c)`）⇒ 抛异常并转述 `DerivePaddedGeometry`
//     的诊断（**不**降级、**不**静默改 `m`/`N`）；
//   * 超 L14 预算 ⇒ `CheckL14Budget` 抛异常并给出算式（不跑到一半抛 `PlinkoBackupsExhausted`）。
//
// ⚠️ 本层**只做派生与校验**，不碰协议语义：`Init` / 谓词解析 / PIR 全部沿用既有实现。

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "mpraq/init.hpp"
#include "mpraq/lcte.hpp"
#include "mpraq/predicate.hpp"

namespace tsb {
namespace mpraq {

// ---------------------------------------------------------------------------
// 配置本体（负责人只需这几个旋钮）
// ---------------------------------------------------------------------------

struct MpraqScaleConfig {
    // ① 行数 = 记录数 N（**必须是 2 的幂**）
    uint64_t rows = 4096;
    // ② 列数 = 每个属性的 LCTE 列数（**必须是 2 的幂**，且 >= 2）
    uint32_t columns_per_attribute = 32;
    // ③ 属性数（>= 1）与谓词数 k（>= 1）
    uint32_t attributes = 2;
    uint32_t predicates = 3;
    // ④ **区间宽度 k**（值域上的宽度；`0` = 现状：生成**单列阈值**谓词）。
    //    > 0 时每个谓词生成 `kRange [a, a+k)`，占 **2 个 LCTE 列**（下界 + 上界）。
    //    ⚠️ 区间模式下**每个属性最多一个区间谓词**：`kRange` 在同一属性上**同时**
    //       给出下界与上界，而"同一属性上的谓词必须同向"这条纪律（见 `MakeSingleColumnPredicate`
    //       上方注释）正是为了防止合取被夹成空集 ⇒ 两个不相交的区间在同一属性上会
    //       让 Count 恒 0、`AvgOverFilter` 抛 `std::domain_error`。
    uint32_t interval_width = 0;
    // ⑤ 安全参数与确定性种子
    uint32_t lambda = 80;   // Plinko 的 λ（失败概率 2^-λ）
    double eps = 1e-4;      // iPRF 的 PRP 目标 ε（D22-1；测试可调小加速）
    uint64_t seed = 7;      // 合成数据 + Init 的确定性种子（D6）
    // ⑥ 运行方式（安全档位）——**接口预留**（见 `src/mpraq/security_mode.hpp`）。
    //    JSON 键 **`security_mode`**（**不是** `mode`：那个名字被 bench 的
    //    `--mode local|grpc` 占用于"传输口径"）；CLI 旗标 `--security-mode`。
    //    严格解析：只认 "malicious" / "semi-honest"，非法值拒绝启动。
    //    ⚠️ 本 gate **不改变行为**：两档目前走同一条代码路径，它的作用是
    //       随 `StoreParams` 上线并被服务端一致性校验（防静默降级）。
    MpraqSecurityMode security_mode = kDefaultMpraqSecurityMode;
    // Plinko 的"重复查询缓存"开关（负责人要求；默认开）。
    // 关掉 ⇒ 重复查询**直接拒绝**（抛 `PlinkoRepeatedQueryRejected`），绝不退化重查同一索引。
    bool enable_repeat_query_cache = true;

    // 默认值（与 `config/mpraq_scale.json` 逐字段一致）
    static MpraqScaleConfig Defaults() { return MpraqScaleConfig{}; }

    // 从 JSON 文件加载（文件不存在/解析失败/字段非法 ⇒ std::invalid_argument）
    static MpraqScaleConfig FromFile(const std::string& path);
    // 从 JSON 文本加载（测试与嵌入用）。**缺省字段取默认值**，未知字段 ⇒ 报错。
    static MpraqScaleConfig FromJson(const std::string& text);
};

// 2 的幂判定（0 不算）
bool IsScalePowerOfTwo(uint64_t v);

// 校验配置（失败抛 std::invalid_argument；消息含字段名/实际值/期望）
void ValidateScaleConfig(const MpraqScaleConfig& config);

// 规范化 JSON 文本（字段顺序固定 ⇒ 输出可 diff；用于往返用例与打印）
std::string ToJsonText(const MpraqScaleConfig& config);

// 派生 schema 时所有属性共用的取值域（闭区间，风格一致）：
//   `domain_min = 0`、`domain_max = columns_per_attribute - 2`
// 理由：D19-5 要求 `range_size >= 跨度 + 2`；取等号即"无损表达全部左阈值谓词"的紧上限，
// 且 R = [0, columns_per_attribute - 1] ⊇ [0, domain_max + 1]（`lcte.hpp` §2）。
int64_t ScaleDomainMin(const MpraqScaleConfig& config);
int64_t ScaleDomainMax(const MpraqScaleConfig& config);

// ---------------------------------------------------------------------------
// CLI 覆盖（JSON 是基底，命令行逐项覆盖）
// ---------------------------------------------------------------------------

// 规模旗标：`--rows` / `--columns` / `--attributes` / `--predicates` / `--lambda` /
// `--eps` / `--seed`（`--columns` = **每属性列数**，即 JSON 的 `columns_per_attribute`）。
struct MpraqScaleOverrides {
    std::optional<uint64_t> rows;
    std::optional<uint32_t> columns_per_attribute;
    std::optional<uint32_t> attributes;
    std::optional<uint32_t> predicates;
    std::optional<uint32_t> interval_width;   // 区间宽度 k（0 = 单列阈值模式）
    std::optional<uint32_t> lambda;
    std::optional<double> eps;
    std::optional<uint64_t> seed;
    std::optional<std::string> security_mode;   // 字符串档位（严格解析在 ApplyOverrides 里做）
    // Plinko 重复查询缓存的开关（`on|off`，严格解析）。**默认 on**。
    std::optional<std::string> repeat_query_cache;

    bool any() const;
    // 该旗标是否属于规模层（接受 "--rows" 与 "rows" 两种写法）
    static bool IsScaleFlag(const std::string& flag);
    // 全部规模旗标名（`--help` 与报错信息用）
    static std::string FlagList();
    // 按旗标名写入一项；**不是**规模旗标、或值无法解析 ⇒ std::invalid_argument
    void Set(const std::string& flag, const std::string& value);
};

// 应用覆盖：只覆盖**显式给出**的项，其余保持 `base`（= JSON 或默认值）。
// 覆盖后不做校验（校验由 `ValidateScaleConfig` / `EstimateScale` 统一做，避免两套规则）。
MpraqScaleConfig ApplyOverrides(MpraqScaleConfig base, const MpraqScaleOverrides& overrides);

// ---------------------------------------------------------------------------
// 预估对照（全部由公式算出，供 app 打印；不含任何实测）
// ---------------------------------------------------------------------------

struct MpraqScaleEstimate {
    // ---- 配置回声 ----
    uint64_t rows = 0;                    // N
    uint64_t columns_per_attribute = 0;   // 每属性列数
    uint64_t attributes = 0;
    uint64_t predicates = 0;              // k
    uint32_t interval_width = 0;          // 区间宽度（0 = 单列阈值模式）
    uint32_t lambda = 0;
    double eps = 0.0;
    MpraqSecurityMode security_mode = kDefaultMpraqSecurityMode;   // 配置回声
    bool enable_repeat_query_cache = true;                          // 配置回声

    // ---- 几何（符号向论文看齐，D41）----
    uint64_t entry_words = 0;      // ⌈n/128⌉：条目宽度（字）
    uint64_t levels = 0;           // 真实 LCTE 层数 = attributes · columns_per_attribute
    uint64_t m = 0;                // PIR 条目数（= 补齐后的层数；只补到 2w 的倍数）
    uint64_t padding_columns = 0;  // m − levels
    uint64_t w = 0;                // 块大小（条目/块；2 的幂）
    uint64_t kappa = 0;            // 块数 κ = m / w（偶数）
    uint64_t main_hints = 0;       // λw
    uint64_t backup_hints = 0;     // N_T = λw/2
    uint64_t hint_slots = 0;       // H = λw + N_T

    // ---- 换算（负责人手算核对的那一条链）----
    uint64_t dedup_columns = 0;           // min(k, levels)
    uint64_t query_sets = 0;              // = dedup_columns（一列 = 一个条目 = 1 个查询集）
    uint64_t rpc_per_server = 1;          // 恒 1（一次 RunBatch）

    // ---- 账目 ----
    uint64_t storage_bytes_padded = 0;    // 数据 + tag(恶意档) + 属性
    uint64_t storage_bytes_unpadded = 0;  // 把 m 换成 levels 的同一公式（双报）
    // ⚠️ **tag 项**：恶意档 = `16·m·entry_words`（与数据表等大）；半诚实档 = 0。

    // ---- 查询预算 ----
    uint64_t pool_m = 0;              // 新鲜索引池 = m
    uint64_t budget = 0;              // min(N_T, m)

    // 一行换算的**结果值**（裸 `key=value`，无任何解释文字）：
    //   N=… C=… A=… M=… m=… k=… qsets=… rpc=…
    // ⚠️ print 精简纪律：派生公式、单位、"（真实列数）"这类括注一律写在注释里，不进输出。
    std::string Headline() const;
    // 逐项数值（多行，仍为裸 `key=value`）：几何 / 存储双报 / L14 预算。
    // 各字段的含义与公式见本文件 §1 与 `EstimateScale` 的实现注释。
    std::string Report() const;
};

// 派生几何 + 算全部预估量。非法配置/几何无解 ⇒ std::invalid_argument（可读原因）。
MpraqScaleEstimate EstimateScale(const MpraqScaleConfig& config);

// L14 预算校验：`query_sets <= min(q, n)` 不成立 ⇒ std::invalid_argument，
// 消息里给出算式、两条上限与处置建议（**先算清楚再跑**，绝不跑到一半抛 hint 用尽）。
void CheckL14Budget(const MpraqScaleEstimate& estimate);

// ---------------------------------------------------------------------------
// 生成物：schema + 合成数据 + 自动谓词 + Init 参数
// ---------------------------------------------------------------------------

struct MpraqScaleSetup {
    MpraqScaleConfig config;              // 生效配置（JSON + CLI 覆盖之后）
    MpraqScaleEstimate estimate;          // 派生量（公式口径；实测见 app 的账目）

    Schema schema;                        // 属性数 = attributes，每个属性同形状、各自一组列
    std::vector<MpraqRecord> records;     // N 条合成记录（feature = i ⇒ D36 行标签）
    std::vector<Predicate> predicates;    // k 个合法谓词，恰好落在 min(k, M) 个不同列上
    uint32_t sum_attr = 0;                // Sum/Avg 作用的属性号（attributes >= 2 ⇒ 1，否则 0）
    MpraqInitParams init;                 // λ / ε / seed（w 交给 DerivePaddedGeometry）

    size_t num_records() const { return records.size(); }
};

// 主入口：校验 → 预估 → L14 预算 → 派生 schema/数据/谓词/Init 参数。
// 任何一步不合法都抛 std::invalid_argument（可读原因），绝不静默取整或降级。
MpraqScaleSetup Build(const MpraqScaleConfig& config);

// 便利：把规模配置的派生结果**逐项**与 `MpraqClient::Init` 之后的实测几何对照
// （测试与 app 都用它断言"M = m 派生口径一致"，避免两处公式漂移）。
// 返回空串表示一致；否则返回不一致的可读描述。
std::string CompareEstimateWithStore(const MpraqScaleEstimate& estimate,
                                     const StoreParams& store);

}  // namespace mpraq
}  // namespace tsb
