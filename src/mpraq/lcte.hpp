#pragma once

// MPRAQ 的 LCTE 编码层（任务 MPA-01）。
//
// ===========================================================================
// 1. 论文口径（`doc/paper/MPARQ.tex`）
// ===========================================================================
// §"Left-Threshold Cumulative Encoding (LCTE)"（\label{sec:LCTE}）原文：
//
//   "Let R = {r_1, r_2, ..., r_m} be a predefined set of integers satisfying
//    r_1 < r_2 < ... < r_m. In this paper, we set
//    R = {r_min, r_min+1, ..., r_min+m-1} for some integer r_min, i.e., the
//    elements are consecutive integers with unit interval. ...
//    For an integer x, the LCTE encoding is defined as
//        LCTE(x) = ([x < r_1], [x < r_2], ..., [x < r_m]),
//    where [·] denotes the Iverson bracket. ...
//    The monotonicity of the resulting vector (i.e., [x < r_i] is
//    non-increasing as i increases) reflects the "cumulative" nature of the
//    encoding. When x < r_1, the entire vector consists of all 1s; when
//    x >= r_m, the entire vector consists of all 0s."
//
// 把 1-based 的 r_i 与 0-based 的列索引 i 对齐，得到本模块的**规范口径**：
//
//     **第 i 列（0-based）的阈值是 r_min + i，i = 0 .. m-1。**
//
// 即 r_1 = r_min、r_m = r_min + m - 1，边界语义为
//   * x <  r_min          ⇒ 全 1
//   * x == r_min          ⇒ 第 0 列为 0，其余为 1
//   * x >= r_min + m - 1  ⇒ 全 0
//
// ⚠️ 修正记录：`shared/database.cpp` 的 `LcteEncode` 此前用 `r_min + i + 1`
// 作为第 i 列阈值，比论文的 R 整体偏移了 1（见 TASK_PLAN.md §9 的下一步第 2 条）。
// 该缺陷已修正，本模块直接复用 `tsb::LcteEncode`，不再自行实现一遍阈值逻辑。
//
// ===========================================================================
// 2. 阈值对齐（决策 Q6）
// ===========================================================================
// 论文 §"Multi-Predicate Filtering Mechanism" 原文：
//
//   "Each threshold must correspond to some column index j in the LCTE range R
//    (i.e., l_i = r_j or r_i = r_j), such that the truth value of the predicate
//    is exactly the corresponding bit of the LCTE encoding vector of that
//    record. If a threshold falls outside R, the system adjusts it to the
//    nearest valid value or aborts via boundary checking."
//
// 本文档据此提供两种模式（Q6 裁决：**默认"调整到最近有效值 + 记录警告"**）：
//
//   * `ThresholdMode::kAlignNearest`（默认）：把越界阈值夹到最近的 R 内元素
//     （因为 R 是单位间隔的连续整数，只要阈值落在 [r_min, r_max] 内就**天然
//     命中** R，所以"调整到最近值"只在越界时发生），并通过警告接收器记录。
//   * `ThresholdMode::kStrict`：阈值不在 R 内直接抛 `std::out_of_range`，
//     上层据此 abort（论文所说的 "aborts via boundary checking"）。
//
// ⚠️ **对齐什么时候是无损的（本实现新增的工程结论，论文未给出）**
// 记某个属性所有记录的取值集合为 X。对 `lt(θ)` 一类谓词，客户端检索的是
// 第 `clamp(θ)` 列，其真值为 `[x < clamp(θ)]`，与真实语义 `[x < θ]` 一致
// 当且仅当阈值被夹过的那一段区间上没有数据：
//   * θ < r_min：夹到 r_min，要求 **X 中没有落在 [θ, r_min) 的值**；
//   * θ > r_max：夹到 r_max，要求 **X 中没有落在 [r_max, θ) 的值**；
//   * θ ∈ R：恒精确。
// 因此**充分条件**是 `X ⊆ [r_min, r_max - 1]`，等价于
//
//     R ⊇ [domain_min, domain_max + 1]
//     ⇔  r_min <= domain_min 且 r_max >= domain_max + 1
//     ⇔  range_size >= (domain_max - domain_min) + 2
//
// 即：**要精确表达闭取值域 [d_min, d_max] 上的全部比较（含右端排他上界
// d_max+1），R 必须比取值域多覆盖一个点。** 该条件由
// `CoversDomainExactly()` 检查、`WarnIfLcteDoesNotCoverDomain()` 在装载期告警。
//
// ===========================================================================
// 3. 分片（决策 D3 / D12）
// ===========================================================================
// LCTE 特征比特最终以 **XOR 共享**上传（论文 §System Model："The feature value
// is encoded using our proposed Left-Threshold Cumulative Encoding (LCTE), and
// each of the two servers holds one of the two secret shares of the encoded
// feature value"；共享方案见 TASK_PLAN 决策 D3）。
// 编码层只产出**明文比特/位打包**，本文件末尾的 `XorShareLcte` 是一个便利
// 辅助（供 MPA-03 使用），它调用 `shared/secret_sharing` 的 XOR 共享原语，
// **不引入任何加法共享**（决策 D12：parity 语义为 ⊕ 的数据必须用 XOR 共享承载）。

#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "core/field.hpp"
#include "shared/database.hpp"
#include "shared/secret_sharing.hpp"

// ⚠️ 命名空间：本模块置于 **`tsb::mpraq`**（而不是 `tsb` 顶层）。
// 原因：`core/config.hpp`（TASK_PLAN §7.7 的 MPRAQ 查询配置）已经在 `tsb` 里
// 定义了 `PredicateOp` / `Predicate` / `ParsePredicateOp` / `ToString(PredicateOp)`
// —— 与 `mpraq/predicate.hpp` 的同名类型结构不同（操作符枚举 KNe vs neq、
// 字段名 range_min/range_max vs lower/upper、属性按名 vs 按 id/名）。
// 若两者都放在 `tsb` 顶层，任何同时包含两个头文件的 TU 都会编译失败，
// 且构成 ODR 违规；而 `core/config.hpp` 不在本任务的允许修改范围内。
// 因此 `src/mpraq/**` 统一使用嵌套命名空间 `tsb::mpraq`。
namespace tsb {
namespace mpraq {

// ---------------------------------------------------------------------------
// 阈值对齐模式与告警（Q6）
// ---------------------------------------------------------------------------

enum class ThresholdMode {
    kAlignNearest,  // 默认：调整到最近有效值 + 记录警告
    kStrict,        // 严格：不在 R 内抛 std::out_of_range（上层可据此 abort）
};

// 阈值对齐告警接收器。
// 默认（未设置时）只累计计数与内部日志、不向任何流输出，便于测试断言。
// 传入空的 std::function 恢复默认行为。
void SetLcteWarningHandler(std::function<void(const std::string&)> handler);

// 累计告警次数（自进程启动起）
size_t LcteWarningCount();

// 取出并清空内部日志中尚未取走的告警文本
std::vector<std::string> TakeLcteWarnings();

// 清空内部日志（不重置计数器）
void ClearLcteWarnings();

// 发出一次告警（供本模块与上层装载期校验复用）
void EmitLcteWarning(const std::string& message);

// ---------------------------------------------------------------------------
// 参数与阈值
// ---------------------------------------------------------------------------

// 校验 LcteParams：range_size > 0，且阈值集合 [range_min, range_min+m-1]
// 落在 int64 内。不合法时抛 std::invalid_argument。
void ValidateLcteParams(const LcteParams& params);

// R 的最小元素 r_1 = range_min
int64_t LcteMinThreshold(const LcteParams& params);

// R 的最大元素 r_m = range_min + range_size - 1
int64_t LcteMaxThreshold(const LcteParams& params);

// 0-based 列索引 column 对应的阈值 = range_min + column；
// column >= range_size 时抛 std::out_of_range。
int64_t LcteThresholdAt(const LcteParams& params, uint32_t column);

// 阈值 θ 是否**恰好**落在 R 内（R 是单位间隔连续整数，等价于
// r_min <= θ <= r_max）。
bool LcteContainsThreshold(const LcteParams& params, int64_t theta);

// 取值 x 是否落在编码范围 [r_min, r_max] 内。
// 落在范围外的取值编码为全 1（x < r_min）或全 0（x > r_max），
// 见 `CoversDomainExactly()` 关于"无损"的讨论。
bool LcteCoversValue(const LcteParams& params, int64_t x);

// 阈值对齐的结果
struct ThresholdAlignment {
    uint32_t column = 0;   // 对齐后应检索的 LCTE 列索引
    int64_t requested = 0; // 客户端原始请求的阈值 θ
    int64_t aligned = 0;   // 对齐后的阈值（= range_min + column）
    bool adjusted = false; // 是否发生了调整（θ ∉ R）
};

// 把请求阈值 θ 对齐到 R。
//   * kAlignNearest：θ ∉ R 时夹到最近的 R 内元素（越界时即端点），
//     并把 adjusted 置为 true 且记录一条告警；
//   * kStrict：θ ∉ R 时抛 std::out_of_range。
ThresholdAlignment AlignLcteThreshold(const LcteParams& params, int64_t theta,
                                      ThresholdMode mode = ThresholdMode::kAlignNearest);

// ---------------------------------------------------------------------------
// 编码
// ---------------------------------------------------------------------------

// 单条记录的 LCTE 编码（明文 0/1 环元素，长度 = range_size）。
// 语义与 `tsb::LcteEncode` 完全一致，额外做参数校验。
std::vector<uint128_t> LcteEncodeRow(int64_t x, const LcteParams& params);

// 单条记录的 LCTE 编码，输出为 uint8_t 比特（便于位打包与 XOR 分片）
std::vector<uint8_t> LcteBits(int64_t x, const LcteParams& params);

// 一批记录 → LCTE 明文表（N 行 × m 列，行优先，元素为 0/1）。
// values.size() 必须等于 params.window_size（window_size == 0 时跳过该校验），
// 否则抛 std::invalid_argument。
PlainTable BuildLcteTable(const std::vector<int64_t>& values, const LcteParams& params);

// 明文表 → 逐列比特（m 个长度 N 的 0/1 向量），列优先视图
std::vector<std::vector<uint8_t>> LcteColumnBits(const PlainTable& table);

// 明文表 → 逐列 128 位打包（m 列 × ⌈N/128⌉ 个 word）。
// 复用 `PackBitsToRing`，与 VMPQ 的按位打包口径一致。
// 第 c 列的第 r 位落在 words[c][r/128] 的第 (r%128) 位上。
std::vector<std::vector<uint128_t>> PackLcteColumns(const PlainTable& table);

// 明文 LCTE 表 → LCTE 打包表（PIR 友好布局）：
//   rows    = ⌈N/128⌉（word 序号）
//   columns = m（LCTE 列序号）
//   entry(w, c) = 第 c 列第 w 个 128 位 word
// 这样 (word, 列) 恰好是 PIR 的一个 entry，而 `ShareTable::ColumnXor(c)`
// 给出第 c 列的 parity（V-OO-PIR / Plinko 的应答语义）。
PlainTable BuildLctePackedTable(const std::vector<int64_t>& values,
                                const LcteParams& params);

// ---------------------------------------------------------------------------
// XOR 分片辅助（决策 D3/D12；供 MPA-03 的 Init 使用）
// ---------------------------------------------------------------------------

// 一批记录经 LCTE 编码、按列 128 位打包、再按 word 做 XOR 分片的结果。
// 两台服务器各持 words0 / words1 之一；重建必须 XOR。
struct XorShardedLcte {
    LcteParams params;
    size_t num_records = 0;       // N
    size_t words_per_column = 0;  // ⌈N/128⌉
    // 列优先扁平布局：words_s[c * words_per_column + w]
    std::vector<uint128_t> words0;
    std::vector<uint128_t> words1;
};

// 编码 + 打包 + XOR 分片。
// 逐 word 用 `shared/secret_sharing` 的 `ShareXorBytes`（XorBit 家族的字节宽度
// 版本）生成掩码，**不使用加法共享**（决策 D12）。
XorShardedLcte XorShareLcte(const std::vector<int64_t>& values,
                            const LcteParams& params);

// 取某台服务器（server = 0 或 1）的分片，整形成 ShareTable：
//   rows = words_per_column，columns = m，entry(w, c) = 该 word 的 XOR 共享
// ⚠️ 表内 RingShare 只是**位容器**，承载的是 XOR 共享；重建必须 XOR，
// 绝不能喂给 `ReconstructRing` / `ReconstructTable`（那是加法共享的重建）。
ShareTable LcteShareTable(const XorShardedLcte& sharded, int server);

// 客户端重建：两台服务器的分片 → 明文 LCTE 比特表（N 行 × m 列，元素 0/1）
PlainTable ReconstructLctePlain(const XorShardedLcte& sharded);

// 由两台服务器的打包共享表重建明文 LCTE 比特表（同上，输入是 ShareTable 形式）。
// num_records 是原始记录数 N（打包容量 ⌈N/128⌉×128 可能大于 N，故必须显式给出）。
PlainTable ReconstructLcteFromShares(const ShareTable& a, const ShareTable& b,
                                     size_t num_records);

// ---------------------------------------------------------------------------
// 取值域覆盖检查（Q6 的"装载期校验"）
// ---------------------------------------------------------------------------

// 属性的 LCTE 参数是否**精确覆盖**其闭取值域：R ⊇ [domain_min, domain_max+1]。
// 满足该条件时，全部左阈值谓词（含对齐到域外阈值的退化情形）都是精确的；
// 详见文件头 §2 的推导。
bool CoversDomainExactly(const LcteParams& params, int64_t domain_min,
                         int64_t domain_max);

// 对一批 (LcteParams, 取值域) 做覆盖检查，不满足者通过 LCTE 告警接收器告警。
// 返回不满足条件的条目数。
size_t WarnIfLcteDoesNotCoverDomain(const LcteParams& params, int64_t domain_min,
                                    int64_t domain_max, const std::string& label);

}  // namespace mpraq
}  // namespace tsb
