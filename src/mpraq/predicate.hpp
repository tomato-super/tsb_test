#pragma once

// MPRAQ 的谓词解析层（任务 MPA-02）。
//
// ===========================================================================
// 1. 论文口径（`doc/paper/MPARQ.tex`）
// ===========================================================================
// §"Preliminaries / symbols" 原文：
//
//   "In this work, we instantiate each predicate as a left-threshold
//    comparison:  P_i(x) = 1 if x < θ_i, 0 otherwise,
//    where θ_i is the predefined threshold associated with P_i. ...
//    a range query t_a <= t < t_b can be expressed as ¬P_a(t) ∧ P_b(t),
//    where P_a and P_b are left-threshold predicates with thresholds t_a and
//    t_b, respectively."
//
// §"Multi-Predicate Filtering Mechanism" 原文：
//
//   "in a discrete numerical encoding system, a point query is essentially a
//    special case of a range query. For example, a point query x = v can be
//    expressed as the range query [v, v+1), provided that both v and v+1 fall
//    within the LCTE range R."
//
//   "For a set of n range conditions [l_i, r_i) with i = 1..n, the
//    multi-predicate filter condition is defined as
//        Φ = ∧_{i=1..n} ( ¬P_{i0}(l_i) ∧ P_{i1}(r_i) ).
//    By applying De Morgan's law, the above expression can be equivalently
//    transformed into the following optimized form:
//        Φ = ¬( ∨_{i=1..n} P_{i0}(l_i) ) ∧ ( ∧_{i=1..n} P_{i1}(r_i) ).
//    This optimized form consolidates the detection of multiple left-boundary
//    conditions into a single unified check, enabling more efficient
//    implementation."
//
//   "The client only needs to retrieve the column vectors corresponding to the
//    specified column indices from the feature table, perform Boolean
//    operations locally, and obtain the final filter vector."
//
// ===========================================================================
// 2. 操作符 → LCTE 列 的归约（Q7）
// ===========================================================================
// 记属性 a 的 LCTE 参数为 (r_min, m)，第 j 列（0-based）的阈值为 r_min + j，
// 第 j 列取值为比特 P_j(x) = [x < r_min + j]。**全部操作符都只归约到左阈值列**
// （外加"取反"，取反在客户端本地做，不需要额外的列）：
//
//   客户端写法         语义                 归约（θ 为对齐后的阈值）
//   -----------------  -------------------  ---------------------------------
//   lt(θ)              x <  θ               P_col(θ)                        （直接取列）
//   le(θ)              x <= θ               P_col(θ+1)                      ([x<θ+1] ⟺ x<=θ)
//   gt(θ)              x >  θ               ¬P_col(θ+1)                     (x>θ ⟺ x>=θ+1 ⟺ ¬[x<θ+1])
//   ge(θ)              x >= θ               ¬P_col(θ)                       (x>=θ ⟺ ¬[x<θ])
//   eq(v)              x == v               ¬P_col(v) ∧ P_col(v+1)          (论文的 [v, v+1))
//   range[a, b)        a <= x < b           ¬P_col(a) ∧ P_col(b)
//   neq(v)             x != v               ¬( ¬P_col(v) ∧ P_col(v+1) )     (= ¬eq(v))
//                                          ≡  P_col(v) ∨ ¬P_col(v+1)
//
// ⚠️ **gt 与 ge 极易写反**：两者都只是"某一列的取反"，被取反的列只差一格
//    （gt 用 θ+1 的列、ge 用 θ 的列）。写反的后果是边界值 `x == θ` 的判定
//    整体错位一格，且静默算错。本层的对照暴力语义用例
//    （`MpraqPredicate.FilterEvaluationMatchesBruteForceAllOperators`）专门固化这一点。
//    推导：`x > θ ⟺ x >= θ+1`（整数域），对偶见 `le(θ) = [x < θ+1]`。
//
// `neq` 的说明：它**不是**合取形式（根节点带一个取反），因此
// `PredicatePlan::IsConjunction()` 会返回 false、`ConjunctiveLiterals()` 会
// 抛 std::logic_error。MVP 的合取口径（Q8：只做 AND）覆盖
// eq/lt/le/gt/ge/range；`neq` 作为"布尔组合计划"完全可表达（本地求值正确），
// 只是不能压平成"纯合取的字面量列表"。
//
// ===========================================================================
// 3. 组合与执行位置（Q5 / Q8）
// ===========================================================================
// * Q5 已裁决：**客户端一次性把所有谓词涉及的列全部取回，在本地做布尔组合**，
//   服务器不参与谓词组合（论文同口径：见上文最后一段引文）。
//   `PredicatePlan::columns` 就是"一次取回"所需列的去重集合。
// * Q8：**MVP 只做合取 AND**（多个谓词 ⇒ 各自子计划的合取）。
//   `∨` / `¬` 通过 `BoolExpr` 的 kOr / kNot 预留；本层已用它们表达
//   （a）`neq`  = Not(And(...))；（b）论文的 De Morgan 优化形式
//   `And(Not(Or(l-原子...)), And(r-原子...))`。
//   一般公式的 `∨`/`¬` 归约成 CNF 不在 MVP 范围内：遇到无法直接支持的形式
//   抛 std::invalid_argument，不静默降级。
//
// ===========================================================================
// 4. 取值域校验（本实现新增，论文未规定）
// ===========================================================================
// 每个属性声明闭取值域 [domain_min, domain_max]：
//   * `eq` / `neq` 的 v 必须落在 [domain_min, domain_max] 内 —— 这两个操作符
//     判断"取值恰好等于 v"，域外取值不可能出现，视为调用方错误；
//   * `lt` / `le` / `gt` / `ge` 的 θ 与 `range` 的 a、b 是**边界**：半开区间的
//     排他上界天然等于 domain_max + 1（表示"取到最大值"），所以允许落在
//     [domain_min, domain_max + 1] 内；
//   * `range` 还要求 a < b（b <= a 视为范围倒置，抛 std::invalid_argument）。
// 越界一律抛 `std::out_of_range`（属性不存在同样抛 std::out_of_range）。
//
// 注意"取值域"与"LCTE 范围 R"是两个不同的概念：
//   * 取值域越界 ⇒ **报错**（调用方写错了查询）；
//   * 阈值不在 R 内 ⇒ 按 `ThresholdMode` 处理（Q6：默认夹到最近有效值 + 告警，
//     严格模式抛异常），见 `mpraq/lcte.hpp`。

#include <cstddef>
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

#include "mpraq/lcte.hpp"
#include "shared/database.hpp"

// ⚠️ 命名空间：与 `mpraq/lcte.hpp` 一致，置于 **`tsb::mpraq`**。
// `core/config.hpp`（TASK_PLAN §7.7）已在 `tsb` 顶层定义了同名的
// `PredicateOp` / `Predicate` / `ParsePredicateOp`（枚举值 kNe、字段
// range_min/range_max、属性仅按名引用），与本模块的解析类型不兼容；
// 放在同一命名空间会重定义冲突 + ODR 违规，而该头文件不在本任务允许修改
// 的范围内。详见 `mpraq/lcte.hpp` 顶部的说明。
namespace tsb {
namespace mpraq {

// ---------------------------------------------------------------------------
// 操作符
// ---------------------------------------------------------------------------

enum class PredicateOp {
    kEq,
    kNeq,
    kLt,
    kLe,
    kGt,
    kGe,
    kRange,
};

// 规范名（"eq" / "neq" / "lt" / "le" / "gt" / "ge" / "range"）
const char* PredicateOpName(PredicateOp op);

// 解析操作符名。**不支持的操作符抛 std::invalid_argument**（消息里列出支持集合）。
PredicateOp ParsePredicateOp(const std::string& name);

// 该操作符是否支持（用于上层配置校验，避免用异常做流程控制）
bool IsSupportedPredicateOp(const std::string& name);

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

// 一个属性的描述：名字、id、LCTE 参数、闭取值域
struct AttributeSchema {
    std::string name;
    uint32_t id = 0;
    LcteParams lcte;         // R = [range_min, range_min + range_size - 1]
    int64_t domain_min = 0;  // 闭取值域下界
    int64_t domain_max = 0;  // 闭取值域上界
};

// 属性集合。按 id 或按名字查找；两条路径都要求属性存在。
class Schema {
public:
    // 追加属性。校验：名字非空、名字与 id 不重复、domain_min <= domain_max、
    // LcteParams 合法。不合法抛 std::invalid_argument。
    void AddAttribute(const AttributeSchema& attr);

    bool HasAttribute(uint32_t id) const;
    bool HasAttribute(const std::string& name) const;

    // 属性不存在 ⇒ std::out_of_range（消息里给出实际 id/名字与已有属性）
    const AttributeSchema& ById(uint32_t id) const;
    const AttributeSchema& ByName(const std::string& name) const;

    size_t num_attributes() const { return attributes_.size(); }
    const std::vector<AttributeSchema>& attributes() const { return attributes_; }

    // 装载期校验：对每个属性做 LCTE 覆盖检查（Q6），不满足者发 LCTE 告警。
    // 返回不满足的属性数。
    size_t WarnOnIncompleteLcteCoverage() const;

private:
    std::vector<AttributeSchema> attributes_;
};

// ---------------------------------------------------------------------------
// 谓词与解析结果
// ---------------------------------------------------------------------------

// 客户端提交的一个谓词。
// 属性引用二选一：by_id == true 时用 attribute_id，否则用 attribute（名字）。
struct Predicate {
    bool by_id = false;
    uint32_t attribute_id = 0;
    std::string attribute;

    PredicateOp op = PredicateOp::kEq;
    int64_t value = 0;  // eq / neq / lt / le / gt / ge 的 v 或 θ
    int64_t lower = 0;  // range 的下界 a（含）
    int64_t upper = 0;  // range 的上界 b（不含）
};

// 客户端最终要检索的一列（属性 + 列索引）
struct LcteColumnRef {
    uint32_t attribute_id = 0;
    uint32_t column = 0;

    bool operator==(const LcteColumnRef& o) const {
        return attribute_id == o.attribute_id && column == o.column;
    }
    bool operator!=(const LcteColumnRef& o) const { return !(*this == o); }
    bool operator<(const LcteColumnRef& o) const {
        return attribute_id != o.attribute_id ? attribute_id < o.attribute_id
                                             : column < o.column;
    }
};

// 一个"字面量"：LCTE 列 + 取反标记。
// filter 上的语义：negated == false ⇒ [x < r_column]；
//                   negated == true  ⇒ ¬[x < r_column]（即 x >= r_column）。
struct PredicateLiteral {
    LcteColumnRef ref;
    bool negated = false;
    int64_t threshold = 0;  // 对齐后的阈值（= 该属性 range_min + column）
    int64_t requested = 0;  // 客户端原始请求的阈值
    bool adjusted = false;  // 是否发生过阈值对齐（Q6）
};

// 客户端本地布尔组合计划（Q5：服务器不参与谓词组合）
struct BoolExpr {
    enum class Kind { kLiteral, kAnd, kOr, kNot };

    Kind kind = Kind::kLiteral;
    size_t literal = 0;             // 仅 kLiteral：下标指向 PredicatePlan::literals
    std::vector<BoolExpr> children; // kAnd / kOr（任意个）与 kNot（恰好一个）

    // 便捷构造
    static BoolExpr Literal(size_t index);
    static BoolExpr And(std::vector<BoolExpr> children);
    static BoolExpr Or(std::vector<BoolExpr> children);
    static BoolExpr Not(BoolExpr child);
};

// 谓词解析结果
struct PredicatePlan {
    // 出现过的全部字面量（按解析顺序，可能含重复的 (列, 取反) 组合）
    std::vector<PredicateLiteral> literals;

    // 需要检索的 (属性, 列) 去重集合，按 (attribute_id, column) 升序排列，
    // 顺序确定 ⇒ 便于批量 PIR 与测试断言（Q5：一次性取回全部列）
    std::vector<LcteColumnRef> columns;

    // 客户端本地组合计划（根节点通常为 kAnd）
    BoolExpr root;

    // 期望的记录数 N（来自所涉属性的 window_size；不一致时解析直接报错）
    size_t n = 0;   // 记录数（= 论文的 n；谓词求值需要知道列长）

    // root 是否为"字面量的合取"（可压平成"列 + 取反标记"的合取列表）
    bool IsConjunction() const;

    // 把 root 压平成字面量列表。仅当 IsConjunction() 为真时可用，
    // 否则抛 std::logic_error（例如 neq 的根节点带取反）。
    std::vector<PredicateLiteral> ConjunctiveLiterals() const;
};

// ---------------------------------------------------------------------------
// 解析入口
// ---------------------------------------------------------------------------

// 解析单个谓词（Q7 的全部操作符）。
// 失败情形一律抛异常：
//   * 属性 id/名字不存在、取值超出取值域 ⇒ std::out_of_range
//   * 操作符不支持（含 range 之外的多值操作符误用）、范围倒置（b <= a）、
//     边界 +1 溢出 int64、属性窗口大小不一致 ⇒ std::invalid_argument
//   * 严格模式下阈值不在 R 内、R 参数非法 ⇒ std::out_of_range / std::invalid_argument
PredicatePlan ParsePredicate(const Predicate& predicate, const Schema& schema,
                             ThresholdMode mode = ThresholdMode::kAlignNearest);

// 解析多个谓词的**合取**（Q8：MVP 只做 AND）。
// 各子计划的字面量按顺序拼接，columns 去重合并，root = And(各子 root)。
PredicatePlan ParseConjunction(const std::vector<Predicate>& predicates,
                               const Schema& schema,
                               ThresholdMode mode = ThresholdMode::kAlignNearest);

// 解析论文的 De Morgan 优化形式（每个谓词必须是 op == kRange）：
//   Φ = ¬( ∨ P_{i0}(l_i) ) ∧ ( ∧ P_{i1}(r_i) )
// 语义与 `ParseConjunction` 的合取完全相同（De Morgan 等价），差别只在
// **本地组合计划的形状**：左边界被合并成"一次 OR + 一次 NOT"，
// 右边界是若干 AND —— 这正是论文所说的 "consolidates the detection of
// multiple left-boundary conditions into a single unified check"。
// 谓词中出现非 kRange 的操作符 ⇒ std::invalid_argument。
PredicatePlan ParseRangeConjunctionDeMorgan(
    const std::vector<Predicate>& ranges, const Schema& schema,
    ThresholdMode mode = ThresholdMode::kAlignNearest);

// ---------------------------------------------------------------------------
// 本地求值（Q5：全部在客户端做）
// ---------------------------------------------------------------------------

// 按 (属性, 列) 取回该列的**明文比特**（长度必须等于 plan.n）。
using LcteColumnLookup =
    std::function<std::vector<uint8_t>(const LcteColumnRef& ref)>;

// 求值：返回长度 N 的 filter 向量（1 = 记录满足 Φ）。
// 同一列只会调用 lookup 一次（结果内部缓存），对应"一次性取回所有列"。
std::vector<uint8_t> EvaluateFilter(const PredicatePlan& plan,
                                    const LcteColumnLookup& lookup);

// 同上，但直接给出与 `plan.columns` 一一对应的列比特
std::vector<uint8_t> EvaluateFilterWithColumns(
    const PredicatePlan& plan,
    const std::vector<std::vector<uint8_t>>& columns);

// 对表达式树求值（literal 的比特值已算好：lit 下标 → 长度 N 的 0/1 向量）。
// 供测试直接比对"合取形式"与"De Morgan 形式"的等价性。
std::vector<uint8_t> EvaluateBoolExpr(
    const BoolExpr& expr, const std::vector<std::vector<uint8_t>>& literal_values,
    size_t n);

}  // namespace mpraq
}  // namespace tsb
