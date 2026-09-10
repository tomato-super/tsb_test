#include "mpraq/predicate.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <sstream>

namespace tsb {
namespace mpraq {

namespace {

std::string SupportedOpsText() {
    return "支持的操作符：eq / neq / lt / le / gt / ge / range";
}

std::string AttributeListText(const Schema& schema) {
    std::ostringstream oss;
    for (size_t i = 0; i < schema.attributes().size(); ++i) {
        if (i != 0) oss << ", ";
        oss << schema.attributes()[i].name << "(id="
            << schema.attributes()[i].id << ")";
    }
    return schema.attributes().empty() ? "(空)" : oss.str();
}

// θ + 1 的溢出保护（le/ge/eq/neq 需要"阈值加 1"这一列）
int64_t PlusOne(int64_t theta, const AttributeSchema& attr, const char* what) {
    if (theta == std::numeric_limits<int64_t>::max()) {
        throw std::invalid_argument(
            std::string("谓词解析：") + what + " 的边界 " +
            std::to_string(theta) + "（属性 \"" + attr.name +
            "\"）加 1 会溢出 int64，无法归约到左阈值列");
    }
    return theta + 1;
}

// eq / neq 的取值必须落在闭取值域内
void RequireValueInDomain(const AttributeSchema& attr, int64_t v,
                          const char* what) {
    if (v < attr.domain_min || v > attr.domain_max) {
        throw std::out_of_range(
            std::string("谓词解析：") + what + " 的取值 " + std::to_string(v) +
            " 超出属性 \"" + attr.name + "\" 的取值域 [" +
            std::to_string(attr.domain_min) + ", " +
            std::to_string(attr.domain_max) + "]");
    }
}

// 比较与区间**边界**允许取到 domain_max + 1（半开区间的排他上界）
void RequireBoundInDomain(const AttributeSchema& attr, int64_t theta,
                          const char* what) {
    if (attr.domain_max == std::numeric_limits<int64_t>::max()) {
        // 域上界已是 int64 最大值时不存在合法的 domain_max + 1
        if (theta < attr.domain_min || theta > attr.domain_max) {
            throw std::out_of_range(
                std::string("谓词解析：") + what + " 的边界 " +
                std::to_string(theta) + " 超出属性 \"" + attr.name +
                "\" 的取值域 [" + std::to_string(attr.domain_min) + ", " +
                std::to_string(attr.domain_max) + "]");
        }
        return;
    }
    if (theta < attr.domain_min || theta > attr.domain_max + 1) {
        throw std::out_of_range(
            std::string("谓词解析：") + what + " 的边界 " + std::to_string(theta) +
            " 超出属性 \"" + attr.name + "\" 的允许边界 [" +
            std::to_string(attr.domain_min) + ", " +
            std::to_string(attr.domain_max + 1) +
            "]（上界 = 取值域上界 + 1，用于表达半开区间的排他上界）");
    }
}

// 构造一个字面量：阈值 θ 对齐到 R 后的列 + 取反标记
PredicateLiteral MakeLiteral(const AttributeSchema& attr, int64_t theta,
                             bool negated, ThresholdMode mode) {
    const ThresholdAlignment aligned = AlignLcteThreshold(attr.lcte, theta, mode);
    PredicateLiteral lit;
    lit.ref.attribute_id = attr.id;
    lit.ref.column = aligned.column;
    lit.negated = negated;
    lit.threshold = aligned.aligned;
    lit.requested = theta;
    lit.adjusted = aligned.adjusted;
    return lit;
}

const AttributeSchema& ResolveAttribute(const Predicate& p, const Schema& schema) {
    if (p.by_id) {
        return schema.ById(p.attribute_id);
    }
    if (p.attribute.empty()) {
        throw std::invalid_argument(
            "谓词解析：谓词既未指定属性 id（by_id=false）也未给出属性名，"
            "无法定位属性");
    }
    return schema.ByName(p.attribute);
}

// 解析结果的公共收尾：去重列集合、推断 num_records
void FinalizePlan(PredicatePlan& plan) {
    std::set<LcteColumnRef> unique_refs;
    for (const auto& lit : plan.literals) {
        unique_refs.insert(lit.ref);
    }
    plan.columns.assign(unique_refs.begin(), unique_refs.end());
}

// 把子树里的字面量下标整体平移（合并多个子计划时用）
void ShiftLiteralIndices(BoolExpr& expr, size_t offset) {
    if (expr.kind == BoolExpr::Kind::kLiteral) {
        expr.literal += offset;
        return;
    }
    for (auto& child : expr.children) {
        ShiftLiteralIndices(child, offset);
    }
}

size_t CheckedRecordCount(size_t current, size_t candidate,
                          const char* context) {
    if (candidate == 0) return current;
    if (current == 0) return candidate;
    if (current != candidate) {
        throw std::invalid_argument(
            std::string(context) + "：涉及的属性 window_size 不一致（" +
            std::to_string(current) + " vs " + std::to_string(candidate) +
            "），无法在同一 filter 向量上做布尔组合");
    }
    return current;
}

void AppendConjunctiveLiterals(const BoolExpr& expr,
                               const std::vector<PredicateLiteral>& literals,
                               std::vector<PredicateLiteral>& out) {
    if (expr.kind == BoolExpr::Kind::kLiteral) {
        out.push_back(literals.at(expr.literal));
        return;
    }
    if (expr.kind != BoolExpr::Kind::kAnd) {
        throw std::logic_error(
            "谓词解析：组合计划的根节点不是字面量的合取，无法压平成"
            "\"列 + 取反标记\"的合取列表（例如 neq 的根节点带取反）");
    }
    for (const auto& child : expr.children) {
        AppendConjunctiveLiterals(child, literals, out);
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// 操作符
// ---------------------------------------------------------------------------

const char* PredicateOpName(PredicateOp op) {
    switch (op) {
        case PredicateOp::kEq:
            return "eq";
        case PredicateOp::kNeq:
            return "neq";
        case PredicateOp::kLt:
            return "lt";
        case PredicateOp::kLe:
            return "le";
        case PredicateOp::kGt:
            return "gt";
        case PredicateOp::kGe:
            return "ge";
        case PredicateOp::kRange:
            return "range";
    }
    throw std::invalid_argument("PredicateOpName: 未知的操作符枚举值");
}

PredicateOp ParsePredicateOp(const std::string& name) {
    if (name == "eq") return PredicateOp::kEq;
    if (name == "neq") return PredicateOp::kNeq;
    if (name == "lt") return PredicateOp::kLt;
    if (name == "le") return PredicateOp::kLe;
    if (name == "gt") return PredicateOp::kGt;
    if (name == "ge") return PredicateOp::kGe;
    if (name == "range") return PredicateOp::kRange;
    throw std::invalid_argument("谓词解析：不支持的操作符 \"" + name + "\"。" +
                                SupportedOpsText());
}

bool IsSupportedPredicateOp(const std::string& name) {
    return name == "eq" || name == "neq" || name == "lt" || name == "le" ||
           name == "gt" || name == "ge" || name == "range";
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

void Schema::AddAttribute(const AttributeSchema& attr) {
    if (attr.name.empty()) {
        throw std::invalid_argument("Schema::AddAttribute: 属性名不能为空");
    }
    if (attr.domain_min > attr.domain_max) {
        throw std::invalid_argument(
            "Schema::AddAttribute: 属性 \"" + attr.name +
            "\" 的取值域倒置：[" + std::to_string(attr.domain_min) + ", " +
            std::to_string(attr.domain_max) + "]");
    }
    ValidateLcteParams(attr.lcte);  // 不合法抛 std::invalid_argument
    for (const auto& existing : attributes_) {
        if (existing.id == attr.id) {
            throw std::invalid_argument(
                "Schema::AddAttribute: 属性 id 重复：" + std::to_string(attr.id) +
                "（已有 \"" + existing.name + "\"）");
        }
        if (existing.name == attr.name) {
            throw std::invalid_argument("Schema::AddAttribute: 属性名重复：\"" +
                                        attr.name + "\"");
        }
    }
    attributes_.push_back(attr);
}

bool Schema::HasAttribute(uint32_t id) const {
    return std::any_of(attributes_.begin(), attributes_.end(),
                       [id](const AttributeSchema& a) { return a.id == id; });
}

bool Schema::HasAttribute(const std::string& name) const {
    return std::any_of(attributes_.begin(), attributes_.end(),
                       [&name](const AttributeSchema& a) { return a.name == name; });
}

const AttributeSchema& Schema::ById(uint32_t id) const {
    for (const auto& a : attributes_) {
        if (a.id == id) return a;
    }
    throw std::out_of_range("Schema: 属性 id 不存在：" + std::to_string(id) +
                            "；已有属性：" + AttributeListText(*this));
}

const AttributeSchema& Schema::ByName(const std::string& name) const {
    for (const auto& a : attributes_) {
        if (a.name == name) return a;
    }
    throw std::out_of_range("Schema: 属性名不存在：\"" + name + "\"；已有属性：" +
                            AttributeListText(*this));
}

size_t Schema::WarnOnIncompleteLcteCoverage() const {
    size_t bad = 0;
    for (const auto& a : attributes_) {
        bad += WarnIfLcteDoesNotCoverDomain(a.lcte, a.domain_min, a.domain_max,
                                            a.name);
    }
    return bad;
}

// ---------------------------------------------------------------------------
// BoolExpr 便捷构造
// ---------------------------------------------------------------------------

BoolExpr BoolExpr::Literal(size_t index) {
    BoolExpr e;
    e.kind = Kind::kLiteral;
    e.literal = index;
    return e;
}

BoolExpr BoolExpr::And(std::vector<BoolExpr> children) {
    BoolExpr e;
    e.kind = Kind::kAnd;
    e.children = std::move(children);
    return e;
}

BoolExpr BoolExpr::Or(std::vector<BoolExpr> children) {
    BoolExpr e;
    e.kind = Kind::kOr;
    e.children = std::move(children);
    return e;
}

BoolExpr BoolExpr::Not(BoolExpr child) {
    BoolExpr e;
    e.kind = Kind::kNot;
    e.children.push_back(std::move(child));
    return e;
}

// ---------------------------------------------------------------------------
// PredicatePlan 辅助
// ---------------------------------------------------------------------------

namespace {

// 表达式树是否为"字面量的合取"（允许 And 嵌套：合取的合取仍是合取）
bool IsConjunctiveExpr(const BoolExpr& expr) {
    if (expr.kind == BoolExpr::Kind::kLiteral) return true;
    if (expr.kind != BoolExpr::Kind::kAnd) return false;
    for (const auto& child : expr.children) {
        if (!IsConjunctiveExpr(child)) return false;
    }
    return true;
}

}  // namespace

bool PredicatePlan::IsConjunction() const { return IsConjunctiveExpr(root); }

std::vector<PredicateLiteral> PredicatePlan::ConjunctiveLiterals() const {
    if (!IsConjunction()) {
        throw std::logic_error(
            "PredicatePlan::ConjunctiveLiterals: 组合计划不是字面量的合取"
            "（例如 neq 的根节点带取反），无法压平成合取列表；"
            "请直接对 root 求值");
    }
    std::vector<PredicateLiteral> out;
    AppendConjunctiveLiterals(root, literals, out);
    return out;
}

// ---------------------------------------------------------------------------
// 解析：单个谓词
// ---------------------------------------------------------------------------

PredicatePlan ParsePredicate(const Predicate& predicate, const Schema& schema,
                             ThresholdMode mode) {
    const AttributeSchema& attr = ResolveAttribute(predicate, schema);

    PredicatePlan plan;
    plan.num_records = attr.lcte.window_size;

    switch (predicate.op) {
        case PredicateOp::kLt: {
            // lt(θ) = [x < θ] → 直接取阈值为 θ 的列
            RequireBoundInDomain(attr, predicate.value, "lt");
            plan.literals.push_back(
                MakeLiteral(attr, predicate.value, false, mode));
            plan.root = BoolExpr::Literal(0);
            break;
        }
        case PredicateOp::kLe: {
            // le(θ) = [x <= θ] = [x < θ+1]
            RequireBoundInDomain(attr, predicate.value, "le");
            const int64_t theta =
                PlusOne(predicate.value, attr, "le");
            plan.literals.push_back(MakeLiteral(attr, theta, false, mode));
            plan.root = BoolExpr::Literal(0);
            break;
        }
        case PredicateOp::kGt: {
            // ⚠️ gt / ge 是**最容易写反**的一对：两者都只是"某一列的取反"，
            // 区别在被取反的列差一格：
            //     gt(θ) = [x >  θ] = [x >= θ+1] = ¬[x < θ+1] ⇒ 取**阈值 θ+1** 的列取反
            //     ge(θ) = [x >= θ]               = ¬[x < θ]   ⇒ 取**阈值 θ**   的列取反
            // 写反的后果是边界值 x == θ 的判定整体错位一格（静默地算错）。
            // 该错误已由 MpraqPredicate.FilterEvaluationMatchesBruteForce 等
            // 对照暴力语义的用例抓出。
            RequireBoundInDomain(attr, predicate.value, "gt");
            const int64_t theta = PlusOne(predicate.value, attr, "gt");
            plan.literals.push_back(MakeLiteral(attr, theta, true, mode));
            plan.root = BoolExpr::Literal(0);
            break;
        }
        case PredicateOp::kGe: {
            // ge(θ) = [x >= θ] = ¬[x < θ]（见上：与 gt 的列相差一格）
            RequireBoundInDomain(attr, predicate.value, "ge");
            plan.literals.push_back(
                MakeLiteral(attr, predicate.value, true, mode));
            plan.root = BoolExpr::Literal(0);
            break;
        }
        case PredicateOp::kEq: {
            // eq(v) = [v, v+1) = ¬[x < v] ∧ [x < v+1]（论文的点查询口径）
            RequireValueInDomain(attr, predicate.value, "eq");
            const int64_t upper = PlusOne(predicate.value, attr, "eq");
            plan.literals.push_back(
                MakeLiteral(attr, predicate.value, true, mode));   // ¬[x < v]
            plan.literals.push_back(MakeLiteral(attr, upper, false, mode));  // [x < v+1]
            plan.root = BoolExpr::And({BoolExpr::Literal(0), BoolExpr::Literal(1)});
            break;
        }
        case PredicateOp::kNeq: {
            // neq(v) = ¬eq(v) = ¬( ¬[x < v] ∧ [x < v+1] )
            //         ≡ [x < v] ∨ ¬[x < v+1] ≡ [x < v] ∨ [x >= v+1]
            // 与 eq 取同样的两列，只是根节点多一次取反；
            // 它不是合取形式，IsConjunction() == false。
            RequireValueInDomain(attr, predicate.value, "neq");
            const int64_t upper = PlusOne(predicate.value, attr, "neq");
            plan.literals.push_back(MakeLiteral(attr, predicate.value, true, mode));
            plan.literals.push_back(MakeLiteral(attr, upper, false, mode));
            plan.root = BoolExpr::Not(
                BoolExpr::And({BoolExpr::Literal(0), BoolExpr::Literal(1)}));
            break;
        }
        case PredicateOp::kRange: {
            // range[a, b) = ¬[x < a] ∧ [x < b]
            if (predicate.upper <= predicate.lower) {
                throw std::invalid_argument(
                    "谓词解析：range 范围倒置或为空：[" +
                    std::to_string(predicate.lower) + ", " +
                    std::to_string(predicate.upper) +
                    ")；要求 上界 > 下界（区间为半开 [a, b)）");
            }
            RequireBoundInDomain(attr, predicate.lower, "range 下界 a");
            RequireBoundInDomain(attr, predicate.upper, "range 上界 b");
            plan.literals.push_back(
                MakeLiteral(attr, predicate.lower, true, mode));   // ¬[x < a]
            plan.literals.push_back(
                MakeLiteral(attr, predicate.upper, false, mode));  // [x < b]
            plan.root = BoolExpr::And({BoolExpr::Literal(0), BoolExpr::Literal(1)});
            break;
        }
    }

    FinalizePlan(plan);
    return plan;
}

// ---------------------------------------------------------------------------
// 解析：合取
// ---------------------------------------------------------------------------

PredicatePlan ParseConjunction(const std::vector<Predicate>& predicates,
                               const Schema& schema, ThresholdMode mode) {
    PredicatePlan merged;
    // 空合取 ≡ 恒真（没有任何过滤条件 ⇒ 全部记录入选），这里显式记录该约定
    merged.root = BoolExpr::And({});

    for (const auto& p : predicates) {
        const PredicatePlan sub = ParsePredicate(p, schema, mode);
        const size_t offset = merged.literals.size();
        merged.literals.insert(merged.literals.end(), sub.literals.begin(),
                               sub.literals.end());
        BoolExpr child = sub.root;
        ShiftLiteralIndices(child, offset);
        merged.root.children.push_back(std::move(child));
        merged.num_records =
            CheckedRecordCount(merged.num_records, sub.num_records, "ParseConjunction");
    }

    FinalizePlan(merged);
    return merged;
}

PredicatePlan ParseRangeConjunctionDeMorgan(
    const std::vector<Predicate>& ranges, const Schema& schema,
    ThresholdMode mode) {
    PredicatePlan plan;

    std::vector<BoolExpr> left_literals;   // ¬P_{i0}(l_i)
    std::vector<BoolExpr> right_literals;  //  P_{i1}(r_i)

    for (const auto& p : ranges) {
        if (p.op != PredicateOp::kRange) {
            throw std::invalid_argument(
                std::string("ParseRangeConjunctionDeMorgan: De Morgan 优化形式只"
                            "接受 range 谓词，实际收到 ") +
                PredicateOpName(p.op));
        }
        if (p.upper <= p.lower) {
            throw std::invalid_argument(
                "ParseRangeConjunctionDeMorgan: range 范围倒置或为空：[" +
                std::to_string(p.lower) + ", " + std::to_string(p.upper) +
                ")；要求 上界 > 下界");
        }
        const AttributeSchema& attr = ResolveAttribute(p, schema);
        RequireBoundInDomain(attr, p.lower, "range 下界 a");
        RequireBoundInDomain(attr, p.upper, "range 上界 b");

        // ⚠️ 这里刻意把两个字面量都建成**正**字面量（P = [x < r] 原样），
        // 取反只由树里的那一次 Not(Or(...)) 承担。若此处先取反、树里再加 Not，
        // 就是双重取反（¬(¬P_l1 ∨ ¬P_l2) = P_l1 ∧ P_l2 = x < l_1 ∧ x < l_2），
        // 语义完全错误 —— 该错误已由本模块的 De Morgan 用例抓出并固化。
        const size_t left_index = plan.literals.size();
        plan.literals.push_back(MakeLiteral(attr, p.lower, false, mode));
        const size_t right_index = plan.literals.size();
        plan.literals.push_back(MakeLiteral(attr, p.upper, false, mode));

        left_literals.push_back(BoolExpr::Literal(left_index));
        right_literals.push_back(BoolExpr::Literal(right_index));

        plan.num_records = CheckedRecordCount(
            plan.num_records, attr.lcte.window_size, "ParseRangeConjunctionDeMorgan");
    }

    // Φ = ¬( ∨_i P_{i0}(l_i) ) ∧ ( ∧_i P_{i1}(r_i) )
    // 树形与论文公式逐字对应：左边界先合并成一次 OR、再整体取反一次
    // （论文所说的 "consolidates the detection of multiple left-boundary
    // conditions into a single unified check"），右边界是若干 AND。
    // 语义上 ¬(∨ P_i0) ≡ ∧ ¬P_i0，因此与逐条合取的扁平形式等价。
    plan.root = BoolExpr::And({BoolExpr::Not(BoolExpr::Or(left_literals)),
                               BoolExpr::And(right_literals)});

    FinalizePlan(plan);
    return plan;
}

// ---------------------------------------------------------------------------
// 本地求值
// ---------------------------------------------------------------------------

std::vector<uint8_t> EvaluateBoolExpr(
    const BoolExpr& expr, const std::vector<std::vector<uint8_t>>& literal_values,
    size_t num_records) {
    switch (expr.kind) {
        case BoolExpr::Kind::kLiteral: {
            if (expr.literal >= literal_values.size()) {
                throw std::invalid_argument(
                    "EvaluateBoolExpr: 字面量下标越界：" +
                    std::to_string(expr.literal) + " >= " +
                    std::to_string(literal_values.size()));
            }
            const auto& v = literal_values[expr.literal];
            if (v.size() != num_records) {
                throw std::invalid_argument(
                    "EvaluateBoolExpr: 字面量 " + std::to_string(expr.literal) +
                    " 的比特数 " + std::to_string(v.size()) +
                    " 与记录数 " + std::to_string(num_records) + " 不符");
            }
            return v;
        }
        case BoolExpr::Kind::kNot: {
            if (expr.children.size() != 1) {
                throw std::invalid_argument("EvaluateBoolExpr: kNot 必须恰好一个子节点");
            }
            const auto inner =
                EvaluateBoolExpr(expr.children[0], literal_values, num_records);
            std::vector<uint8_t> out(num_records, 0);
            for (size_t i = 0; i < num_records; ++i) {
                out[i] = static_cast<uint8_t>(inner[i] == 0 ? 1 : 0);
            }
            return out;
        }
        case BoolExpr::Kind::kAnd: {
            // 空合取 ≡ 恒真（与 ParseConjunction 对空谓词列表的约定一致）
            std::vector<uint8_t> out(num_records, 1);
            for (const auto& child : expr.children) {
                const auto v = EvaluateBoolExpr(child, literal_values, num_records);
                for (size_t i = 0; i < num_records; ++i) {
                    out[i] = static_cast<uint8_t>(out[i] & v[i]);
                }
            }
            return out;
        }
        case BoolExpr::Kind::kOr: {
            // 空析取 ≡ 恒假
            std::vector<uint8_t> out(num_records, 0);
            for (const auto& child : expr.children) {
                const auto v = EvaluateBoolExpr(child, literal_values, num_records);
                for (size_t i = 0; i < num_records; ++i) {
                    out[i] = static_cast<uint8_t>(out[i] | v[i]);
                }
            }
            return out;
        }
    }
    throw std::invalid_argument("EvaluateBoolExpr: 未知的表达式节点类型");
}

namespace {

// 把"列 → 明文比特"解析成"字面量 → 取值比特"（含取反），并确定 N
std::vector<uint8_t> EvaluateWithResolvedColumns(
    const PredicatePlan& plan,
    const std::map<LcteColumnRef, std::vector<uint8_t>>& column_bits) {
    size_t n = plan.num_records;
    for (const auto& [ref, bits] : column_bits) {
        (void)ref;
        if (n == 0) n = bits.size();
        if (bits.size() != n) {
            throw std::invalid_argument(
                "EvaluateFilter: 各列的比特数不一致（" +
                std::to_string(bits.size()) + " vs " + std::to_string(n) + "）");
        }
    }
    if (plan.num_records != 0 && n != plan.num_records) {
        throw std::invalid_argument(
            "EvaluateFilter: 列的比特数 " + std::to_string(n) +
            " 与计划的记录数 " + std::to_string(plan.num_records) + " 不符");
    }

    std::vector<std::vector<uint8_t>> literal_values(plan.literals.size());
    for (size_t i = 0; i < plan.literals.size(); ++i) {
        const PredicateLiteral& lit = plan.literals[i];
        const auto it = column_bits.find(lit.ref);
        if (it == column_bits.end()) {
            throw std::invalid_argument(
                "EvaluateFilter: 缺少字面量所需的列（attribute_id=" +
                std::to_string(lit.ref.attribute_id) +
                ", column=" + std::to_string(lit.ref.column) + "）");
        }
        const auto& bits = it->second;
        if (!lit.negated) {
            literal_values[i] = bits;
        } else {
            literal_values[i].assign(n, 0);
            for (size_t r = 0; r < n; ++r) {
                literal_values[i][r] = static_cast<uint8_t>(bits[r] == 0 ? 1 : 0);
            }
        }
    }
    return EvaluateBoolExpr(plan.root, literal_values, n);
}

}  // namespace

std::vector<uint8_t> EvaluateFilter(const PredicatePlan& plan,
                                    const LcteColumnLookup& lookup) {
    if (!lookup) {
        throw std::invalid_argument("EvaluateFilter: lookup 为空");
    }
    // 同一列只取一次（Q5：所有谓词列一次性取回，客户端本地做组合）
    std::map<LcteColumnRef, std::vector<uint8_t>> cache;
    for (const auto& lit : plan.literals) {
        if (cache.find(lit.ref) != cache.end()) continue;
        cache.emplace(lit.ref, lookup(lit.ref));
    }
    return EvaluateWithResolvedColumns(plan, cache);
}

std::vector<uint8_t> EvaluateFilterWithColumns(
    const PredicatePlan& plan,
    const std::vector<std::vector<uint8_t>>& columns) {
    if (columns.size() != plan.columns.size()) {
        throw std::invalid_argument(
            "EvaluateFilterWithColumns: 列数不符：给出 " +
            std::to_string(columns.size()) + " 列，计划需要 " +
            std::to_string(plan.columns.size()) + " 列");
    }
    std::map<LcteColumnRef, std::vector<uint8_t>> map;
    for (size_t i = 0; i < plan.columns.size(); ++i) {
        map.emplace(plan.columns[i], columns[i]);
    }
    return EvaluateWithResolvedColumns(plan, map);
}

}  // namespace mpraq
}  // namespace tsb
