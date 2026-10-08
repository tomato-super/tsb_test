// MPRAQ 规模配置层的实现（口径/公式/约束全部写在 `scale_config.hpp` 的文件头）。
//
// 实现要点（为什么这么写）：
//   * JSON 一律走仓库既有的 `core/config.hpp`（`JsonConfig` / `JsonValue`），
//     **不引入新依赖**；`ConfigError` 在本层统一转成 `std::invalid_argument`
//     （任务书要求"非法配置抛 std::invalid_argument"）。
//   * `JsonValue` 没有"枚举键名"的 API（且 `core/config.hpp` 在本任务里是只读的），
//     因此未知字段用 `JsonValue::Dump()`（nlohmann 的规范化紧凑 JSON）+ 一个**只认顶层键名**
//     的小扫描器来定位（`TopLevelKeysFromDump`）。它只影响**报错信息**：真正的取值仍全部
//     经 `JsonValue` 的类型化接口，所以即使扫描器失效也只会让报错少一个键名，不会改变语义。
//   * 几何**只**由 `DerivePaddedGeometry` 派生（含 D35 的 ×2 升级），本层不重写一套判据；
//     几何无解时原样转述它的诊断信息（那是唯一权威的"为什么无解"）。
//   * 谓词生成刻意只用**单列**操作符（lt / le / gt / ge）：
//     它们的归约（`predicate.hpp` §2）各自只落在一列上 —— 记 range_min = 0 时列号：
//         lt(θ) → 列 θ、le(θ) → 列 θ+1、gt(θ) → 列 θ+1（取反）、ge(θ) → 列 θ（取反）
//     ⇒ "k 个谓词 ⇒ 去重列数 = min(k, M)" 这条换算才**精确**成立
//     （eq/neq/range 会各占两列，那就不是 min(k, M) 了）。

#include "mpraq/scale_config.hpp"

#include "core/config.hpp"
#include "core/random.hpp"
#include "mpraq/secure_mul_flow.hpp"  // MakeAesSeed

#include <algorithm>
#include <cstddef>
#include <limits>
#include <set>
#include <sstream>
#include <utility>

namespace tsb {
namespace mpraq {

namespace {

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

uint64_t NextPow2Local(uint64_t v) {
    uint64_t p = 1;
    while (p < v && p < (static_cast<uint64_t>(1) << 62)) p <<= 1;
    return p;
}

[[noreturn]] void BadConfig(const std::string& msg) {
    throw std::invalid_argument("规模配置错误: " + msg);
}

const char* const kKnownFields[] = {"rows",       "columns_per_attribute", "attributes",
                                    "predicates", "lambda",                "eps",
                                    "seed",       "security_mode"};

bool IsKnownField(const std::string& k) {
    for (const char* f : kKnownFields) {
        if (k == f) return true;
    }
    return false;
}

std::string KnownFieldList() {
    std::string s;
    for (const char* f : kKnownFields) {
        if (!s.empty()) s += ", ";
        s += f;
    }
    return s;
}

std::string JsonNumber(double v) {
    std::ostringstream oss;
    oss.precision(17);
    oss << v;
    return oss.str();
}

// ---------------------------------------------------------------------------
// 顶层键名扫描（只用于"未知字段"的可读报错；见文件头说明）
// ---------------------------------------------------------------------------

std::vector<std::string> TopLevelKeysFromDump(const std::string& dump) {
    std::vector<std::string> keys;
    size_t i = 0;
    const auto skip_ws = [&]() {
        while (i < dump.size() &&
               (dump[i] == ' ' || dump[i] == '\n' || dump[i] == '\t' || dump[i] == '\r')) {
            ++i;
        }
    };
    // 读一个 JSON 字符串字面量（i 指向开引号），内容写入 out，i 停在闭引号之后
    const auto read_string = [&](std::string* out) -> bool {
        if (i >= dump.size() || dump[i] != '"') return false;
        ++i;
        out->clear();
        while (i < dump.size()) {
            const char c = dump[i];
            if (c == '\\') {
                if (i + 1 >= dump.size()) return false;
                const char e = dump[i + 1];
                switch (e) {
                    case '"': out->push_back('"'); break;
                    case '\\': out->push_back('\\'); break;
                    case '/': out->push_back('/'); break;
                    case 'b': out->push_back('\b'); break;
                    case 'f': out->push_back('\f'); break;
                    case 'n': out->push_back('\n'); break;
                    case 'r': out->push_back('\r'); break;
                    case 't': out->push_back('\t'); break;
                    case 'u':
                        // 键名里的 \uXXXX 极少见：原样保留转义文本（只为报错可读）
                        if (i + 5 >= dump.size()) return false;
                        out->append(dump, i, 6);
                        i += 6;
                        continue;
                    default: return false;
                }
                i += 2;
                continue;
            }
            if (c == '"') {
                ++i;
                return true;
            }
            out->push_back(c);
            ++i;
        }
        return false;
    };
    // 跳过一个 JSON 值（字符串 / 嵌套容器 / 标量）
    const auto skip_value = [&]() -> bool {
        skip_ws();
        if (i >= dump.size()) return false;
        if (dump[i] == '"') {
            std::string tmp;
            return read_string(&tmp);
        }
        if (dump[i] == '{' || dump[i] == '[') {
            int depth = 0;
            while (i < dump.size()) {
                const char c = dump[i];
                if (c == '"') {
                    std::string tmp;
                    if (!read_string(&tmp)) return false;
                    continue;
                }
                if (c == '{' || c == '[') {
                    ++depth;
                    ++i;
                    continue;
                }
                if (c == '}' || c == ']') {
                    --depth;
                    ++i;
                    if (depth == 0) return true;
                    continue;
                }
                ++i;
            }
            return false;
        }
        while (i < dump.size() && dump[i] != ',' && dump[i] != '}') ++i;
        return true;
    };

    skip_ws();
    if (i >= dump.size() || dump[i] != '{') return {};
    ++i;
    skip_ws();
    if (i < dump.size() && dump[i] == '}') return {};
    while (i < dump.size()) {
        skip_ws();
        std::string key;
        if (!read_string(&key)) return keys;  // 结构不符 ⇒ 返回已取到的部分（够报错用）
        skip_ws();
        if (i >= dump.size() || dump[i] != ':') return keys;
        ++i;
        if (!skip_value()) return keys;
        keys.push_back(key);
        skip_ws();
        if (i < dump.size() && dump[i] == ',') {
            ++i;
            continue;
        }
        break;
    }
    return keys;
}

// ---------------------------------------------------------------------------
// 类型化取值（把 `ConfigError` 统一转成 `std::invalid_argument`）
// ---------------------------------------------------------------------------

uint64_t GetU64(const JsonValue& root, const std::string& key, uint64_t def) {
    try {
        return root.Uint64Or(key, def);
    } catch (const std::exception& e) {
        BadConfig("字段 '" + key + "' 取值失败：" + e.what());
    }
}

double GetDouble(const JsonValue& root, const std::string& key, double def) {
    try {
        if (!root.Has(key)) return def;
        return root[key].AsDouble();
    } catch (const std::exception& e) {
        BadConfig("字段 '" + key + "' 取值失败：" + e.what());
    }
}

uint32_t ToU32Field(uint64_t v, const std::string& key) {
    if (v > std::numeric_limits<uint32_t>::max()) {
        BadConfig("字段 '" + key + "' = " + std::to_string(v) + " 超出 uint32 范围（上限 " +
                  std::to_string(std::numeric_limits<uint32_t>::max()) + "）");
    }
    return static_cast<uint32_t>(v);
}

// 从已解析的 JSON 文档里取出规模配置（`FromFile` / `FromJson` 共用同一条路径）
MpraqScaleConfig ParseDoc(const JsonConfig& doc) {
    const JsonValue root = doc.root();
    if (!root.IsObject()) {
        BadConfig("JSON 根节点必须是 object（实际 " + root.DescribeType() + "）");
    }
    const std::vector<std::string> keys = TopLevelKeysFromDump(root.Dump());
    std::string unknown;
    for (const std::string& k : keys) {
        if (IsKnownField(k)) continue;
        if (!unknown.empty()) unknown += ", ";
        unknown += "'" + k + "'";
    }
    if (!unknown.empty()) {
        BadConfig("JSON 里有未知字段 " + unknown + "（本层只认识 " + KnownFieldList() +
                  "）—— 拼错的字段名会被当成「没配」，因此这里**直接拒绝**而不是静默忽略");
    }
    if (keys.size() != root.Size()) {
        BadConfig("JSON 顶层字段个数 = " + std::to_string(root.Size()) + "，但只解析出 " +
                  std::to_string(keys.size()) + " 个键名（已知字段：" + KnownFieldList() + "）");
    }

    MpraqScaleConfig c;  // 缺省字段取默认值（部分配置是合法的）
    c.rows = GetU64(root, "rows", c.rows);
    c.columns_per_attribute =
        ToU32Field(GetU64(root, "columns_per_attribute", c.columns_per_attribute),
                   "columns_per_attribute");
    c.attributes = ToU32Field(GetU64(root, "attributes", c.attributes), "attributes");
    c.predicates = ToU32Field(GetU64(root, "predicates", c.predicates), "predicates");
    c.lambda = ToU32Field(GetU64(root, "lambda", c.lambda), "lambda");
    c.eps = GetDouble(root, "eps", c.eps);
    c.seed = GetU64(root, "seed", c.seed);
    // 档位：字符串键，**严格解析**（非法值在这里就拒绝启动，不静默回落）
    c.security_mode = ParseMpraqSecurityMode(
        root.StringOr("security_mode", MpraqSecurityModeName(c.security_mode)));
    return c;
}

// ---------------------------------------------------------------------------
// 合成数据的 PRNG 标签（独立字节流 ⇒ 与 Plinko / 掩码 / SecureMul 的流互不干扰）
// ---------------------------------------------------------------------------

constexpr char kScaleGenTag[] = "mpraq-scale-gen";

// 每个谓词**恰好落在 1 列**上，且列的"方向"按属性奇偶固定（保证 k 个谓词的合取
// **可满足且非退化** —— 否则 demo 的 Count/Sum 会恒为 0）：
//
//   偶属性 a：视为**下界** `x >= c`（列号 c 就是下界）
//                c 偶 → `ge(c)`（阈值 c，取反）；c 奇 → `gt(c−1)`（阈值 c，取反）
//   奇属性 a：视为**上界** `x <  c`（列号 c 就是上界）
//                c 偶 → `lt(c)`（阈值 c）；        c 奇 → `le(c−1)`（阈值 c）
//   ⇒ 两种写法归约到的列号都恰好是 c（`predicate.hpp` §2 的归约表），且阈值都落在
//     `RequireBoundInDomain` 允许的 [domain_min, domain_max+1] 内。
//
// ⚠️ 为什么同一属性上的谓词必须**同向**：若同一属性既有下界又有上界（例如 x >= 8 ∧ x < 8），
//    合取会被夹成空集 ⇒ Count = 0，而 `AvgOverFilter` 在 count == 0 时按设计抛
//    `std::domain_error`（"没有记录满足"与"均值恰好为 0"不可区分）。同向之后，每个属性上的
//    合取退化为"最紧的那一个界"，恒**可满足**（下界取 q=0 的最小列、上界同理）。
//
// 列号的取法（都是 [0, 每属性列数−1] 上的**置换** ⇒ q < 每属性列数 时互不相同）：
//   偶属性（下界）：c = (1 + q) mod C        —— 从 1 起 ⇒ `x >= 1` 通过 ~(C−2)/(C−1)
//   奇属性（上界）：c = (C − 2 − q) mod C    —— 从 C−2 起 ⇒ `x < C−2` 通过 ~(C−2)/(C−1)
//   两者**对称**且都**不贴取值域边界**（x >= 0 恒真、x < C−1 恒真都躲开了），
//   最紧的那个界在 q = ceil(k/属性数)−1 处取得 ⇒ 合取的选择性约 ((C−2)/(C−1))^属性数，
//   既非空也非全命中（`test_mpraq_scale_config` 的 ⑫' 用例把这条钉住）。
//   其中 q = j / 属性数（j = 全局谓词序号），C = 每属性列数。
Predicate MakeSingleColumnPredicate(uint32_t attr_id, uint32_t column, bool lower_bound) {
    Predicate p;
    p.by_id = true;
    p.attribute_id = attr_id;
    const bool even = (column % 2 == 0);
    if (lower_bound) {
        p.op = even ? PredicateOp::kGe : PredicateOp::kGt;
    } else {
        p.op = even ? PredicateOp::kLt : PredicateOp::kLe;
    }
    p.value = even ? static_cast<int64_t>(column) : static_cast<int64_t>(column) - 1;
    return p;
}

}  // namespace

// ---------------------------------------------------------------------------
// 配置本体：校验 / JSON 往返
// ---------------------------------------------------------------------------

bool IsScalePowerOfTwo(uint64_t v) { return v != 0 && (v & (v - 1)) == 0; }

int64_t ScaleDomainMin(const MpraqScaleConfig& config) {
    (void)config;
    return 0;
}

int64_t ScaleDomainMax(const MpraqScaleConfig& config) {
    // D19-5 的紧上限：range_size >= 跨度 + 2 ⇒ 取 domain_max = 每属性列数 − 2
    return static_cast<int64_t>(config.columns_per_attribute) - 2;
}

void ValidateScaleConfig(const MpraqScaleConfig& c) {
    // 档位：JSON/CLI 路径已由 ParseMpraqSecurityMode 严格把关；这里挡住**程序内构造**
    // 出的非法值（`static_cast<MpraqSecurityMode>(7)` 是编译得过的）。
    if (!IsKnownMpraqSecurityMode(static_cast<uint32_t>(c.security_mode))) {
        BadConfig("security_mode 不是合法档位（只认 malicious / semi-honest）");
    }
    // ① 行数 = 记录数 N，必须是 2 的幂
    if (c.rows == 0) {
        BadConfig("字段 'rows'（记录数 N）不能为 0 —— 必须 >= 1 且是 2 的幂");
    }
    if (!IsScalePowerOfTwo(c.rows)) {
        BadConfig("字段 'rows'（记录数 N）= " + std::to_string(c.rows) +
                  " 不是 2 的幂 —— 本层**绝不**静默取整到最近的 2 的幂，请显式改成 2 的幂"
                  "（例如 " +
                  std::to_string(NextPow2Local(c.rows)) + " 或 " +
                  std::to_string(NextPow2Local(c.rows) >> 1) + "）");
    }
    if (c.rows > std::numeric_limits<uint32_t>::max()) {
        BadConfig("字段 'rows'（记录数 N）= " + std::to_string(c.rows) +
                  " 超出 uint32 范围 —— `LcteParams::window_size` 是 uint32（上限 " +
                  std::to_string(std::numeric_limits<uint32_t>::max()) + "）");
    }

    // ② 列数 = 每属性 LCTE 列数，必须是 2 的幂（且 >= 2）
    if (c.columns_per_attribute == 0) {
        BadConfig(
            "字段 'columns_per_attribute'（每属性列数）不能为 0 —— 必须 >= 2 且是 2 的幂");
    }
    if (!IsScalePowerOfTwo(c.columns_per_attribute)) {
        BadConfig("字段 'columns_per_attribute'（每属性列数）= " +
                  std::to_string(c.columns_per_attribute) +
                  " 不是 2 的幂 —— 本层**绝不**静默取整，请显式改成 2 的幂（例如 " +
                  std::to_string(NextPow2Local(c.columns_per_attribute)) + "）");
    }
    if (c.columns_per_attribute < 2) {
        BadConfig("字段 'columns_per_attribute'（每属性列数）= " +
                  std::to_string(c.columns_per_attribute) +
                  " < 2 —— 取值域会是空的（本层口径：domain = [0, 每属性列数 − 2]，"
                  "因为 D19-5 要求 range_size >= 跨度 + 2）");
    }

    // ③ 属性数与谓词数
    if (c.attributes == 0) {
        BadConfig(
            "字段 'attributes'（属性数）不能为 0 —— 至少 1 个属性（M = 属性数 × 每属性列数）");
    }
    if (c.predicates == 0) {
        BadConfig("字段 'predicates'（谓词数 k）不能为 0 —— 至少要生成 1 个谓词；"
                  "`CountPredicates` 同样把空谓词列表视为调用方错误");
    }
    const uint64_t M = static_cast<uint64_t>(c.attributes) *
                       static_cast<uint64_t>(c.columns_per_attribute);
    if (M > std::numeric_limits<uint32_t>::max()) {
        BadConfig("attributes × columns_per_attribute = " + std::to_string(M) +
                  " 超出 uint32 范围（真实列数 M 上限 " +
                  std::to_string(std::numeric_limits<uint32_t>::max()) + "）");
    }

    // ④ 安全参数与 ε
    if (c.lambda == 0) {
        BadConfig("字段 'lambda'（安全参数 λ）不能为 0 —— Plinko 要求 λ >= 1（q = λw/2）");
    }
    if (!(c.eps > 0.0) || !(c.eps < 1.0)) {
        BadConfig("字段 'eps'（iPRF 的 PRP 目标 ε）= " + JsonNumber(c.eps) +
                  " 必须落在开区间 (0, 1) 内（`PlinkoParams::Validate` 的硬要求）");
    }
}

std::string ToJsonText(const MpraqScaleConfig& c) {
    std::ostringstream oss;
    oss << "{\n"
        << "  \"rows\": " << c.rows << ",\n"
        << "  \"columns_per_attribute\": " << c.columns_per_attribute << ",\n"
        << "  \"attributes\": " << c.attributes << ",\n"
        << "  \"predicates\": " << c.predicates << ",\n"
        << "  \"lambda\": " << c.lambda << ",\n"
        << "  \"eps\": " << JsonNumber(c.eps) << ",\n"
        << "  \"seed\": " << c.seed << "\n"
        << "}\n";
    return oss.str();
}

MpraqScaleConfig MpraqScaleConfig::FromJson(const std::string& text) {
    try {
        const JsonConfig doc = JsonConfig::FromString(text);
        return ParseDoc(doc);
    } catch (const std::invalid_argument&) {
        throw;  // 本层已经给出可读原因，不要包第二层
    } catch (const std::exception& e) {
        BadConfig(std::string("JSON 解析失败：") + e.what());
    }
}

MpraqScaleConfig MpraqScaleConfig::FromFile(const std::string& path) {
    if (path.empty()) {
        BadConfig("`FromFile` 的路径为空");
    }
    try {
        const JsonConfig doc = JsonConfig::FromFile(path);
        return ParseDoc(doc);
    } catch (const std::invalid_argument&) {
        throw;
    } catch (const std::exception& e) {
        BadConfig("读取/解析文件 '" + path + "' 失败：" + e.what());
    }
}

// ---------------------------------------------------------------------------
// CLI 覆盖
// ---------------------------------------------------------------------------

bool MpraqScaleOverrides::any() const {
    return rows || columns_per_attribute || attributes || predicates || lambda || eps || seed;
}

std::string MpraqScaleOverrides::FlagList() {
    return "--rows, --columns（= 每属性列数）, --attributes, --predicates, --lambda, "
           "--eps, --seed, --security-mode";
}

namespace {

// 归一化旗标名：接受 "--rows" / "rows" / "--columns-per-attribute"
std::string NormalizeFlag(const std::string& flag) {
    size_t i = 0;
    while (i < flag.size() && flag[i] == '-') ++i;
    std::string s = flag.substr(i);
    for (char& ch : s) {
        if (ch == '-') ch = '_';
    }
    return s;
}

uint64_t ParseU64OrThrow(const std::string& flag, const std::string& value) {
    try {
        size_t used = 0;
        const unsigned long long v = std::stoull(value, &used);
        if (used != value.size()) {
            BadConfig("旗标 --" + flag + " 的值 '" + value + "' 不是纯整数");
        }
        return static_cast<uint64_t>(v);
    } catch (const std::invalid_argument& e) {
        BadConfig("旗标 --" + flag + " 的值 '" + value + "' 无法解析为无符号整数：" +
                  e.what());
    } catch (const std::out_of_range& e) {
        BadConfig("旗标 --" + flag + " 的值 '" + value + "' 超出 uint64：" + e.what());
    }
}

double ParseDoubleOrThrow(const std::string& flag, const std::string& value) {
    try {
        size_t used = 0;
        const double v = std::stod(value, &used);
        if (used != value.size()) {
            BadConfig("旗标 --" + flag + " 的值 '" + value + "' 不是纯数值");
        }
        return v;
    } catch (const std::invalid_argument& e) {
        BadConfig("旗标 --" + flag + " 的值 '" + value + "' 无法解析为浮点数：" + e.what());
    } catch (const std::out_of_range& e) {
        BadConfig("旗标 --" + flag + " 的值 '" + value + "' 超出 double 范围：" + e.what());
    }
}

}  // namespace

bool MpraqScaleOverrides::IsScaleFlag(const std::string& flag) {
    const std::string f = NormalizeFlag(flag);
    return f == "rows" || f == "columns" || f == "columns_per_attribute" ||
           f == "attributes" || f == "predicates" || f == "lambda" || f == "eps" ||
           f == "seed" || f == "security_mode" || f == "security-mode";
}

void MpraqScaleOverrides::Set(const std::string& flag, const std::string& value) {
    const std::string f = NormalizeFlag(flag);
    if (f == "rows") {
        rows = ParseU64OrThrow(f, value);
    } else if (f == "columns" || f == "columns_per_attribute") {
        columns_per_attribute = ToU32Field(ParseU64OrThrow(f, value), f);
    } else if (f == "attributes") {
        attributes = ToU32Field(ParseU64OrThrow(f, value), f);
    } else if (f == "predicates") {
        predicates = ToU32Field(ParseU64OrThrow(f, value), f);
    } else if (f == "lambda") {
        lambda = ToU32Field(ParseU64OrThrow(f, value), f);
    } else if (f == "eps") {
        eps = ParseDoubleOrThrow(f, value);
    } else if (f == "seed") {
        seed = ParseU64OrThrow(f, value);
    } else if (f == "security_mode" || f == "security-mode") {
        // 先严格解析（非法值立刻拒绝），再存字符串
        (void)ParseMpraqSecurityMode(value);
        security_mode = value;
    } else {
        BadConfig("旗标 --" + flag + " 不是规模旗标（规模旗标： " + FlagList() + "）");
    }
}

MpraqScaleConfig ApplyOverrides(MpraqScaleConfig base, const MpraqScaleOverrides& ov) {
    if (ov.rows) base.rows = *ov.rows;
    if (ov.columns_per_attribute) base.columns_per_attribute = *ov.columns_per_attribute;
    if (ov.attributes) base.attributes = *ov.attributes;
    if (ov.predicates) base.predicates = *ov.predicates;
    if (ov.lambda) base.lambda = *ov.lambda;
    if (ov.eps) base.eps = *ov.eps;
    if (ov.seed) base.seed = *ov.seed;
    if (ov.security_mode) base.security_mode = ParseMpraqSecurityMode(*ov.security_mode);
    return base;
}

// ---------------------------------------------------------------------------
// 预估对照
//
// ⚠️ print 精简纪律（全仓库）：这里只产出**裸 `key=value`**。
//    派生公式、单位、口径括注、出处引用一律写在注释里，**不进输出**。
//    公式出处：本文件 §1 的注释 与 `scale_config.hpp` 文件头。
//      entry_words = ⌈n/128⌉                        条目宽度（字）
//      levels      = 属性数 × 每属性列数             真实层数
//      m           = ceil(levels/(2w))·2w            PIR 条目数（补齐后；2w | m）
//      w           = 2^j（最接近 √m）                块大小（条目/块）
//      kappa       = m / w                          块数（偶数）
//      去重列数 = min(k, M)
//      查询集数 = 去重列数 × L
//      每台 RPC = 1（一次 RunBatch 把所有查询集放进一次 ServerRespBatch）
//      存储/台  = 16·m·L + 16·N·|attrs|（含补齐；换成 M 即不含补齐）
//      L14 预算 = 去重列数 · L ≤ min(q = λw/2, n)
// ---------------------------------------------------------------------------

std::string MpraqScaleEstimate::Headline() const {
    std::ostringstream oss;
    oss << "n=" << rows << " C=" << columns_per_attribute << " A=" << attributes
        << " levels=" << levels << " m=" << m << " k=" << predicates
        << " qsets=" << query_sets << " rpc=" << rpc_per_server
        << " security=" << MpraqSecurityModeName(security_mode);
    return oss.str();
}

std::string MpraqScaleEstimate::Report() const {
    // 只出裸 `key=value`（D40）；标签向论文看齐（D41）：
    //   n = 记录数、entry_words = ⌈n/128⌉、levels = 真实层数、m = PIR 条目数（含补齐）、
    //   w = 块大小、kappa = 块数、lw = λw、N_T = λw/2、H = λw + N_T、
    //   pool_m = 新鲜索引池（= m）、budget = min(N_T, m)。
    std::ostringstream oss;
    oss << "n=" << rows << " entry_words=" << entry_words
        << " security=" << MpraqSecurityModeName(security_mode) << "\n";
    oss << "levels=" << levels << "\n";
    oss << "m=" << m << " padding=" << padding_columns << "\n";
    oss << "w=" << w << " kappa=" << kappa << "\n";
    oss << "dedup=" << dedup_columns << "\n";
    oss << "qsets=" << query_sets << " rpc=" << rpc_per_server << "\n";
    oss << "srv_padded=" << storage_bytes_padded << " srv_unpadded=" << storage_bytes_unpadded
        << "\n";
    oss << "lw=" << main_hints << " N_T=" << backup_hints << " H=" << hint_slots
        << " pool_m=" << pool_m << " budget=" << budget
        << " over=" << (query_sets <= budget ? 0 : 1) << "\n";
    return oss.str();
}

MpraqScaleEstimate EstimateScale(const MpraqScaleConfig& config) {
    ValidateScaleConfig(config);

    MpraqScaleEstimate e;
    e.rows = config.rows;
    e.columns_per_attribute = config.columns_per_attribute;
    e.attributes = config.attributes;
    e.predicates = config.predicates;
    e.lambda = config.lambda;
    e.eps = config.eps;
    e.security_mode = config.security_mode;   // 配置回声（Headline/Report 会打印）

    e.entry_words = (config.rows + 127) / 128;
    e.levels = static_cast<uint64_t>(config.attributes) *
                       static_cast<uint64_t>(config.columns_per_attribute);

    // 几何**只**由 `DerivePaddedGeometry` 派生（D15(a) 只补条目；D41 只抬到 2w 的倍数）
    MpraqPaddedGeometry g;
    try {
        g = DerivePaddedGeometry(static_cast<size_t>(e.levels),
                                 static_cast<size_t>(config.rows), config.lambda, config.eps);
    } catch (const std::invalid_argument& ex) {
        std::ostringstream oss;
        oss << "规模配置无法派生出合法几何（N=" << config.rows
            << "、每属性列数=" << config.columns_per_attribute
            << "、属性数=" << config.attributes << " ⇒ M=" << e.levels
            << "、λ=" << config.lambda << "、ε=" << JsonNumber(config.eps) << "）：\n  "
            << ex.what();
        throw std::invalid_argument(oss.str());
    }

    e.m = static_cast<uint64_t>(g.m);
    e.padding_columns = static_cast<uint64_t>(g.padding_columns);
    e.m = e.m;   // PIR 条目数 = m（一个条目 = 一整列）
    e.w = g.plinko.w;
    e.kappa = g.plinko.blocks();
    e.main_hints = g.plinko.main_hints();
    e.backup_hints = g.plinko.backup_hints();
    e.hint_slots = g.plinko.hint_slots();

    e.dedup_columns = std::min<uint64_t>(config.predicates, e.levels);
    // ⚠️ **一次列查询 = 1 个查询集**（一个条目 = 一整列）⇒ 查询集数 = 去重列数
    e.query_sets = e.dedup_columns;
    e.rpc_per_server = 1;

    const uint64_t attr_blob = 16ull * config.rows * static_cast<uint64_t>(config.attributes);
    e.storage_bytes_padded = 16ull * e.m * e.entry_words + attr_blob;    e.storage_bytes_unpadded = 16ull * e.levels * e.entry_words + attr_blob;

    e.pool_m = e.m;
    e.budget = std::min(e.backup_hints, e.pool_m);

    // 内部一致性（几何与公式必须自洽；不一致说明本层公式漂移了）
    // ⚠️ 列粒度下**不再要求 m 是 2 的幂**：只要求 `m >= levels`、`w | m`、`κ = m/w` 为偶数。
    //    （旧口径的 `m = m · ⌈n/128⌉` 也已经变成 `m = m`。）
    if (e.m < e.levels || e.w == 0 ||
        e.m % e.w != 0 || e.kappa % 2 != 0 ||
        e.m != e.kappa * e.w || e.m != e.m) {
        std::ostringstream oss;
        oss << "规模派生的内部一致性被破坏：m=" << e.m
            << "（levels=" << e.levels << "）、m=" << e.m
            << "、w=" << e.w << "、kappa=" << e.kappa;
        throw std::logic_error(oss.str());
    }
    return e;
}

// ---------------------------------------------------------------------------
// L14 查询预算（台账 L14）
// ---------------------------------------------------------------------------
// 两条硬约束（详见 `TASK_PLAN.md` §7.8 的 L14 与决策 D41）：
//   ① **备份 hint 上限**：Plinko 每次查询消费 1 条常规 hint 并提升 1 条备份；
//      一次离线只有 `N_T = λw/2` 条备份 ⇒ 最多支持 `N_T` 个查询集。用尽即
//      `PlinkoBackupsExhausted`；D8 明确不做摊销式离线 ⇒ 只能重跑 `HintInit`。
//   ② **新鲜索引池上限**：重复访问同一索引时 Plinko **不复用**原 hint，而是另取一个
//      "未被答复过"的新索引（隐私：服务器不能看到重复）⇒ 池子只有 `m` 个条目。
//   ⇒ 预算 = `min(N_T, m)`，约束的是**查询集个数**（= 列数，因为一列 = 一个条目）。
// ⚠️ 迁移前（word 粒度）一次列查询要 `⌈n/128⌉` 个查询集，预算因此按"word 查询数"算；
//    列粒度下 **一次列查询 = 1 个查询集**，所以此处比较的直接就是列数。
void CheckL14Budget(const MpraqScaleEstimate& e) {
    if (e.query_sets <= e.budget) return;
    std::ostringstream oss;
    oss << "查询预算不足：计划查询集数 " << e.query_sets
        << " > 上限 min(N_T, m) = " << e.budget << " (N_T=lambda*w/2=" << e.backup_hints
        << ", m=" << e.pool_m << ", binding="
        << (e.pool_m <= e.backup_hints ? "pool(m)" : "hint(N_T)") << ")"
        << " plan dedup_columns=" << e.dedup_columns
        << " rows=" << e.rows << " cols_per_attr=" << e.columns_per_attribute
        << " attrs=" << e.attributes << " levels=" << e.levels
        << " padded_m=" << e.m << " lambda=" << e.lambda
        << " w=" << e.w;
    throw std::invalid_argument(oss.str());
}

// ---------------------------------------------------------------------------
// 生成物
// ---------------------------------------------------------------------------

MpraqScaleSetup Build(const MpraqScaleConfig& config) {
    // ---- ① 校验 + ② 预估 + ③ L14 预算（**先算清楚再说**，全部 fail-loudly）----
    MpraqScaleSetup setup;
    setup.config = config;
    setup.estimate = EstimateScale(config);
    CheckL14Budget(setup.estimate);

    const MpraqScaleEstimate& e = setup.estimate;
    const int64_t dmin = ScaleDomainMin(config);
    const int64_t dmax = ScaleDomainMax(config);

    // ---- schema：属性数 = attributes，**同形状**（同 range_size / window_size / 取值域风格），
    //      但每个属性**各自一组列**（否则跨属性谓词会互相串列）
    for (uint32_t a = 0; a < config.attributes; ++a) {
        AttributeSchema attr;
        attr.name = "attr" + std::to_string(a);
        attr.id = a;
        attr.lcte.window_size = static_cast<uint32_t>(config.rows);
        attr.lcte.range_min = dmin;
        attr.lcte.range_size = config.columns_per_attribute;
        attr.domain_min = dmin;
        attr.domain_max = dmax;
        setup.schema.AddAttribute(attr);
    }

    // ---- 合成数据（DeterministicPrng + 显式 seed；`feature = i` 是 D36 的行标签）----
    // 取值顺序固定为"逐记录、逐属性"⇒ 同一 seed **逐位可复现**（铁律 D6）。
    random::DeterministicPrng prng(
        MakeAesSeed(
            std::vector<uint8_t>(kScaleGenTag, kScaleGenTag + sizeof(kScaleGenTag) - 1)),
        config.seed);
    const uint64_t span = static_cast<uint64_t>(dmax - dmin) + 1;  // 取值域点数
    setup.records.assign(static_cast<size_t>(config.rows), MpraqRecord{});
    for (uint64_t i = 0; i < config.rows; ++i) {
        MpraqRecord& rec = setup.records[static_cast<size_t>(i)];
        rec.feature = static_cast<int64_t>(i);  // D36：行标签（死字段，客户端明文）
        rec.attributes.resize(config.attributes);
        for (uint32_t a = 0; a < config.attributes; ++a) {
            const uint128_t off = prng.Below(static_cast<uint128_t>(span));
            rec.attributes[a] = dmin + static_cast<int64_t>(off);
        }
    }

    // ---- 自动谓词：k 个，**尽量落在互不相同的列**上 ⇒ 去重列数 = min(k, M) ----
    // (属性, 列) 取 (j % attributes, (j / attributes) % 每属性列数)：
    // j < M 时这些二元组两两不同（j = q·attributes + a，q < 每属性列数）⇒ 恰好 k 列；
    // k > M 时按模回绕 ⇒ 恰好 M 列（不越界、不重复计数）。
    setup.predicates.clear();
    setup.predicates.reserve(config.predicates);
    std::set<std::pair<uint32_t, uint32_t>> seen;
    const uint32_t C = config.columns_per_attribute;
    for (uint32_t j = 0; j < config.predicates; ++j) {
        const uint32_t a = j % config.attributes;
        const uint32_t q = (j / config.attributes) % C;   // 同一属性上的第几个谓词
        const bool lower_bound = (a % 2 == 0);            // 偶属性 = 下界、奇属性 = 上界
        const uint32_t c = lower_bound ? (1u + q) % C : (C - 2u + C - q) % C;
        setup.predicates.push_back(MakeSingleColumnPredicate(a, c, lower_bound));
        seen.insert({a, c});
    }
    if (static_cast<uint64_t>(seen.size()) != e.dedup_columns) {
        std::ostringstream oss;
        oss << "规模层的内部不变量被破坏：生成的谓词落在 " << seen.size()
            << " 个不同 (属性, 列) 上，但预估的去重列数是 " << e.dedup_columns
            << "（k=" << config.predicates << "、M=" << e.levels << "）";
        throw std::logic_error(oss.str());
    }

    // ---- Sum/Avg 的属性号：默认 1（attributes >= 2），否则 0 ----
    setup.sum_attr = config.attributes >= 2 ? 1u : 0u;

    // ---- Init 参数（λ / ε / seed；w 由 DerivePaddedGeometry 自动派生）----
    setup.init = MpraqInitParams{};
    setup.init.lambda = config.lambda;
    setup.init.prp_epsilon = config.eps;
    setup.init.seed = config.seed;
    // 档位随 `MpraqInitParams` 进入 `StoreParams`（服务端据此做一致性校验）
    setup.init.security_mode = config.security_mode;
    return setup;
}

std::string CompareEstimateWithStore(const MpraqScaleEstimate& e, const StoreParams& store) {
    std::ostringstream oss;
    if (store.entry_words != e.entry_words) {
        oss << "entry_words 不一致：预估 " << e.entry_words << " vs Init 实测 "
            << store.entry_words << "；";
    }
    if (store.levels != e.levels) {
        oss << "levels 不一致：预估 " << e.levels << " vs Init 实测 "
            << store.levels << "；";
    }
    if (store.m != e.m) {
        oss << "m 不一致：预估 " << e.m << " vs Init 实测 " << store.m << "；";
    }
    if (store.plinko.w != e.w || store.plinko.blocks() != e.kappa ||
        store.entry_count() != e.m || store.plinko.backup_hints() != e.backup_hints) {
        oss << "几何不一致：预估 (m=" << e.m << ", w=" << e.w
            << ", kappa=" << e.kappa << ", N_T=" << e.backup_hints << ") vs Init 实测 (m="
            << store.entry_count() << ", w=" << store.plinko.w
            << ", kappa=" << store.plinko.blocks()
            << ", N_T=" << store.plinko.backup_hints() << ")；";
    }
    const uint64_t attr_blob =
        16ull * store.n * static_cast<uint64_t>(store.num_attributes());
    const uint64_t storage = 16ull * store.m * store.entry_words + attr_blob;
    if (storage != e.storage_bytes_padded || store.n != e.rows ||
        store.num_attributes() != e.attributes) {
        oss << "存储不一致：预估 " << e.storage_bytes_padded << " B（n=" << e.rows
            << "、|attrs|=" << e.attributes << "）vs Init 实测 " << storage
            << " B（n=" << store.n << "、|attrs|=" << store.num_attributes() << "）；";
    }
    return oss.str();
}

}  // namespace mpraq
}  // namespace tsb
