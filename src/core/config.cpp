#include "core/config.hpp"

#include <cmath>
#include <fstream>
#include <limits>
#include <memory>
#include <sstream>

#include "json.hpp"

namespace tsb {

using json = nlohmann::json;

// 辅助：把 JSON 类型名转成可读描述
namespace {

std::string TypeName(const json& j) {
    if (j.is_null()) return "null";
    if (j.is_boolean()) return "boolean";
    if (j.is_number_integer()) return "integer";
    if (j.is_number_unsigned()) return "unsigned";
    if (j.is_number_float()) return "number";
    if (j.is_string()) return "string";
    if (j.is_array()) return "array";
    if (j.is_object()) return "object";
    return "unknown";
}

[[noreturn]] void Fail(const std::string& path, const std::string& msg) {
    const std::string where = path.empty() ? std::string("<root>") : path;
    throw ConfigError("配置错误 [" + where + "]: " + msg);
}

}  // namespace

// ---------------------------------------------------------------------------
// JsonValue
// ---------------------------------------------------------------------------

JsonValue::JsonValue(void* node, std::string path, const std::string* source)
    : node_(node), path_(std::move(path)), source_(source) {}

bool JsonValue::IsNull() const {
    return node_ == nullptr || static_cast<const json*>(node_)->is_null();
}

bool JsonValue::IsObject() const {
    return node_ != nullptr && static_cast<const json*>(node_)->is_object();
}

bool JsonValue::IsArray() const {
    return node_ != nullptr && static_cast<const json*>(node_)->is_array();
}

size_t JsonValue::Size() const {
    if (node_ == nullptr) return 0;
    return static_cast<const json*>(node_)->size();
}

bool JsonValue::Has(const std::string& key) const {
    if (!IsObject()) return false;
    return static_cast<const json*>(node_)->contains(key);
}

JsonValue JsonValue::operator[](const std::string& key) const {
    if (!IsObject()) {
        Fail(path_, "期望 object 才能取键 '" + key + "'，实际是 " + DescribeType());
    }
    const json& j = *static_cast<const json*>(node_);
    if (!j.contains(key)) {
        Fail(path_, "缺少必需字段 '" + key + "'");
    }
    const std::string child = path_.empty() ? key : path_ + "." + key;
    // 注意：&j[key] 的生命周期由 document_ 持有，这里只借用
    return JsonValue(const_cast<json*>(&j[key]), child, source_);
}

JsonValue JsonValue::operator[](size_t index) const {
    if (!IsArray()) {
        Fail(path_, "期望 array 才能按下标取值，实际是 " + DescribeType());
    }
    const json& j = *static_cast<const json*>(node_);
    if (index >= j.size()) {
        Fail(path_, "下标 " + std::to_string(index) + " 越界（长度 " +
                        std::to_string(j.size()) + "）");
    }
    const std::string child = path_ + "[" + std::to_string(index) + "]";
    return JsonValue(const_cast<json*>(&j[index]), child, source_);
}

std::string JsonValue::DescribeType() const {
    if (node_ == nullptr) return "null";
    return TypeName(*static_cast<const json*>(node_));
}

std::string JsonValue::Dump() const {
    if (node_ == nullptr) return "null";
    return static_cast<const json*>(node_)->dump();
}

std::string JsonValue::AsString() const {
    if (node_ == nullptr || !static_cast<const json*>(node_)->is_string()) {
        Fail(path_, "期望 string，实际是 " + DescribeType());
    }
    return static_cast<const json*>(node_)->get<std::string>();
}

int64_t JsonValue::AsInt64() const {
    const json& j = *static_cast<const json*>(node_);
    if (j.is_number_integer()) {
        return j.get<int64_t>();
    }
    if (j.is_number_unsigned()) {
        const uint64_t v = j.get<uint64_t>();
        if (v > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
            Fail(path_, "整数超出 int64 范围: " + j.dump());
        }
        return static_cast<int64_t>(v);
    }
    Fail(path_, "期望整数，实际是 " + DescribeType());
}

uint64_t JsonValue::AsUint64() const {
    const json& j = *static_cast<const json*>(node_);
    if (j.is_number_unsigned()) {
        return j.get<uint64_t>();
    }
    if (j.is_number_integer()) {
        const int64_t v = j.get<int64_t>();
        if (v < 0) {
            Fail(path_, "期望非负整数，实际是 " + j.dump());
        }
        return static_cast<uint64_t>(v);
    }
    Fail(path_, "期望非负整数，实际是 " + DescribeType());
}

uint32_t JsonValue::AsUint32() const {
    const uint64_t v = AsUint64();
    if (v > std::numeric_limits<uint32_t>::max()) {
        Fail(path_, "数值超出 uint32 范围: " + std::to_string(v));
    }
    return static_cast<uint32_t>(v);
}

bool JsonValue::AsBool() const {
    if (node_ == nullptr || !static_cast<const json*>(node_)->is_boolean()) {
        Fail(path_, "期望 boolean，实际是 " + DescribeType());
    }
    return static_cast<const json*>(node_)->get<bool>();
}

double JsonValue::AsDouble() const {
    const json& j = *static_cast<const json*>(node_);
    if (!j.is_number()) {
        Fail(path_, "期望数值，实际是 " + DescribeType());
    }
    return j.get<double>();
}

uint128_t JsonValue::AsUint128() const {
    const json& j = *static_cast<const json*>(node_);
    if (j.is_string()) {
        try {
            return parse(j.get<std::string>());
        } catch (const std::exception& e) {
            Fail(path_, std::string("无法解析为 128 位整数: ") + e.what());
        }
    }
    if (j.is_number_unsigned()) {
        return static_cast<uint128_t>(j.get<uint64_t>());
    }
    if (j.is_number_integer()) {
        const int64_t v = j.get<int64_t>();
        if (v < 0) {
            Fail(path_, "128 位整数不能为负");
        }
        return static_cast<uint128_t>(v);
    }
    Fail(path_, "期望 128 位整数（十进制/0x 十六进制字符串或整数），实际是 " +
                    DescribeType());
}

std::string JsonValue::StringOr(const std::string& key,
                                const std::string& def) const {
    if (!Has(key)) return def;
    return (*this)[key].AsString();
}

uint64_t JsonValue::Uint64Or(const std::string& key, uint64_t def) const {
    if (!Has(key)) return def;
    return (*this)[key].AsUint64();
}

uint32_t JsonValue::Uint32Or(const std::string& key, uint32_t def) const {
    if (!Has(key)) return def;
    return (*this)[key].AsUint32();
}

bool JsonValue::BoolOr(const std::string& key, bool def) const {
    if (!Has(key)) return def;
    return (*this)[key].AsBool();
}

int64_t JsonValue::Int64Or(const std::string& key, int64_t def) const {
    if (!Has(key)) return def;
    return (*this)[key].AsInt64();
}

// ---------------------------------------------------------------------------
// JsonConfig
// ---------------------------------------------------------------------------

JsonConfig::JsonConfig(std::string source, void* document)
    : source_(std::move(source)), document_(std::shared_ptr<void>(document, [](void* p) {
          delete static_cast<json*>(p);
      })) {}

JsonConfig JsonConfig::FromString(const std::string& text) {
    json* doc = nullptr;
    try {
        doc = new json(json::parse(text));
    } catch (const json::parse_error& e) {
        delete doc;
        throw ConfigError(std::string("JSON 解析失败: ") + e.what());
    }
    return JsonConfig(text, doc);
}

JsonConfig JsonConfig::FromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw ConfigError("无法打开配置文件: " + path);
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    const std::string text = ss.str();
    try {
        return FromString(text);
    } catch (const ConfigError& e) {
        throw ConfigError(std::string("配置文件 ") + path + " " + e.what());
    }
}

JsonValue JsonConfig::root() const {
    return JsonValue(document_.get(), "", &source_);
}

// ---------------------------------------------------------------------------
// ServerConfig
// ---------------------------------------------------------------------------

ServerConfig ServerConfig::FromFile(const std::string& path) {
    const JsonConfig cfg = JsonConfig::FromFile(path);
    const JsonValue root = cfg.root();
    if (!root.IsObject()) {
        throw ConfigError("服务端配置的根必须是 object");
    }
    ServerConfig out;
    out.server_id = static_cast<int>(root.Int64Or("server_id", -1));
    if (out.server_id < 0) {
        throw ConfigError("服务端配置缺少 server_id");
    }
    if (!root.Has("host_port")) {
        throw ConfigError("服务端配置缺少 host_port");
    }
    out.host_port = root["host_port"].AsString();
    if (out.host_port.empty()) {
        throw ConfigError("host_port 不能为空");
    }
    return out;
}

// ---------------------------------------------------------------------------
// VmpqConfig
// ---------------------------------------------------------------------------

void VmpqConfig::Validate() const {
    if (servers.empty()) {
        throw ConfigError("VMPQ 配置缺少 servers");
    }
    if (servers.size() != 2) {
        throw ConfigError("VMPQ 是双服务器协议，servers 必须恰好 2 个，实际 " +
                          std::to_string(servers.size()) + " 个");
    }
    for (size_t i = 0; i < servers.size(); ++i) {
        if (servers[i].address.empty()) {
            throw ConfigError("servers[" + std::to_string(i) + "].address 不能为空");
        }
    }
    if (params.window_size == 0) {
        throw ConfigError("params.window_size 必须 > 0");
    }
    if (params.attr_sizes.empty()) {
        // 单属性场景：由 num_bucket 推导
        if (params.num_bucket < 2) {
            throw ConfigError("params.num_bucket 必须 >= 2（是 2^l 的形式）");
        }
        if ((params.num_bucket & (params.num_bucket - 1)) != 0) {
            throw ConfigError("params.num_bucket 必须是 2 的幂（代表 2^l），实际 " +
                              std::to_string(params.num_bucket));
        }
    } else {
        // 多属性场景：逐个校验取值域是 2 的幂
        for (size_t i = 0; i < params.attr_sizes.size(); ++i) {
            const uint32_t s = params.attr_sizes[i];
            if (s < 2 || (s & (s - 1)) != 0) {
                throw ConfigError("params.attr_sizes[" + std::to_string(i) +
                                  "] 必须是 >= 2 的 2 的幂，实际 " +
                                  std::to_string(s));
            }
        }
    }
    if (params.lambda == 0) {
        throw ConfigError("params.lambda 必须 > 0");
    }
    if (params.entry_bytes == 0 || params.entry_bytes > 128) {
        throw ConfigError("params.entry_bytes 必须在 1..128");
    }
    if (params.deterministic && params.seed.empty()) {
        throw ConfigError("deterministic = true 时必须提供 seed");
    }
}

VmpqConfig VmpqConfig::FromString(const std::string& json_text) {
    const JsonConfig cfg = JsonConfig::FromString(json_text);
    const JsonValue root = cfg.root();
    if (!root.IsObject()) {
        throw ConfigError("VMPQ 配置的根必须是 object");
    }

    VmpqConfig out;

    if (!root.Has("servers")) {
        throw ConfigError("VMPQ 配置缺少 servers");
    }
    const JsonValue servers = root["servers"];
    if (!servers.IsArray()) {
        throw ConfigError("servers 必须是 array");
    }
    for (size_t i = 0; i < servers.Size(); ++i) {
        const JsonValue s = servers[i];
        ServerEndpoint ep;
        ep.id = static_cast<uint8_t>(s["id"].AsUint32());
        ep.address = s["address"].AsString();
        out.servers.push_back(std::move(ep));
    }

    if (!root.Has("params")) {
        throw ConfigError("VMPQ 配置缺少 params");
    }
    const JsonValue p = root["params"];
    VmpqConfigParams& vp = out.params;
    vp.window_size = p.Uint32Or("window_size", 0);
    vp.num_bucket = p.Uint32Or("num_bucket", 0);
    if (p.Has("attr_sizes")) {
        const JsonValue as = p["attr_sizes"];
        if (!as.IsArray()) {
            throw ConfigError("params.attr_sizes 必须是 array");
        }
        for (size_t i = 0; i < as.Size(); ++i) {
            vp.attr_sizes.push_back(as[i].AsUint32());
        }
    }
    vp.lambda = p.Uint32Or("lambda", 80);
    vp.entry_bytes = p.Uint32Or("entry_bytes", 16);
    vp.verification = p.BoolOr("verification", false);
    vp.deterministic = p.BoolOr("deterministic", false);
    vp.seed = p.StringOr("seed", "");

    out.Validate();
    return out;
}

VmpqConfig VmpqConfig::FromFile(const std::string& path) {
    const JsonConfig cfg = JsonConfig::FromFile(path);
    // 重新走一遍字符串路径，保持校验逻辑单一
    return FromString(cfg.source());
}

uint64_t VmpqConfig::NumPrimaryHints() const {
    // M = lambda * sqrt(N)，取整
    const double root = std::sqrt(static_cast<double>(params.window_size));
    return static_cast<uint64_t>(static_cast<double>(params.lambda) * root);
}

// ---------------------------------------------------------------------------
// QueryConfig
// ---------------------------------------------------------------------------

std::string ToString(PredicateOp op) {
    switch (op) {
        case PredicateOp::kEq: return "eq";
        case PredicateOp::kNe: return "ne";
        case PredicateOp::kLt: return "lt";
        case PredicateOp::kLe: return "le";
        case PredicateOp::kGt: return "gt";
        case PredicateOp::kGe: return "ge";
        case PredicateOp::kRange: return "range";
    }
    return "unknown";
}

std::string ToString(CombineOp op) {
    return op == CombineOp::kAnd ? "and" : "or";
}

std::string ToString(AggregateType t) {
    switch (t) {
        case AggregateType::kCount: return "count";
        case AggregateType::kSum: return "sum";
        case AggregateType::kAvg: return "avg";
    }
    return "unknown";
}

PredicateOp ParsePredicateOp(const std::string& s) {
    if (s == "eq") return PredicateOp::kEq;
    if (s == "ne") return PredicateOp::kNe;
    if (s == "lt") return PredicateOp::kLt;
    if (s == "le") return PredicateOp::kLe;
    if (s == "gt") return PredicateOp::kGt;
    if (s == "ge") return PredicateOp::kGe;
    if (s == "range") return PredicateOp::kRange;
    throw ConfigError("未知的谓词操作符: '" + s +
                      "'（支持 eq/ne/lt/le/gt/ge/range）");
}

CombineOp ParseCombineOp(const std::string& s) {
    if (s == "and") return CombineOp::kAnd;
    if (s == "or") return CombineOp::kOr;
    throw ConfigError("未知的组合操作: '" + s + "'（支持 and/or）");
}

AggregateType ParseAggregateType(const std::string& s) {
    if (s == "count") return AggregateType::kCount;
    if (s == "sum") return AggregateType::kSum;
    if (s == "avg") return AggregateType::kAvg;
    throw ConfigError("未知的聚合类型: '" + s + "'（支持 count/sum/avg）");
}

void QueryConfig::Validate() const {
    if (time_range.end < time_range.start) {
        throw ConfigError("time_range.end 不能小于 start");
    }
    if (filters.empty()) {
        throw ConfigError("filters 不能为空");
    }
    for (size_t i = 0; i < filters.size(); ++i) {
        const Predicate& p = filters[i];
        const std::string where = "filters[" + std::to_string(i) + "]";
        if (p.attribute.empty()) {
            throw ConfigError(where + ".attribute 不能为空");
        }
        if (p.op == PredicateOp::kRange && p.range_max <= p.range_min) {
            throw ConfigError(where + ": range_max 必须大于 range_min");
        }
    }
    if (aggregate != AggregateType::kCount && aggregate_attribute.empty()) {
        throw ConfigError(std::string("聚合类型为 ") + ToString(aggregate) +
                          " 时必须提供 aggregate_attribute");
    }
}

QueryConfig QueryConfig::FromString(const std::string& json_text) {
    const JsonConfig cfg = JsonConfig::FromString(json_text);
    const JsonValue root = cfg.root();
    if (!root.IsObject()) {
        throw ConfigError("查询配置的根必须是 object");
    }

    QueryConfig out;

    if (!root.Has("time_range")) {
        throw ConfigError("查询配置缺少 time_range");
    }
    const JsonValue tr = root["time_range"];
    out.time_range.start = tr["start"].AsInt64();
    out.time_range.end = tr["end"].AsInt64();
    out.time_range.end_inclusive = tr.BoolOr("end_inclusive", false);

    if (root.Has("filters")) {
        const JsonValue filters = root["filters"];
        if (!filters.IsArray()) {
            throw ConfigError("filters 必须是 array");
        }
        for (size_t i = 0; i < filters.Size(); ++i) {
            const JsonValue f = filters[i];
            Predicate p;
            p.attribute = f["attribute"].AsString();
            p.op = ParsePredicateOp(f["op"].AsString());
            if (p.op == PredicateOp::kRange) {
                p.range_min = f["min"].AsInt64();
                p.range_max = f["max"].AsInt64();
            } else {
                p.value = f["value"].AsInt64();
            }
            out.filters.push_back(std::move(p));
        }
    }

    if (root.Has("combine")) {
        out.combine = ParseCombineOp(root["combine"].AsString());
    }
    if (root.Has("aggregate")) {
        out.aggregate = ParseAggregateType(root["aggregate"].AsString());
    }
    out.aggregate_attribute = root.StringOr("aggregate_attribute", "");

    out.Validate();
    return out;
}

QueryConfig QueryConfig::FromFile(const std::string& path) {
    const JsonConfig cfg = JsonConfig::FromFile(path);
    return FromString(cfg.source());
}

}  // namespace tsb
