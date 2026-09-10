#pragma once

// 配置系统。
//
// 设计目标（TASK_PLAN 决策 D5）：所有参数走配置，**禁止硬编码**；
// 非法配置必须快速失败并给出**可定位**的错误信息（指出哪个键、什么类型、
// 期望什么），而不是让程序带着坏参数跑到一半才崩。
//
// 分层：
//   ConfigValue  —— JSON 的薄封装，提供带类型校验的取值，错误信息统一
//   VmpqConfig   —— VMPQ 半诚实版本的参数集
//   QueryConfig  —— MPRAQ 的查询描述（时间窗 + 谓词 + 聚合）
//   ServerConfig —— 服务端监听配置

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "core/field.hpp"

namespace tsb {

// 配置错误：任何非法/缺失字段都抛这个类型，便于上层统一处理
class ConfigError : public std::runtime_error {
public:
    explicit ConfigError(const std::string& what) : std::runtime_error(what) {}
};

// ---------------------------------------------------------------------------
// JSON 薄封装
// ---------------------------------------------------------------------------

class JsonValue;

class JsonConfig {
public:
    // 从文件加载。文件不存在或解析失败时抛 ConfigError。
    static JsonConfig FromFile(const std::string& path);
    // 从字符串加载（测试用）
    static JsonConfig FromString(const std::string& text);

    JsonValue root() const;
    // 原始文本，便于错误上报时回显上下文
    const std::string& source() const { return source_; }

private:
    JsonConfig(std::string source, void* document);

    std::string source_;
    // 用 void* 隐藏 nlohmann::json，避免其头文件污染所有包含者
    std::shared_ptr<void> document_;
};

class JsonValue {
public:
    // 基础查询
    bool IsNull() const;
    bool IsObject() const;
    bool IsArray() const;
    size_t Size() const;

    // 是否存在某个键
    bool Has(const std::string& key) const;

    // 取子节点。键不存在时抛 ConfigError（除非提供了 default）。
    JsonValue operator[](const std::string& key) const;
    JsonValue operator[](size_t index) const;

    // 带校验的取值
    std::string AsString() const;
    int64_t AsInt64() const;
    uint64_t AsUint64() const;
    uint32_t AsUint32() const;
    bool AsBool() const;
    double AsDouble() const;

    // 128 位整数：接受十进制字符串、0x 十六进制字符串，或 JSON 数字
    uint128_t AsUint128() const;

    // 取可选值（键缺失时返回 default）
    std::string StringOr(const std::string& key, const std::string& def) const;
    uint64_t Uint64Or(const std::string& key, uint64_t def) const;
    uint32_t Uint32Or(const std::string& key, uint32_t def) const;
    bool BoolOr(const std::string& key, bool def) const;
    int64_t Int64Or(const std::string& key, int64_t def) const;

    // 路径（点分）+ 错误定位
    std::string Path() const { return path_; }

    // 供错误信息使用的渲染
    std::string DescribeType() const;
    std::string Dump() const;

private:
    friend class JsonConfig;
    JsonValue(void* node, std::string path, const std::string* source);

    void* node_ = nullptr;
    std::string path_;
    const std::string* source_ = nullptr;
};

// ---------------------------------------------------------------------------
// 服务端配置
// ---------------------------------------------------------------------------

struct ServerEndpoint {
    uint8_t id = 0;
    std::string address;  // 例如 "localhost:50051"
};

struct ServerConfig {
    int server_id = 0;
    std::string host_port;
    size_t num_servers = 2;  // 双服务器

    static ServerConfig FromFile(const std::string& path);
};

// ---------------------------------------------------------------------------
// VMPQ（半诚实版本）配置
// ---------------------------------------------------------------------------

struct VmpqConfigParams {
    // 模式表：N 行 × 2^l 列
    uint32_t window_size = 0;  // N
    uint32_t num_bucket = 0;   // 2^l（单属性场景；多属性请用 attr_sizes）

    // 多属性 schema：每个属性的取值域 2^{l_a}。
    // 非空时优先于 num_bucket（num_bucket 仅为向后兼容保留）。
    std::vector<uint32_t> attr_sizes;

    // V-OO-PIR / S3PIR 参数
    uint32_t lambda = 80;         // 安全参数，hint 数 M = lambda * sqrt(n)
    uint32_t entry_bytes = 16;    // 每个 entry 的字节数（论文用 16）
    bool verification = false;    // 半诚实版本默认关闭（决策 D4）

    // 是否使用确定性随机源（复现实验）；生产必须为 false
    bool deterministic = false;
    std::string seed;  // deterministic = true 时的十六进制种子
};

struct VmpqConfig {
    std::vector<ServerEndpoint> servers;
    VmpqConfigParams params;

    static VmpqConfig FromFile(const std::string& path);
    static VmpqConfig FromString(const std::string& json_text);

    // 校验：服务器数、参数范围
    void Validate() const;

    // number of primary hints M = lambda * sqrt(window_size)
    uint64_t NumPrimaryHints() const;
};

// ---------------------------------------------------------------------------
// MPRAQ 查询配置
// ---------------------------------------------------------------------------

enum class PredicateOp {
    kEq,     // x == v
    kNe,     // x != v
    kLt,     // x < v
    kLe,     // x <= v
    kGt,     // x > v
    kGe,     // x >= v
    kRange,  // min <= x < max
};

enum class CombineOp { kAnd, kOr };

enum class AggregateType { kCount, kSum, kAvg };

struct Predicate {
    std::string attribute;
    PredicateOp op = PredicateOp::kEq;
    int64_t value = 0;      // 单值操作符使用
    int64_t range_min = 0;  // kRange 使用
    int64_t range_max = 0;  // kRange 使用（不含）
};

struct TimeRange {
    int64_t start = 0;
    int64_t end = 0;
    bool end_inclusive = false;
};

struct QueryConfig {
    TimeRange time_range;
    std::vector<Predicate> filters;
    CombineOp combine = CombineOp::kAnd;
    AggregateType aggregate = AggregateType::kCount;
    std::string aggregate_attribute;  // kSum/kAvg 时必填

    static QueryConfig FromFile(const std::string& path);
    static QueryConfig FromString(const std::string& json_text);
    void Validate() const;
};

// 字符串 <-> 枚举（供配置解析与日志使用）
std::string ToString(PredicateOp op);
std::string ToString(CombineOp op);
std::string ToString(AggregateType t);
PredicateOp ParsePredicateOp(const std::string& s);
CombineOp ParseCombineOp(const std::string& s);
AggregateType ParseAggregateType(const std::string& s);

}  // namespace tsb
