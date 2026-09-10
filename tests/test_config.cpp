#include "core/config.hpp"
#include "test_framework.hpp"

#include <stdexcept>
#include <string>

using namespace tsb;

namespace {

const char* kValidVmpq = R"({
    "servers": [
        {"id": 0, "address": "localhost:50051"},
        {"id": 1, "address": "localhost:50052"}
    ],
    "params": {
        "window_size": 200,
        "num_bucket": 16,
        "lambda": 80,
        "entry_bytes": 16,
        "verification": false
    }
})";

}  // namespace

// ---------------------------------------------------------------------------
// JsonConfig / JsonValue
// ---------------------------------------------------------------------------

TEST(JsonConfig, ParsesObjectAndAccessesFields) {
    const auto cfg = JsonConfig::FromString(R"({"a": 1, "b": "hi", "c": true})");
    const JsonValue root = cfg.root();
    EXPECT_TRUE(root.IsObject());
    EXPECT_TRUE(root.Has("a"));
    EXPECT_FALSE(root.Has("zzz"));
    EXPECT_EQ(root["a"].AsInt64(), static_cast<int64_t>(1));
    EXPECT_EQ(root["b"].AsString(), std::string("hi"));
    EXPECT_TRUE(root["c"].AsBool());
}

TEST(JsonConfig, NestedAndArrayAccess) {
    const auto cfg = JsonConfig::FromString(R"({"xs": [10, 20, 30]})");
    const JsonValue xs = cfg.root()["xs"];
    EXPECT_TRUE(xs.IsArray());
    EXPECT_EQ(xs.Size(), static_cast<size_t>(3));
    EXPECT_EQ(xs[0].AsInt64(), static_cast<int64_t>(10));
    EXPECT_EQ(xs[2].AsInt64(), static_cast<int64_t>(30));
}

TEST(JsonConfig, MalformedJsonThrowsConfigError) {
    EXPECT_THROW(JsonConfig::FromString("{not json"), ConfigError);
    EXPECT_THROW(JsonConfig::FromString(""), ConfigError);
}

TEST(JsonConfig, MissingFileThrowsConfigError) {
    EXPECT_THROW(JsonConfig::FromFile("/nonexistent/path/cfg.json"), ConfigError);
}

TEST(JsonValue, MissingKeyErrorNamesTheKey) {
    const auto cfg = JsonConfig::FromString(R"({"a": 1})");
    try {
        (void)cfg.root()["missing"];
        EXPECT_TRUE(false);  // 不应到达
    } catch (const ConfigError& e) {
        const std::string msg = e.what();
        EXPECT_TRUE(msg.find("missing") != std::string::npos);
    }
}

TEST(JsonValue, TypeMismatchErrorNamesPathAndTypes) {
    const auto cfg = JsonConfig::FromString(R"({"outer": {"inner": "text"}})");
    try {
        (void)cfg.root()["outer"]["inner"].AsInt64();
        EXPECT_TRUE(false);
    } catch (const ConfigError& e) {
        const std::string msg = e.what();
        // 应指出完整路径与实际类型
        EXPECT_TRUE(msg.find("outer.inner") != std::string::npos);
        EXPECT_TRUE(msg.find("string") != std::string::npos);
    }
}

TEST(JsonValue, ArrayIndexOutOfRangeThrows) {
    const auto cfg = JsonConfig::FromString(R"({"xs": [1]})");
    EXPECT_THROW(cfg.root()["xs"][5], ConfigError);
    EXPECT_THROW(cfg.root()["xs"]["key"], ConfigError);  // 对数组取键
}

TEST(JsonValue, RangeChecksOnIntegerTypes) {
    const auto cfg = JsonConfig::FromString(R"({"neg": -5, "big": 4294967296})");
    EXPECT_THROW(cfg.root()["neg"].AsUint64(), ConfigError);
    EXPECT_THROW(cfg.root()["big"].AsUint32(), ConfigError);  // 超出 uint32
    EXPECT_EQ(cfg.root()["big"].AsUint64(), static_cast<uint64_t>(4294967296ull));
}

TEST(JsonValue, OptionalAccessorsUseDefaults) {
    const auto cfg = JsonConfig::FromString(R"({"present": 7})");
    const JsonValue root = cfg.root();
    EXPECT_EQ(root.Uint64Or("present", 99), static_cast<uint64_t>(7));
    EXPECT_EQ(root.Uint64Or("absent", 99), static_cast<uint64_t>(99));
    EXPECT_EQ(root.StringOr("absent", "def"), std::string("def"));
    EXPECT_TRUE(root.BoolOr("absent", true));
    // 存在的键若类型不对，仍然报错（而不是静默用默认值）
    EXPECT_THROW(root.StringOr("present", "def"), ConfigError);
}

TEST(JsonValue, Uint128AcceptsDecimalHexAndNumber) {
    const auto cfg = JsonConfig::FromString(
        R"({"dec": "340282366920938463463374607431768211455",
            "hex": "0xff",
            "num": 42})");
    const JsonValue root = cfg.root();
    EXPECT_EQ(root["dec"].AsUint128(), ~static_cast<uint128_t>(0));
    EXPECT_EQ(root["hex"].AsUint128(), static_cast<uint128_t>(255));
    EXPECT_EQ(root["num"].AsUint128(), static_cast<uint128_t>(42));
    EXPECT_THROW(root["dec"].AsUint64(), ConfigError);  // 字符串不是整数
}

// ---------------------------------------------------------------------------
// VmpqConfig
// ---------------------------------------------------------------------------

TEST(VmpqConfig, ParsesValidConfig) {
    const VmpqConfig c = VmpqConfig::FromString(kValidVmpq);
    EXPECT_EQ(c.servers.size(), static_cast<size_t>(2));
    EXPECT_EQ(static_cast<int>(c.servers[0].id), 0);
    EXPECT_EQ(c.servers[0].address, std::string("localhost:50051"));
    EXPECT_EQ(c.servers[1].address, std::string("localhost:50052"));
    EXPECT_EQ(c.params.window_size, static_cast<uint32_t>(200));
    EXPECT_EQ(c.params.num_bucket, static_cast<uint32_t>(16));
    EXPECT_EQ(c.params.lambda, static_cast<uint32_t>(80));
    EXPECT_EQ(c.params.entry_bytes, static_cast<uint32_t>(16));
    EXPECT_FALSE(c.params.verification);
}

TEST(VmpqConfig, DefaultsAreApplied) {
    const char* minimal = R"({
        "servers": [{"id":0,"address":"a:1"},{"id":1,"address":"b:2"}],
        "params": {"window_size": 100, "num_bucket": 4}
    })";
    const VmpqConfig c = VmpqConfig::FromString(minimal);
    EXPECT_EQ(c.params.lambda, static_cast<uint32_t>(80));       // 默认安全参数
    EXPECT_EQ(c.params.entry_bytes, static_cast<uint32_t>(16));  // 论文默认
    EXPECT_FALSE(c.params.verification);                         // 半诚实默认关闭
    EXPECT_FALSE(c.params.deterministic);
}

TEST(VmpqConfig, RejectsWrongServerCount) {
    const char* one_server = R"({
        "servers": [{"id":0,"address":"a:1"}],
        "params": {"window_size": 100, "num_bucket": 4}
    })";
    EXPECT_THROW(VmpqConfig::FromString(one_server), ConfigError);

    const char* three = R"({
        "servers": [{"id":0,"address":"a:1"},{"id":1,"address":"b:2"},{"id":2,"address":"c:3"}],
        "params": {"window_size": 100, "num_bucket": 4}
    })";
    EXPECT_THROW(VmpqConfig::FromString(three), ConfigError);
}

TEST(VmpqConfig, RejectsNonPowerOfTwoNumBucket) {
    // num_bucket 必须是 2^l；S3PIR 的掩码/分区映射依赖这一点
    const char* bad = R"({
        "servers": [{"id":0,"address":"a:1"},{"id":1,"address":"b:2"}],
        "params": {"window_size": 100, "num_bucket": 12}
    })";
    try {
        (void)VmpqConfig::FromString(bad);
        EXPECT_TRUE(false);
    } catch (const ConfigError& e) {
        EXPECT_TRUE(std::string(e.what()).find("2 的幂") != std::string::npos);
    }
}

TEST(VmpqConfig, RejectsInvalidValues) {
    const char* zero_window = R"({
        "servers": [{"id":0,"address":"a:1"},{"id":1,"address":"b:2"}],
        "params": {"window_size": 0, "num_bucket": 4}
    })";
    EXPECT_THROW(VmpqConfig::FromString(zero_window), ConfigError);

    const char* small_bucket = R"({
        "servers": [{"id":0,"address":"a:1"},{"id":1,"address":"b:2"}],
        "params": {"window_size": 100, "num_bucket": 1}
    })";
    EXPECT_THROW(VmpqConfig::FromString(small_bucket), ConfigError);

    const char* empty_addr = R"({
        "servers": [{"id":0,"address":""},{"id":1,"address":"b:2"}],
        "params": {"window_size": 100, "num_bucket": 4}
    })";
    EXPECT_THROW(VmpqConfig::FromString(empty_addr), ConfigError);
}

TEST(VmpqConfig, RejectsMissingSections) {
    EXPECT_THROW(VmpqConfig::FromString(R"({"params": {"window_size":1,"num_bucket":2}})"),
                 ConfigError);
    EXPECT_THROW(VmpqConfig::FromString(
                     R"({"servers":[{"id":0,"address":"a"},{"id":1,"address":"b"}]})"),
                 ConfigError);
    EXPECT_THROW(VmpqConfig::FromString("[]"), ConfigError);
}

TEST(VmpqConfig, DeterministicRequiresSeed) {
    const char* no_seed = R"({
        "servers": [{"id":0,"address":"a:1"},{"id":1,"address":"b:2"}],
        "params": {"window_size": 100, "num_bucket": 4, "deterministic": true}
    })";
    EXPECT_THROW(VmpqConfig::FromString(no_seed), ConfigError);

    const char* with_seed = R"({
        "servers": [{"id":0,"address":"a:1"},{"id":1,"address":"b:2"}],
        "params": {"window_size": 100, "num_bucket": 4,
                   "deterministic": true, "seed": "0xdeadbeef"}
    })";
    const VmpqConfig c = VmpqConfig::FromString(with_seed);
    EXPECT_TRUE(c.params.deterministic);
    EXPECT_EQ(c.params.seed, std::string("0xdeadbeef"));
}

TEST(VmpqConfig, NumPrimaryHintsFollowsLambdaSqrtN) {
    const VmpqConfig c = VmpqConfig::FromString(kValidVmpq);
    // N = 200, sqrt(200) ≈ 14.14, lambda = 80 -> M ≈ 1131
    const uint64_t m = c.NumPrimaryHints();
    EXPECT_TRUE(m >= 1130 && m <= 1132);
}

// ---------------------------------------------------------------------------
// QueryConfig
// ---------------------------------------------------------------------------

TEST(QueryConfig, ParsesRangeQueryWithSum) {
    const char* q = R"({
        "time_range": {"start": 1000, "end": 2000},
        "filters": [
            {"attribute": "patient_id", "op": "eq", "value": 3},
            {"attribute": "heart_rate", "op": "range", "min": 60, "max": 100}
        ],
        "combine": "and",
        "aggregate": "sum",
        "aggregate_attribute": "blood_glucose"
    })";
    const QueryConfig c = QueryConfig::FromString(q);
    EXPECT_EQ(c.time_range.start, static_cast<int64_t>(1000));
    EXPECT_EQ(c.time_range.end, static_cast<int64_t>(2000));
    EXPECT_FALSE(c.time_range.end_inclusive);
    EXPECT_EQ(c.filters.size(), static_cast<size_t>(2));
    EXPECT_EQ(c.filters[0].attribute, std::string("patient_id"));
    EXPECT_TRUE(c.filters[0].op == PredicateOp::kEq);
    EXPECT_EQ(c.filters[0].value, static_cast<int64_t>(3));
    EXPECT_TRUE(c.filters[1].op == PredicateOp::kRange);
    EXPECT_EQ(c.filters[1].range_min, static_cast<int64_t>(60));
    EXPECT_EQ(c.filters[1].range_max, static_cast<int64_t>(100));
    EXPECT_TRUE(c.combine == CombineOp::kAnd);
    EXPECT_TRUE(c.aggregate == AggregateType::kSum);
    EXPECT_EQ(c.aggregate_attribute, std::string("blood_glucose"));
}

TEST(QueryConfig, CountNeedsNoAggregateAttribute) {
    const char* q = R"({
        "time_range": {"start": 0, "end": 100},
        "filters": [{"attribute": "a", "op": "eq", "value": 1}],
        "aggregate": "count"
    })";
    const QueryConfig c = QueryConfig::FromString(q);
    EXPECT_TRUE(c.aggregate == AggregateType::kCount);
    EXPECT_TRUE(c.aggregate_attribute.empty());
}

TEST(QueryConfig, SumRequiresAggregateAttribute) {
    const char* q = R"({
        "time_range": {"start": 0, "end": 100},
        "filters": [{"attribute": "a", "op": "eq", "value": 1}],
        "aggregate": "sum"
    })";
    try {
        (void)QueryConfig::FromString(q);
        EXPECT_TRUE(false);
    } catch (const ConfigError& e) {
        EXPECT_TRUE(std::string(e.what()).find("aggregate_attribute") !=
                    std::string::npos);
    }
}

TEST(QueryConfig, AllPredicateOperatorsParse) {
    for (const char* op : {"eq", "ne", "lt", "le", "gt", "ge"}) {
        const std::string q = std::string(R"({
            "time_range": {"start": 0, "end": 10},
            "filters": [{"attribute": "x", "op": ")") + op + R"(", "value": 5}]
        })";
        const QueryConfig c = QueryConfig::FromString(q);
        EXPECT_EQ(c.filters.size(), static_cast<size_t>(1));
        EXPECT_EQ(ToString(c.filters[0].op), std::string(op));
    }
}

TEST(QueryConfig, RejectsUnknownOperatorWithHelpfulMessage) {
    const char* q = R"({
        "time_range": {"start": 0, "end": 10},
        "filters": [{"attribute": "x", "op": "between", "value": 5}]
    })";
    try {
        (void)QueryConfig::FromString(q);
        EXPECT_TRUE(false);
    } catch (const ConfigError& e) {
        const std::string msg = e.what();
        EXPECT_TRUE(msg.find("between") != std::string::npos);
    }
}

TEST(QueryConfig, RejectsEmptyFiltersAndBadRange) {
    const char* empty = R"({
        "time_range": {"start": 0, "end": 10},
        "filters": []
    })";
    EXPECT_THROW(QueryConfig::FromString(empty), ConfigError);

    const char* bad_range = R"({
        "time_range": {"start": 0, "end": 10},
        "filters": [{"attribute": "x", "op": "range", "min": 100, "max": 50}]
    })";
    EXPECT_THROW(QueryConfig::FromString(bad_range), ConfigError);

    const char* bad_time = R"({
        "time_range": {"start": 500, "end": 10},
        "filters": [{"attribute": "x", "op": "eq", "value": 1}]
    })";
    EXPECT_THROW(QueryConfig::FromString(bad_time), ConfigError);
}

TEST(QueryConfig, MissingTimeRangeThrows) {
    const char* q = R"({"filters": [{"attribute": "x", "op": "eq", "value": 1}]})";
    EXPECT_THROW(QueryConfig::FromString(q), ConfigError);
}

TEST(QueryConfig, EnumRoundTrip) {
    EXPECT_TRUE(ParsePredicateOp("eq") == PredicateOp::kEq);
    EXPECT_TRUE(ParsePredicateOp("range") == PredicateOp::kRange);
    EXPECT_TRUE(ParseCombineOp("or") == CombineOp::kOr);
    EXPECT_TRUE(ParseAggregateType("avg") == AggregateType::kAvg);
    EXPECT_EQ(ToString(AggregateType::kAvg), std::string("avg"));
    EXPECT_THROW(ParseAggregateType("median"), ConfigError);
    EXPECT_THROW(ParseCombineOp("xor"), ConfigError);
}
