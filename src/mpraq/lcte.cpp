#include "mpraq/lcte.hpp"

#include <algorithm>
#include <limits>
#include <string>

#include "core/random.hpp"
#include "shared/secret_sharing.hpp"

namespace tsb {
namespace mpraq {

namespace {

// 告警接收器（默认空：只计数与记录日志，不向任何流输出，便于测试断言）
std::function<void(const std::string&)>& WarningHandlerStorage() {
    static std::function<void(const std::string&)> handler;
    return handler;
}

size_t& WarningCountStorage() {
    static size_t count = 0;
    return count;
}

std::vector<std::string>& WarningLogStorage() {
    static std::vector<std::string> log;
    return log;
}

// 内部日志上限：告警可能来自逐条记录的海量调用，避免无界增长
constexpr size_t kMaxLoggedWarnings = 1024;

std::string RangeText(const LcteParams& params) {
    return "[" + std::to_string(LcteMinThreshold(params)) + ", " +
           std::to_string(LcteMaxThreshold(params)) + "]（r_min=" +
           std::to_string(params.range_min) + ", m=" +
           std::to_string(params.range_size) + "）";
}

}  // namespace

// ---------------------------------------------------------------------------
// 告警
// ---------------------------------------------------------------------------

void SetLcteWarningHandler(std::function<void(const std::string&)> handler) {
    WarningHandlerStorage() = std::move(handler);
}

size_t LcteWarningCount() { return WarningCountStorage(); }

std::vector<std::string> TakeLcteWarnings() {
    std::vector<std::string> out;
    out.swap(WarningLogStorage());
    return out;
}

void ClearLcteWarnings() { WarningLogStorage().clear(); }

void EmitLcteWarning(const std::string& message) {
    ++WarningCountStorage();
    auto& log = WarningLogStorage();
    if (log.size() < kMaxLoggedWarnings) {
        log.push_back(message);
    }
    const auto& handler = WarningHandlerStorage();
    if (handler) {
        handler(message);
    }
}

// ---------------------------------------------------------------------------
// 参数与阈值
// ---------------------------------------------------------------------------

void ValidateLcteParams(const LcteParams& params) {
    if (params.range_size == 0) {
        throw std::invalid_argument(
            "LCTE: range_size 必须 >= 1（R 至少含一个阈值；range_size=0 时"
            "编码为空向量，任何谓词都无法表达）");
    }
    const int64_t span = static_cast<int64_t>(params.range_size) - 1;
    if (params.range_min > std::numeric_limits<int64_t>::max() - span) {
        throw std::invalid_argument(
            "LCTE: 阈值集合 [range_min, range_min + range_size - 1] 溢出 int64："
            "range_min=" + std::to_string(params.range_min) +
            ", range_size=" + std::to_string(params.range_size));
    }
}

int64_t LcteMinThreshold(const LcteParams& params) { return params.range_min; }

int64_t LcteMaxThreshold(const LcteParams& params) {
    return params.range_min + static_cast<int64_t>(params.range_size) - 1;
}

int64_t LcteThresholdAt(const LcteParams& params, uint32_t column) {
    ValidateLcteParams(params);
    if (column >= params.range_size) {
        throw std::out_of_range(
            "LCTE: 列索引越界：column=" + std::to_string(column) +
            " >= range_size=" + std::to_string(params.range_size));
    }
    return params.range_min + static_cast<int64_t>(column);
}

bool LcteContainsThreshold(const LcteParams& params, int64_t theta) {
    ValidateLcteParams(params);
    return theta >= LcteMinThreshold(params) && theta <= LcteMaxThreshold(params);
}

bool LcteCoversValue(const LcteParams& params, int64_t x) {
    ValidateLcteParams(params);
    return x >= LcteMinThreshold(params) && x <= LcteMaxThreshold(params);
}

ThresholdAlignment AlignLcteThreshold(const LcteParams& params, int64_t theta,
                                      ThresholdMode mode) {
    ValidateLcteParams(params);
    const int64_t lo = LcteMinThreshold(params);
    const int64_t hi = LcteMaxThreshold(params);

    ThresholdAlignment out;
    out.requested = theta;
    if (theta < lo) {
        out.aligned = lo;
        out.adjusted = true;
    } else if (theta > hi) {
        out.aligned = hi;
        out.adjusted = true;
    } else {
        // R 是单位间隔的连续整数 ⇒ [r_min, r_max] 内的整数**天然**命中 R，
        // 因此"调整到最近有效值"只会在越界时发生。
        out.aligned = theta;
        out.adjusted = false;
    }
    out.column = static_cast<uint32_t>(out.aligned - lo);

    if (out.adjusted) {
        if (mode == ThresholdMode::kStrict) {
            throw std::out_of_range(
                "LCTE 阈值对齐（严格模式）：请求阈值 " + std::to_string(theta) +
                " 不在 R = " + RangeText(params) +
                " 内。严格模式下按论文 \"aborts via boundary checking\" 处理；"
                "若希望夹到最近有效值请使用 ThresholdMode::kAlignNearest");
        }
        EmitLcteWarning("LCTE 阈值对齐：请求阈值 " + std::to_string(theta) +
                        " 不在 R = " + RangeText(params) +
                        " 内，已调整到最近有效值 " + std::to_string(out.aligned) +
                        "（列索引 " + std::to_string(out.column) + "）");
    }
    return out;
}

// ---------------------------------------------------------------------------
// 编码
// ---------------------------------------------------------------------------

std::vector<uint128_t> LcteEncodeRow(int64_t x, const LcteParams& params) {
    ValidateLcteParams(params);
    // 阈值逻辑只在 shared/database 里实现一次（避免两处口径漂移）
    return LcteEncode(x, params);
}

std::vector<uint8_t> LcteBits(int64_t x, const LcteParams& params) {
    const auto row = LcteEncodeRow(x, params);
    std::vector<uint8_t> bits(row.size(), 0);
    for (size_t i = 0; i < row.size(); ++i) {
        bits[i] = static_cast<uint8_t>(row[i] != 0 ? 1 : 0);
    }
    return bits;
}

PlainTable BuildLcteTable(const std::vector<int64_t>& values,
                          const LcteParams& params) {
    ValidateLcteParams(params);
    if (params.window_size != 0 && values.size() != params.window_size) {
        throw std::invalid_argument(
            "LCTE: 记录数与 LcteParams.window_size 不一致：values.size()=" +
            std::to_string(values.size()) +
            ", window_size=" + std::to_string(params.window_size));
    }
    const auto flat = EncodeLcteRows(values, params);
    PlainTable table(params.range_size);
    for (size_t r = 0; r < values.size(); ++r) {
        std::vector<uint128_t> row(params.range_size);
        for (uint32_t c = 0; c < params.range_size; ++c) {
            row[c] = flat[r * params.range_size + c];
        }
        table.AppendRow(row);
    }
    return table;
}

std::vector<std::vector<uint8_t>> LcteColumnBits(const PlainTable& table) {
    const size_t cols = table.num_columns();
    const size_t rows = table.num_rows();
    std::vector<std::vector<uint8_t>> out(cols, std::vector<uint8_t>(rows, 0));
    for (size_t c = 0; c < cols; ++c) {
        for (size_t r = 0; r < rows; ++r) {
            out[c][r] = static_cast<uint8_t>(table.At(r, c) != 0 ? 1 : 0);
        }
    }
    return out;
}

std::vector<std::vector<uint128_t>> PackLcteColumns(const PlainTable& table) {
    const auto bits = LcteColumnBits(table);
    std::vector<std::vector<uint128_t>> out(bits.size());
    for (size_t c = 0; c < bits.size(); ++c) {
        out[c] = PackBitsToRing(bits[c]);
    }
    return out;
}

PlainTable BuildLctePackedTable(const std::vector<int64_t>& values,
                                const LcteParams& params) {
    const PlainTable plain = BuildLcteTable(values, params);
    const auto packed = PackLcteColumns(plain);
    const size_t words = packed.empty() ? 0 : packed.front().size();
    // rows = word 序号，columns = LCTE 列序号
    PlainTable out(params.range_size, words);
    for (size_t c = 0; c < packed.size(); ++c) {
        for (size_t w = 0; w < words; ++w) {
            out.Set(w, c, packed[c][w]);
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// XOR 分片
// ---------------------------------------------------------------------------

XorShardedLcte XorShareLcte(const std::vector<int64_t>& values,
                            const LcteParams& params) {
    const PlainTable packed = BuildLctePackedTable(values, params);
    const size_t cols = packed.num_columns();
    const size_t words = packed.num_rows();

    XorShardedLcte sharded;
    sharded.params = params;
    sharded.n = values.size();
    sharded.entry_words = words;

    // 列优先扁平化 → 序列化 → 逐字节 XOR 共享（shared/secret_sharing 的
    // XOR 家族原语；决策 D12：比特/parity 语义的数据绝不用加法共享）
    std::vector<uint8_t> bytes(cols * words * kUint128Bytes, 0);
    size_t offset = 0;
    for (size_t c = 0; c < cols; ++c) {
        for (size_t w = 0; w < words; ++w) {
            toBytesLE(packed.At(w, c), bytes.data() + offset);
            offset += kUint128Bytes;
        }
    }

    auto [b0, b1] = ShareXorBytes(bytes);
    sharded.words0.resize(cols * words);
    sharded.words1.resize(cols * words);
    for (size_t i = 0; i < cols * words; ++i) {
        sharded.words0[i] = fromBytesLE(b0.data() + i * kUint128Bytes);
        sharded.words1[i] = fromBytesLE(b1.data() + i * kUint128Bytes);
    }
    return sharded;
}

ShareTable LcteShareTable(const XorShardedLcte& sharded, int server) {
    if (server != 0 && server != 1) {
        throw std::invalid_argument("LcteShareTable: server 必须是 0 或 1，实际=" +
                                    std::to_string(server));
    }
    const size_t cols = sharded.params.range_size;
    const size_t words = sharded.entry_words;
    const auto& src = (server == 0) ? sharded.words0 : sharded.words1;
    if (src.size() != cols * words) {
        throw std::invalid_argument(
            "LcteShareTable: 分片数据长度与参数不符（分片未初始化或参数不匹配）");
    }
    ShareTable table(cols, words);
    for (size_t c = 0; c < cols; ++c) {
        for (size_t w = 0; w < words; ++w) {
            table.Set(w, c, RingShare{src[c * words + w]});
        }
    }
    return table;
}

PlainTable ReconstructLcteFromShares(const ShareTable& a, const ShareTable& b,
                                     size_t n) {
    if (a.num_columns() != b.num_columns() || a.num_rows() != b.num_rows()) {
        throw std::invalid_argument(
            "ReconstructLcteFromShares: 两个共享表的形状不一致");
    }
    const size_t cols = a.num_columns();
    const size_t words = a.num_rows();
    if (n > words * 128) {
        throw std::invalid_argument(
            "ReconstructLcteFromShares: n=" +
            std::to_string(n) + " 超出打包容量 " +
            std::to_string(words * 128));
    }
    PlainTable out(cols);
    for (size_t r = 0; r < n; ++r) {
        std::vector<uint128_t> row(cols, 0);
        for (size_t c = 0; c < cols; ++c) {
            const uint128_t word = static_cast<uint128_t>(
                a.At(r / 128, c).value ^ b.At(r / 128, c).value);
            row[c] = static_cast<uint128_t>((word >> (r % 128)) & 1u);
        }
        out.AppendRow(row);
    }
    return out;
}

PlainTable ReconstructLctePlain(const XorShardedLcte& sharded) {
    const ShareTable a = LcteShareTable(sharded, 0);
    const ShareTable b = LcteShareTable(sharded, 1);
    return ReconstructLcteFromShares(a, b, sharded.n);
}

// ---------------------------------------------------------------------------
// 取值域覆盖检查
// ---------------------------------------------------------------------------

bool CoversDomainExactly(const LcteParams& params, int64_t domain_min,
                         int64_t domain_max) {
    ValidateLcteParams(params);
    if (domain_min > domain_max) {
        throw std::invalid_argument(
            "LCTE 覆盖检查: 取值域倒置 domain_min=" + std::to_string(domain_min) +
            " > domain_max=" + std::to_string(domain_max));
    }
    // 需要 R ⊇ [domain_min, domain_max + 1]：右端多一个点是"排他上界"，
    // 否则 lt(d_max+1)（即 x <= d_max）无法表达。
    if (domain_max == std::numeric_limits<int64_t>::max()) {
        return false;  // d_max + 1 溢出，不可能覆盖
    }
    return LcteMinThreshold(params) <= domain_min &&
           LcteMaxThreshold(params) >= domain_max + 1;
}

size_t WarnIfLcteDoesNotCoverDomain(const LcteParams& params, int64_t domain_min,
                                    int64_t domain_max,
                                    const std::string& label) {
    if (CoversDomainExactly(params, domain_min, domain_max)) {
        return 0;
    }
    // 所需 range_size = (domain_max + 1) - domain_min + 1；注意溢出
    std::string required;
    if (domain_max > std::numeric_limits<int64_t>::max() - 2) {
        required = "（所需 range_size 超出 int64 可表达范围）";
    } else {
        required = "（需要 range_size >= " +
                   std::to_string(domain_max - domain_min + 2) + "）";
    }
    EmitLcteWarning(
        "LCTE 装载期覆盖检查：属性 \"" + label + "\" 的 R = " + RangeText(params) +
        " 未覆盖取值域 [" + std::to_string(domain_min) + ", " +
        std::to_string(domain_max) +
        "]+1，对齐到域外阈值的谓词可能不再精确" + required);
    return 1;
}

}  // namespace mpraq
}  // namespace tsb
