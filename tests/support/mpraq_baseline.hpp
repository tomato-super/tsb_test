#pragma once

// MPRAQ 的**明文基准**（测试支撑，header-only）。
//
// 用途：给 MPRAQ 协议层（`MPA-04` Count / `MPA-06` Sum·Avg / `MPA-07` 恶意验证 / `MPA-08` demo）
// 提供**与协议实现完全独立**的暴力答案，落实项目铁律 **D6**（"每个算法都要有确定性随机源下的
// 期望值测试"，只验"跑通"不算）。
//
// ⚠️ 三条设计约定（别破坏）：
//   1. **不引用 `tsb::mpraq` 的 `Schema` / `Predicate` / `EvaluateFilter`** —— 基准若复用被测代码，
//      等于自己证明自己。谓词语义在这里用朴素比较**重写一遍**（`==` `<` `<=` `>` `>=` 与半开区间）。
//   2. 数据集用 `tsb::random::DeterministicPrng` + **显式种子**生成（底座的 nonce 处理已按 D23 修好），
//      并对固定密钥，因此跨运行逐位可复现。
//   3. 聚合返回**整数矩** `(count, sum, sum_sq)`（与 VMPQ 的 `AggregateResult` 同口径）：
//      方差/标准差由调用方从矩推导，**不引入浮点误差**；`Avg` 用整数向下取整除法。
//
// 用法示例：
// ```cpp
// const auto d = mpraq_baseline::MakeDataset(1024, {0, 0}, {63, 31}, /*seed=*/7);
// const std::vector<mpraq_baseline::Pred> preds = {
//     {0, mpraq_baseline::Op::kRange, 0, 10, 40},   // 属性 0 ∈ [10, 40)
//     {1, mpraq_baseline::Op::kGe, 5},              // 属性 1 >= 5
// };
// const auto m = mpraq_baseline::Aggregate(d, preds, /*sum_attr=*/1);
// ```
// 与 `tsb::mpraq::Predicate` 的对应关系（**要在测试里显式转写，不要在本文件里做适配**）：
// `kEq↔eq`、`kNe↔neq`、`kLt↔lt`、`kLe↔le`、`kGt↔gt`、`kGe↔ge`、`kRange[lower,upper)↔range`。

#include "core/random.hpp"

#include <cstdint>
#include <numeric>
#include <stdexcept>
#include <string>
#include <vector>

namespace mpraq_baseline {

enum class Op { kEq, kNe, kLt, kLe, kGt, kGe, kRange };

inline const char* OpName(Op op) {
    switch (op) {
        case Op::kEq: return "eq";
        case Op::kNe: return "neq";
        case Op::kLt: return "lt";
        case Op::kLe: return "le";
        case Op::kGt: return "gt";
        case Op::kGe: return "ge";
        case Op::kRange: return "range";
    }
    return "?";
}

// 一个谓词。`kEq/kNe/kLt/kLe/kGt/kGe` 用 `value`；`kRange` 用 `[lower, upper)`。
struct Pred {
    size_t attr = 0;
    Op op = Op::kEq;
    int64_t value = 0;
    int64_t lower = 0;
    int64_t upper = 0;
};

inline bool Match(int64_t v, const Pred& p) {
    switch (p.op) {
        case Op::kEq: return v == p.value;
        case Op::kNe: return v != p.value;
        case Op::kLt: return v < p.value;
        case Op::kLe: return v <= p.value;
        case Op::kGt: return v > p.value;
        case Op::kGe: return v >= p.value;
        case Op::kRange: return v >= p.lower && v < p.upper;
    }
    throw std::invalid_argument("mpraq_baseline::Match: 未知操作符");
}

struct Dataset {
    size_t num_attributes = 0;
    std::vector<int64_t> domain_min;              // 每个属性的闭取值域下界
    std::vector<int64_t> domain_max;              // 闭取值域上界
    std::vector<std::vector<int64_t>> records;    // records[rec][attr]

    size_t size() const { return records.size(); }
    bool empty() const { return records.empty(); }
};

// 全部谓词的**合取**（MPRAQ 的 MVP：Φ 只做 AND）
inline std::vector<uint8_t> Filter(const Dataset& d, const std::vector<Pred>& preds) {
    std::vector<uint8_t> out(d.size(), 1);
    for (const Pred& p : preds) {
        if (p.attr >= d.num_attributes) {
            throw std::out_of_range("mpraq_baseline::Filter: 属性号越界");
        }
    }
    for (size_t r = 0; r < d.size(); ++r) {
        for (const Pred& p : preds) {
            if (!Match(d.records[r][p.attr], p)) {
                out[r] = 0;
                break;
            }
        }
    }
    return out;
}

// 整数矩（与 VMPQ 的 AggregateResult 同口径）
struct Moments {
    uint64_t count = 0;
    uint64_t sum = 0;
    uint64_t sum_sq = 0;
};

inline Moments Aggregate(const Dataset& d, const std::vector<Pred>& preds, size_t sum_attr) {
    if (sum_attr >= d.num_attributes) {
        throw std::out_of_range("mpraq_baseline::Aggregate: 求和属性号越界");
    }
    const std::vector<uint8_t> f = Filter(d, preds);
    Moments m;
    for (size_t r = 0; r < d.size(); ++r) {
        if (!f[r]) continue;
        const uint64_t v = static_cast<uint64_t>(d.records[r][sum_attr]);
        ++m.count;
        m.sum += v;
        m.sum_sq += v * v;
    }
    return m;
}

inline uint64_t Count(const Dataset& d, const std::vector<Pred>& preds) {
    return Aggregate(d, preds, 0).count;
}

inline uint64_t Sum(const Dataset& d, const std::vector<Pred>& preds, size_t sum_attr) {
    return Aggregate(d, preds, sum_attr).sum;
}

// 整数向下取整除法；无命中返回 0（与 VMPQ 的 AvgWithFilter 同约定）
inline uint64_t Avg(const Dataset& d, const std::vector<Pred>& preds, size_t sum_attr) {
    const Moments m = Aggregate(d, preds, sum_attr);
    return m.count == 0 ? 0 : m.sum / m.count;
}

// 确定性数据集：每个属性的取值均匀落在其闭取值域内。
// 固定密钥 + 显式种子 ⇒ 同一 (n, domains, seed) 跨运行逐位一致。
inline Dataset MakeDataset(size_t n, const std::vector<int64_t>& domain_min,
                           const std::vector<int64_t>& domain_max, uint64_t seed) {
    if (domain_min.size() != domain_max.size() || domain_min.empty()) {
        throw std::invalid_argument(
            "mpraq_baseline::MakeDataset: domain_min/domain_max 长度必须一致且非空");
    }
    for (size_t a = 0; a < domain_min.size(); ++a) {
        if (domain_min[a] > domain_max[a]) {
            throw std::invalid_argument("mpraq_baseline::MakeDataset: domain_min > domain_max");
        }
    }
    Dataset d;
    d.num_attributes = domain_min.size();
    d.domain_min = domain_min;
    d.domain_max = domain_max;

    std::array<uint8_t, 16> key{};
    key.fill(0xA5);
    tsb::random::DeterministicPrng prng(key, seed);
    d.records.assign(n, std::vector<int64_t>(d.num_attributes, 0));
    for (size_t r = 0; r < n; ++r) {
        for (size_t a = 0; a < d.num_attributes; ++a) {
            const int64_t span = domain_max[a] - domain_min[a] + 1;
            const tsb::uint128_t off =
                prng.Below(static_cast<tsb::uint128_t>(span));
            d.records[r][a] = domain_min[a] + static_cast<int64_t>(off);
        }
    }
    return d;
}

// 诊断：把过滤向量渲染成 `0...01...1` 形状的字符串（失败时直接看出差异）
inline std::string FilterShape(const std::vector<uint8_t>& filter) {
    std::string s;
    s.reserve(filter.size());
    for (uint8_t b : filter) s.push_back(b ? '1' : '0');
    return s;
}

// 诊断：把谓词渲染成可读文本
inline std::string Describe(const Pred& p) {
    std::string s = "attr" + std::to_string(p.attr) + " " + OpName(p.op);
    if (p.op == Op::kRange) {
        s += "[" + std::to_string(p.lower) + "," + std::to_string(p.upper) + ")";
    } else {
        s += " " + std::to_string(p.value);
    }
    return s;
}

}  // namespace mpraq_baseline
