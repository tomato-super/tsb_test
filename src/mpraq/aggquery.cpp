#include "mpraq/aggquery.hpp"

// `MPA-04`：`AggQuery` – `Count`（逐列 PIR 检索 → 本地布尔组合 → 数 1 的个数）。
// 六步口径、验证层边界与代价见头文件；实现里刻意**只有**这四件事：
//   ① 让 `MPA-02` 解析谓词（本文件不认识任何操作符语义）
//   ② 把一个批次的全部查询集一次发完（Q5/D24）
//   ③ 重建出的 word → `N` 位比特（唯一需要 `MPA-04` 自己写的一步）
//   ④ `EvaluateFilter` 做布尔组合 + `popcount`

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace tsb {
namespace mpraq {

namespace {

std::string Num(uint64_t v) { return std::to_string(v); }

double MsSince(const std::chrono::steady_clock::time_point& t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0)
        .count();
}

// 该计划涉及的记录数 N：
//   * `MPA-02` 从属性的 `lcte.window_size` 推出（不一致时它自己已经报错）；
//   * 属性的 `window_size` 允许为 0（"未声明"）⇒ 退回到 `Init` 实际用的记录数。
size_t ResolveNumRecords(const Schema& schema, const PredicatePlan& plan,
                         const MpraqClient& client) {
    if (plan.n != 0) return plan.n;
    const size_t n = client.store_params().n;
    if (n == 0) {
        throw std::invalid_argument(
            "MPRAQ Count: 无法确定记录数 n（`PredicatePlan::num_records` = 0，"
            "且客户端的 `store_params().n` 也为 0）");
    }
    return n;
}

// 校验计划的列都能落进**真实列**（`attr_id < M`、`column < m_a`）。
// ⚠️ 这里显式拒绝"越界属性号/越界列"，而不是让它退化成"检索到补齐列"（明文恒 0 ⇒ 静默错结果）。
void ValidatePlanColumns(const Schema& schema, const PredicatePlan& plan) {
    for (const LcteColumnRef& ref : plan.columns) {
        if (!schema.HasAttribute(ref.attribute_id)) {
            throw std::out_of_range(
                "MPRAQ Count: 计划引用了 schema 里不存在的属性 id " +
                Num(ref.attribute_id));
        }
        const AttributeSchema& attr = schema.ById(ref.attribute_id);
        if (ref.column >= attr.lcte.range_size) {
            throw std::out_of_range(
                "MPRAQ Count: 属性 " + Num(ref.attribute_id) + "(\"" + attr.name +
                "\") 的列索引越界：" + Num(ref.column) + " >= m = " +
                Num(attr.lcte.range_size));
        }
    }
}

// ③ 把一个重建出的**整列**（entry_words 个字）展开成**恰好 n 位**。
// ⚠️ 不变量 I3：**尾部填充位必须被忽略** —— `n` 不是 128 的倍数时，最后一个 word 里
// `j >= n` 的位按不变量 I2 恒为 0，但"恒为 0"是**契约**而不是可依赖的巧合 ——
// 展开时只取 `j < n`，把契约变成结构上的保证。
std::vector<uint8_t> ExpandEntryToBits(const PlinkoEntry& entry, size_t n) {
    const size_t need = (n + 127) / 128;
    if (entry.size() < need) {
        throw std::logic_error(
            "MPRAQ Count: 重建出的整列宽度不足（需要 ⌈n/128⌉ = " + Num(need) +
            " 个字，实际 " + Num(entry.size()) + " 个）—— 不变量 I1/I4 被破坏");
    }
    std::vector<uint8_t> bits(n, 0);
    for (size_t j = 0; j < n; ++j) {
        const uint128_t word = entry[j / 128];
        bits[j] = static_cast<uint8_t>((word >> (j % 128)) & static_cast<uint128_t>(1));
    }
    return bits;
}

}  // namespace

// ---------------------------------------------------------------------------
// 单列检索：检索一整列的**比特向量**
// ---------------------------------------------------------------------------

std::vector<uint8_t> RetrieveColumnBits(MpraqClient& client, const Schema& schema,
                                        uint32_t attr_id, uint32_t column) {
    if (!schema.HasAttribute(attr_id)) {
        throw std::out_of_range("RetrieveColumnBits: schema 里不存在属性 id " +
                                Num(attr_id));
    }
    const AttributeSchema& attr = schema.ById(attr_id);
    if (column >= attr.lcte.range_size) {
        throw std::out_of_range(
            "RetrieveColumnBits: 属性 " + Num(attr_id) + "(\"" + attr.name +
            "\") 的列索引越界：" + Num(column) + " >= m = " + Num(attr.lcte.range_size));
    }
    const size_t n = ResolveNumRecords(schema, PredicatePlan{}, client);
    const size_t entry_words = client.entry_words();
    if (entry_words != (n + 127) / 128) {
        throw std::logic_error("RetrieveColumnBits: 客户端的 entry_words = " +
                               Num(entry_words) + " 与记录数 n = " + Num(n) + " 不符");
    }

    // ② **一次列查询 = 1 个查询集**（一个条目 = 一整列）⇒ 一次 RPC（Q5）
    std::vector<ColumnEntry> targets;
    targets.push_back(ColumnEntry{attr_id, column});
    MpraqQueryBatch batch = client.CreateQueries(targets);
    std::vector<PlinkoEntry> cols = client.RunBatch(batch);
    if (cols.size() != 1) {
        throw std::logic_error("RetrieveColumnBits: 期望重建出恰好 1 个整列");
    }

    // ④ 重建出的整列 → 该列的恰好 n 位比特（I3）
    return ExpandEntryToBits(cols[0], n);
}

// ---------------------------------------------------------------------------
// 主入口：计划 → ②③④⑤⑥
// ---------------------------------------------------------------------------

CountResult CountPlan(MpraqClient& client, const Schema& schema, const PredicatePlan& plan) {
    ValidatePlanColumns(schema, plan);

    const size_t num_records = ResolveNumRecords(schema, plan, client);
    const size_t entry_words = client.entry_words();
    if (entry_words != (num_records + 127) / 128) {
        throw std::logic_error(
            "MPRAQ Count: 客户端的 entry_words = " + Num(entry_words) +
            " 与记录数 n = " + Num(num_records) +
            " 不符（plan 与 client 不是同一份数据/几何？）");
    }

    CountResult res;
    res.columns.reserve(plan.columns.size());
    res.filter.assign(num_records, 1);  // 空合取 ≡ 恒真（与 MPA-02 的约定一致）

    // RPC 计数（口径见 `MpraqRpcStats`）：批量路径下一次 `RunBatch` 每台**恰好 1 次**往返
    const MpraqRpcStats rpc_before0 = client.channel_rpc_stats(0);
    const MpraqRpcStats rpc_before1 = client.channel_rpc_stats(1);

    const auto t_retrieve = std::chrono::steady_clock::now();

    // ---- ② 全部列 → 一个批次（一次 RPC；每台服务器 1 次 ServerRespBatch）----
    // ⚠️ **一个条目 = 一整列**（1 个查询集），查询顺序与返回顺序**严格一致**：
    //    第 i 列就是返回数组的第 i 个元素。
    std::vector<ColumnEntry> targets;
    targets.reserve(plan.columns.size());
    for (const LcteColumnRef& ref : plan.columns) {
        targets.push_back(ColumnEntry{ref.attribute_id, ref.column});
    }
    if (targets.empty()) {
        throw std::invalid_argument(
            "MPRAQ Count: 计划没有任何需要检索的列（`PredicatePlan::columns` 为空）"
            "—— 请检查谓词解析结果");
    }

    // ③④ 服务器应答（每台在自己的 XOR 共享上）+ 客户端逐列重建 + 位展开（I3 截断）
    MpraqQueryBatch batch = client.CreateQueries(targets);
    res.queries_issued = static_cast<uint64_t>(batch.size());
    std::vector<PlinkoEntry> cols = client.RunBatch(batch);

    std::vector<std::vector<uint8_t>> column_bits;
    column_bits.reserve(plan.columns.size());
    for (size_t i = 0; i < plan.columns.size(); ++i) {
        const LcteColumnRef& ref = plan.columns[i];
        res.columns.emplace_back(ref.attribute_id, ref.column);
        column_bits.push_back(ExpandEntryToBits(cols[i], num_records));
    }

    res.retrieve_ms = MsSince(t_retrieve);

    // ---- ⑤ 本地布尔组合：全部复用 MPA-02 的 `LcteColumnLookup` + `EvaluateFilter` ----
    // ⚠️ 取反 / 合取 / De Morgan 的树求值都在 `predicate.cpp` 里（它已有"与暴力语义逐记录
    //    对照"的用例，含 `gt`/`ge` 极易写反的那一格）⇒ 本层**不重写**任何布尔语义。
    //    同一列只会被查一次（`EvaluateFilter` 内部缓存），本 lambda 只做一次线性查找。
    const auto t_combine = std::chrono::steady_clock::now();
    const LcteColumnLookup lookup = [&column_bits, &plan](
                                        const LcteColumnRef& ref) -> std::vector<uint8_t> {
        for (size_t i = 0; i < plan.columns.size(); ++i) {
            if (plan.columns[i] == ref) return column_bits[i];
        }
        throw std::logic_error(
            "MPRAQ Count: 计划要求的列 (attribute_id=" + Num(ref.attribute_id) +
            ", column=" + Num(ref.column) + ") 不在已检索的列集合里");
    };
    res.filter = EvaluateFilter(plan, lookup);
    if (res.filter.size() != num_records) {
        throw std::logic_error(
            "MPRAQ Count: filter 向量长度 " + Num(res.filter.size()) +
            " 与记录数 N = " + Num(num_records) + " 不符");
    }
    res.combine_ms = MsSince(t_combine);

    // ---- ⑥ Count = popcount(filter) ----
    uint64_t ones = 0;
    for (uint8_t b : res.filter) {
        if (b) ++ones;
    }
    res.count = ones;

    const MpraqRpcStats rpc_after0 = client.channel_rpc_stats(0);
    const MpraqRpcStats rpc_after1 = client.channel_rpc_stats(1);
    res.server_resp_batch_calls[0] =
        rpc_after0.server_resp_batch_calls - rpc_before0.server_resp_batch_calls;
    res.server_resp_batch_calls[1] =
        rpc_after1.server_resp_batch_calls - rpc_before1.server_resp_batch_calls;
    res.server_resp_single_calls[0] =
        rpc_after0.server_resp_single_calls - rpc_before0.server_resp_single_calls;
    res.server_resp_single_calls[1] =
        rpc_after1.server_resp_single_calls - rpc_before1.server_resp_single_calls;
    // `server_resp_calls` = **RPC 次数**（本次查询在每台服务器上的网络往返数）
    res.server_resp_calls[0] =
        res.server_resp_batch_calls[0] + res.server_resp_single_calls[0];
    res.server_resp_calls[1] =
        res.server_resp_batch_calls[1] + res.server_resp_single_calls[1];
    return res;
}

// ---------------------------------------------------------------------------
// 谓词入口
// ---------------------------------------------------------------------------

CountResult CountPredicates(MpraqClient& client, const Schema& schema,
                            const std::vector<Predicate>& predicates, ThresholdMode mode) {
    if (predicates.empty()) {
        throw std::invalid_argument(
            "MPRAQ Count: 谓词列表为空。空合取在 `MPA-02` 里被定义为\"恒真\"（计划为空"
            "是合法情形），但对上层 API 而言\"一个过滤条件都没有\"是调用方错误 —— "
            "本层显式报错，绝不静默把 N 条记录全算成命中。");
    }
    // ① 谓词解析（操作符归约 / 取值域校验 / 阈值对齐全部在 `MPA-02`）
    const PredicatePlan plan = ParseConjunction(predicates, schema, mode);
    return CountPlan(client, schema, plan);
}

CountResult CountPredicate(MpraqClient& client, const Schema& schema, const Predicate& p,
                           ThresholdMode mode) {
    return CountPredicates(client, schema, std::vector<Predicate>{p}, mode);
}

CountResult CountRangeConjunctionDeMorgan(MpraqClient& client, const Schema& schema,
                                          const std::vector<Predicate>& ranges,
                                          ThresholdMode mode) {
    if (ranges.empty()) {
        throw std::invalid_argument(
            "MPRAQ Count: 谓词列表为空（De Morgan 形式同样拒绝\"没有任何条件\"）");
    }
    // ⚠️ 这里刻意**不**复用 `CountPredicates`：De Morgan 形式的价值就在于"本地组合计划的
    //    形状不同"（左边界合并成一次 OR + 一次 NOT），共用同一个入口就测不出等价性。
    //    语义等价性由测试断言（与扁平合取**逐位**一致）。
    const PredicatePlan plan = ParseRangeConjunctionDeMorgan(ranges, schema, mode);
    return CountPlan(client, schema, plan);
}

}  // namespace mpraq
}  // namespace tsb
