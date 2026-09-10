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
    if (plan.num_records != 0) return plan.num_records;
    const size_t n = client.store_params().num_records;
    if (n == 0) {
        throw std::invalid_argument(
            "MPRAQ Count: 无法确定记录数 N（`PredicatePlan::num_records` = 0，"
            "且客户端的 `store_params().num_records` 也为 0）");
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

// ③ 把 `⌈N/128⌉` 个重建出的 word 展开成 `N` 位。
// ⚠️ **尾部填充位必须被忽略**：`N` 不是 128 的倍数时，最后一个 word 里
// `j >= N` 的位按 `MPRAQ_IMPL.md` §1 恒为 0，但"恒为 0"是**契约**而不是可依赖的巧合 ——
// 展开时只取 `j < N`，把契约变成结构上的保证。
std::vector<uint8_t> ExpandWordsToBits(const std::vector<uint128_t>& words, size_t base,
                                       size_t num_records) {
    const size_t words_needed = (num_records + 127) / 128;
    if (base + words_needed > words.size()) {
        throw std::logic_error(
            "MPRAQ Count: 重建出的 word 个数不足（需要第 " + Num(base) + ".." +
            Num(base + words_needed) + " 个，实际只有 " + Num(words.size()) + " 个）");
    }
    std::vector<uint8_t> bits(num_records, 0);
    for (size_t j = 0; j < num_records; ++j) {
        const uint128_t word = words[base + j / 128];
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
    const size_t num_records = ResolveNumRecords(schema, PredicatePlan{}, client);
    const size_t words_per_column = client.ColumnWordCount();
    if (words_per_column != (num_records + 127) / 128) {
        throw std::logic_error(
            "RetrieveColumnBits: 客户端的 ⌈N/128⌉ = " + Num(words_per_column) +
            " 与记录数 N = " + Num(num_records) + " 不符");
    }

    // ② 一个整列的 `⌈N/128⌉` 个 word ⇒ **一个**批次（= 一次 RPC，Q5/D24）
    std::vector<ColumnWord> targets;
    targets.reserve(words_per_column);
    for (size_t w = 0; w < words_per_column; ++w) {
        targets.push_back(ColumnWord{attr_id, column, w});
    }
    MpraqQueryBatch batch = client.CreateQueries(targets);
    const std::vector<uint128_t> words = client.RunBatch(batch);

    // ④ 重建出的 word → 该列的 N 位比特
    return ExpandWordsToBits(words, 0, num_records);
}

// ---------------------------------------------------------------------------
// 主入口：计划 → ②③④⑤⑥
// ---------------------------------------------------------------------------

CountResult CountPlan(MpraqClient& client, const Schema& schema, const PredicatePlan& plan) {
    ValidatePlanColumns(schema, plan);

    const size_t num_records = ResolveNumRecords(schema, plan, client);
    const size_t words_per_column = client.ColumnWordCount();
    if (words_per_column != (num_records + 127) / 128) {
        throw std::logic_error(
            "MPRAQ Count: 客户端的 ⌈N/128⌉ = " + Num(words_per_column) +
            " 与记录数 N = " + Num(num_records) +
            " 不符（plan 与 client 不是同一份数据/几何？）");
    }

    CountResult res;
    res.columns.reserve(plan.columns.size());
    res.filter.assign(num_records, 1);  // 空合取 ≡ 恒真（与 MPA-02 的约定一致）

    // RPC 计数（口径见 `MpraqRpcStats`）：批量路径下一次 `RunBatch` 每台**恰好 1 次**往返
    const MpraqRpcStats rpc_before0 = client.channel_rpc_stats(0);
    const MpraqRpcStats rpc_before1 = client.channel_rpc_stats(1);

    const auto t_retrieve = std::chrono::steady_clock::now();

    // ---- ② 全部列的全部 word → 一个批次（一次 RPC；每台服务器 1 次 ServerResp）----
    // ⚠️ 查询顺序必须与展开顺序**严格一致**：按 `plan.columns` 的（已去重升序）顺序，
    //    每列内按 word 号升序 ⇒ `column_word_base[i]` 就是第 i 列在返回数组里的起点。
    std::vector<ColumnWord> targets;
    targets.reserve(plan.columns.size() * words_per_column);
    std::vector<size_t> column_word_base;
    column_word_base.reserve(plan.columns.size());
    for (const LcteColumnRef& ref : plan.columns) {
        column_word_base.push_back(targets.size());
        for (size_t w = 0; w < words_per_column; ++w) {
            targets.push_back(ColumnWord{ref.attribute_id, ref.column, w});
        }
    }
    if (targets.empty()) {
        throw std::invalid_argument(
            "MPRAQ Count: 计划没有任何需要检索的列（`PredicatePlan::columns` 为空）"
            "—— 请检查谓词解析结果");
    }

    // ③④ 服务器应答（每台在自己的 XOR 共享上）+ 客户端逐 word 重建 + 位展开
    MpraqQueryBatch batch = client.CreateQueries(targets);
    res.queries_issued = static_cast<uint64_t>(batch.size());
    const std::vector<uint128_t> words = client.RunBatch(batch);

    std::vector<std::vector<uint8_t>> column_bits;
    column_bits.reserve(plan.columns.size());
    for (size_t i = 0; i < plan.columns.size(); ++i) {
        const LcteColumnRef& ref = plan.columns[i];
        res.columns.emplace_back(ref.attribute_id, ref.column);
        column_bits.push_back(
            ExpandWordsToBits(words, column_word_base[i], num_records));
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
