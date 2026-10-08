#pragma once

// MPRAQ 的 `AggQuery` – **`Count`**（任务 `MPA-04`）—— `MPRAQ_IMPL.md` §3 的六步。
//
// ===========================================================================
// 0. 六步与本文件的位置（逐条对应 `doc/design/MPRAQ_IMPL.md` §3）
// ===========================================================================
//   ① 谓词解析（`MPA-02`）：`ParseConjunction` / `ParseRangeConjunctionDeMorgan`
//      → `PredicatePlan`（字面量 = 列 + 取反标记；`columns` = 去重升序的待检索列）
//      ⚠️ **操作符语义（含 `gt`/`ge` 差一格、De Morgan 形式、取反）一律复用
//      `mpraq/predicate.hpp`**，本文件**不重新实现**任何操作符归约。
//   ② 取 `plan.columns`（已去重升序）→ **每列 = 一个条目 = 1 个查询集**
//      ⇒ **全部查询集放进一个 `MpraqQueryBatch`，一次 RPC 发完**（Q5）
//   ③ 服务器：Plinko `ServerResp`（各自在本方 XOR 共享上按 `P'` 分两组 XOR 累加）
//      → 每查询集 2 个 parity（**服务器之间零通信**）
//   ④ 客户端：`ClientRecon` 逐条目重建**整列**（`entry_words` 个字）→ 展开成该列的 `n` 位比特
//      ⚠️ `MpraqClient::RunBatch` 返回的是**重建出的整列**（`PlinkoEntry`），
//      **不是**展开的比特 ⇒ 本层自己做位展开：
//          bit j = entry[j/128] >> (j % 128) & 1，**只取 j < n**（不变量 I3）
//      （末字 `j >= n` 的尾部填充位按不变量 I2 恒为 0，但仍必须被忽略）
//   ⑤ 本地布尔组合（取反 / 合取；De Morgan 形式按 `MPA-02` 的树求值）→ filter 向量
//      ⇒ 走 `LcteColumnLookup` + `EvaluateFilter(plan, lookup)`（Q5：服务器不参与组合）
//   ⑥ `Count = popcount(filter)`
//
// ===========================================================================
// 1. 验证层：**不做**（`TASK_PLAN.md` §7.13 的 V1/V2 未裁决）
// ===========================================================================
// 论文的 HMAC 多集证明在共享域上**不成立**（D24① / 台账 L9；`F` 建在明文、`C` 建在共享），
// `Count` 的完整性在论文框架内**没有**可用机制（§5 的 "❌ 待 V2"）。
// ⇒ 本文件**不写**任何 HMAC / 多集证明 / "验证通过" 的假象，也不声称有任何完整性保证：
//   服务器返回错值时会**静默给出错结果**，这是当前已知的、如实声明的边界。
//   ⚠️ 谁都不许为了"让流程看起来完整"而在这里加一个数学上不成立的检查（D16 的先例）。
//
// ===========================================================================
// 2. 代价（`MPRAQ_IMPL.md` §3 末 / §6）
// ===========================================================================
//   * 检索量 = **去重列数** 个查询集（**一列 = 一个条目 = 1 个查询集**）；
//   * 客户端 `1×IF⁻¹ + c×IF` per 查询集；服务器 `c` 次随机读 + `c` 次 XOR；
//   * 一次 `Count` 的网络往返 = **每台服务器恰好 1**（`ServerRespBatch` 整批一次，
//     Q5），与谓词个数、列个数 **全都无关**
//     ⇒ 用 `CountResult::server_resp_calls` / `MpraqClient::channel_rpc_stats()` 断言。
//     ⚠️ 别把"RPC 次数"与"查询集个数"混起来：后者 = **去重列数**。
//   * 不做不必要的拷贝：整列一次取回（`RunBatch`），只有展开后的比特向量会留下
//     （`CountResult::filter` 是 `MPA-06` 的输入，必须暴露；各列的比特只在
//     `combine_ms` 期间存在，`EvaluateFilter` 返回后即释放）。
//
// ===========================================================================
// 3. 给 `MPA-06`（Sum/Avg）的用法与三条**硬预算**（实测踩出来的，务必先读）
// ===========================================================================
//   * **`MPA-06` 拿 filter 向量**：调用一次 `CountPredicates` / `CountPredicate`，
//     直接用返回的 `CountResult::filter`（长度 `N`，`1` = 命中）逐记录喂 `SecureMul`；
//     `CountResult::count` 就是 `Avg` 的分母。**不要**自己再去检索列或重算谓词。
//   * 若还需要**别的列**（例如 `sum_attr` 的特征列），用 `RetrieveColumnBits`（一列一次）。
//     想把多列放进**同一个批次**时，直接按 `MPA-03` 的接口自己拼：
//     `client.CreateQueries({ColumnWord{a,c,w}, ...})` + `client.RunBatch(batch)`
//     （本文件内部就是这么做的，`CountPlan` 可作范本）。
//   * 🔴 一次离线（`Init`）能支撑的查询量有**三条独立上限**（都与 RPC 次数无关；
//     RPC 恒为每台 1 次，受限的是**本地 hint/索引预算**），最小的一条说了算：
//       ① 备份 hint 数 `q = λw/2`（D8：**每个查询集消费 1 条**，不刷新）；
//       ② **查询集总数 <= n**（每个查询集消耗一个 `[0,n)` 里的索引）；
//       ③ 更隐蔽的一条：Plinko 对**重复索引**（同一 `(列, word)` 被再次检索）会另取一个
//          "未答复"的**随机**索引（`PLINKO_SPEC` §3.5 的重复查询分支）⇒ 大量重复检索同一列
//          会把 ② 的预算抽干得更快。
//     ⇒ 一次 `Count` 消耗 `去重列数` 个查询集（一列 = 一个条目 = 1 个查询集）；查询多了会抛
//       `PlinkoBackupsExhausted`（①/②）或 `std::runtime_error`（"全部 n 个索引都已答复过"，③）
//       —— 都表示**必须重跑 `Init`**（D8：不做摊销式离线）。
//   * 检索量口径（`MPRAQ_IMPL.md` §6）：**去重列数** 个查询集（一列 = 一个条目）。

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include "mpraq/init.hpp"
#include "mpraq/lcte.hpp"
#include "mpraq/predicate.hpp"

namespace tsb {
namespace mpraq {

// ---------------------------------------------------------------------------
// `Count` 的结果
// ---------------------------------------------------------------------------

struct CountResult {
    // ⑥ Count = popcount(filter)
    uint64_t count = 0;

    // ⑤ filter 位向量：长度 `N`，`1` = 该记录满足 Φ（合取）。
    // ⚠️ **`MPA-06`（Sum/Avg）的输入**：逐记录 `SecureMul(filter[i], ⟨E_i⟩)`。
    //    `MPA-06` 必须用它，**不要**自己去检索列或重算谓词。
    std::vector<uint8_t> filter;

    // ② 实际检索的列（= `PredicatePlan::columns` 的去重升序集合）
    std::vector<std::pair<uint32_t, uint32_t>> columns;

    // ③ 本批实际发出的查询集个数 = `columns.size()`（一列 = 一个条目 = 1 个查询集）
    //    （一个查询集 = 一个 128 位 word 的 PIR 检索；**不是** RPC 次数）
    uint64_t queries_issued = 0;

    // 🔴 **RPC 次数**（本次 `Count` 在各服务器上产生的网络往返数）。
    //    `MpraqClient::RunBatch` 把整批查询集走**一次** `IMpraqChannel::ServerRespBatch`
    //    ⇒ 远程部署下**每台服务器恰好 1 次往返**（Q5 / D24④ / `MPRAQ_IMPL.md` §3）。
    //    本层只用批量路径 ⇒ 等于 `server_resp_batch_calls`，且标量计数恒为 0。
    uint64_t server_resp_calls[2] = {0, 0};
    // 明细（口径见 `MpraqRpcStats`）：批量接口调用次数 / 标量 `ServerResp` 调用次数
    uint64_t server_resp_batch_calls[2] = {0, 0};
    uint64_t server_resp_single_calls[2] = {0, 0};

    double retrieve_ms = 0.0;                // ②③④ 检索 + word → 比特展开
    double combine_ms = 0.0;                 // ⑤ 本地布尔组合（含逐字面量取反）
};

// ---------------------------------------------------------------------------
// 主入口
// ---------------------------------------------------------------------------

// **合取**（`Φ = ∧_i P_i`；Q8：MVP 只做 AND）的 `Count`。
// 各谓词的操作符语义、取值域校验、阈值对齐（Q6）全部由 `MPA-02` 的
// `ParseConjunction` 完成；这里只负责"检索去重后的列 + 本地布尔组合 + 数 1"。
//
// 异常（消息可读）：
//   * `predicates` 为空 ⇒ `std::invalid_argument`
//     （空合取在 `MPA-02` 里被定义为"恒真"，但那是"计划为空"的合法情形；
//      对**上层 API** 而言"一个谓词都没有"是调用方错误 ⇒ 显式报错，绝不静默返回 `N`）
//   * 属性号越界（含 `by_id = false` 且没给属性名）⇒ `std::out_of_range`（来自 `MPA-02`）
//   * `kStrict` 下阈值不在 R 内 ⇒ `std::out_of_range`（论文的 "aborts via boundary checking"）
//   * 取值域越界、`range` 空区间倒置 ⇒ `std::out_of_range` / `std::invalid_argument`
CountResult CountPredicates(MpraqClient& client, const Schema& schema,
                            const std::vector<Predicate>& predicates,
                            ThresholdMode mode = ThresholdMode::kAlignNearest);

// 便利：单个谓词（等价于 `CountPredicates({p})`，但**不复用** `ParseConjunction`
// 的合并，语义完全一致）。同样拒绝"空谓词列表"这一类调用方错误。
CountResult CountPredicate(MpraqClient& client, const Schema& schema, const Predicate& p,
                           ThresholdMode mode = ThresholdMode::kAlignNearest);

// 论文的 **De Morgan 优化形式** `Φ = ¬(∨_i P_{i0}(l_i)) ∧ (∧_i P_{i1}(r_i))` 的 `Count`。
// ⚠️ 语义与 `CountPredicates` 完全等价（De Morgan），差别只在**本地组合计划的形状**
// （左边界合并成一次 OR + 一次 NOT）⇒ 它是"组合形状"的对照组，不是另一种语义。
// 谓词必须全部是 `range`，否则 `MPA-02` 抛 `std::invalid_argument`。
CountResult CountRangeConjunctionDeMorgan(MpraqClient& client, const Schema& schema,
                                          const std::vector<Predicate>& ranges,
                                          ThresholdMode mode = ThresholdMode::kAlignNearest);

// 直接对**已解析的计划**求值（`MPA-06` / 基准 / 诊断用：同一批列可以喂不同的组合树）。
// 本层不解析任何谓词，只做 ②–⑥。
CountResult CountPlan(MpraqClient& client, const Schema& schema, const PredicatePlan& plan);

// ---------------------------------------------------------------------------
// 检索一整列的**比特向量**
// ---------------------------------------------------------------------------

// 取属性 `attr_id` 第 `column` 列的 `N` 位比特（`bit j = word[j/128] >> (j % 128) & 1`）。
// ⚠️ 这是上层（`MPA-06` 以及任何需要列的应用）**唯一**该用的"列取回"入口：
//    * 条目号一律走 `MpraqClient::EntryIndex`（**一列 = 一个条目**，条目号 = 全局列号）；
//    * 一个整列（**一个条目**）放进**一个** `MpraqQueryBatch` ⇒ 每台服务器
//      **恰好 1 次** `ServerRespBatch`（= 1 次往返，Q5/D24④）；
//    * 尾部填充位（`j >= N`）被忽略（`MPRAQ_IMPL.md` §1 保证它们为 0）。
// 越界（属性号不存在 / `column >= m_a`）⇒ `std::out_of_range`；补齐列不属于任何属性，
// 因此**不可能**通过本入口被检索（补齐列只有裸条目号能定位）。
// 返回值的长度恒为记录的 `N`（`schema` 的 `window_size`，未声明时取客户端记录的 N）。
std::vector<uint8_t> RetrieveColumnBits(MpraqClient& client, const Schema& schema,
                                        uint32_t attr_id, uint32_t column);

}  // namespace mpraq
}  // namespace tsb
