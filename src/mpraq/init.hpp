#pragma once

// MPRAQ 的客户端 `Init`（任务 MPA-03）—— `MPRAQ_IMPL.md` §2 的七步。
//
// ===========================================================================
// 0. 输入 / 输出（`MPRAQ_IMPL.md` §2）
// ===========================================================================
//   输入: records[N]（feature 值 + 各属性值）、schema（每属性 LcteParams + 取值域）、
//         Plinko 参数（λ / ε / 可选显式 w）
//   输出: st = (hint 表, 每区块 iPRF 密钥 K[c], MAC 密钥 α, 明文副本[仿真用])
//         + 两台服务器的共享表
//
// ===========================================================================
// 1. 七步与落地位置
// ===========================================================================
//   ① 参数校验（D19-5 的 `m >= 跨度+2`、`w = 2^k`、`c` 偶数、N>0、越域）
//      → `MpraqClient::Init` 的 `ValidateInputs`
//   ② LCTE 编码（复用 MPA-01 的 `LcteBits`）→ 位打包 → 客户端明文特征表
//      → **一个条目 = 一整列**：条目号 = 全局列号，条目宽度 = `entry_words = ⌈n/128⌉` 字
//   ③ 属性值 → mod q 加法共享（强类型 `ModShare`；D11/D24）
//   ④ `PlinkoClient::HintInit`（客户端本地，对**明文** feature word 表；论文 `:524`）
//      ⚠️ 真实部署里 hint 由 **offline server**（持有 DB 的那一方）生成后发给客户端；
//         本仓库沿用 `voo_pir`/Plinko 的**单机仿真约定**：客户端持有一份明文副本、
//         在本地跑 `HintInit`。两种做法产出的 hint 完全相同（PLINKO_SPEC §2 的注）。
//   ⑤ 上传：特征**整条目**的 **XOR** 共享（分块，按 `entry_words` 对齐）+ 属性值共享（带 attr_id）
//   ⑥ `st`：hint 表（在 `PlinkoClient` 内）、每区块密钥、MAC 密钥 α
//      （`GenerateMacKey(2, q)`，**全局一份**，Q3）+ 明文副本
//   ⑦ ❌ **不生成任何 HMAC 验证值**：论文 `:527`「对 ⟨E⟩_p 算 HMAC」在共享域上
//      不可实现（D24① / 台账 L9），机制待 `TASK_PLAN.md` §7.13 的 V1 裁决。
//      本文件**没有**任何 HMAC 标签、"每条 hint 一个 F" 之类的字段——绝不伪造验证层。
//
// ===========================================================================
// 2. 补齐到合法几何（D15(a) + D41 + PLINKO_SPEC §1）
// ===========================================================================
// Plinko 的几何约束（`PlinkoParams::Validate`，符号见 D41）：
//     `m = kappa·w`、`w` 为**2 的幂**、`kappa` **为偶数**、`m ≥ 4`
// 而 LCTE 布局给出的条目数是 **`levels = Σ_a m_a`**（真实层数）——
// 一般**不满足**上述约束（例如 `levels = 3 < 4`；`levels = 6` 时需 `2w | 6`）。
//
// ⇒ 与 D15(a) 的分工一致：**补齐是上层（本层）的事**，
//    `core/iprf` 与 `pir/plinko` 都**不偷偷改 `m`**（`PlinkoParams::Derive` 会直接抛错
//    并给出"应补齐到多少"的建议）。
//
// 补齐**只用"补齐列"（= 补齐条目）**，绝不补记录：
//   * 增加一列 = 在展平表末尾追加 `entry_words` 个字（= 一个条目），其**明文恒为 0**
//     ⇒ 两台服务器的共享**逐位相同**（本实现取 `s0 = 0、s1 = 0`），
//     因此不变量 I2（尾部填充两台恒 0）自动满足。
//   * 补记录会改变 `entry_words` 并给真实记录引入伪造行，语义上更脏，因此不做。
//   * **w 是自由参数**（`PlinkoParams::w`），且多个取值常常都合法 ⇒ 本层在全部合法候选中
//     取 **`w` 最接近 `√m`** 的那个（主键：`|log₂w − ½log₂m|` 最小 ⇒ `kappa` 次线性；
//     次键 = 更少补齐列；末键 = hint 表更小）。候选 `w = 2^j` 满足 `2w | m`。
//     ⚠️ **不能取 `w = 1`**：那会让一次列查询退化成整表扫描（`kappa = m`）。
//   * 补齐列只影响**服务器存储**（多存 `16·padding_columns·entry_words` B）与 `m`，
//     不影响任何真实列的条目号（条目号 = 全局列号，前缀连续）。
//   * ⚠️ 列粒度下补齐量很小：只需把 `levels` 抬到最近的 `2w` 倍数
//     （旧口径"抬到 2 的幂"连同 D35 的 ×2 升级搜索**已整体删除**）。
//
// ===========================================================================
// 3. 给 `MPA-04` / `MPA-06` 留的入口
// ===========================================================================
//   * `MpraqClient::CreateQueries({ColumnEntry, ...})` / `CreateColumnQuery(...)` →
//     构造查询批次（**只生成查询集，不发 RPC**）。
//   * `MpraqQueryBatch::Run()` → 每台服务器**一次** `IMpraqChannel::ServerRespBatch`
//     （= **一次网络往返**承载整批查询集，Q5 / `MPRAQ_IMPL.md` §3）
//     + `XorAnswers` + 逐条 `ClientRecon`（重建是客户端本地工作，逐条做）。
//     ⇒ 一次 `AggQuery`（任意多少列；**一列 = 一个条目 = 1 个查询集**）的网络往返数恒为 **1**。
//   * `MpraqClient::EntryIndex(attr_id, column)`：**一列 = 一个条目**，条目号 = 全局列号。
//   * `MpraqClient::AttributeShare(attr_id, record)`（mod q 加法共享，MPA-06 的 SecureMul 输入）
//     与 `MpraqClient::mac_key_shares()`（α 的分享，Q3 全局一份）。
//   * `MpraqClient::node(i)` / `storage_bytes()`：账目与测试。
//   * `MpraqClient::InitWithChannels(...)`：远程通道（`MPA-08` 的 gRPC）就绪后
//     无需改本层代码。

#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "core/field.hpp"
#include "core/random.hpp"
#include "mpraq/lcte.hpp"
#include "mpraq/node.hpp"
#include "mpraq/predicate.hpp"
#include "pir/plinko.hpp"
#include "shared/verify.hpp"

namespace tsb {
namespace mpraq {

// ---------------------------------------------------------------------------
// 初始化输入
// ---------------------------------------------------------------------------

// 一条记录：`feature` 标签 + 各属性值（与 `schema.attributes()` 同序）
//
// ⚠️ **`feature` 是"死字段"（决策 D36，负责人 2026-09-10 指令）** —— 刻意的，不是遗漏：
//    * **不参与协议**：不参与 LCTE 编码、不上传、不建列、不被谓词引用、不做取值域校验。
//      `Init` 只把它拷进客户端本地的 `plain_feature_values()`（`init.cpp` 的
//      `plain_features_[i] = records[i].feature`）——**服务器永远看不到它**，改它不会
//      改变 filter / count / sum 的任何一个比特（已由 `test_mpraq_init.cpp` 的
//      `FeatureFieldIsInertAndOnlyALocalLabel` 钉住）。
//    * **它的用途**：给测试与 demo 一个**确定的逐记录标签**（例如 `feature = i` 或
//      `7i+3`），便于**手算与预估期望结果**、定位"第几条记录"。
//    * **不要**把它当成论文 §System Model 里"被 LCTE 编码、被谓词过滤的 feature value"：
//      在本实现里**那个角色由 `attributes` 承担**（`Schema` 的每个属性各配一套 `LcteParams`，
//      即对论文"单 feature"模型的推广）。⚠️ 另注意术语撞车：代码里还有 **feature word /
//      `FeatureWord` / feature 表**（= LCTE 编码+位打包后的 PIR 数据库），那是**活的**，
//      与本字段无关。
//    * 若要让它参与协议，必须先裁决"谓词是否允许作用于 feature 列"，并补取值域校验
//      （否则会绕过 `RequireBoundInDomain` 那套边界检查，见台账 L5 的教训）。
struct MpraqRecord {
    int64_t feature = 0;
    std::vector<int64_t> attributes;
};

// `Init` 的参数
struct MpraqInitParams {
    // λ（Plinko 安全参数；论文部署值 80）
    uint32_t lambda = 80;
    // iPRF 的 PRP 目标 ε（D22-1）。默认 1e-10；**测试可调小**以加速
    // （`HintInit` 的实测预算是 `n × IF⁻¹ ≈ 1.0 ms × n`，与 w 无关）。
    double prp_epsilon = 1e-10;
    // 显式指定区块大小 w；未设置时由 `DerivePaddedGeometry` 按 PLINKO_SPEC §1 派生。
    // 设置后仍会做"2 的幂 / n = c·w / c 偶数"的完整校验（失败即抛）。
    bool has_explicit_w = false;
    uint64_t w = 0;
    // 确定性随机源（铁律 D6）：同一 seed 在**任何进程/任何次运行**都给出逐位相同的
    // 区块密钥、hint 子集、共享掩码。nonce 固定为 0（D23 的教训：nonce 必须显式）。
    uint64_t seed = 0;
    // 特征 word 共享的上传分块大小（**word 数**）
    // 理由：一次消息不宜过大（VMPQ 侧用同一量级），同时要让分块数远小于条目数
    // 以免 RPC 元数据成为瓶颈 ⇒ 4096 个 word = 64 KiB/块。
    size_t upload_chunk_words = 4096;
    // 运行方式（安全档位）——**接口预留**（负责人要求"保留一个半诚实运行方式，
    // 用配置文件配置"）。默认恶意档；半诚实档为显式 opt-in。
    // ⚠️ 本 gate **不改变任何行为**：两个档位目前走同一条代码路径；
    //    它的作用是随 `StoreParams` **上线**，让服务端能拒绝"档位不一致"（防静默降级）。
    //    落地机制（按档位跳过 xmac / SPDZ MAC / §4.5-A/B / 逐记录校验）见
    //    `src/mpraq/security_mode.hpp` 的文件头。
    MpraqSecurityMode security_mode = kDefaultMpraqSecurityMode;
};

// 各阶段的实测耗时（毫秒；供验收报告与基准使用，**不是**估算）
// 拆开口径：`lcte_ms` = 逐记录 LCTE 编码；`pack_ms` = 位打包 + 列主序展平；
// `share_ms` = 生成两台服务器的共享材料（XOR 掩码 + mod q 掩码）；
// `hint_ms` = Plinko `HintInit`（含 c 个 iPRF 求值器的构造）；`upload_ms` = 分块上传；
// `total_ms` = 以上五段 + 参数校验/几何补齐/对象构造的其余开销。
struct MpraqInitTimings {
    double lcte_ms = 0.0;      // ② LCTE 编码
    double pack_ms = 0.0;      // ② 位打包 + 一列一条目
    double hint_ms = 0.0;      // ④ Plinko HintInit（客户端本地）
    double share_ms = 0.0;     // ③ 生成共享（XOR 掩码 + mod q 掩码）
    double upload_ms = 0.0;    // ⑤ 分块上传到两台服务器
    double total_ms = 0.0;
    // 规模（符号向论文看齐）
    size_t n = 0;               // 记录数 = 列长（bit）
    size_t entry_words = 0;     // ⌈n/128⌉：条目宽度（字）
    size_t m = 0;               // PIR 条目数 = 补齐后的 LCTE 层数
    size_t levels = 0;          // 真实 LCTE 层数 = Σ_a lcte.range_size
    size_t padding_columns = 0; // 补齐列数 = m − levels
    uint64_t blocks = 0;        // κ = m/w
    uint64_t block_size = 0;    // w
    size_t chunk_words = 0;     // 实际分块大小（word 数）
    size_t chunk_count = 0;     // 分块数
};

// 最小合法几何的建议（由 `DerivePaddedGeometry` 给出；供上层/测试直接使用）
struct MpraqPaddedGeometry {
    PlinkoParams plinko;        // m / entry_words / w / κ / λ / ε
    size_t levels = 0;          // 真实 LCTE 层数
    size_t m = 0;               // PIR 条目数（= 补齐后的层数）
    size_t padding_columns = 0; // m − levels（全零列）
};

// 由 (真实层数 levels, 记录数 n, λ, ε) 求**最小**的合法补齐几何。
// 失败（找不到合法 w）时抛 std::invalid_argument，消息里给出原因与建议。
MpraqPaddedGeometry DerivePaddedGeometry(size_t levels, size_t n, uint32_t lambda = 80,
                                         double prp_epsilon = 1e-10,
                                         bool has_explicit_w = false, uint64_t w = 0);

// ---------------------------------------------------------------------------
// RPC 计数（Q5 / D24④ 口径的结构性断言）
// ---------------------------------------------------------------------------

// ⚠️ 三个量的口径**不同**，别混用：
//   * `server_resp_batch_calls` = `IMpraqChannel::ServerRespBatch` 的次数。
//     **远程部署下这就是网络往返（RPC）次数** —— 一次 `RunBatch`（任意多少列、
//     每列任意多个 word）恒为 **1**。
//   * `server_resp_single_calls` = 标量 `IMpraqChannel::ServerResp` 的次数
//     （只有 `RunQuery` 单条路径会用到）。
//   * `queries` = 一共处理了多少个**查询集**（= Σ 批次大小）—— 与 RPC 次数无关，
//     一次 `RunBatch(k 列)` 的 `queries = k`（**一个条目 = 一整列 = 1 个查询集**）
//     而 `server_resp_batch_calls = 1`。
// 进程内通道下"一次方法调用"就代表"一次往返"（无序列化开销可省）。
struct MpraqRpcStats {
    uint64_t server_resp_batch_calls = 0;
    uint64_t server_resp_single_calls = 0;
    uint64_t queries = 0;
    uint64_t rpc_calls() const { return server_resp_batch_calls + server_resp_single_calls; }
};

// ---------------------------------------------------------------------------
// 单次列查询
// ---------------------------------------------------------------------------

// 上层要检索的列：**一个条目 = 一整列**，因此只有 (属性, 列) 两个坐标，
// **没有 word 维度**（旧口径的 `k·⌈N/128⌉` 个查询集已作废）。
struct ColumnEntry {
    uint32_t attr_id = 0;
    uint32_t column = 0;
};

class MpraqClient;

// 一次 PIR 查询的完整生命周期：QueryGen → 两台 ServerResp → XorAnswers → ClientRecon。
class MpraqQuery {
public:
    MpraqQuery(MpraqQuery&&) = default;
    MpraqQuery& operator=(MpraqQuery&&) = default;
    MpraqQuery(const MpraqQuery&) = delete;
    MpraqQuery& operator=(const MpraqQuery&) = delete;

    uint64_t flat_index() const { return flat_index_; }
    PlinkoQuery& query() { return query_; }                  // 服务器可见的全部信息
    const PlinkoQuery& query() const { return query_; }
    const PlinkoQueryHandle& handle() const { return handle_; }
    // 累加器选择位 b（a = p ⊕ r_b）；诊断/测试用
    uint8_t accumulator() const { return handle_.b; }

    // Run() 之前为假
    bool answered() const { return answered_; }
    const PlinkoAnswer& answer0() const;  // 服务器 0 的应答
    const PlinkoAnswer& answer1() const;  // 服务器 1 的应答
    const PlinkoAnswer& answer() const;   // 两者 XOR（= 明文应答）
    // 重建出的**明文整列**（entry_words 个字；Run() 之前抛 std::logic_error）
    const PlinkoEntry& value() const;

private:
    friend class MpraqClient;
    MpraqQuery() = default;

    uint64_t flat_index_ = 0;
    PlinkoQuery query_;
    PlinkoQueryHandle handle_;
    PlinkoAnswer answer0_{};
    PlinkoAnswer answer1_{};
    PlinkoAnswer answer_{};
    PlinkoEntry value_;   // 重建出的明文整列（entry_words 个字）
    bool answered_ = false;
};
// 一批查询：**一次 RPC** 把全部查询集发给两台服务器（Q5：所有谓词的所有 word 一起发）
class MpraqQueryBatch {
public:
    MpraqQueryBatch(MpraqQueryBatch&&) = default;
    MpraqQueryBatch& operator=(MpraqQueryBatch&&) = default;
    MpraqQueryBatch(const MpraqQueryBatch&) = delete;
    MpraqQueryBatch& operator=(const MpraqQueryBatch&) = delete;

    size_t size() const { return queries_.size(); }
    bool empty() const { return queries_.empty(); }
    MpraqQuery& at(size_t i);
    const MpraqQuery& at(size_t i) const;

    // 每台服务器**一次** `ServerRespBatch`（整批查询集 ⇒ **一次往返**），
    // 随后逐条 `XorAnswers` + `ClientRecon`（本地计算）。
    // 返回本批全部重建出的明文**整列**（与查询顺序一致；每条 entry_words 个字）。
    // 抛出：`PlinkoBackupsExhausted`/`PlinkoHintCoverageFailure`（来自 `ClientRecon`）。
    std::vector<PlinkoEntry> Run();

private:
    friend class MpraqClient;
    explicit MpraqQueryBatch(MpraqClient& owner) : owner_(&owner) {}

    MpraqClient* owner_ = nullptr;
    std::vector<MpraqQuery> queries_;
};

// ---------------------------------------------------------------------------
// 客户端
// ---------------------------------------------------------------------------

class MpraqClient {
public:
    MpraqClient(MpraqClient&&) = default;
    MpraqClient& operator=(MpraqClient&&) = default;
    MpraqClient(const MpraqClient&) = delete;
    MpraqClient& operator=(const MpraqClient&) = delete;

    // ===================== `MPRAQ_IMPL.md` §2 的七步 =====================
    //
    // 单进程仿真：自建两台 `MpraqNode` 与两条 `LocalMpraqChannel`。
    // ⚠️ 与 VMPQ 侧同一约定：调用方**不会**为 `Schema` 的 `window_size` 不一致
    //    买单 —— 这里直接用 `records.size()` 作为 N，并要求每个属性的
    //    `lcte.window_size`（若声明了）与之一致。
    static std::unique_ptr<MpraqClient> Init(const Schema& schema,
                                             const std::vector<MpraqRecord>& records,
                                             const MpraqInitParams& params = {});

    // 同上，但用调用方给定的两条通道（远程通道 = `MPA-08` 的接入口）。
    static std::unique_ptr<MpraqClient> InitWithChannels(
        const Schema& schema, const std::vector<MpraqRecord>& records,
        const MpraqInitParams& params, IMpraqChannel& channel0, IMpraqChannel& channel1);

    // ---------------------------- 客户端状态 st ----------------------------
    const StoreParams& store_params() const { return store_; }
    const PlinkoParams& plinko_params() const { return store_.plinko; }
    const Schema& schema() const { return schema_; }
    const MpraqInitTimings& timings() const { return timings_; }

    // 每区块的 iPRF 密钥 K[i]（论文 Fig 7 的 `K[i] ← iF.Gen`，**每区块一把**）。
    // 由 `Iprf::GenBlockKeys(c, /*use_csprng=*/false, seed)` 确定性地生成 ——
    // `PlinkoClient` 内部生成的是**同一批**密钥（同样的算法、同样的 seed 作为 nonce，
    // 见 `pir/plinko.cpp` 的构造函数与 `HintInit`），因此这里不重复存一份材料。
    IprfKey block_key(uint64_t block) const;
    // MAC 密钥 α 及其分享（`GenerateMacKey(2, q)`，**全局一份**，Q3）。
    // ⚠️ α 本身只留在客户端；分享给两台服务器的是 ⟨α⟩_p（供 MPA-06 的 SPDZ MAC）。
    const MacKeyShares& mac_key_shares() const { return mac_keys_; }
    uint128_t modulus() const { return kMpraqModulus; }

    // hint 表口径（`PLINKO_SPEC` §2 / §6）
    size_t hint_slot_count() const;      // H = λw+q
    size_t hint_state_bytes() const;     // 实际分配的状态字节
    double logical_hint_bytes() const;   // 按 §2 表口径的每条 hint 开销
    size_t backup_remaining() const;
    uint64_t query_count() const;
    // 覆盖掩码（诊断/测试）：长度 n，1 = 该 word 被某条 hint 覆盖
    std::vector<uint8_t> coverage_mask() const;

    // 明文副本（**仿真约定**：真实部署里它属于 offline server，见文件头 §1 的 ④）
    const std::vector<uint128_t>& plain_feature_words() const { return plain_words_; }
    // ⚠️ 这是 `MpraqRecord::feature`（**死字段**，D36）**唯一**的去处：纯客户端明文副本，
    //    不参与编码/上传/查询。用途 = 给测试与 demo 一个确定的逐记录标签，便于预估/手算结果。
    const std::vector<int64_t>& plain_feature_values() const { return plain_features_; }
    const std::vector<std::vector<int64_t>>& plain_attribute_values() const {
        return plain_attrs_;
    }
    // 重建出的明文 feature word（由 `plain_words_` 直接读；供测试逐位对照）
    uint128_t PlainFeatureWord(uint64_t i) const;

    // --------------------- 给 MPA-04 / MPA-06 的入口 ---------------------

    // ⚠️ **一列 = 一个条目**：条目号就是全局列号（不再有 word 维度）。
    //    这是上层**唯一**应该用来算条目号的地方。
    uint64_t EntryIndex(uint32_t attr_id, uint32_t column) const;
    // 直接按**全局列号**（= Σ_{a < attr_id} m_a + column）取条目号。
    // 用途：补齐列（`column ∈ [levels, m)`）不属于任何属性，
    // 只有全局列号能定位它（上层 predicate 层永远不会请求补齐列）。
    uint64_t GlobalEntryIndex(size_t global_column) const;
    size_t entry_words() const { return store_.entry_words; }
    size_t levels() const { return store_.levels; }
    size_t m() const { return store_.m; }

    // 取该属性的**明文**列比特（长度恰好 n；word 的第 j 位 = 第 j 条记录）—— 不变量 I3
    std::vector<uint8_t> PlainColumnBits(uint32_t attr_id, uint32_t column) const;

    // 构造一批查询（**只生成查询集，不发 RPC**）
    MpraqQueryBatch CreateQueries(const std::vector<ColumnEntry>& targets);
    // 按**裸条目号**构造（诊断/测试用：补齐列不属于任何属性，只有裸条目号能定位）
    MpraqQueryBatch CreateQueriesForIndices(const std::vector<uint64_t>& flat_indices);
    // 取回一整列（**1 个条目 = 1 个查询集**）⇒ 直接喂 `predicate.hpp` 的
    // `LcteColumnLookup` / `EvaluateFilter`
    MpraqQueryBatch CreateColumnQuery(uint32_t attr_id, uint32_t column);

    // 两台服务器的应答（各自在自己那半 XOR 共享上）：
    //   - `RunBatch`：**整批**查询集走每台服务器的**一次** `ServerRespBatch`
    //     ⇒ **每批 1 次网络往返**（Q5 / `MPRAQ_IMPL.md` §3）。
    //     重建逐条做（客户端本地），返回与批次同序的明文**整列**（每条 entry_words 个字）。
    //   - `RunQuery`：单条路径，走标量 `ServerResp`（1 个查询集 ⇒ 1 次往返）。
    std::vector<PlinkoEntry> RunBatch(MpraqQueryBatch& batch);
    PlinkoEntry RunQuery(MpraqQuery& query);

    // 属性值的**本方**加法共享（mod q，强类型 —— 绝不与 XOR 共享混用）
    ModShare AttributeShare(uint32_t attr_id, size_t record, int server) const;
    // 同一记录的**两台**服务器分量（`first` = 服务器 0、`second` = 服务器 1）。
    // 重建必须用 `ReconstructMod(first, second, modulus())`（**不是** XOR）。
    std::pair<ModShare, ModShare> AttributeShare(uint32_t attr_id, size_t record) const;
    // 该属性全部记录共享分量的快照（长度 N）
    std::vector<ModShare> AttributeShares(uint32_t attr_id, int server) const;

    // 服务器（进程内模式）/ 通道（远程模式）
    MpraqNode& node(int server_id);
    const MpraqNode& node(int server_id) const;
    IMpraqChannel& channel(int server_id);
    // RPC 调用计数（结构性断言用；口径见 `MpraqRpcStats` 的注释）：
    //   * `server_resp_batch_calls` = `ServerRespBatch` 的次数 ⇒ **远程部署下就是 RPC 次数**；
    //   * `server_resp_single_calls` = 标量 `ServerResp` 的次数。
    // ⚠️ 这两个量与"处理了多少个查询集"**不是**一回事：一次 `RunBatch` 里
    //    `batch_calls` 恒为 1，而查询集个数 = `batch.size()`。
    MpraqRpcStats channel_rpc_stats(int server_id) const;
    // 兼容旧名：**标量** `ServerResp` 的调用次数（= `channel_rpc_stats().server_resp_single_calls`）。
    // ⚠️ 它**不是** RPC 次数 —— 批量路径不经过标量接口。
    uint64_t channel_server_resp_calls(int server_id) const;

private:
    // 两条路径共用的**客户端本地**收尾：两台应答 XOR → `ClientRecon`（不产生通道调用）
    PlinkoEntry FinishOne(MpraqQuery& q, const PlinkoAnswer& a0, const PlinkoAnswer& a1);

public:

    // 账目：两台服务器的存储口径与总通信量
    uint64_t storage_bytes(int server_id) const;
    uint64_t upload_bytes() const { return upload_bytes_; }

    // 底层 Plinko 客户端（诊断/测试：hint 子集、候选、覆盖率等）
    const PlinkoClient& plinko() const { return *plinko_; }

private:
    MpraqClient() = default;

    void BuildPlainTable(const std::vector<MpraqRecord>& records);
    // 生成两台服务器的共享**材料**（不落盘/不上传）：③ 掩码 + ④ HintInit + ⑥ α
    void PrepareShares(const MpraqInitParams& params);
    // ⑤ 分块上传到两台服务器（**必须在通道就绪之后**调用）
    void DistributeUpload();

    Schema schema_;
    StoreParams store_;
    MpraqInitParams init_params_;
    MpraqInitTimings timings_;
    MacKeyShares mac_keys_;
    // 共享掩码的确定性随机源（**延迟构造**：`DeterministicPrng` 没有默认构造）
    std::unique_ptr<random::DeterministicPrng> rng_;

    std::unique_ptr<PlinkoClient> plinko_;
    std::vector<uint128_t> plain_words_;                  // 明文特征表（列主序）
    std::vector<int64_t> plain_features_;                 // 明文 feature 列（N 条）
    std::vector<std::vector<int64_t>> plain_attrs_;       // 明文属性值（N × |attrs|）
    std::vector<uint128_t> feature_share0_, feature_share1_;  // 特征 word 的 XOR 共享
    std::vector<std::vector<ModShare>> attr_share0_, attr_share1_;  // 属性值 mod q 共享

    // ⚠️ 声明顺序：两台服务器节点必须在通道之前销毁（通道持有节点的引用）。
    std::vector<std::unique_ptr<MpraqNode>> owned_nodes_;
    std::vector<std::unique_ptr<LocalMpraqChannel>> owned_channels_;
    IMpraqChannel* channels_[2] = {nullptr, nullptr};
    bool owns_nodes_ = true;

    uint64_t upload_bytes_ = 0;
    uint64_t server_resp_calls_[2] = {0, 0};        // 标量 ServerResp 次数
    uint64_t server_resp_batch_calls_[2] = {0, 0};  // 批量 ServerRespBatch 次数 = RPC 次数
    uint64_t server_resp_queries_[2] = {0, 0};      // 累计处理的查询集个数

};

}  // namespace mpraq
}  // namespace tsb
