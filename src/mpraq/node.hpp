#pragma once

// MPRAQ 的**服务器侧节点**（存储）与**与传输无关的通道抽象**（任务 MPA-03）。
//
// 分层意图与 `vmpq/node.hpp` 完全一致：`MpraqNode` 只负责"持有本方共享 → 应答
// `PlinkoQuery`"，不关心消息怎么送到它；于是同一份客户端代码既能跑在进程内
// （测试、单机仿真），也能跑在真实 gRPC 上（MPA-08 demo）。
//
// ===========================================================================
// 1. 数据布局（符号向论文看齐；一个 PIR 条目 = **一整列向量**）
// ===========================================================================
// **表 1：特征表（LCTE，XOR 共享）**
//   * 语义：`n` 条记录 × `levels` 列（LCTE 层），每个单元 1 bit（`LCTE(x) = ([x < r_i])`）。
//   * 打包：**每列**按记录顺序打包成 `entry_words = ⌈n/128⌉` 个 128 位 word，
//     word 的第 `j` 位 = 第 `j` 条记录。
//   * **一个 PIR 条目 = 一整列**：条目 i（= 全局列号 i）就是列 `C_i`，占
//     `entry_words` 个连续 word。⇒ **条目数 = 列数 `m`**（不再是 `列数 × ⌈n/128⌉`）。
//     ⚠️ 于是 **PIR 的 index 就是列索引**，**一次列查询 = 1 个查询集**
//     （旧口径"每条 word 一个条目、一列要 ⌈n/128⌉ 次查询"已作废）。
//   * 补齐（列级）：为满足 Plinko 几何（`m = κ·w`、κ 偶数）追加的**全零列**，
//     条目号 `≥ levels`；明文与两台共享上**恒为 0**，几何公开 ⇒ 不泄露。
//   * 位级补齐：`n` 不是 128 的倍数时，末字的尾部填充位**必须两台恒 0**
//     （不变量 I2）；对外只暴露 `n` bit（不变量 I3）。
//   * 共享：每个条目**整列 XOR 共享**（`s0 ⊕ s1 = 列`，D3/D12 —— 绝不用加法共享）。
//
// **表 2：属性值（每个属性一条长度 `n` 的向量，`mod q` 加法共享）**
//   * `q = 2^127 − 1`（`kMpraqModulus`，D11/D14/D24）；每台服务器存 `n × |attrs|` 个
//     16 字节元素。
//   * ⚠️ 属性值是**加法共享**、特征比特是 **XOR 共享**：本文件用 `ModShare` 与裸
//     `uint128_t`（XOR 分量）两种类型把两者分开，混用在编译期就会报错（D12）。
//
// **存储公式**（本实现口径）：
//     每服务器 = 16 · m · entry_words     （特征表，**含补齐列**）
//              + 16 · n · |attrs|          （属性值）
//   `StorageBytes()` 据此计算；`levels` 与 `m` **必须双报**（补齐前后）。
//
// ===========================================================================
// 2. 范围校验（历史缺陷的反面教材）
// ===========================================================================
// 旧的 VMPQ 服务器侧存储有**堆越界写**与"**静默隐式创建空 vector**"两类缺陷
// （见 `TASK_PLAN.md` §3.2）。本节点**每一个**下标/长度都显式校验并抛异常，
// 绝不静默扩容、绝不静默截断、绝不返回局部缓冲区的引用。

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "core/field.hpp"
#include "mpraq/lcte.hpp"
#include "mpraq/security_mode.hpp"
#include "pir/plinko.hpp"
#include "shared/secret_sharing.hpp"

namespace tsb {
namespace mpraq {

// ---------------------------------------------------------------------------
// 模数（属性值的加法共享，D11/D14/D24）
// ---------------------------------------------------------------------------

// q = 2^127 − 1（梅森素数）。`shared/verify` 的 SPDZ MAC 也要求**奇**模数 q，
// 且推荐恰好是这个值（`core/field` 的 modmul/reduce 在同一量级下工作）。
constexpr uint128_t kMpraqModulus =
    (static_cast<uint128_t>(1) << 127) - static_cast<uint128_t>(1);

// 属性共享向量不参与 PIR 的条目编号 => 用**独立命名空间**的下标，
// 而不是复用全局"列主序条目号"（后者覆盖多个属性，见 StorageBytes 的说明）。
struct AttributeShareRef {
    uint32_t attr_id = 0;
    size_t record = 0;
};

// 一个属性在本层所需的最小描述。
// ⚠️ 刻意**不**依赖 `mpraq/predicate.hpp` 的 `AttributeSchema`：那会把谓词解析层
//    （及其 `BoolExpr`/`PredicatePlan` 等）拖进服务器侧的头文件依赖里。上层
//    （`init.cpp`）负责把 `AttributeSchema` 映射成本结构，两者字段一一对应。
struct StoreAttribute {
    std::string name;         // 可读名（只用于报错信息）
    uint32_t id = 0;          // 必须按 0,1,2,... 连续编号
    LcteParams lcte;          // R = [range_min, range_min + range_size - 1]
    int64_t domain_min = 0;   // 闭取值域下界
    int64_t domain_max = 0;   // 闭取值域上界
};

// ---------------------------------------------------------------------------
// 存储几何（客户端与服务器**必须**用同一份推导）
// ---------------------------------------------------------------------------
//
// ⚠️ 一台服务器只持有**特征表**的共享：属性值共享是"每个属性一条长度 N 的向量"，
// 不参与 PIR 的条目编号，因此 AttributeShareRef 用 (attr_id, record) 定位，
// 不复用全局条目号。

struct StoreParams {
    // ---- 几何（符号向论文看齐）----
    size_t n = 0;             // 记录数 = 列长（bit）
    size_t entry_words = 0;   // 条目宽度（字）= ⌈n/128⌉
    size_t m = 0;             // PIR 条目数 = **补齐后**的 LCTE 层数（一个条目 = 一整列）
    size_t levels = 0;        // 真实（未补齐）的 LCTE 层数 = Σ_a m_a
    // PIR 参数。**必须**满足 `m = κ·w`、`κ` 为偶数、`w` 为 2 的幂（D21/D15(a)）；
    // 且 `plinko.m == m`、`plinko.entry_words == entry_words`（Validate 交叉校验）。
    PlinkoParams plinko;

    // ---- 属性 ----
    std::vector<StoreAttribute> attrs;

    // ---- 运行方式（**接口预留**：本 gate 只把它上线做校验，不改变行为）----
    // 服务端据此**显式校验**客户端与服务端的档位是否一致，不一致即拒绝 ——
    // 这是唯一会静默降级安全性的失败模式（见 `mpraq/security_mode.hpp`）。
    MpraqSecurityMode security_mode = kDefaultMpraqSecurityMode;

    // 本档是否**必须**带 xmac 的 tag（论文 §sec:xmac）。
    // ⚠️ **由档位推出，不另设字段** —— 避免出现"标志说带 tag、档位说半诚实"这种自相矛盾。
    //    恶意档 ⇒ 必须有 tag（xmac 是恶意档的值层完整性机制，没有它就无法检出篡改）；
    //    半诚实档 ⇒ 不生成、不存、不传、不校验 tag（存储与应答各减半）。
    bool has_tags() const { return security_mode == MpraqSecurityMode::kMalicious; }

    // ---- 派生量 ----
    size_t num_attributes() const { return attrs.size(); }
    uint64_t entry_count() const { return static_cast<uint64_t>(m); }  // PIR 条目数 = m
    size_t padding_columns() const { return m - levels; }
    bool is_padded_column(size_t column) const { return column >= levels; }

    // 某个属性第 `column` 列在**全局列号**里的基址：Σ_{a < attr_id} m_a
    size_t column_base(uint32_t attr_id) const;
    size_t global_column(uint32_t attr_id, uint32_t column) const;
    // ⚠️ 一列 = 一个条目：条目号就是全局列号（**不再有 word 维度的展平**）
    uint64_t EntryIndex(uint32_t attr_id, uint32_t column) const;
    uint64_t EntryIndex(size_t global_column) const;

    void Validate() const;
};

// ---------------------------------------------------------------------------
// 服务器节点
// ---------------------------------------------------------------------------

class MpraqNode {
public:
    MpraqNode() = default;

    // 按 schema 分配存储（条目数 = `params.entry_count()`，**含补齐列**）。
    // ⚠️ **档位一致性闸门**：若客户端在 `params.security_mode` 里报的档位与本机
    //    配置的档位不同，**直接拒绝**（`std::invalid_argument`）——
    //    这是唯一会**静默降级安全性**的失败模式（客户端以为在跑恶意档、
    //    服务器按半诚实档应答，或反之），必须在装载阶段就 fail-loudly。
    void InitTable(const StoreParams& params);

    // 本机配置的运行方式（安全档位）。默认恶意档。
    void SetSecurityMode(MpraqSecurityMode m) { configured_security_mode_ = m; }
    MpraqSecurityMode security_mode() const { return configured_security_mode_; }

    // 写入一段**本方**特征 word 共享（XOR 分量）。分块上传由客户端负责。
    // 越界一律抛 std::out_of_range；`words` 长度必须等于 `count`。
    void UploadFeatureWords(uint64_t base_index, const std::vector<uint128_t>& words,
                            size_t count);

    // 便捷版（长度即 count）
    void UploadFeatureWords(uint64_t base_index, const std::vector<uint128_t>& words) {
        UploadFeatureWords(base_index, words, words.size());
    }

    // 写入一段**本方**特征 **tag** 共享（xmac，论文 §sec:xmac）。
    // ⚠️ 与 `UploadFeatureWords` **同形状、同规则**（`base_index` 语义、`entry_words`
    //    对齐、长度校验都一样）——因为 tag 与条目**等宽**（ℓ = 128 = 一个字）。
    // ⚠️ **仅恶意档**调用；半诚实档该表为空（`tag_words_` 不分配）。
    //    在未分配时调用 ⇒ 抛异常（绝不静默写入别处）。
    void UploadFeatureTags(uint64_t base_index, const std::vector<uint128_t>& tags,
                           size_t count);

    // 便捷版（长度即 count）
    void UploadFeatureTags(uint64_t base_index, const std::vector<uint128_t>& tags) {
        UploadFeatureTags(base_index, tags, tags.size());
    }

    // 写入某属性的**本方**加法共享（mod q）。长度必须等于 N；attr_id 越界抛异常。
    void SetAttributeShares(uint32_t attr_id, const std::vector<ModShare>& shares);

    // 服务器侧应答：在本方共享上跑 `PlinkoClient::ServerRespShared`。
    // 两个 parity 分别是"分组 0 / 分组 1"区块上的 XOR 累加；客户端把两台服务器的
    // 应答 XOR 起来即得明文应答（⊕ 与 XOR 共享线性相容，D12/D3）。
    //
    // ⚠️ `ServerResp` 是**标量**接口：一次调用 = 一个查询集 = **一整列**。
    //    **批量路径**请用 `ServerRespBatch`（一次调用处理整批，对应一次网络往返）。
    //    两者都在返回前完成几何/格式校验；`queries_served()` / `words_read()` 的口径相同。
    PlinkoAnswer ServerResp(const PlinkoQuery& q) const;

    // **批量应答**：一次调用处理整批查询集。返回的答案与 `qs` 一一对应（同序同长）。
    //
    // 本地节点语义：循环调用上面的标量实现（进程内没有"往返"可省）。
    // 远程通道语义：**必须**只发**一次** RPC 携带整批查询集（`proto/mpraq.proto`
    // 请求里就是 `repeated` 查询集）—— 这是 Q5（"全部查询集一次 RPC"）与 `MPRAQ_IMPL.md`
    // §3 的硬要求：逐条发 RPC 会让一次多谓词查询变成"每个列 × 每个查询集"个往返。
    // ⚠️ 一次列查询 = **1 个查询集**（一个条目 = 一整列），不再有 word 维度的展开。
    //
    // ⚠️ 校验语义：**先在整批上做几何/格式校验**（与标量路径同一套检查），
    //    再逐条应答 ⇒ 非法批次要么整批 abort、要么整批成功（绝不半途返回部分结果）。
    //    `qs` 为空时抛 `std::invalid_argument`（"空批次"通常是上层算错了目标集合）。
    std::vector<PlinkoAnswer> ServerRespBatch(const std::vector<PlinkoQuery>& qs) const;

    bool initialized() const { return inited_; }
    const StoreParams& params() const { return params_; }
    // PIR 条目数 = m（一个条目 = 一整列）
    uint64_t num_entries() const { return params_.entry_count(); }

    // 读取某个条目的第 `word` 个 XOR 分量（本服务器的 XorBit 家族分量）。
    // ⚠️ **按值返回**：绝不返回内部缓冲区的引用（见文件头 §2 的历史缺陷）。
    uint128_t FeatureEntryWord(uint64_t entry, size_t word) const;
    // 某条目整列的起始指针（entry_words 个连续 word）—— 供 `ServerRespShared` 使用。
    // ⚠️ 生命周期与节点绑定；调用方不得持有超过本次调用。
    const uint128_t* FeatureEntryData(uint64_t entry) const;
    // ---- xmac 的 tag（与特征表**同形状**）：仅恶意档存在 ----
    // 读取某条目第 `word` 个 tag 共享分量（按值返回，理由同 `FeatureEntryWord`）。
    uint128_t FeatureTagWord(uint64_t entry, size_t word) const;
    // 某条目整列的 tag 共享起始指针 —— 供 `ServerRespSharedTagged` 使用。
    const uint128_t* FeatureTagData(uint64_t entry) const;
    bool has_tag_table() const { return !tag_words_.empty(); }
    // 读取某属性某记录的共享分量
    ModShare AttributeShare(uint32_t attr_id, size_t record) const;

    // 存储口径：16·m·entry_words + 16·n·|attrs|
    // ⚠️ **含补齐列**（补齐列是 PIR 数据库的一部分，服务器必须真的存）。
    // ⚠️ **双报**：`FeatureStorageBytes()` 只算数据；tag 单独一项。
    //    恶意档 `StorageBytes() = Feature + FeatureTag + Attribute`；
    //    半诚实档 `FeatureTagStorageBytes() == 0`（该档不存在 tag 表）。
    uint64_t StorageBytes() const;
    uint64_t FeatureStorageBytes() const;    // 特征**数据**表（含补齐条目）
    uint64_t FeatureTagStorageBytes() const; // xmac 的 tag 表（仅恶意档；与数据表等大）
    uint64_t AttributeStorageBytes() const;  // 属性值部分

    // 统计（只增不减，供测试与基准量出"实际发生了多少次 PIR"，而不是靠公式估算）
    // ⚠️ 三个计数器的口径不同，别混用：
    //   * `rpc_count()`          = **标量** `ServerResp` 被调用了几次（= 多少次单条应答）。
    //     批量路径**不**让它增长（那会让"一次往返"与"多少个查询集"两个量纠缠不清）。
    //   * `batch_rpc_count()`    = `ServerRespBatch` 被调用了几次（本地节点 = 方法调用次数；
    //     远程通道应等于"网络往返次数"）。
    //   * `queries_served()` / `words_read()` = 两条路径**共同**累计的工作量口径。
    uint64_t rpc_count() const { return rpc_count_; }            // 标量 ServerResp 调用次数
    uint64_t batch_rpc_count() const { return batch_rpc_count_; }  // 批量 ServerRespBatch 次数
    uint64_t queries_served() const { return queries_served_; }  // 累计查询集个数
    uint64_t words_read() const { return words_read_; }          // 累计读到的 word 数

    void Clear();

private:
    // 校验一条查询（几何 + 格式），非法即抛。标量与批量路径共用。
    void ValidateQuery(const PlinkoQuery& q) const;
    // 单条应答的**核心**：只做累加，不碰计数器（由两条路径分别维护自己的计数）
    PlinkoAnswer AnswerOne(const PlinkoQuery& q) const;

    bool inited_ = false;
    // 本机（服务器进程）配置的档位；`InitTable` 用它做一致性校验（防静默降级）。
    MpraqSecurityMode configured_security_mode_ = kDefaultMpraqSecurityMode;
    StoreParams params_;
    std::vector<uint128_t> words_;                          // 特征表（字典布局，含补齐条目）
    // xmac 的 tag 表（与 `words_` **同形状**）。**仅恶意档**分配；半诚实档为空。
    std::vector<uint128_t> tag_words_;
    std::vector<std::vector<ModShare>> attr_shares_;        // 每属性一条长度 N 的向量
    mutable uint64_t rpc_count_ = 0;
    mutable uint64_t batch_rpc_count_ = 0;
    mutable uint64_t queries_served_ = 0;
    mutable uint64_t words_read_ = 0;
};

// ---------------------------------------------------------------------------
// 客户端 → 单台服务器的通道
// ---------------------------------------------------------------------------
//
// ⚠️ 这里的 `WarnUnbatchedServerResp()`（"走了退化默认实现"的一次性告警）已随
//    `ServerRespBatch` 的**纯虚化**一并删除（`MPA-08` 裁决 2，2026-09-10）：
//    纯虚之后"默认实现被触发"这一状态**在类型层面不可能存在**，留一个永不触发的
//    告警函数只会让人误以为仍有退化路径。全库无调用点（`grep` 确认，删除后由
//    编译器兜底：任何残留调用都会在链接期失败）。

class IMpraqChannel {
public:
    virtual ~IMpraqChannel() = default;

    virtual void InitTable(const StoreParams& params) = 0;
    virtual void UploadFeatureWords(uint64_t base_index,
                                    const std::vector<uint128_t>& words,
                                    size_t count) = 0;
    // xmac 的 tag 上传（**仅恶意档**调用；半诚实档的客户端根本不调）。
    // ⚠️ 同样保持**纯虚**：忘记覆写 = 编译期错误，而不是运行期静默少传（本仓库纪律）。
    virtual void UploadFeatureTags(uint64_t base_index,
                                   const std::vector<uint128_t>& tags,
                                   size_t count) = 0;
    virtual void SetAttributeShares(uint32_t attr_id,
                                    const std::vector<ModShare>& shares) = 0;

    // 单条应答（标量）。一次调用 = 一个查询集。
    virtual PlinkoAnswer ServerResp(const PlinkoQuery& q) = 0;

    // **整批一次往返**：`qs` 里全部查询集走**一次** `ServerRespBatch` 调用。
    //
    // ⚠️ 这是 Q5 与 `MPRAQ_IMPL.md` §3 的口径落地：一次 `AggQuery`
    //    （全部谓词涉及的**全部列的全部 word**）只对应**一次** RPC。
    //    * 本地通道（`LocalMpraqChannel`）：一次方法调用，内部循环（无往返可省）；
    //    * 远程通道（`MPA-08` 的 `GrpcMpraqChannel`）：必须只发 **1 次** RPC，
    //      请求里带整批查询集（`proto/mpraq.proto` 的 `repeated`），因为逐条发会让
    //      `N = 2^14` 的一列（128 个 word）变成 128 个往返（回环 ~1.6 ms/次 ⇒ ~200 ms/列）。
    //
    // ✅ **纯虚**（`MPA-08` 裁决 2，2026-09-10）：本方法此前有一个"对每条调用标量
    //    `ServerResp`（语义正确但退化成 N 次往返）"的默认实现，当时的顾虑是
    //    "纯虚会直接破坏进行中的 `MPA-08` 构建"。现在**全部实现方都已覆写**：
    //      * `LocalMpraqChannel`（进程内：一次方法调用、内部循环）；
    //      * `GrpcMpraqChannel`（`MPA-08`：整批装进**一个** `PirQueryRequest` ⇒ 1 次 RPC）；
    //      * `PlaceholderRemoteMpraqChannel`（**大声抛异常**，绝不静默退化）；
    //      * 测试里的装饰器 `InjectChannel`（`test_mpraq_malicious.cpp`，它转调内层通道）。
    //    ⇒ 改成纯虚，让"忘记覆写"变成**编译期错误**。`tests/test_mpraq_grpc.cpp` 里有
    //    `static_assert(std::is_abstract<ChannelWithoutBatch>::value, ...)` 把这条
    //    性质钉住：若将来有人把默认实现加回来，那条断言会当场编译失败。
    //    ⚠️ 纯虚化**不改变**任何实现方的语义、也不改变任何调用点的行为。
    virtual std::vector<PlinkoAnswer> ServerRespBatch(
        const std::vector<PlinkoQuery>& qs) = 0;

    // 远程通道需要显式建立连接；进程内通道为空操作
    virtual void Connect() {}

    // **本通道已收到的应答字节数**（下行口径；账目/实验用）。
    // ⚠️ 这里给**默认实现 0** 是**刻意的**、不是偷懒：
    //    * 进程内通道（`LocalMpraqChannel`）**根本没有"线上字节"** ⇒ 0 是**语义正确**的值；
    //    * 只有真实 gRPC 通道才需要覆写它（按 `ByteSizeLong()` 实测）。
    //    ⇒ 与 `ServerRespBatch` 那种"忘记覆写会静默退化成 N 次往返"的情形不同，
    //      这里默认 0 不会掩盖任何错误。
    virtual uint64_t recv_bytes() const { return 0; }
};

// 进程内通道：直接调用本地节点，无序列化开销
class LocalMpraqChannel : public IMpraqChannel {
public:
    explicit LocalMpraqChannel(MpraqNode& node) : node_(node) {}

    void InitTable(const StoreParams& params) override { node_.InitTable(params); }
    void UploadFeatureWords(uint64_t base_index,
                            const std::vector<uint128_t>& words,
                            size_t count) override {
        node_.UploadFeatureWords(base_index, words, count);
    }
    void UploadFeatureTags(uint64_t base_index, const std::vector<uint128_t>& tags,
                           size_t count) override {
        node_.UploadFeatureTags(base_index, tags, count);
    }
    void SetAttributeShares(uint32_t attr_id,
                            const std::vector<ModShare>& shares) override {
        node_.SetAttributeShares(attr_id, shares);
    }
    PlinkoAnswer ServerResp(const PlinkoQuery& q) override {
        return node_.ServerResp(q);
    }
    // 一次方法调用处理整批（进程内直连，无序列化 ⇒ 没有"往返"概念可省）
    std::vector<PlinkoAnswer> ServerRespBatch(
        const std::vector<PlinkoQuery>& qs) override {
        return node_.ServerRespBatch(qs);
    }

    MpraqNode& node() { return node_; }
    const MpraqNode& node() const { return node_; }

private:
    MpraqNode& node_;
};

// ⚠️ 远程模式**占位**：真正的 gRPC 通道是 `MPA-08`（需要 MPRAQ 自己的
// `proto/mpraq.proto` + `src/net/grpc_mpraq.*`，语义与 `proto/vmpq.proto` 不同：
// 特征 word 共享上传、属性值共享上传、**一次 RPC 携带全部列的全部查询集**）。
// 在此之前**任何**远程路径都必须**显式报错**，绝不静默退化成本地调用。
class RemoteMpraqChannelNotImplemented : public std::logic_error {
public:
    explicit RemoteMpraqChannelNotImplemented(const std::string& what)
        : std::logic_error(what) {}
};

// 远程模式的接口占位实现（仅供上层提前按 `IMpraqChannel` 编程）。
//
// ⚠️ `ServerRespBatch` 现在是**纯虚**（`MPA-08` 裁决 2）：本占位**必须**实现它，
//    实现方式是**大声抛异常**（`RemoteMpraqChannelNotImplemented`，消息里说明
//    "远程通道必须覆写 `ServerRespBatch`"）—— 绝不静默退化成本地调用、
//    也绝不偷偷逐条发 RPC。`test_mpraq_grpc.cpp` 有专门用例钉住这条语义。
class PlaceholderRemoteMpraqChannel : public IMpraqChannel {
public:
    explicit PlaceholderRemoteMpraqChannel(std::string endpoint)
        : endpoint_(std::move(endpoint)) {}

    void Connect() override;
    void InitTable(const StoreParams&) override;
    void UploadFeatureWords(uint64_t, const std::vector<uint128_t>&, size_t) override;
    void UploadFeatureTags(uint64_t, const std::vector<uint128_t>&, size_t) override;
    void SetAttributeShares(uint32_t, const std::vector<ModShare>&) override;
    PlinkoAnswer ServerResp(const PlinkoQuery&) override;
    // 同上：占位通道**任何**远程调用都抛（绝不静默退化成本地调用）
    std::vector<PlinkoAnswer> ServerRespBatch(
        const std::vector<PlinkoQuery>&) override;

    const std::string& endpoint() const { return endpoint_; }

private:
    [[noreturn]] void Unsupported(const char* what) const;
    std::string endpoint_;
};

}  // namespace mpraq
}  // namespace tsb
