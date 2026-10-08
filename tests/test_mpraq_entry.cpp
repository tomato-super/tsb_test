// `test_mpraq_entry` —— 列粒度迁移的**条目精确性契约**（不变量 I1–I4）与 D40 护栏。
//
// ===========================================================================
// 为什么这份测试是迁移的核心验收
// ===========================================================================
// 迁移把 PIR 条目从「128 位 word」改成「**一整列向量**」：条目数 = LCTE 层数 `m`、
// PIR index = 列索引、hint parity = 整列。只要有一个环节把"字"与"条目"搞混，
// 结果就会**静默错值**（旧口径下这正是"错 128 倍"的来源）。因此本测试把四条不变量
// 写成可执行断言：
//
//   **I1** 宽度自洽：`D[i].words.size() == entry_words == ⌈n/128⌉`
//   **I2** 位级填充：`n` 不是 128 的倍数时，末字尾部 `j >= n` 的 bit **两台恒 0**，
//        且重建出的整列在这些位置也是 0
//   **I3** 只暴露 n bit：上层拿到的列比特长度**恰好 n**，绝不外泄填充位
//   **I4** 宽度不符即拒绝：`entry_words` 与数据库登记不一致 ⇒ 抛异常（不截断、不补零）
//
// 另有 **E1 精确性矩阵**：`n ∈ {1,127,128,129,255,256,1000}`（覆盖 128 的边界两侧、
// 非 2 的幂、非 128 的倍数），逐记录与**独立转写**的 LCTE 语义对照 —— 不复用被测
// 代码的编码路径（铁律 D6：每个算法都要有确定性期望值测试）。
//
// 以及 **D40 护栏**：`Headline()`/`Report()` 必须是**纯 ASCII** 的裸 `key=value`；
// 任何解释文字漏进运行期输出都会让这条断言失败。

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "core/gf128.hpp"
#include "mpraq/aggquery.hpp"
#include "mpraq/init.hpp"
#include "net/grpc_mpraq.hpp"
#include "mpraq/secure_mul_flow.hpp"
#include "mpraq/node.hpp"
#include "mpraq/predicate.hpp"
#include "mpraq/scale_config.hpp"
#include "mpraq/security_mode.hpp"
#include "test_framework.hpp"

namespace {

using namespace tsb;
using namespace tsb::mpraq;

// ---------------------------------------------------------------------------
// 夹具：确定性 schema + 记录（同一 seed ⇒ 逐位可复现）
// ---------------------------------------------------------------------------

struct Fix {
    Schema schema;
    std::vector<MpraqRecord> records;
    size_t n = 0;
    uint32_t cols_per_attr = 0;
    std::unique_ptr<MpraqClient> client;
};

// 取值域 [0, C-2] ⇒ 跨度 = C-2，range_size = C 满足无损条件 `range_size >= 跨度+2`。
Fix MakeFix(size_t n, uint32_t cols_per_attr = 2, uint32_t attrs = 2, uint32_t lambda = 24,
            MpraqSecurityMode mode = MpraqSecurityMode::kMalicious) {
    Fix f;
    f.n = n;
    f.cols_per_attr = cols_per_attr;
    for (uint32_t a = 0; a < attrs; ++a) {
        AttributeSchema at;
        at.name = "a" + std::to_string(a);
        at.id = a;
        at.lcte.window_size = static_cast<uint32_t>(n);
        at.lcte.range_min = 0;
        at.lcte.range_size = cols_per_attr;
        at.domain_min = 0;
        at.domain_max = static_cast<int64_t>(cols_per_attr) - 2;
        f.schema.AddAttribute(at);
    }
    f.records.resize(n);
    for (size_t i = 0; i < n; ++i) {
        f.records[i].feature = static_cast<int64_t>(i);   // D36 的死字段（只做行标签）
        f.records[i].attributes.resize(attrs);
        for (uint32_t a = 0; a < attrs; ++a) {
            f.records[i].attributes[a] = static_cast<int64_t>((i + a) % (cols_per_attr - 1));
        }
    }
    MpraqInitParams p;
    p.lambda = lambda;
    p.prp_epsilon = 1e-6;
    p.seed = 7;
    p.security_mode = mode;
    f.client = MpraqClient::Init(f.schema, f.records, p);
    return f;
}

// **独立转写**的 LCTE 期望值（不复用被测代码的编码路径）：
//   第 j 位 = [x < r_min + j]
std::vector<uint8_t> ExpectedColumnBits(const Fix& f, uint32_t attr, uint32_t col) {
    const AttributeSchema& as = f.schema.ById(attr);
    std::vector<uint8_t> out(f.n, 0);
    for (size_t i = 0; i < f.n; ++i) {
        const int64_t v = f.records[i].attributes[attr];
        out[i] = (v < as.lcte.range_min + static_cast<int64_t>(col)) ? 1 : 0;
    }
    return out;
}

uint8_t BitOf(const PlinkoEntry& e, size_t j) {
    return static_cast<uint8_t>((e[j / 128] >> (j % 128)) & static_cast<uint128_t>(1));
}

// 取回某一列的原始整列（走真正的 PIR 路径：QueryGen → 两台 ServerRespBatch → Recon）
PlinkoEntry RetrieveRawEntry(Fix& f, uint32_t attr, uint32_t col) {
    MpraqQueryBatch batch = f.client->CreateColumnQuery(attr, col);
    std::vector<PlinkoEntry> cols = f.client->RunBatch(batch);
    if (cols.size() != 1) {
        TSB_FAIL_("一次列查询应当重建出恰好 1 个整列");
        return {};
    }
    return cols[0];
}

bool AsciiOnly(const std::string& s) {
    for (unsigned char c : s) {
        if (c >= 0x80) return false;
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// E1：精确性矩阵 —— 逐记录对照独立转写的 LCTE 语义
// ---------------------------------------------------------------------------

TEST(MpraqEntry, ExactColumnReconstructionAcrossN) {
    // 128 的边界两侧（127/128/129）、非 128 倍数（1000）、退化（1）、2 的幂（256）
    const std::vector<size_t> ns = {1, 127, 128, 129, 255, 256, 1000};
    for (size_t n : ns) {
        Fix f = MakeFix(n);
        for (uint32_t attr = 0; attr < 2; ++attr) {
            for (uint32_t col = 0; col < f.cols_per_attr; ++col) {
                const PlinkoEntry e = RetrieveRawEntry(f, attr, col);
                const std::vector<uint8_t> want = ExpectedColumnBits(f, attr, col);
                if (e.size() * 128 < n) {
                    TSB_FAIL_("n=" + std::to_string(n) + " 的重建整列宽度不足");
                    continue;
                }
                for (size_t i = 0; i < n; ++i) {
                    if (BitOf(e, i) != want[i]) {
                        TSB_FAIL_("n=" + std::to_string(n) + " attr=" + std::to_string(attr) +
                                  " col=" + std::to_string(col) + " 第 " +
                                  std::to_string(i) + " 位不符");
                        break;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// I1 / I2：宽度自洽 + 尾部填充位两台恒 0（且重建出的整列也为 0）
// ---------------------------------------------------------------------------

TEST(MpraqEntry, EntryWidthAndTailPadding) {
    for (size_t n : {1, 127, 129, 1000}) {   // 都**不是** 128 的倍数
        Fix f = MakeFix(n);
        const StoreParams& sp = f.client->store_params();
        EXPECT_EQ(sp.entry_words, (n + 127) / 128);          // I1
        EXPECT_EQ(sp.n, n);

        const PlinkoEntry e = RetrieveRawEntry(f, 0, 0);
        EXPECT_EQ(e.size(), sp.entry_words);                 // I1
        // I2：重建出的整列在 `j >= n` 处必须为 0（填充位不得变成数据）
        for (size_t j = n; j < sp.entry_words * 128; ++j) {
            if (BitOf(e, j) != 0) {
                TSB_FAIL_("n=" + std::to_string(n) + " 的重建整列在填充位 j=" +
                          std::to_string(j) + " 非 0");
                break;
            }
        }
        // I2：两台服务器的**分片**在同一位置也必须同为 0（0 ⊕ 0 = 0，不是靠掩码相消）
        for (int s = 0; s < 2; ++s) {
            const MpraqNode& node = f.client->node(s);
            for (size_t w = 0; w < sp.entry_words; ++w) {
                const uint128_t word = node.FeatureEntryWord(0, w);
                for (size_t bit = 0; bit < 128; ++bit) {
                    const size_t j = w * 128 + bit;
                    if (j < n) continue;
                    if (((word >> bit) & static_cast<uint128_t>(1)) != 0) {
                        TSB_FAIL_("服务器 " + std::to_string(s) + " 的分片在填充位 j=" +
                                  std::to_string(j) + " 非 0");
                        break;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// I3：上层只暴露**恰好 n 个有效 bit**
// ---------------------------------------------------------------------------

TEST(MpraqEntry, UpperLayerExposesExactlyNBits) {
    for (size_t n : {1, 127, 129, 1000}) {
        Fix f = MakeFix(n);
        const std::vector<uint8_t> bits = RetrieveColumnBits(*f.client, f.schema, 0, 0);
        EXPECT_EQ(bits.size(), n);
        const std::vector<uint8_t> want = ExpectedColumnBits(f, 0, 0);
        for (size_t i = 0; i < n; ++i) {
            if (bits[i] != want[i]) {
                TSB_FAIL_("n=" + std::to_string(n) + " 的上层列比特第 " + std::to_string(i) +
                          " 位不符");
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// E5：**一次列查询 = 1 个查询集 = 每台 1 次批量 RPC**（计数器断言，非公式断言）
// ---------------------------------------------------------------------------

TEST(MpraqEntry, OneColumnIsOneQuerySetAndOneRpcPerServer) {
    Fix f = MakeFix(1024);
    const MpraqRpcStats before0 = f.client->channel_rpc_stats(0);
    const MpraqRpcStats before1 = f.client->channel_rpc_stats(1);
    const uint64_t q0 = f.client->node(0).queries_served();
    const uint64_t q1 = f.client->node(1).queries_served();

    const PlinkoEntry e = RetrieveRawEntry(f, 0, 0);
    EXPECT_EQ(e.size(), f.client->store_params().entry_words);

    const MpraqRpcStats after0 = f.client->channel_rpc_stats(0);
    const MpraqRpcStats after1 = f.client->channel_rpc_stats(1);
    // 一台一次批量调用（= 一次网络往返），标量路径恒 0
    EXPECT_EQ(after0.server_resp_batch_calls - before0.server_resp_batch_calls, 1u);
    EXPECT_EQ(after1.server_resp_batch_calls - before1.server_resp_batch_calls, 1u);
    EXPECT_EQ(after0.server_resp_single_calls - before0.server_resp_single_calls, 0u);
    EXPECT_EQ(after1.server_resp_single_calls - before1.server_resp_single_calls, 0u);
    // 查询集个数 = 1（**不是** ⌈n/128⌉）
    EXPECT_EQ(after0.queries - before0.queries, 1u);
    EXPECT_EQ(f.client->node(0).queries_served() - q0, 1u);
    EXPECT_EQ(f.client->node(1).queries_served() - q1, 1u);
}

// ---------------------------------------------------------------------------
// I4：宽度不符即拒绝（两处闸门：StoreParams 交叉校验 + 服务端查询校验）
// ---------------------------------------------------------------------------

TEST(MpraqEntry, WidthMismatchIsRejected) {
    Fix f = MakeFix(1000);
    const StoreParams sp = f.client->store_params();

    // ① StoreParams 的静态交叉校验：plinko.entry_words 与 entry_words 必须一致
    {
        StoreParams bad = sp;
        bad.plinko.entry_words = sp.entry_words + 1;
        EXPECT_THROW(bad.Validate(), std::invalid_argument);
    }
    // ② plinko.m 与 m 必须一致
    {
        StoreParams bad = sp;
        bad.plinko.m = sp.m + 2;
        if ((sp.m + 2) % bad.plinko.w == 0) {   // 保持 w | m，让失败只能来自 m 不一致
            bad.plinko.m = sp.m + 2 * bad.plinko.w;
        }
        EXPECT_THROW(bad.Validate(), std::invalid_argument);
    }
    // ③ 服务端的运行期闸门：查询携带的 entry_words 与数据库不符 ⇒ 抛（不截断、不补零）
    {
        MpraqQueryBatch batch = f.client->CreateColumnQuery(0, 0);
        PlinkoQuery q = batch.at(0).query();
        q.entry_words = sp.entry_words + 1;
        EXPECT_THROW(f.client->node(0).ServerRespBatch({q}), std::invalid_argument);
    }
    // ④ 条目号越界（一列 = 一个条目 ⇒ 条目号必须 < m）
    {
        StoreParams bad = sp;
        EXPECT_THROW(bad.EntryIndex(static_cast<size_t>(sp.m)), std::out_of_range);
    }
}

// ---------------------------------------------------------------------------
// E7：列级补齐（全零列）—— 两台分片恒 0，且不参与真实列
// ---------------------------------------------------------------------------

TEST(MpraqEntry, PaddingColumnsAreZeroOnBothServers) {
    // cols_per_attr = 3、attrs = 1 ⇒ levels = 3（奇数）；几何要求 2w | m ⇒ 必须补列
    Fix f = MakeFix(64, /*cols_per_attr=*/3, /*attrs=*/1);
    const StoreParams& sp = f.client->store_params();
    EXPECT_TRUE(sp.m >= sp.levels);
    EXPECT_TRUE(sp.padding_columns() > 0);   // 这个 schema 一定触发补齐

    for (size_t entry = sp.levels; entry < sp.m; ++entry) {
        for (int s = 0; s < 2; ++s) {
            const MpraqNode& node = f.client->node(s);
            for (size_t w = 0; w < sp.entry_words; ++w) {
                if (node.FeatureEntryWord(entry, w) != 0) {
                    TSB_FAIL_("补齐条目 " + std::to_string(entry) + " 在服务器 " +
                              std::to_string(s) + " 上非 0");
                    break;
                }
            }
        }
    }
    // 真实列仍然逐位正确
    for (uint32_t col = 0; col < sp.levels; ++col) {
        const PlinkoEntry e = RetrieveRawEntry(f, 0, col);
        const std::vector<uint8_t> want = ExpectedColumnBits(f, 0, col);
        for (size_t i = 0; i < f.n; ++i) {
            if (BitOf(e, i) != want[i]) {
                TSB_FAIL_("补齐几何下第 " + std::to_string(col) + " 列第 " + std::to_string(i) +
                          " 位不符");
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// D40 护栏：运行期输出只出裸 `key=value`（纯 ASCII）
// ---------------------------------------------------------------------------

TEST(MpraqEntry, HeadlineAndReportAreBareAsciiKeyValues) {
    for (auto [rows, cols, attrs, preds] :
         std::vector<std::tuple<uint64_t, uint32_t, uint32_t, uint32_t>>{
             {256, 8, 2, 3}, {1024, 32, 2, 5}, {4096, 32, 3, 2}}) {
        MpraqScaleConfig cfg;
        cfg.rows = rows;
        cfg.columns_per_attribute = cols;
        cfg.attributes = attrs;
        cfg.predicates = preds;
        const MpraqScaleSetup setup = Build(cfg);
        const std::string head = setup.estimate.Headline();
        const std::string report = setup.estimate.Report();
        // D40：任何非 ASCII 字节都说明"解释文字"漏进了运行期输出
        EXPECT_TRUE(AsciiOnly(head));
        EXPECT_TRUE(AsciiOnly(report));
        // 且必须仍包含关键结果值（不是被删空）
        // 符号按 D41：n = 记录数、levels = 真实层数、security = 档位
        EXPECT_TRUE(head.find("n=") != std::string::npos);
        EXPECT_TRUE(head.find("levels=") != std::string::npos);
        EXPECT_TRUE(head.find("qsets=") != std::string::npos);
        EXPECT_TRUE(head.find("rpc=") != std::string::npos);
        EXPECT_TRUE(head.find("security=malicious") != std::string::npos);
        EXPECT_TRUE(report.find("budget=") != std::string::npos);
        if (!AsciiOnly(head)) TSB_FAIL_("Headline 含非 ASCII：" + head);
        if (!AsciiOnly(report)) TSB_FAIL_("Report 含非 ASCII：" + report);
    }
}

// ---------------------------------------------------------------------------
// 规模派生量 vs Init 实测：公式必须等于实测（迁移后口径）
// ---------------------------------------------------------------------------

TEST(MpraqEntry, EstimateMatchesMeasuredGeometry) {
    MpraqScaleConfig cfg;
    cfg.rows = 1024;
    cfg.columns_per_attribute = 8;
    cfg.attributes = 2;
    cfg.predicates = 3;
    const MpraqScaleSetup setup = Build(cfg);
    auto client = MpraqClient::Init(setup.schema, setup.records, setup.init);
    const StoreParams& sp = client->store_params();
    const MpraqScaleEstimate& e = setup.estimate;

    EXPECT_EQ(sp.n, e.rows);
    EXPECT_EQ(sp.entry_words, e.entry_words);
    EXPECT_EQ(sp.levels, e.levels);
    EXPECT_EQ(sp.m, e.m);
    EXPECT_EQ(sp.plinko.blocks(), e.kappa);
    // 存储公式 = 实测（含补齐）
    EXPECT_EQ(client->node(0).StorageBytes(), e.storage_bytes_padded);
    // 一次列查询的查询集数 = 1（规模层口径：查询集 = 去重列数）
    EXPECT_EQ(e.query_sets, e.dedup_columns);
}

// ---------------------------------------------------------------------------
// 半诚实档的**接口预留**契约（本阶段只留接口，不落地行为）
// ---------------------------------------------------------------------------

TEST(MpraqEntry, SecurityModeInterfaceIsStrictAndGateIsLive) {
    using tsb::mpraq::kDefaultMpraqSecurityMode;
    using tsb::mpraq::MpraqSecurityMode;
    using tsb::mpraq::MpraqSecurityModeFromRaw;
    using tsb::mpraq::MpraqSecurityModeName;
    using tsb::mpraq::ParseMpraqSecurityMode;

    // ① 默认档 = 恶意档（半诚实是**显式 opt-in**）
    EXPECT_TRUE(kDefaultMpraqSecurityMode == MpraqSecurityMode::kMalicious);

    // ② 名称唯一且稳定（进 JSON / 输出 / proto）
    EXPECT_EQ(std::string(MpraqSecurityModeName(MpraqSecurityMode::kMalicious)), "malicious");
    EXPECT_EQ(std::string(MpraqSecurityModeName(MpraqSecurityMode::kSemiHonest)), "semi-honest");

    // ③ **严格解析**：只认两个字面量；拼错/大小写不符/带空格/空串一律拒绝
    EXPECT_TRUE(ParseMpraqSecurityMode("malicious") == MpraqSecurityMode::kMalicious);
    EXPECT_TRUE(ParseMpraqSecurityMode("semi-honest") == MpraqSecurityMode::kSemiHonest);
    EXPECT_THROW(ParseMpraqSecurityMode("Malicious"), std::invalid_argument);
    EXPECT_THROW(ParseMpraqSecurityMode("semi_honest"), std::invalid_argument);
    EXPECT_THROW(ParseMpraqSecurityMode("semi-honest "), std::invalid_argument);
    EXPECT_THROW(ParseMpraqSecurityMode(""), std::invalid_argument);

    // ④ 线上/存储来的整数：非法编码**抛异常**，绝不静默回落默认档
    EXPECT_TRUE(MpraqSecurityModeFromRaw(0) == MpraqSecurityMode::kSemiHonest);
    EXPECT_TRUE(MpraqSecurityModeFromRaw(1) == MpraqSecurityMode::kMalicious);
    EXPECT_THROW(MpraqSecurityModeFromRaw(2), std::invalid_argument);
    EXPECT_THROW(MpraqSecurityModeFromRaw(7), std::invalid_argument);

    // ⑤ `StoreParams::Validate` 挡住"程序内构造出的非法档位"
    {
        Fix f = MakeFix(64);
        StoreParams bad = f.client->store_params();
        bad.security_mode = static_cast<MpraqSecurityMode>(7);   // static_cast 编译得过
        EXPECT_THROW(bad.Validate(), std::invalid_argument);
    }

    // ⑥ **服务端一致性闸门**：档位不一致 ⇒ 拒绝装载（唯一的静默降级失败模式）
    {
        Fix f = MakeFix(64);
        const StoreParams sp = f.client->store_params();
        EXPECT_TRUE(sp.security_mode == MpraqSecurityMode::kMalicious);   // 夹具用默认档

        MpraqNode semi;
        semi.SetSecurityMode(MpraqSecurityMode::kSemiHonest);
        EXPECT_THROW(semi.InitTable(sp), std::invalid_argument);          // 不一致 ⇒ 拒绝
        EXPECT_THROW(semi.FeatureEntryWord(0, 0), std::logic_error);      // 且没被装载进去

        MpraqNode same;
        same.SetSecurityMode(MpraqSecurityMode::kMalicious);
        same.InitTable(sp);                                              // 一致 ⇒ 正常装载
        EXPECT_EQ(same.security_mode(), MpraqSecurityMode::kMalicious);
    }

    // ⑦ 配置层：非法档位在 `Build` 阶段就被拒绝（不静默回落）
    {
        MpraqScaleConfig cfg;
        cfg.security_mode = static_cast<MpraqSecurityMode>(9);
        EXPECT_THROW(Build(cfg), std::invalid_argument);
    }
    {
        MpraqScaleOverrides ov;
        EXPECT_THROW(ov.Set("security-mode", "semi_honest"), std::invalid_argument);
        ov.Set("security-mode", "semi-honest");                          // 合法值可写入
        MpraqScaleConfig cfg;
        cfg.security_mode = MpraqSecurityMode::kMalicious;
        EXPECT_TRUE(ApplyOverrides(cfg, ov).security_mode == MpraqSecurityMode::kSemiHonest);
    }
}

// ---------------------------------------------------------------------------
// xmac 的 tag 存储契约（**半诚实档保留**的落点）
// ---------------------------------------------------------------------------

TEST(MpraqEntry, TagStorageIsPresentOnlyInMaliciousMode) {
    using tsb::mpraq::MpraqSecurityMode;

    // ① 恶意档：tag 表存在，且与数据表**等大**（tag 与条目等宽，ℓ = 128 = 一个字）
    {
        Fix f = MakeFix(256, 2, 2, 24, MpraqSecurityMode::kMalicious);
        const StoreParams& sp = f.client->store_params();
        EXPECT_TRUE(sp.has_tags());
        for (int srv = 0; srv < 2; ++srv) {
            const MpraqNode& node = f.client->node(srv);
            EXPECT_TRUE(node.has_tag_table());
            EXPECT_EQ(node.FeatureTagStorageBytes(), node.FeatureStorageBytes());
            EXPECT_EQ(node.StorageBytes(),
                      node.FeatureStorageBytes() + node.FeatureTagStorageBytes() +
                          node.AttributeStorageBytes());
        }
        // ---- tag 分片的**代数契约**（比"未上传 ⇒ 全 0"强得多）----
        // 真实条目：两台的 tag 异或 == γ ⊙ 明文（论文 :122-123 的定义式）
        const uint128_t gamma = f.client->tag_key();
        EXPECT_TRUE(gamma != 0);                       // γ ←$ GF(2^128)\{0}，绝不为 0
        const std::vector<uint128_t>& plain = f.client->plain_feature_words();
        const std::vector<uint128_t>& t0 = f.client->tag_share(0);
        const std::vector<uint128_t>& t1 = f.client->tag_share(1);
        EXPECT_EQ(t0.size(), plain.size());
        EXPECT_EQ(t1.size(), plain.size());
        for (size_t e = 0; e < sp.levels; ++e) {       // 真实条目
            for (size_t w = 0; w < sp.entry_words; ++w) {
                const size_t i = e * sp.entry_words + w;
                if (static_cast<uint128_t>(t0[i] ^ t1[i]) !=
                    tsb::Gf128Mul(gamma, plain[i])) {
                    TSB_FAIL_("条目 " + std::to_string(e) + " 第 " + std::to_string(w) +
                              " 字的 tag 不满足 mac1 ^ mac2 == γ ⊙ D");
                    break;
                }
            }
        }
        for (size_t e = sp.levels; e < sp.m; ++e) {    // 补齐条目：两台**恒 0**（与 I2 同纪律）
            for (size_t w = 0; w < sp.entry_words; ++w) {
                const size_t i = e * sp.entry_words + w;
                if (t0[i] != 0 || t1[i] != 0) {
                    TSB_FAIL_("补齐条目 " + std::to_string(e) + " 的 tag 非 0（留下了结构性痕迹）");
                    break;
                }
            }
        }
        // 服务器的 tag 表内容 == 客户端上传的分片（确实上传了，不是预留空表）
        for (size_t w = 0; w < sp.entry_words; ++w) {
            EXPECT_EQ(f.client->node(0).FeatureTagWord(1, w), t0[sp.entry_words + w]);
            EXPECT_EQ(f.client->node(1).FeatureTagWord(1, w), t1[sp.entry_words + w]);
        }
    }

    // ② 半诚实档：**没有** tag 表 ⇒ 存储减半（这是"半诚实档保留"的核心契约）
    {
        Fix f = MakeFix(256, 2, 2, 24, MpraqSecurityMode::kSemiHonest);
        const StoreParams& sp = f.client->store_params();
        EXPECT_FALSE(sp.has_tags());
        for (int srv = 0; srv < 2; ++srv) {
            const MpraqNode& node = f.client->node(srv);
            EXPECT_FALSE(node.has_tag_table());
            EXPECT_EQ(node.FeatureTagStorageBytes(), 0u);
            EXPECT_EQ(node.StorageBytes(),
                      node.FeatureStorageBytes() + node.AttributeStorageBytes());
        }
        // 半诚实档下碰 tag ⇒ **抛异常**（绝不静默返回 0 或写入别处）
        EXPECT_THROW(f.client->node(0).FeatureTagWord(0, 0), std::logic_error);
        EXPECT_THROW(f.client->node(0).FeatureTagData(0), std::logic_error);
        std::vector<uint128_t> junk(static_cast<size_t>(sp.entry_words), 0);
        EXPECT_THROW(f.client->node(0).UploadFeatureTags(0, junk), std::logic_error);
    }

    // ③ tag 上传的对齐检查（不变量 I5：tag 与条目等宽 ⇒ 必须是 entry_words 的整数倍）
    {
        Fix f = MakeFix(256, 2, 2, 24, MpraqSecurityMode::kMalicious);
        const StoreParams& sp = f.client->store_params();
        EXPECT_TRUE(sp.entry_words >= 2);
        std::vector<uint128_t> bad(static_cast<size_t>(sp.entry_words) - 1, 0);
        EXPECT_THROW(f.client->node(0).UploadFeatureTags(0, bad), std::invalid_argument);
        // 合法长度：能写入且能读回
        std::vector<uint128_t> good = {0x1234u, 0x5678u};
        if (sp.entry_words == 2) {
            f.client->node(0).UploadFeatureTags(0, good);
            EXPECT_EQ(f.client->node(0).FeatureTagWord(0, 0), static_cast<uint128_t>(0x1234u));
            EXPECT_EQ(f.client->node(0).FeatureTagWord(0, 1), static_cast<uint128_t>(0x5678u));
        }
    }
}

// ---------------------------------------------------------------------------
// xmac 的**核心**：篡改必须被拒（论文 Lemma `lem:pir` 的场景）
// ---------------------------------------------------------------------------

TEST(MpraqEntry, XmacRejectsTamperedAnswers) {
    using tsb::mpraq::MpraqSecurityMode;

    // ① 诚实流程能过，且校验**确实执行了**
    {
        Fix f = MakeFix(256, 2, 2, 24, MpraqSecurityMode::kMalicious);
        const StoreParams& sp = f.client->store_params();
        EXPECT_TRUE(sp.has_tags());
        EXPECT_TRUE(f.client->tag_key() != 0);      // γ ←$ GF(2^128)\{0}
        MpraqQueryBatch b = f.client->CreateColumnQuery(0, 0);
        EXPECT_EQ(f.client->RunBatch(b).size(), 1u);
        EXPECT_TRUE(f.client->tag_checks() >= 1);
    }

    // ② **确定性**地测校验入口本身（不走 Plinko 全流程）。
    //    ⚠️ 为什么不走全流程：篡改落在 `r_b` 还是 `r_{1-b}` 取决于查询集的分组位，
    //       只有约一半概率被本次校验看到 —— 我第一版测试就因此出现"篡改却没抛"的假阴性。
    //       直接构造 `(R_b, M_b)` 才能把判定**钉死**。
    Fix f = MakeFix(256, 2, 2, 24, MpraqSecurityMode::kMalicious);
    const size_t ew = f.client->store_params().entry_words;
    const uint128_t gamma = f.client->tag_key();

    auto make_answer = [&](uint128_t r, uint128_t m) {
        PlinkoAnswer a;
        a.r0.assign(ew, r); a.r1.assign(ew, r);
        a.m0.assign(ew, m); a.m1.assign(ew, m);
        return a;
    };
    const uint128_t rv = 0xDEADBEEFu;
    const uint128_t mv = tsb::Gf128Mul(gamma, rv);

    // ②a 自洽的 `(R, M = γ⊙R)` ⇒ **通过**（不抛）
    {
        PlinkoAnswer a = make_answer(rv, mv);
        f.client->VerifyXmacOrThrow(a, 0);          // 不抛
        f.client->VerifyXmacOrThrow(a, 1);          // 两侧都查
    }

    // ②b 篡改**数据**、tag 不动 ⇒ 必须抛
    {
        PlinkoAnswer a = make_answer(rv, mv);
        a.r0[0] = static_cast<uint128_t>(a.r0[0] ^ 1u);
        EXPECT_THROW(f.client->VerifyXmacOrThrow(a, 0), std::runtime_error);
    }

    // ②c 篡改 **tag**、数据不动 ⇒ 必须抛
    {
        PlinkoAnswer a = make_answer(rv, mv);
        a.m1[0] = static_cast<uint128_t>(a.m1[0] ^ 1u);
        EXPECT_THROW(f.client->VerifyXmacOrThrow(a, 1), std::runtime_error);
    }

    // ②d **两台一致偏移**（论文 Lemma `lem:pir` 的场景）：`R ← R ⊕ δ`、`M` 不动。
    //     服务器**不知道 γ**，因此算不出配平的 `ε = γ⊙δ` ⇒ 必然被拒。
    //     （若攻击者知道 γ 并能算出 ε，则会通过 —— 这正是安全界 `1/(2^128−1)` 的含义：
    //       盲猜 `ε` 命中 `γ⊙δ` 的概率是 2^{-128} 量级。）
    {
        PlinkoAnswer a = make_answer(rv, mv);
        const uint128_t delta = 0x1234u;
        a.r0[0] = static_cast<uint128_t>(a.r0[0] ^ delta);
        a.r1[0] = static_cast<uint128_t>(a.r1[0] ^ delta);
        EXPECT_THROW(f.client->VerifyXmacOrThrow(a, 0), std::runtime_error);
        EXPECT_THROW(f.client->VerifyXmacOrThrow(a, 1), std::runtime_error);
    }

    // ②e 恶意档收到**空 tag** ⇒ 必须抛（绝不降级为"只校验数据"）
    {
        PlinkoAnswer a;
        a.r0.assign(ew, rv); a.r1.assign(ew, rv);   // m0/m1 为空
        EXPECT_THROW(f.client->VerifyXmacOrThrow(a, 0), std::runtime_error);
    }

    // ②f **宽度不符**（不变量 I5）⇒ 必须抛
    {
        PlinkoAnswer a = make_answer(rv, mv);
        a.m0.resize(ew + 1, mv);
        EXPECT_THROW(f.client->VerifyXmacOrThrow(a, 0), std::runtime_error);
    }

    // ③ 半诚实档：调用校验入口是**逻辑错误** ⇒ 必须抛（该档不生成 γ、不校验）
    {
        Fix g = MakeFix(256, 2, 2, 24, MpraqSecurityMode::kSemiHonest);
        EXPECT_FALSE(g.client->store_params().has_tags());
        PlinkoAnswer a = make_answer(rv, mv);
        EXPECT_THROW(g.client->VerifyXmacOrThrow(a, 0), std::logic_error);
        // 该档跑完整流程也**不校验**（tag_checks 恒 0）
        MpraqQueryBatch b = g.client->CreateColumnQuery(0, 0);
        EXPECT_EQ(g.client->RunBatch(b).size(), 1u);
        EXPECT_EQ(g.client->tag_checks(), 0u);
    }
}

// ---------------------------------------------------------------------------
// J10：线协议版本不匹配必须被拒（xmac 加了 tag 字段 ⇒ 版本 2 的 peer 不可静默接受）
// ---------------------------------------------------------------------------

TEST(MpraqEntry, WireProtocolVersionMismatchIsRejected) {
    // `StoreParamsProto.protocol_version` 必须等于本端的 `kMpraqWireProtocolVersion`。
    // ⚠️ 为什么这条重要：v2 的 peer 不认识 `PirAnswer.mac_acc0/mac_acc1`，
    //    若被静默接受，恶意档会拿到"没有 tag"的应答 ⇒ 退化成"只校验数据"，
    //    正是 xmac 要防的静默降级。
    MpraqNode node;
    MpraqServiceImpl svc(node);

    ::mpraqwire::InitTableRequest req;
    // 只设一个**错的**版本号即可：版本检查在 `FromProto` 的**最前面**，
    // 早于几何校验，所以不必构造完整的合法几何。
    req.mutable_params()->set_protocol_version(2);   // 旧版本
    ::mpraqwire::InitTableResponse resp;
    grpc::ServerContext ctx;
    const grpc::Status st = svc.InitTable(&ctx, &req, &resp);
    EXPECT_FALSE(st.ok());                            // 必须被拒
    EXPECT_FALSE(resp.ok());

    // 版本正确但几何非法 ⇒ 仍应被拒（证明拒绝不是因为别的字段缺失）
    ::mpraqwire::InitTableRequest req2;
    req2.mutable_params()->set_protocol_version(3);
    ::mpraqwire::InitTableResponse resp2;
    const grpc::Status st2 = svc.InitTable(&ctx, &req2, &resp2);
    EXPECT_FALSE(st2.ok());
}

// ---------------------------------------------------------------------------
// P1-A：半诚实档的 SecureMul **不做任何验证**（如实声明的边界）
// ---------------------------------------------------------------------------

TEST(MpraqEntry, SemiHonestSecureMulDoesNotVerify) {
    using tsb::mpraq::kDefaultMpraqSecurityMode;
    using tsb::mpraq::MpraqSecurityMode;
    using tsb::mpraq::Phase2Response;
    using tsb::mpraq::SecureMulClientState;
    using tsb::mpraq::SecureMulFailure;
    using tsb::mpraq::SecureMulStatus;
    using tsb::mpraq::VerifyAndReconstruct;

    const uint128_t q = tsb::mpraq::kSecureMulModulus;

    // 构造一组**诚实**的两轮应答（单条记录）：
    //   z_lin = c + d·b + e·a（服务端线性部分，论文 :554）
    //   mac   = α·z_lin
    // 然后**篡改 `mac_share`**，看两种档位怎么判。
    auto build = [&](MpraqSecurityMode mode, bool tamper_mac, bool* ok_out,
                     SecureMulFailure* fail_out) {
        const uint128_t alpha = 0x1234567890ABCDEFull;   // 任意非零
        const uint128_t s0 = 0x1111ull;
        const uint128_t s1 = tsb::subMod(alpha, s0, q);   // ⟨α⟩_0 + ⟨α⟩_1 == α
        tsb::MacKeyShares keys;
        keys.alpha = alpha;
        keys.alpha_shares.clear();
        keys.alpha_shares.push_back(s0);
        keys.alpha_shares.push_back(s1);
        SecureMulClientState client(std::move(keys), q, mode);

        // 客户端本地的 triple 与公开量
        const uint128_t a = 100, b = 200, c = tsb::mulMod(a, b, q);
        const uint128_t f = 1;                        // filter 位
        const uint128_t e_sent = 7;                   // 客户端重建出的 e
        const uint128_t d = tsb::subMod(f, a, q);
        const uint128_t z_lin = tsb::addMod(
            tsb::addMod(c, tsb::mulMod(d, b, q), q), tsb::mulMod(e_sent, a, q), q);
        const uint128_t mac = tsb::mulMod(alpha, z_lin, q);

        const uint64_t session = 42;
        Phase2Response r0;
        r0.session = session; r0.status = static_cast<uint8_t>(SecureMulStatus::kOk);
        r0.z_share = 0xAAAAull;
        r0.mac_share = 0xBBBBull;
        Phase2Response r1;
        r1.session = session; r1.status = static_cast<uint8_t>(SecureMulStatus::kOk);
        // 让两台之和恰好等于 z_lin / mac（「诚实」的定义）
        r1.z_share = tsb::subMod(z_lin, r0.z_share, q);
        r1.mac_share = tsb::subMod(mac, r0.mac_share, q);
        if (tamper_mac) {
            r1.mac_share = tsb::addMod(r1.mac_share, 1, q);   // 篡改 MAC 分片
        }

        tsb::BeaverTriple triple;
        triple.a = a; triple.b = b; triple.c = c;

        const auto res = VerifyAndReconstruct(
            session, {r0, r1}, client, /*ctx=*/nullptr, f, e_sent, &triple, 0, 0);
        *ok_out = res.ok;
        *fail_out = res.failure;
        // 无论哪种档位，重建出的 `z` 都应当是**正确**的乘积（z 分片本身没被改）
        const uint128_t want = tsb::mulMod(f, tsb::addMod(e_sent, b, q), q);
        return std::make_pair(res.z, want);
    };

    // ① 恶意档 + 诚实应答 ⇒ 通过
    {
        bool ok = false; SecureMulFailure f = SecureMulFailure::kNone;
        auto [z, want] = build(MpraqSecurityMode::kMalicious, /*tamper_mac=*/false, &ok, &f);
        EXPECT_TRUE(ok);
        EXPECT_TRUE(f == SecureMulFailure::kNone);
        EXPECT_EQ(z, want);
    }

    // ② **恶意档 + 篡改 MAC ⇒ 必须拒绝**（这是 xmac/SPDZ MAC 的意义）
    {
        bool ok = true; SecureMulFailure f = SecureMulFailure::kNone;
        (void)build(MpraqSecurityMode::kMalicious, /*tamper_mac=*/true, &ok, &f);
        EXPECT_FALSE(ok);
        EXPECT_TRUE(f == SecureMulFailure::kMacMismatch);
    }

    // ③ **半诚实档 + 同样的篡改 ⇒ 被静默接受**
    //    ⚠️ 这是**如实声明的边界**，不是缺陷：半诚实档的威胁模型里服务器不偏离协议。
    //       若要验证，必须用恶意档（默认档）。
    {
        bool ok = false; SecureMulFailure f = SecureMulFailure::kNone;
        auto [z, want] = build(MpraqSecurityMode::kSemiHonest, /*tamper_mac=*/true, &ok, &f);
        EXPECT_TRUE(ok);                                   // ← 不看 mac
        EXPECT_TRUE(f == SecureMulFailure::kNone);
        EXPECT_EQ(z, want);                                // z 仍正确（z 分片没被改）
    }
}
