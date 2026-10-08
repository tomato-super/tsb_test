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

#include "mpraq/aggquery.hpp"
#include "mpraq/init.hpp"
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
Fix MakeFix(size_t n, uint32_t cols_per_attr = 2, uint32_t attrs = 2, uint32_t lambda = 24) {
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
