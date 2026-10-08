// `test_grpc_mpraq` —— MPRAQ 的 **gRPC 线协议层**（`net/grpc_mpraq`）的集成测试。
//
// ===========================================================================
// 为什么需要它
// ===========================================================================
// `src/net/grpc_mpraq.{hpp,cpp}`（790 行）是 MPRAQ 客户端与服务器之间**唯一的通道**，
// 而它此前只有 **1 条**用例（`test_mpraq_entry` 里的协议版本拒绝）。也就是说
// **编解码、宽度校验、tag 成对性、批量语义、错误传播全都没有覆盖**。
//
// 本文件用 `InProcessMpraqNode`（**进程内真实 gRPC 服务器**，不是 mock）+
// `GrpcMpraqChannel` 走**真实链路**。
//
// ⚠️ 端口一律用 `127.0.0.1:0`（临时端口）：`InProcessMpraqNode` 的类注释明确要求 ——
//    固定端口会让并发跑第二份测试套件时绑定失败。
// ⚠️ 本套件**会起真实 gRPC 服务器**，因此每个用例都有被挂住的风险；
//    `tests/CMakeLists.txt` 的 `TIMEOUT 300` 就是为它准备的（把"挂死"变成"失败"）。
//
// ===========================================================================
// 覆盖
// ===========================================================================
//   W1  `InitTable` 往返：几何 + 档位逐字段一致
//   W2  **档位不一致 ⇒ 服务端拒绝**（`MpraqNode::InitTable` 的一致性闸门）
//   W3  `UploadFeatureWords`：读到正确值；`count != size` **客户端先拒**（不发 RPC）
//   W4  `UploadFeatureTags`：恶意档能存；**半诚实档上传 tag ⇒ 服务端拒**
//   W5  `SetAttributeShares`：长度 != N ⇒ 拒绝
//   W6  `ServerResp` 标量：真实链路取回一列，与明文逐字一致
//   W7  `ServerRespBatch`：**一次 RPC** 承载整批；空批 ⇒ 拒绝
//   W8  应答的 tag 字段：恶意档**有**、半诚实档**没有**（跨真实 gRPC 的存在性）
//   W9  **> 4 MiB 的应答能通**（收包上限那条路径的 e2e 证据）
//   W10 服务端拒绝 ⇒ 客户端**抛异常**（不静默成功）

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "core/config.hpp"
#include "mpraq/node.hpp"
#include "net/grpc_mpraq.hpp"
#include "pir/plinko.hpp"
#include "test_framework.hpp"

namespace {

using namespace tsb;
using namespace tsb::mpraq;

// 一条最小但**合法**的几何：n=256 ⇒ entry_words=2；levels=2；m=8 ⇒ w=2、κ=4（偶）。
// 与 `test_mpraq_entry` 的夹具同源，但这里**不建 `MpraqClient`** ——
// 线协议层只关心 `StoreParams`，不该把整条上层依赖拖进来。
StoreParams MakeParams(uint64_t n = 256, size_t levels = 2, uint64_t m = 8,
                       MpraqSecurityMode mode = MpraqSecurityMode::kMalicious) {
    StoreParams p;
    p.n = n;
    p.entry_words = (n + 127) / 128;
    p.levels = levels;
    p.m = m;
    p.plinko = PlinkoParams::Derive(m, /*lambda=*/24, /*prp_epsilon=*/1e-6, p.entry_words);
    p.security_mode = mode;
    p.attrs.clear();
    // ⚠️ `Validate` 要求 `levels == Σ_a lcte.range_size`（本层只验和，不管别的）。
    //    这里两个属性各 `range_size = 1` ⇒ Σ = 2 = levels ✓。
    //    （取值域与 range 的关系由上层 `MPA-02` 管，本层只要求 `range_size >= 1` 且域不倒置。）
    for (uint32_t a = 0; a < 2; ++a) {
        StoreAttribute at;
        at.name = "a" + std::to_string(a);
        at.id = a;
        at.lcte.window_size = static_cast<uint32_t>(n);
        at.lcte.range_min = 0;
        at.lcte.range_size = 1;
        at.domain_min = 0;
        at.domain_max = 1;
        p.attrs.push_back(at);
    }
    p.Validate();
    return p;
}

// 两台**进程内真实 gRPC 服务器** + 两条真实通道
struct Wire {
    std::unique_ptr<InProcessMpraqNode> s0, s1;
    std::unique_ptr<GrpcMpraqChannel> c0, c1;

    Wire() {
        s0 = std::make_unique<InProcessMpraqNode>("127.0.0.1:0");
        s1 = std::make_unique<InProcessMpraqNode>("127.0.0.1:0");
        EXPECT_TRUE(s0->started());
        EXPECT_TRUE(s1->started());
        c0 = std::make_unique<GrpcMpraqChannel>(s0->local_address());
        c1 = std::make_unique<GrpcMpraqChannel>(s1->local_address());
        c0->Connect();
        c1->Connect();
        EXPECT_TRUE(c0->WaitForConnection(5000));
        EXPECT_TRUE(c1->WaitForConnection(5000));
    }

    // 档位要在 `InitTable` **之前**告诉节点（服务端据此做一致性校验）
    void SetNodeModes(MpraqSecurityMode m) {
        s0->node().SetSecurityMode(m);
        s1->node().SetSecurityMode(m);
    }
    void InitBoth(const StoreParams& p) {
        c0->InitTable(p);
        c1->InitTable(p);
    }
    MpraqNode& node(int i) { return i == 0 ? s0->node() : s1->node(); }
    GrpcMpraqChannel& ch(int i) { return i == 0 ? *c0 : *c1; }
};

// 一列的 XOR 共享（服务器 i 那份）
std::vector<uint128_t> ShareFor(const StoreParams& p, uint64_t salt, int server) {
    std::vector<uint128_t> v(static_cast<size_t>(p.m) * p.entry_words);
    uint64_t s = salt + static_cast<uint64_t>(server) * 0x9E3779B97F4A7C15ull;
    for (auto& w : v) {
        uint128_t x = 0;
        for (int k = 0; k < 4; ++k) {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            x = static_cast<uint128_t>(x << 32) | static_cast<uint32_t>(s);
        }
        w = x;
    }
    return v;
}

}  // namespace

// ---------------------------------------------------------------------------
// W1：`InitTable` 往返（几何 + 档位逐字段一致）
// ---------------------------------------------------------------------------

TEST(GrpcMpraq, InitTableRoundTripsGeometryAndMode) {
    Wire w;
    w.SetNodeModes(MpraqSecurityMode::kMalicious);
    const StoreParams p = MakeParams();
    w.InitBoth(p);

    for (int i = 0; i < 2; ++i) {
        const StoreParams& got = w.node(i).params();
        EXPECT_TRUE(w.node(i).initialized());
        EXPECT_EQ(got.n, p.n);
        EXPECT_EQ(got.entry_words, p.entry_words);
        EXPECT_EQ(got.levels, p.levels);
        EXPECT_EQ(got.m, p.m);
        EXPECT_EQ(got.plinko.w, p.plinko.w);
        EXPECT_EQ(got.plinko.blocks(), p.plinko.blocks());
        EXPECT_EQ(got.attrs.size(), p.attrs.size());
        EXPECT_TRUE(got.security_mode == p.security_mode);   // 档位必须过线
        // 恶意档 ⇒ 服务端**必须**分配了 tag 表（档位语义过线的证据）
        EXPECT_TRUE(w.node(i).has_tag_table());
    }
}

// ---------------------------------------------------------------------------
// W2：档位不一致 ⇒ 服务端拒绝（`InitTable` 的一致性闸门）
// ---------------------------------------------------------------------------

TEST(GrpcMpraq, SecurityModeMismatchIsRejectedByServer) {
    Wire w;
    // 服务端按**恶意档**配置，客户端却报**半诚实档** ⇒ 必须被拒。
    // 这是唯一的"静默降级安全性"失败模式：若放行，客户端以为在半诚实档（不校验），
    // 服务端却按恶意档分配了 tag 表 —— 或反过来，客户端以为在恶意档、实际没有 tag。
    w.SetNodeModes(MpraqSecurityMode::kMalicious);
    const StoreParams p = MakeParams(256, 2, 8, MpraqSecurityMode::kSemiHonest);
    EXPECT_THROW(w.c0->InitTable(p), std::exception);

    // 反过来：服务端半诚实、客户端报恶意 ⇒ 同样必须被拒
    Wire w2;
    w2.SetNodeModes(MpraqSecurityMode::kSemiHonest);
    const StoreParams pm = MakeParams(256, 2, 8, MpraqSecurityMode::kMalicious);
    EXPECT_THROW(w2.c0->InitTable(pm), std::exception);

    // 档位一致时半诚实档能正常装载，且**没有** tag 表
    Wire w3;
    w3.SetNodeModes(MpraqSecurityMode::kSemiHonest);
    const StoreParams ps = MakeParams(256, 2, 8, MpraqSecurityMode::kSemiHonest);
    w3.InitBoth(ps);
    EXPECT_TRUE(w3.node(0).initialized());
    EXPECT_FALSE(w3.node(0).has_tag_table());
}

// ---------------------------------------------------------------------------
// W3：`UploadFeatureWords`（含"客户端先拒"）
// ---------------------------------------------------------------------------

TEST(GrpcMpraq, UploadFeatureWordsStoresAndRejectsBadCount) {
    Wire w;
    w.SetNodeModes(MpraqSecurityMode::kMalicious);
    const StoreParams p = MakeParams();
    w.InitBoth(p);

    const std::vector<uint128_t> sh0 = ShareFor(p, 0x1234, 0);

    // ① **只传 entry 0**（`entry_words` 个字）⇒ 验证 `base_index` 的语义：
    //    写到正确的位置，且**不碰**别的条目（不是"整表被覆盖成垃圾"）。
    std::vector<uint128_t> first(sh0.begin(), sh0.begin() + static_cast<ptrdiff_t>(p.entry_words));
    w.ch(0).UploadFeatureWords(0, first, first.size());
    for (size_t wd = 0; wd < p.entry_words; ++wd) {
        EXPECT_EQ(w.node(0).FeatureEntryWord(0, wd), sh0[wd]);
    }
    EXPECT_EQ(w.node(0).FeatureEntryWord(1, 0), static_cast<uint128_t>(0));   // 未被碰过

    // ② 再传**整表**，并按 `base_index` 偏移传最后一个条目 ⇒ 首尾都要对
    w.ch(0).UploadFeatureWords(0, sh0, sh0.size());
    const uint64_t last = p.m - 1;
    const size_t base = static_cast<size_t>(last) * p.entry_words;
    for (size_t wd = 0; wd < p.entry_words; ++wd) {
        EXPECT_EQ(w.node(0).FeatureEntryWord(last, wd), sh0[base + wd]);
    }
    // 非零起始偏移：单独重传最后一个条目，值不变（幂等 + 偏移正确）
    std::vector<uint128_t> tail(sh0.begin() + static_cast<ptrdiff_t>(base), sh0.end());
    w.ch(0).UploadFeatureWords(base, tail, tail.size());
    for (size_t wd = 0; wd < p.entry_words; ++wd) {
        EXPECT_EQ(w.node(0).FeatureEntryWord(last, wd), sh0[base + wd]);
    }

    // `count != size` ⇒ **客户端在发 RPC 之前**就拒绝（错误不被网络层掩盖）
    const uint64_t before = w.c0->rpc_count();
    std::vector<uint128_t> v(2, 0);
    EXPECT_THROW(w.c0->UploadFeatureWords(0, v, /*count=*/1), std::invalid_argument);
    EXPECT_EQ(w.c0->rpc_count(), before);      // 确认**没有**发出 RPC
}

// ---------------------------------------------------------------------------
// W4：`UploadFeatureTags`（恶意档能存；半诚实档被服务端拒）
// ---------------------------------------------------------------------------

TEST(GrpcMpraq, UploadFeatureTagsRespectsSecurityMode) {
    // 恶意档：tag 与数据同形状，能存能读
    {
        Wire w;
        w.SetNodeModes(MpraqSecurityMode::kMalicious);
        const StoreParams p = MakeParams();
        w.InitBoth(p);
        const std::vector<uint128_t> t = ShareFor(p, 0x5678, 1);
        w.ch(1).UploadFeatureTags(0, t, t.size());
        for (size_t wd = 0; wd < p.entry_words; ++wd) {
            EXPECT_EQ(w.node(1).FeatureTagWord(0, wd), t[wd]);
        }
    }
    // 半诚实档：服务端**没有** tag 表 ⇒ 必须拒绝（绝不静默丢弃这批 tag）
    {
        Wire w;
        w.SetNodeModes(MpraqSecurityMode::kSemiHonest);
        const StoreParams p = MakeParams(256, 2, 8, MpraqSecurityMode::kSemiHonest);
        w.InitBoth(p);
        const std::vector<uint128_t> t = ShareFor(p, 0x5678, 1);
        EXPECT_THROW(w.ch(1).UploadFeatureTags(0, t, t.size()), std::exception);
    }
}

// ---------------------------------------------------------------------------
// W5：`SetAttributeShares` 长度必须 == N
// ---------------------------------------------------------------------------

TEST(GrpcMpraq, SetAttributeSharesRequiresLengthN) {
    Wire w;
    w.SetNodeModes(MpraqSecurityMode::kMalicious);
    const StoreParams p = MakeParams();
    w.InitBoth(p);

    const std::vector<ModShare> good(static_cast<size_t>(p.n), ModShare{1});
    w.ch(0).SetAttributeShares(0, good);
    EXPECT_EQ(w.node(0).AttributeShare(0, 0).value, static_cast<uint128_t>(1));

    // 少一条 / 多一条都必须被拒
    std::vector<ModShare> shortv(static_cast<size_t>(p.n) - 1, ModShare{2});
    EXPECT_THROW(w.ch(0).SetAttributeShares(0, shortv), std::exception);
    std::vector<ModShare> longv(static_cast<size_t>(p.n) + 1, ModShare{2});
    EXPECT_THROW(w.ch(0).SetAttributeShares(0, longv), std::exception);
    // 属性号越界
    EXPECT_THROW(w.ch(0).SetAttributeShares(99, good), std::exception);
}

// ---------------------------------------------------------------------------
// W6：`ServerResp` 标量 —— 真实链路取回一列（与明文逐字一致）
// ---------------------------------------------------------------------------

TEST(GrpcMpraq, ServerRespOverRealGrpcReconstructsColumn) {
    Wire w;
    w.SetNodeModes(MpraqSecurityMode::kMalicious);
    const StoreParams p = MakeParams();
    w.InitBoth(p);

    // 明文表 + 两台 XOR 共享；共享上传到各自节点
    std::vector<uint128_t> plain(static_cast<size_t>(p.m) * p.entry_words);
    for (size_t i = 0; i < plain.size(); ++i) plain[i] = static_cast<uint128_t>(0x1000 + i);
    const std::vector<uint128_t> sh0 = ShareFor(p, 0xABCD, 0);
    std::vector<uint128_t> sh1(plain.size());
    for (size_t i = 0; i < plain.size(); ++i) {
        sh1[i] = static_cast<uint128_t>(sh0[i] ^ plain[i]);
    }
    w.ch(0).UploadFeatureWords(0, sh0, sh0.size());
    w.ch(1).UploadFeatureWords(0, sh1, sh1.size());

    // 用真实的 `PlinkoClient` 生成查询集（保证几何形状是生产用的那种）
    PlinkoClient pc(p.plinko, /*seed=*/7);
    pc.HintInit(plain);
    const uint64_t target = 3;
    auto [q, h] = pc.QueryGen(target);

    const PlinkoAnswer a0 = w.ch(0).ServerResp(q);
    const PlinkoAnswer a1 = w.ch(1).ServerResp(q);
    EXPECT_EQ(a0.r0.size(), p.entry_words);      // 应答宽度 = entry_words（I4）
    EXPECT_EQ(a1.r1.size(), p.entry_words);

    const PlinkoAnswer merged = PlinkoClient::XorAnswers(a0, a1);
    const PlinkoEntry got = pc.ClientRecon(h, merged);
    EXPECT_EQ(got.size(), p.entry_words);
    for (size_t wd = 0; wd < p.entry_words; ++wd) {
        if (got[wd] != plain[static_cast<size_t>(target) * p.entry_words + wd]) {
            TSB_FAIL_("经真实 gRPC 取回的列与明文不一致（第 " + std::to_string(wd) + " 字）");
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// W7：`ServerRespBatch` —— **一次 RPC** 承载整批
// ---------------------------------------------------------------------------

TEST(GrpcMpraq, ServerRespBatchUsesOneRpcAndRejectsEmpty) {
    Wire w;
    w.SetNodeModes(MpraqSecurityMode::kMalicious);
    const StoreParams p = MakeParams();
    w.InitBoth(p);
    const std::vector<uint128_t> sh0 = ShareFor(p, 0x1111, 0);
    w.ch(0).UploadFeatureWords(0, sh0, sh0.size());

    // 造 3 个查询集（形状取自真实 `PlinkoClient`）
    std::vector<uint128_t> plain(static_cast<size_t>(p.m) * p.entry_words, 0x55);
    PlinkoClient pc(p.plinko, 7);
    pc.HintInit(plain);
    std::vector<PlinkoQuery> qs;
    for (uint64_t t = 0; t < 3; ++t) {
        auto [q, h] = pc.QueryGen(t);
        (void)h;
        qs.push_back(q);
    }

    const uint64_t rpc_before = w.s0->rpc_count();
    const uint64_t batch_before = w.s0->batch_rpc_count();
    const std::vector<PlinkoAnswer> ans = w.ch(0).ServerRespBatch(qs);

    // ⚠️ Q5 的硬要求：整批**一次** RPC。逐条发会让多谓词查询退化成"列数 × 查询集数"个往返。
    EXPECT_EQ(ans.size(), qs.size());                        // 应答与请求一一对应
    EXPECT_EQ(w.s0->rpc_count(), rpc_before + 1);            // 只多了一次
    EXPECT_EQ(w.s0->batch_rpc_count(), batch_before + 1);    // 且走的正是**批量**入口
    EXPECT_EQ(w.s0->queries_served() >= 3, true);            // 工作量口径：3 个查询集
    for (const PlinkoAnswer& a : ans) {
        EXPECT_EQ(a.r0.size(), p.entry_words);
        EXPECT_EQ(a.r1.size(), p.entry_words);
    }

    // 空批 ⇒ 拒绝（"空批次"通常是上层算错了目标集合）
    std::vector<PlinkoQuery> none;
    EXPECT_THROW(w.ch(0).ServerRespBatch(none), std::exception);
}

// ---------------------------------------------------------------------------
// W8：应答的 tag 字段 —— 恶意档**有**、半诚实档**没有**
// ---------------------------------------------------------------------------

TEST(GrpcMpraq, TagFieldsPresenceFollowsSecurityMode) {
    auto run_once = [](MpraqSecurityMode mode) {
        Wire w;
        w.SetNodeModes(mode);
        const StoreParams p = MakeParams(256, 2, 8, mode);
        w.InitBoth(p);
        const std::vector<uint128_t> sh0 = ShareFor(p, 0x2222, 0);
        w.ch(0).UploadFeatureWords(0, sh0, sh0.size());
        if (mode == MpraqSecurityMode::kMalicious) {
            const std::vector<uint128_t> t0 = ShareFor(p, 0x3333, 0);
            w.ch(0).UploadFeatureTags(0, t0, t0.size());
        }
        std::vector<uint128_t> plain(static_cast<size_t>(p.m) * p.entry_words, 0x77);
        PlinkoClient pc(p.plinko, 7);
        pc.HintInit(plain);
        auto [q, h] = pc.QueryGen(1);
        (void)h;
        return w.ch(0).ServerResp(q);
    };

    const PlinkoAnswer m = run_once(MpraqSecurityMode::kMalicious);
    EXPECT_TRUE(m.has_tags());                                   // 恶意档：带 tag
    EXPECT_EQ(m.m0.size(), m.r0.size());                          // tag 与数据**等宽**（I5）
    EXPECT_EQ(m.m1.size(), m.r1.size());

    const PlinkoAnswer s = run_once(MpraqSecurityMode::kSemiHonest);
    EXPECT_FALSE(s.has_tags());                                  // 半诚实档：不带 tag
}

// ---------------------------------------------------------------------------
// W9：**超过 4 MiB 的应答能通**（收包上限那条路径的 e2e 证据）
// ---------------------------------------------------------------------------
//
// 一次列查询的应答 = **两条 parity × 一整列** = `2 · entry_words · 16` 字节。
// gRPC 的默认收包上限是 **4 MiB**，不计就断：`2·ew·16 > 4 MiB ⇔ ew > 131072`
// （⇔ n > 2^24）。这里取 `n = 2^25` ⇒ `entry_words = 262144` ⇒ 应答 **8 MiB**。
//
// ⚠️ 本用例**不上传数据**（节点 `InitTable` 已把表清零）：它要证明的是
//    "这么大的帧能过链路"，而不是"值对不对"（值由 W6 覆盖）。
//    这也让用例不必搬运 32 MiB 的共享。
// ⚠️ 这条同时补上了我在修 VMPQ 收包上限（`34055c4`）时**自己承认缺失**的那份 e2e 证据
//    —— 当时只做了代码核对与解析界，没有实测。

TEST(GrpcMpraq, ResponseLargerThanFourMiBTransits) {
    Wire w;
    w.SetNodeModes(MpraqSecurityMode::kSemiHonest);
    const StoreParams p = MakeParams(/*n=*/1ull << 25, /*levels=*/2, /*m=*/8,
                                     MpraqSecurityMode::kSemiHonest);
    EXPECT_TRUE(p.entry_words > 131072);            // 前提：应答确实超过 4 MiB
    const uint64_t answer_bytes = 2ull * p.entry_words * 16ull;
    EXPECT_TRUE(answer_bytes > (4ull << 20));       // > 4 MiB
    w.InitBoth(p);

    std::vector<uint128_t> plain(static_cast<size_t>(p.m) * p.entry_words, 0x11);
    PlinkoClient pc(p.plinko, 7);
    pc.HintInit(plain);
    auto [q, h] = pc.QueryGen(0);
    (void)h;

    bool ok = true;
    std::vector<PlinkoAnswer> ans;
    try {
        ans = w.ch(0).ServerRespBatch({q});
    } catch (const std::exception& e) {
        TSB_FAIL_(std::string("8 MiB 应答未能通过链路（默认 4 MiB 收包上限没放宽？）：") +
                  e.what());
        ok = false;
    }
    if (!ok) return;
    EXPECT_EQ(ans.size(), 1u);
    EXPECT_EQ(ans[0].r0.size(), p.entry_words);     // 整列都在（未被截断）
    EXPECT_EQ(ans[0].r1.size(), p.entry_words);
}

// ---------------------------------------------------------------------------
// W10：服务端拒绝 ⇒ 客户端**抛异常**（不静默成功）
// ---------------------------------------------------------------------------

TEST(GrpcMpraq, ServerSideRejectionRaisesOnClient) {
    Wire w;
    w.SetNodeModes(MpraqSecurityMode::kMalicious);
    const StoreParams p = MakeParams();
    w.InitBoth(p);

    // 上传区间越界 ⇒ 服务端 `out_of_range` ⇒ RPC 非 OK ⇒ 客户端必须抛
    const std::vector<uint128_t> v(static_cast<size_t>(p.entry_words), 0xAB);
    const uint64_t way_out = static_cast<uint64_t>(p.m) * p.entry_words + 1000;
    EXPECT_THROW(w.ch(0).UploadFeatureWords(way_out, v, v.size()), std::exception);

    // 越界请求**不得**改变已装载的表（拒绝是原子的，不是"写了一部分"）
    EXPECT_EQ(w.node(0).FeatureEntryWord(0, 0), static_cast<uint128_t>(0));

    // tag 上传同样：区间越界 ⇒ 抛
    EXPECT_THROW(w.ch(0).UploadFeatureTags(way_out, v, v.size()), std::exception);
}
