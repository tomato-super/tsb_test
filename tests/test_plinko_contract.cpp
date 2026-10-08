// `test_plinko_contract` —— **Plinko 检索底座**的契约测试（`PIR-04` / `PIR-05`）。
//
// ===========================================================================
// 为什么需要这份测试
// ===========================================================================
// `pir/plinko` 是 MPRAQ 最微妙的一层：hint 生命周期、备份提升的 `η` 折算、
// `dummy offset` 放在补集一侧、`α ∈ 覆盖集` 的显式检查 —— 任何一处写错都**不会崩**，
// 只会**静默给出错值**（或其 25% 的偶然正确）。而它此前**没有任何直接覆盖**：
// MPRAQ 的用例只从上层间接走到它。
//
// 本文件**只依赖 `pir/plinko`**，不碰 MPRAQ：既是回归网，也是这一层"可独立测试"
// 这一设计（见 D42 的裁决）的实证。
//
// ===========================================================================
// 覆盖的契约（逐条对应 PLINKO_SPEC）
// ===========================================================================
//   C1  `PlinkoParams::Derive/Validate` 的几何自洽（m = κ·w、κ 偶、w 是 2 的幂）
//   C2  `PlinkoQuery::well_formed()` 拒绝坏形状
//   C3  **精确重建**：m 个索引逐个取回，与明文逐字一致
//   C4  **XOR 共享线性**：`ServerRespShared(s0) ⊕ ServerRespShared(s1) == ServerResp(明文)`
//   C5  **提示生命周期**：H = λw + N_T、`hints_in_table()` 恒为 λw、
//       每次查询消耗 1 条备份、提升计入 `η=0/1` 之一
//   C6  **重复查询**：第二次走"重采样新索引"分支（`target != requested`）且结果仍正确
//   C7  **备份耗尽**：耗尽后必须抛 `PlinkoBackupsExhausted`（绝不回退到明文取值）
//   C8  `Verify` **恒抛** `PlinkoVerificationUnsupported`（不返回假的通过）
//   C9  **确定性**（铁律 D6）：同 seed ⇒ 逐位相同的 hint 表与查询偏移
//   C10 **应答宽度 = entry_words**（不变量 I4 的 PIR 层部分）

#include <cstdint>
#include <set>
#include <vector>

#include "pir/plinko.hpp"
#include "test_framework.hpp"

namespace {

using namespace tsb;

// 固定的演示几何：m = 16、每条目 3 个字、w = 4 ⇒ κ = 4。
// λ 取得小（24）以让"备份耗尽"用例跑得快；`H = 3λw/2` 仍是合法规模。
struct Fixture {
    PlinkoParams p;
    std::vector<uint128_t> plain;   // 明文 DB（扁平 m·entry_words）
    std::vector<uint128_t> sh0, sh1;
    PlinkoClient client;

    explicit Fixture(uint64_t m = 16, size_t entry_words = 3, uint32_t lambda = 24)
        : p(PlinkoParams::Derive(m, lambda, 1e-6, entry_words)),
          client(p, /*seed=*/7) {
        plain.assign(static_cast<size_t>(m) * entry_words, 0);
        // 确定性伪随机明文（不依赖被测代码）
        uint64_t s = 0x9E3779B97F4A7C15ull;
        for (auto& w : plain) {
            uint128_t v = 0;
            for (int k = 0; k < 4; ++k) {
                s ^= s << 13; s ^= s >> 7; s ^= s << 17;   // xorshift64
                v = static_cast<uint128_t>(v << 32) | static_cast<uint32_t>(s);
            }
            w = v;
        }
        sh0.resize(plain.size());
        sh1.resize(plain.size());
        uint64_t t = 0xDEADBEEFCAFEF00Dull;
        for (size_t i = 0; i < plain.size(); ++i) {
            uint128_t mask = 0;
            for (int k = 0; k < 4; ++k) {
                t ^= t << 13; t ^= t >> 7; t ^= t << 17;
                mask = static_cast<uint128_t>(mask << 32) | static_cast<uint32_t>(t);
            }
            sh0[i] = mask;
            sh1[i] = static_cast<uint128_t>(mask ^ plain[i]);
        }
        client.HintInit(plain);
    }

    // 走**真正的 PIR 路径**取回一个索引（两台"服务器"各在自方共享上应答）
    PlinkoEntry Retrieve(uint64_t index) {
        auto [q, h] = client.QueryGen(index);
        const PlinkoAnswer a0 = PlinkoClient::ServerRespShared(
            q, [this](uint64_t i) { return &sh0[i * p.entry_words]; }, p.entry_words);
        const PlinkoAnswer a1 = PlinkoClient::ServerRespShared(
            q, [this](uint64_t i) { return &sh1[i * p.entry_words]; }, p.entry_words);
        const PlinkoAnswer merged = PlinkoClient::XorAnswers(a0, a1);
        return client.ClientRecon(h, merged);
    }
};

bool SameEntry(const PlinkoEntry& a, const std::vector<uint128_t>& plain, uint64_t index,
               size_t entry_words) {
    if (a.size() != entry_words) return false;
    for (size_t w = 0; w < entry_words; ++w) {
        if (a[w] != plain[static_cast<size_t>(index) * entry_words + w]) return false;
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// C1：几何自洽
// ---------------------------------------------------------------------------

TEST(PlinkoContract, GeometryIsSelfConsistent) {
    for (uint64_t m : {4ull, 8ull, 16ull, 64ull}) {
        const PlinkoParams p = PlinkoParams::Derive(m, 24, 1e-6, /*entry_words=*/2);
        EXPECT_EQ(p.m, m);
        EXPECT_TRUE(p.w >= 1);
        EXPECT_EQ((p.w & (p.w - 1)) == 0, true);              // w 是 2 的幂
        EXPECT_EQ(p.m % p.w, 0u);                            // m = κ·w
        EXPECT_EQ(p.blocks(), p.m / p.w);
        EXPECT_EQ(p.blocks() % 2, 0u);                       // κ 为偶数
        EXPECT_EQ(p.main_hints(), p.lambda * p.w);            // λw
        EXPECT_EQ(p.backup_hints(), p.lambda * p.w / 2);      // N_T = λw/2
        EXPECT_EQ(p.hint_slots(), p.main_hints() + p.backup_hints());   // H
        EXPECT_TRUE(p.entry_words == 2);
    }
    // 非法几何必须被拒（绝不静默调整）
    PlinkoParams bad = PlinkoParams::Derive(16, 24, 1e-6, 1);
    bad.w = 3;                     // 不是 2 的幂
    EXPECT_THROW(bad.Validate(), std::invalid_argument);
    bad = PlinkoParams::Derive(16, 24, 1e-6, 1);
    bad.entry_words = 0;           // 条目宽度必须 >= 1
    EXPECT_THROW(bad.Validate(), std::invalid_argument);
}

// ---------------------------------------------------------------------------
// C2：查询形状校验
// ---------------------------------------------------------------------------

TEST(PlinkoContract, MalformedQueryIsRejected) {
    Fixture f;   // `QueryGen` 会改状态（预留槽位），故非 const
    auto [q, h] = f.client.QueryGen(0);
    (void)h;
    EXPECT_TRUE(q.well_formed());
    EXPECT_EQ(q.entry_words, f.p.entry_words);
    EXPECT_EQ(q.offsets.size(), q.groups.size());

    { PlinkoQuery bad = q; bad.entry_words = 0; EXPECT_FALSE(bad.well_formed()); }
    { PlinkoQuery bad = q; bad.offsets.pop_back(); EXPECT_FALSE(bad.well_formed()); }
    { PlinkoQuery bad = q; bad.groups[0] = 2; EXPECT_FALSE(bad.well_formed()); }
}

// ---------------------------------------------------------------------------
// C3 + C10：精确重建（全部索引）+ 应答宽度
// ---------------------------------------------------------------------------

TEST(PlinkoContract, EveryIndexReconstructsExactly) {
    Fixture f;
    for (uint64_t x = 0; x < f.p.m; ++x) {
        const PlinkoEntry got = f.Retrieve(x);
        if (!SameEntry(got, f.plain, x, f.p.entry_words)) {
            TSB_FAIL_("索引 " + std::to_string(x) + " 的重建值与明文不一致");
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// C4：XOR 共享的线性相容（服务端只碰共享，客户端异或后等于明文应答）
// ---------------------------------------------------------------------------

TEST(PlinkoContract, SharedServerResponseIsLinear) {
    Fixture f;   // 同上：`QueryGen` 非 const
    auto [q, h] = f.client.QueryGen(3);
    (void)h;
    const PlinkoAnswer a0 = PlinkoClient::ServerRespShared(
        q, [&f](uint64_t i) { return &f.sh0[i * f.p.entry_words]; }, f.p.entry_words);
    const PlinkoAnswer a1 = PlinkoClient::ServerRespShared(
        q, [&f](uint64_t i) { return &f.sh1[i * f.p.entry_words]; }, f.p.entry_words);
    const PlinkoAnswer merged = PlinkoClient::XorAnswers(a0, a1);
    const PlinkoAnswer plain_ans = PlinkoClient::ServerResp(q, f.plain);

    EXPECT_EQ(merged.r0.size(), f.p.entry_words);
    EXPECT_EQ(merged.r1.size(), f.p.entry_words);
    for (size_t j = 0; j < f.p.entry_words; ++j) {
        if (merged.r0[j] != plain_ans.r0[j] || merged.r1[j] != plain_ans.r1[j]) {
            TSB_FAIL_("XOR 合并后的应答与明文应答不一致（第 " + std::to_string(j) + " 字）");
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// C5：提示生命周期（PLINKO_SPEC 的核心不变量）
// ---------------------------------------------------------------------------

TEST(PlinkoContract, HintLifecycleInvariants) {
    Fixture f;
    EXPECT_EQ(f.client.hint_slot_count(), f.p.hint_slots());
    EXPECT_EQ(f.client.backup_remaining(), f.p.backup_hints());
    EXPECT_EQ(f.client.query_count(), 0u);

    for (int round = 0; round < 6; ++round) {
        // **论文的关键不变量**：H 里可用 hint 总数恒为 λw（消耗 1 条 → 提升 1 条）
        EXPECT_EQ(f.client.hints_in_table(), f.p.main_hints());
        const size_t before_backup = f.client.backup_remaining();
        (void)f.Retrieve(static_cast<uint64_t>(round));      // 不同索引，避免走缓存分支
        EXPECT_EQ(f.client.backup_remaining(), before_backup - 1);
        EXPECT_EQ(f.client.query_count(), static_cast<uint64_t>(round + 1));
    }
    // 提升的每一条都落在 η=0 或 η=1 之一（没有"没提升"或"提升两次"）
    EXPECT_EQ(f.client.promotion_count_eta0() + f.client.promotion_count_eta1(), 6u);
    EXPECT_EQ(f.client.hints_in_table(), f.p.main_hints());
}

// ---------------------------------------------------------------------------
// C6：重复查询走"重采样新索引"分支，且结果仍正确
// ---------------------------------------------------------------------------

TEST(PlinkoContract, RepeatedQueryResamplesAndStaysCorrect) {
    Fixture f;
    const uint64_t x = 5;
    auto [q1, h1] = f.client.QueryGen(x);
    const PlinkoAnswer m1 = PlinkoClient::XorAnswers(
        PlinkoClient::ServerRespShared(q1, [&f](uint64_t i) { return &f.sh0[i * f.p.entry_words]; },
                                       f.p.entry_words),
        PlinkoClient::ServerRespShared(q1, [&f](uint64_t i) { return &f.sh1[i * f.p.entry_words]; },
                                       f.p.entry_words));
    const PlinkoEntry v1 = f.client.ClientRecon(h1, m1);
    EXPECT_EQ(h1.target, x);
    EXPECT_EQ(h1.requested, x);

    // 同一个索引再查一次：**必须**另取一个"未答复过"的新索引（隐私要求），
    // 结果仍必须等于明文（正确性要求）。
    auto [q2, h2] = f.client.QueryGen(x);
    EXPECT_TRUE(h2.target != h2.requested);          // 走的是重采样分支
    EXPECT_EQ(h2.requested, x);
    const PlinkoAnswer m2 = PlinkoClient::XorAnswers(
        PlinkoClient::ServerRespShared(q2, [&f](uint64_t i) { return &f.sh0[i * f.p.entry_words]; },
                                       f.p.entry_words),
        PlinkoClient::ServerRespShared(q2, [&f](uint64_t i) { return &f.sh1[i * f.p.entry_words]; },
                                       f.p.entry_words));
    const PlinkoEntry v2 = f.client.ClientRecon(h2, m2);
    EXPECT_TRUE(SameEntry(v1, f.plain, x, f.p.entry_words));
    EXPECT_TRUE(SameEntry(v2, f.plain, x, f.p.entry_words));
}

// ---------------------------------------------------------------------------
// C7：备份耗尽 ⇒ 抛异常（**绝不**回退到明文取值）
// ---------------------------------------------------------------------------

TEST(PlinkoContract, BackupExhaustionThrows) {
    // 几何要同时满足**三件事**，否则根本走不到"备份耗尽"这条路径：
    //   ① `N_T < m`：否则索引池先被用光（抛的是"全部索引都已答复过"）；
    //   ② λ 足够大：否则主提示表的**覆盖失败**（概率 `2^{-λ}`）会先发生
    //      —— 我第二版取 λ=2（25% 覆盖失败）就撞上了这条，抛的是
    //      "找不到覆盖索引的 hint"；
    //   ③ m 足够大：让 ① 与 ② 同时成立。
    // 这里 m=256、λ=16 ⇒ w=16、N_T=128 < 256，覆盖失败率 2^{-16}。
    Fixture f(/*m=*/256, /*entry_words=*/1, /*lambda=*/16);
    const size_t n_t = f.p.backup_hints();
    EXPECT_TRUE(n_t > 0);
    EXPECT_TRUE(n_t < f.p.m);              // 前提：备份数少于索引池

    // ⚠️ 必须查**互不相同**的索引。我第一版用 `k % m` 轮转，结果 40 次循环只消耗了
    //    16 条备份、也没抛 `PlinkoBackupsExhausted`。**当时我以为是"缓存命中不消耗备份"，
    //    实测证明是错的**（见 `/tmp/probe_cache2` 的完整往返）：
    //      * k=0..15：16 个互异索引，每次消耗 1 条备份（N_T 48→32）；
    //      * k=16 起：请求的索引已缓存 ⇒ `QueryGen` 要另挑一个"未答复"的索引，
    //        但 `answered_ == m`（16 个索引已全部答复）⇒ **直接抛**
    //        "全部 n 个索引都已答复过"；
    //      * 而我的 `catch (const std::exception&) {}` 把这 24 次异常**吞掉了**，
    //        于是循环"跑完"40 次却只消耗 16 条。
    //    ⇒ 真因是**新鲜索引池耗尽**（`m` 太小），不是"缓存命中免费"。
    //    本用例因此改成逐个用新索引，并要求 `N_T < m` 让备份先耗尽。
    size_t issued = 0;
    bool threw_backups = false;
    try {
        for (uint64_t x = 0; x < f.p.m; ++x) {
            (void)f.Retrieve(x);
            ++issued;
        }
    } catch (const PlinkoBackupsExhausted&) {
        threw_backups = true;
    }
    EXPECT_TRUE(threw_backups);            // 必须是**备份耗尽**那条路径
    EXPECT_EQ(issued, n_t);                // 恰好 N_T 次成功
    EXPECT_EQ(f.client.backup_remaining(), 0u);
}

// ---------------------------------------------------------------------------
// C8：Verify 恒抛（不返回假的"通过"）
// ---------------------------------------------------------------------------

TEST(PlinkoContract, VerifyAlwaysThrows) {
    Fixture f;
    auto [q, h] = f.client.QueryGen(0);
    const PlinkoAnswer a = PlinkoClient::ServerResp(q, f.plain);
    EXPECT_THROW(PlinkoClient::Verify(h, q, a), PlinkoVerificationUnsupported);
}

// ---------------------------------------------------------------------------
// C9：确定性（铁律 D6）—— 同 seed 的两份实例逐位一致
// ---------------------------------------------------------------------------

TEST(PlinkoContract, SameSeedGivesIdenticalStateAndQueries) {
    Fixture a;
    Fixture b;
    EXPECT_EQ(a.client.hint_slot_count(), b.client.hint_slot_count());
    // 抽查若干槽位的有效覆盖集（提升 hint 会按 η 折算，是个好指纹）
    for (size_t slot = 0; slot < a.client.hint_slot_count(); slot += 7) {
        for (uint64_t blk = 0; blk < a.p.blocks(); ++blk) {
            if (a.client.slot_contains_block(slot, blk) !=
                b.client.slot_contains_block(slot, blk)) {
                TSB_FAIL_("同 seed 的槽位 " + std::to_string(slot) + " 覆盖集不一致");
                return;
            }
        }
    }
    // 同 seed ⇒ 同一次查询的服务器可见信息逐字相同
    Fixture ca;
    Fixture cb;
    auto [q1, h1] = ca.client.QueryGen(1);
    auto [q2, h2] = cb.client.QueryGen(1);
    EXPECT_EQ(h1.target, h2.target);
    EXPECT_EQ(h1.b, h2.b);
    EXPECT_EQ(q1.offsets.size(), q2.offsets.size());
    for (size_t i = 0; i < q1.offsets.size(); ++i) {
        EXPECT_EQ(q1.offsets[i], q2.offsets[i]);
        EXPECT_EQ(q1.groups[i], q2.groups[i]);
    }
}

// ---------------------------------------------------------------------------
// C11：**重复查询缓存的开关**（负责人要求）—— 关掉即拒绝，绝不重查同一索引
// ---------------------------------------------------------------------------

TEST(PlinkoContract, CacheSwitchOffRejectsRepeatQueries) {
    // 开（默认）：重复查询照常服务（见 C6）。
    {
        Fixture f;
        EXPECT_TRUE(f.p.enable_repeat_cache);
        auto [q1, h1] = f.client.QueryGen(5);
        (void)q1;
        (void)f.client.ClientRecon(h1, PlinkoAnswer{PlinkoEntry(f.p.entry_words, 0),
                                                    PlinkoEntry(f.p.entry_words, 0)});
        auto [q2, h2] = f.client.QueryGen(5);      // 重复 ⇒ 走缓存分支，**不抛**
        (void)q2; (void)h2;
        EXPECT_TRUE(h2.cache_hit);
        EXPECT_TRUE(h2.target != h2.requested);
    }
    // 关：同一情形**必须拒绝**，且异常类型是专属的
    // `PlinkoRepeatedQueryRejected`（调用方要能把"被开关拒绝"与备份耗尽/覆盖失败区分开）。
    {
        Fixture f;
        f.p.enable_repeat_cache = false;
        // ⚠️ 光改 `p` 不够：`PlinkoClient` 在构造时就把参数拷走了 ⇒ 必须重建客户端。
        PlinkoClient c(f.p, 7);
        c.HintInit(f.plain);
        auto [q1, h1] = c.QueryGen(5);
        (void)q1;
        (void)c.ClientRecon(h1, PlinkoAnswer{PlinkoEntry(f.p.entry_words, 0),
                                             PlinkoEntry(f.p.entry_words, 0)});
        // 已答复过的索引再次 QueryGen ⇒ 拒绝
        EXPECT_THROW(c.QueryGen(5), PlinkoRepeatedQueryRejected);
        // 而**未答复过**的索引仍然正常工作（开关只影响"重复"，不是把功能关掉）
        auto [q3, h3] = c.QueryGen(6);
        (void)q3;
        EXPECT_EQ(h3.target, 6u);
        EXPECT_FALSE(h3.cache_hit);

        // ⚠️ 关掉缓存**不是静默降级**：它让行为**更严格**（拒绝而非重查）——
        //    这正是负责人选 C 的理由：宁可报错，也不让服务器看到重复索引。
        //    若将来有人把它改成"重查同一索引"，本断言会失败：
        bool threw = false;
        try { (void)c.QueryGen(5); } catch (const PlinkoRepeatedQueryRejected&) { threw = true; }
        EXPECT_TRUE(threw);
        // 缓存值数组在关闭时**不分配**（省 m·entry_words·16 字节）
        EXPECT_TRUE(c.cache_value_bytes() == 0);
    }
    // 开着的实例：缓存值数组**必须**分配
    {
        Fixture f;
        EXPECT_TRUE(f.client.cache_value_bytes() > 0);
    }
}
