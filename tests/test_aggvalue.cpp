// `test_aggvalue` —— `Sum` / `Avg` 聚合层（`MPA-06`）的契约测试。
//
// ===========================================================================
// 为什么需要它
// ===========================================================================
// `aggvalue` 是**用户最终看到的那两个数字**（Sum / Avg）的产地，而它此前**没有任何
// 直接用例**：只有两进程 demo 的 `baseline_match=1` 间接证明"没算错"。
// 这一层的失效模式都不显眼：
//   * `Sum` 走**逐记录**批量 SecureMul，任一记录校验失败必须**整体 abort**
//     （返回部分和是最危险的失败模式：数字看着正常，实际漏了一部分记录）；
//   * `Avg` 在 `count == 0` 时**无定义**，库口径是**抛**（绝不静默返回 0/NaN）；
//   * `filter` 由上层给，长度/取值必须校验。
//
// ===========================================================================
// 覆盖的契约
// ===========================================================================
//   A1 `Count` 与 `filter` 自洽：`count == popcount(filter)`
//   A2 `Sum` == 明文基准 `Σ f_i · E_i`（空集 / 全集 / 任意子集三种）
//   A3 `Avg` == `floor(sum / count)`（整数向下取整，与 VMPQ 同口径）
//   A4 `count == 0` ⇒ `AvgOverFilter` **抛 `std::domain_error`**（不静默给 0）
//   A5 **篡改 ⇒ 整体 abort**（抛 `SecureMulBatchAbort`，绝不返回部分和）
//   A6 `filter` 长度 ≠ N ⇒ 拒绝
//   A7 确定性（铁律 D6）：同 salt + 同 prng 种子 ⇒ 逐位相同

#include <cstdint>
#include <functional>
#include <memory>
#include <numeric>
#include <vector>

#include "core/config.hpp"
#include "core/gf128.hpp"
#include "mpraq/aggvalue.hpp"
#include "mpraq/aggquery.hpp"
#include "mpraq/init.hpp"
#include "net/transport.hpp"
#include "test_framework.hpp"

namespace {

using namespace tsb;
using namespace tsb::mpraq;

// 与 `test_mpraq_entry` 同一套夹具：小规模、确定性、属性值域 [0, C-2]。
struct Fix {
    Schema schema;
    std::vector<MpraqRecord> records;
    size_t n = 0;
    std::unique_ptr<MpraqClient> client;
};

Fix MakeFix(size_t n, uint32_t cols_per_attr = 8, uint32_t attrs = 2, uint32_t lambda = 24,
            MpraqSecurityMode mode = MpraqSecurityMode::kMalicious) {
    Fix f;
    f.n = n;
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
        // ⚠️ **必须产生非零且多样的值**：早先照抄 `test_mpraq_entry` 的夹具用
        //    `(i + a) % (cols_per_attr - 1)`，而那里 `cols_per_attr = 2` ⇒ **恒为 0**
        //    ⇒ `Sum` 恒等于 0、明文基准也恒为 0 ⇒ 用例**永远通过**却什么都没测到。
        //    这里取 `cols_per_attr = 8` 并用一个不规则的确定性取值。
        for (uint32_t a = 0; a < attrs; ++a) {
            f.records[i].attributes[a] =
                static_cast<int64_t>((i * 3 + a * 5 + 1) % (cols_per_attr - 1));
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

// 明文基准：Σ_i filter[i] · E_i（E 取属性的明文值）
//
// ⚠️ **下标顺序容易搞反**：`plain_attribute_values()` 的布局是 **`[属性][记录]`**
//    （`init.cpp`：`plain_attrs_.assign(attrs.size(), vector<int64_t>(N, 0))`），
//    **不是** `[记录][属性]`。本用例第一版照 `init.hpp` 里那条写错的注释
//    （"明文属性值（N × |attrs|）"）写成 `pa[i][attr_id]`，于是在"全集 filter"上
//    `i` 一路走到 63 而外层只有 `|attrs| = 2` 行 ⇒ **越界段错误**。
//    那条注释已一并订正为 `|attrs| × N`。
uint128_t ExpectedSum(const Fix& f, const std::vector<uint8_t>& filter, uint32_t attr_id) {
    const auto& pa = f.client->plain_attribute_values();
    if (attr_id >= pa.size()) {
        TSB_FAIL_("ExpectedSum: attr_id=" + std::to_string(attr_id) +
                  " 超出明文属性表行数 " + std::to_string(pa.size()));
        return 0;
    }
    const std::vector<int64_t>& col = pa[attr_id];      // ← [属性] 取行
    uint128_t acc = 0;
    for (size_t i = 0; i < filter.size(); ++i) {
        if (filter[i] == 0) continue;
        if (i >= col.size()) {
            TSB_FAIL_("ExpectedSum: 记录下标越界（" + std::to_string(i) + " >= " +
                      std::to_string(col.size()) + "）—— filter 长度与明文表不一致");
            return acc;
        }
        acc += static_cast<uint128_t>(col[i]);          // ← [记录] 取列
    }
    return acc;
}

CountResult MakeCountResult(const std::vector<uint8_t>& filter) {
    CountResult c;
    c.filter = filter;
    c.count = static_cast<uint64_t>(
        std::count_if(filter.begin(), filter.end(), [](uint8_t b) { return b != 0; }));
    return c;
}

// 跑一次 Sum：每例用**新的** prng / salt，避免跨例耦合
SumResult RunSum(Fix& f, const std::vector<uint8_t>& filter, uint32_t attr_id,
                 uint64_t salt = 0x1234,
                 std::function<void(int, Payload&)> tamper = nullptr) {
    LocalTransportOptions opt;
    opt.tamper_hook = std::move(tamper);
    LocalTransport net(2, opt);
    SecureMulClientState mac(f.client->mac_key_shares(), f.client->modulus(),
                             f.client->store_params().security_mode);
    random::DeterministicPrng prng(
        MakeAesSeed(std::vector<uint8_t>{'a', 'g', 'g', 'v', 'a', 'l', 'u', 'e'}),
        /*nonce=*/11);
    const CountResult c = MakeCountResult(filter);
    return SumOverFilter(c, f.schema, attr_id, *f.client, net, mac, prng, salt);
}

}  // namespace

// ---------------------------------------------------------------------------
// A1 + A2：Count 自洽，Sum == 明文基准（三种 filter）
// ---------------------------------------------------------------------------

TEST(AggValue, SumMatchesPlaintextBaseline) {
    Fix f = MakeFix(64);
    const size_t N = f.n;
    const uint32_t attr = 0;

    // 三种 filter：空集 / 全集 / 任意子集（含 `f=0` 与 `f=1` 交错）
    std::vector<std::vector<uint8_t>> filters;
    filters.push_back(std::vector<uint8_t>(N, 0));                       // 空集
    filters.push_back(std::vector<uint8_t>(N, 1));                       // 全集
    {
        std::vector<uint8_t> v(N, 0);
        for (size_t i = 0; i < N; i += 3) v[i] = 1;                      // 子集
        filters.push_back(v);
    }
    {
        std::vector<uint8_t> v(N, 0);
        for (size_t i = 0; i < N; ++i) v[i] = (i % 2 == 0) ? 1 : 0;      // 交错
        filters.push_back(v);
    }

    for (size_t k = 0; k < filters.size(); ++k) {
        const std::vector<uint8_t>& flt = filters[k];
        const CountResult c = MakeCountResult(flt);
        // A1：count == popcount(filter)
        EXPECT_EQ(c.count, static_cast<uint64_t>(std::count(flt.begin(), flt.end(), 1)));

        const uint128_t want = ExpectedSum(f, flt, attr);
        const SumResult r = RunSum(f, flt, attr, /*salt=*/0x100 + k);
        if (r.sum != want) {
            TSB_FAIL_("filter #" + std::to_string(k) + " 的 Sum 与明文基准不一致");
            return;
        }
        EXPECT_EQ(r.count, c.count);      // Sum 必须回填同一个 count
    }
}

// ---------------------------------------------------------------------------
// A3 + A4：Avg 口径（整数向下取整；count == 0 ⇒ 抛）
// ---------------------------------------------------------------------------

TEST(AggValue, AvgRoundsDownAndRejectsZeroCount) {
    Fix f = MakeFix(64);
    const size_t N = f.n;

    // 非空 filter ⇒ Avg == floor(sum / count)
    std::vector<uint8_t> flt(N, 0);
    for (size_t i = 0; i < N; i += 2) flt[i] = 1;
    const SumResult r = RunSum(f, flt, /*attr_id=*/0, /*salt=*/0x200);
    EXPECT_TRUE(r.count > 0);
    const uint128_t want_avg = r.sum / static_cast<uint128_t>(r.count);
    EXPECT_EQ(AvgOverFilter(r), want_avg);

    // ⚠️ 空 filter ⇒ **必须抛 `std::domain_error`**（绝不静默返回 0/NaN）。
    //    这是库的明确口径（`aggvalue.hpp` §8）：`Avg` 在无记录时数学上无定义，
    //    静默给 0 会让上层把"没有匹配"与"平均值真的是 0"混为一谈。
    std::vector<uint8_t> empty(N, 0);
    const SumResult r0 = RunSum(f, empty, /*attr_id=*/0, /*salt=*/0x201);
    EXPECT_EQ(r0.count, 0u);
    EXPECT_EQ(r0.sum, static_cast<uint128_t>(0));      // Sum = 0 是**良定义**的
    EXPECT_THROW(AvgOverFilter(r0), std::domain_error);
}

// ---------------------------------------------------------------------------
// A5：篡改 ⇒ **整体 abort**（绝不返回部分和）
// ---------------------------------------------------------------------------

TEST(AggValue, TamperingAbortsInsteadOfReturningPartialSum) {
    Fix f = MakeFix(64, 8, 2, 24, MpraqSecurityMode::kMalicious);
    const size_t N = f.n;
    std::vector<uint8_t> flt(N, 1);                    // 全集：每条记录都要过 SecureMul
    const uint32_t attr = 0;

    // 基线：诚实流程能过，且 sum 与明文基准一致
    const SumResult ok = RunSum(f, flt, attr, /*salt=*/0x300);
    EXPECT_EQ(ok.count, static_cast<uint64_t>(N));
    EXPECT_EQ(ok.sum, ExpectedSum(f, flt, attr));

    // 篡改：模拟**恶意服务器**（`LocalTransportOptions::tamper_hook` 在应答返回客户端
    // 之前就地改 payload），翻转服务器 1 第 2 轮应答里 `z_share` 的最低位。
    //
    // ⚠️ **不要**改成"篡改 `client->node(0).SetAttributeShares(...)`"：**本地路径**下
    //    服务器侧材料取自 `client.AttributeShares()`（客户端自己的副本），
    //    `node` 里那份**根本不参与**本层计算 —— 那样写篡改会是**空操作**，
    //    用例会以"没抛异常"的形式**假失败**（第一版就是这么写的）。
    int fired = 0;
    auto tamper = [&fired](int server_id, Payload& resp) {
        if (server_id != 1) return;                    // 只让服务器 1 作恶
        if (resp.size() < 10) return;
        resp.back() = static_cast<uint8_t>(resp.back() ^ 0x01);   // 改应答的最后一个字节
        ++fired;
    };

    bool aborted = false;
    try {
        (void)RunSum(f, flt, attr, /*salt=*/0x301, tamper);
    } catch (const SecureMulBatchAbort&) {
        aborted = true;
    } catch (const std::exception&) {
        // 其它异常也意味着"没有返回部分和"，但本用例要求走 abort 那条路径
    }
    EXPECT_TRUE(fired > 0);      // 钩子确实生效了（否则"没抛"是假阴性）
    EXPECT_TRUE(aborted);        // **绝不返回部分和**

    // 不篡改时仍能通过（证明前面的 abort 来自篡改，而不是把夹具弄坏了）
    const SumResult again = RunSum(f, flt, attr, /*salt=*/0x302);
    EXPECT_EQ(again.sum, ExpectedSum(f, flt, attr));
}

// ---------------------------------------------------------------------------
// A6：`filter` 长度 ≠ N ⇒ 拒绝
// ---------------------------------------------------------------------------

TEST(AggValue, FilterLengthMismatchIsRejected) {
    Fix f = MakeFix(32);
    const uint32_t attr = 0;

    // 短一位
    {
        std::vector<uint8_t> bad(f.n - 1, 1);
        LocalTransport net(2);
        SecureMulClientState mac(f.client->mac_key_shares(), f.client->modulus(),
                                 f.client->store_params().security_mode);
        random::DeterministicPrng prng(
            MakeAesSeed(std::vector<uint8_t>{'a', 'g', 'g', 'v', 'a', 'l', 'u', 'e'}),
            11);
        const CountResult c = MakeCountResult(bad);
        EXPECT_THROW(
            SumOverFilter(c, f.schema, attr, *f.client, net, mac, prng, 0x400),
            std::exception);
    }
    // 多一位
    {
        std::vector<uint8_t> bad(f.n + 1, 1);
        LocalTransport net(2);
        SecureMulClientState mac(f.client->mac_key_shares(), f.client->modulus(),
                                 f.client->store_params().security_mode);
        random::DeterministicPrng prng(
            MakeAesSeed(std::vector<uint8_t>{'a', 'g', 'g', 'v', 'a', 'l', 'u', 'e'}),
            11);
        const CountResult c = MakeCountResult(bad);
        EXPECT_THROW(
            SumOverFilter(c, f.schema, attr, *f.client, net, mac, prng, 0x401),
            std::exception);
    }
}

// ---------------------------------------------------------------------------
// A7：确定性（同 salt + 同 prng 种子 ⇒ 逐位相同）
// ---------------------------------------------------------------------------

TEST(AggValue, SameInputsGiveIdenticalSum) {
    Fix f1 = MakeFix(48);
    Fix f2 = MakeFix(48);
    std::vector<uint8_t> flt(48, 0);
    for (size_t i = 0; i < 48; i += 4) flt[i] = 1;

    const SumResult a = RunSum(f1, flt, 0, /*salt=*/0x500);
    const SumResult b = RunSum(f2, flt, 0, /*salt=*/0x500);
    EXPECT_EQ(a.sum, b.sum);
    EXPECT_EQ(a.count, b.count);
    EXPECT_EQ(a.securemul.rounds, b.securemul.rounds);
    EXPECT_EQ(a.securemul.wire_messages, b.securemul.wire_messages);
}

// ---------------------------------------------------------------------------
// A8：两档都要能跑（半诚实档**不做验证**，但 Sum 必须仍然正确）
// ---------------------------------------------------------------------------

TEST(AggValue, SemiHonestModeAlsoComputesCorrectSum) {
    using tsb::mpraq::MpraqSecurityMode;
    Fix f = MakeFix(48, 2, 2, 24, MpraqSecurityMode::kSemiHonest);
    std::vector<uint8_t> flt(48, 0);
    for (size_t i = 1; i < 48; i += 2) flt[i] = 1;

    const SumResult r = RunSum(f, flt, /*attr_id=*/0, /*salt=*/0x600);
    // 半诚实档只是**不校验**（篡改会被静默接受），诚实输入下结果必须同样正确。
    EXPECT_EQ(r.sum, ExpectedSum(f, flt, 0));
    EXPECT_EQ(r.count, static_cast<uint64_t>(24));
    EXPECT_EQ(AvgOverFilter(r), r.sum / static_cast<uint128_t>(r.count));
}
