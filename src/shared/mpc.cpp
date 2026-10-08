#include "shared/mpc.hpp"

#include "core/random.hpp"

#include <stdexcept>

namespace tsb {

void RequireOddModulus(uint128_t q) {
    if (q < 3) {
        throw std::invalid_argument("SecureMul: 模数 q 必须 >= 3");
    }
    if ((q & 1u) == 0) {
        // ⚠️ 本检查的**理由已变**（2026-10-08，对齐新版论文）：
        //    SecureMul 不再使用 `2^{-1}`（公开项 `e·d` 改由客户端在验证后补），
        //    因此"偶数模数下 e·d·2^{-1} 无定义"这条**不再是**本检查的动机。
        //    现在要求奇数的真实理由是 **SPDZ MAC 需要域**：`mac = α·z` 要求 α 可逆，
        //    而 `Z_{2^k}` 里 α 可能是偶数（不可逆）⇒ 非零偏差未必可逆 ⇒ 恶意服务器
        //    可返回任意错值而校验仍通过（论文 :137-141 对同类失败的说明）。
        //    ⚠️ 本函数只校验**奇数**（廉价的必要条件）；**素数性**由调用方与
        //    决策 D11 / `core/field` 保证，本函数不做素性测试。
        throw std::invalid_argument(
            "SecureMul: 模数 q 必须为奇数（SPDZ MAC 需要域：Z_{2^k} 里 α 可能不可逆，"
            "非零偏差未必可逆 ⇒ 校验可被绕过；见 TASK_PLAN 决策 D11 与论文 §xmac）");
    }
    if (q > (static_cast<uint128_t>(1) << 127)) {
        throw std::invalid_argument(
            "SecureMul: 模数 q 必须 <= 2^127（core/field 的 modmul 约束）");
    }
}

// ---------------------------------------------------------------------------
// triple 生成与共享
// ---------------------------------------------------------------------------

std::pair<TripleShare, TripleShare> GenerateTripleShares(const MacKeyShares& keys,
                                                         uint128_t q) {
    RequireOddModulus(q);
    if (keys.alpha_shares.size() != 2) {
        throw std::invalid_argument(
            "GenerateTripleShares: 需要恰好 2 份 α 分享（双服务器）");
    }

    // 生成 a、b 及其乘积 c
    const uint128_t a = random::Below(q);
    const uint128_t b = random::Below(q);
    const uint128_t c = mulMod(a, b, q);

    TripleShare s0, s1;
    {
        auto [x0, x1] = ShareMod(a, q);
        s0.a = x0;
        s1.a = x1;
    }
    {
        auto [x0, x1] = ShareMod(b, q);
        s0.b = x0;
        s1.b = x1;
    }
    {
        auto [x0, x1] = ShareMod(c, q);
        s0.c = x0;
        s1.c = x1;
    }
    // α 的分享由调用方提供（全局 MAC 密钥），这里直接取用
    s0.alpha = ModShare{keys.alpha_shares[0]};
    s1.alpha = ModShare{keys.alpha_shares[1]};

    // α·a、α·b、α·c 的分享。掩码必须独立，不能复用上面的掩码，
    // 否则 ⟨α·a⟩ 与 ⟨a⟩ 相关联会泄露 α。
    {
        auto [x0, x1] = ShareMod(mulMod(keys.alpha, a, q), q);
        s0.alpha_a = x0;
        s1.alpha_a = x1;
    }
    {
        auto [x0, x1] = ShareMod(mulMod(keys.alpha, b, q), q);
        s0.alpha_b = x0;
        s1.alpha_b = x1;
    }
    {
        auto [x0, x1] = ShareMod(mulMod(keys.alpha, c, q), q);
        s0.alpha_c = x0;
        s1.alpha_c = x1;
    }
    return {s0, s1};
}

// ---------------------------------------------------------------------------
// 服务器两阶段
// ---------------------------------------------------------------------------

SecureMulRound1 SecureMulServerPhase1(const SecureMulServerInput& in, uint128_t q) {
    RequireOddModulus(q);
    // ⟨e⟩_p = ⟨y⟩_p − ⟨b⟩_p
    return SecureMulRound1{subMod(in.y.value, in.triple.b.value, q)};
}

SecureMulRound2 SecureMulServerPhase2(const SecureMulServerInput& in, uint128_t d,
                                      uint128_t e, uint128_t q) {
    RequireOddModulus(q);

    // ⚠️ 公式**已按新版论文对齐**（2026-10-08）：服务端只算**纯线性**部分，
    //    公开项 `e·d` **不由服务端折入**，而是由客户端在 MAC 校验通过后补上。
    //
    //    ⟨z⟩_p   = ⟨c⟩_p + d·⟨b⟩_p + e·⟨a⟩_p                 （无 e·d）
    //    ⟨mac⟩_p = ⟨αc⟩_p + d·⟨αb⟩_p + e·⟨αa⟩_p              （无 ⟨α⟩_p·e·d）
    //
    //    于是两台求和：z = c + d·b + e·a，mac = α·(c + d·b + e·a) = α·z ✔
    //    客户端校验通过后输出 `z + e·d = (a+d)(b+e) = f·E` ✔
    //
    // 为什么必须这样（两条理由，指向同一改法）：
    //   ① 论文 :556-557 明确：`e·d` **故意**不折进服务端表达式，
    //      "keeps the servers' expressions purely linear in their shares,
    //       which is the form the soundness argument relies on"；
    //   ② 折进服务端需要 `2^{-1}`（两台各给一半才能凑成整份），而
    //      **特征 2 的域/环（GF(2^ℓ) / Z_{2^k}）里 `2` 不可逆**；更强的是，
    //      在特征 2 下"两台各加一次"恒为 `x ⊕ x = 0`，**没有"各给一半"的类比**。
    //      ⇒ 只要层可能落在特征 2，客户端补公开项就是**唯一**可行做法。
    //    （旧实现用 `e·d·2^{-1}` + `⟨α⟩_p·e·d`，在 `Z_q`（奇素数）下结果等价，
    //      但它破坏了 ① 的形式、且绑定了奇特征；决策 D14 的勘误仍然有效：
    //      **mac 末项绝不能再乘 `2^{-1}`**，否则 `mac ≠ α·z` 恒失败。）
    //
    // ⚠️ 易错点：`in.triple.*.value` 是**本服务器分片**，不是重建值；
    //    本函数算的是"单台分片"，两台求和才等于 z/mac。
    uint128_t z = in.triple.c.value;
    z = addMod(z, mulMod(d, in.triple.b.value, q), q);
    z = addMod(z, mulMod(e, in.triple.a.value, q), q);

    uint128_t mac = in.triple.alpha_c.value;
    mac = addMod(mac, mulMod(d, in.triple.alpha_b.value, q), q);
    mac = addMod(mac, mulMod(e, in.triple.alpha_a.value, q), q);

    return SecureMulRound2{ModShare{z}, ModShare{mac}};
}

// ---------------------------------------------------------------------------
// 客户端驱动
// ---------------------------------------------------------------------------

SecureMulResult SecureMulRun(uint128_t x, const SecureMulServerInput& share0,
                             const SecureMulServerInput& share1,
                             const BeaverTriple& triple, const MacKeyShares& keys,
                             uint128_t q) {
    RequireOddModulus(q);

    // 1. d = x − a
    const uint128_t d = subMod(x, triple.a, q);

    // 2. 各服务器算 ⟨e⟩_p
    const SecureMulRound1 r1_0 = SecureMulServerPhase1(share0, q);
    const SecureMulRound1 r1_1 = SecureMulServerPhase1(share1, q);

    // 3. 客户端中转后两服务器各自重建 e
    const uint128_t e = addMod(r1_0.e.value, r1_1.e.value, q);

    // 4. 各服务器算 ⟨z⟩_p 与 ⟨mac⟩_p
    const SecureMulRound2 r2_0 = SecureMulServerPhase2(share0, d, e, q);
    const SecureMulRound2 r2_1 = SecureMulServerPhase2(share1, d, e, q);

    // 5. 客户端重建并验证
    SecureMulResult out;
    const AuthenticatedShare a0{r2_0.z, r2_0.mac};
    const AuthenticatedShare a1{r2_1.z, r2_1.mac};
    out.mac_result = VerifyAuthenticatedDetailed(a0, a1, keys.alpha, q);
    out.ok = out.mac_result.ok;
    out.z = out.mac_result.z;
    // 6. **验证通过后**才补公开项（新版论文 :556-562）：
    //    服务端只给了线性部分 `z = c + d·b + e·a`（其 MAC 恰好是 `α·z`），
    //    真正的乘积累 `z + e·d = (a+d)(b+e) = x·y` 由客户端补。
    //    ⚠️ 顺序不能反：先补再校验会让 `mac ?= α·z` 两侧不等。
    if (out.ok) {
        out.z = addMod(out.z, mulMod(e, d, q), q);
    }
    return out;
}

SecureMulResult SecureMulSimple(uint128_t x, const ModShare& y0, const ModShare& y1,
                                const MacKeyShares& keys, uint128_t q) {
    RequireOddModulus(q);
    auto [t0, t1] = GenerateTripleShares(keys, q);

    // 重建 a、b 以构造客户端本地的 triple
    BeaverTriple triple;
    triple.a = addMod(t0.a.value, t1.a.value, q);
    triple.b = addMod(t0.b.value, t1.b.value, q);
    triple.c = addMod(t0.c.value, t1.c.value, q);

    SecureMulServerInput in0{y0, t0};
    SecureMulServerInput in1{y1, t1};
    return SecureMulRun(x, in0, in1, triple, keys, q);
}

}  // namespace tsb
