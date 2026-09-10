#include "shared/mpc.hpp"

#include "core/random.hpp"

#include <stdexcept>

namespace tsb {

void RequireOddModulus(uint128_t q) {
    if (q < 3) {
        throw std::invalid_argument("SecureMul: 模数 q 必须 >= 3");
    }
    if ((q & 1u) == 0) {
        // 决策 D11：偶数模数下 2 不可逆，SecureMul 公式中的 e·d·2^{-1} 无定义
        throw std::invalid_argument(
            "SecureMul: 模数 q 必须为奇数（Z_{2^k} 中 2 不可逆，"
            "公式里的 e·d·2^{-1} 无定义；见 TASK_PLAN 决策 D11）");
    }
    if (q > (static_cast<uint128_t>(1) << 127)) {
        throw std::invalid_argument(
            "SecureMul: 模数 q 必须 <= 2^127（core/field 的 modmul 约束）");
    }
}

namespace {

// 2^{-1} mod q，q 为奇数
uint128_t Inv2(uint128_t q) { return modInverse(static_cast<uint128_t>(2), q); }

}  // namespace

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
    const uint128_t inv2 = Inv2(q);

    // ⟨z⟩_p = ⟨c⟩_p + d·⟨b⟩_p + e·⟨a⟩_p + e·d·2^{-1}
    uint128_t z = in.triple.c.value;
    z = addMod(z, mulMod(d, in.triple.b.value, q), q);
    z = addMod(z, mulMod(e, in.triple.a.value, q), q);
    z = addMod(z, mulMod(mulMod(e, d, q), inv2, q), q);

    // ⟨mac⟩_p = ⟨αc⟩_p + d·⟨αb⟩_p + e·⟨αa⟩_p + ⟨α⟩_p·e·d
    //
    // ⚠️ **勘误**：MPRAQ 论文 Algorithm 5 把最后一项写成 `⟨α⟩_p·e·d·2^{-1}`，
    // 这是错的——照抄会导致 `mac ≠ α·z`，MAC 校验恒失败（见决策 D14）。
    //
    // 推导：z 的公式里末项是 `e·d·2^{-1}`，因此
    //     z = c + d·b + e·a + e·d/2
    //     正确 MAC 应为 α·z = αc + d·(αb) + e·(αa) + α·e·d/2
    // 而论文把它写成了 …… + α·e·d/2 之外**又**乘了一次 2^{-1}，
    // 于是 mac = α·z 不成立。本实现按正确公式计算。
    uint128_t mac = in.triple.alpha_c.value;
    mac = addMod(mac, mulMod(d, in.triple.alpha_b.value, q), q);
    mac = addMod(mac, mulMod(e, in.triple.alpha_a.value, q), q);
    mac = addMod(mac, mulMod(in.triple.alpha.value, mulMod(e, d, q), q), q);

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
    out.z = out.mac_result.z;
    out.ok = out.mac_result.ok;
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
