#include "core/field.hpp"

#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace tsb {

namespace {
constexpr uint128_t kMax = ~static_cast<uint128_t>(0);
constexpr uint128_t kLo64Mask = static_cast<uint128_t>(0xffffffffffffffffULL);
constexpr uint128_t kPow2_127 = static_cast<uint128_t>(1) << 127;
}  // namespace

uint128_t reduce(uint128_t v, uint128_t q) {
    if (q == 0) {
        throw std::invalid_argument("field::reduce: 模数 q 不能为 0");
    }
    if (v < q) {
        return v;
    }
    // 逐位（MSB→LSB）长除法：维护 r < q，每一步 r ← (2r + bit) mod q。
    //
    // 曾经用"把 q 左移到与 v 的最高位对齐"的写法，但当 v 与 q 位长相差
    // 很大时（例如 v = 2^128-2, q = 7），t 会在移位过程中溢出回绕成 0，
    // 使约减结果完全错误。逐位法没有这个问题。
    //
    // 约束：需要 2r + b < 2^128。由 r < min(q, 2^127) 可得
    //   2r + 1 <= 2*min(q-1, 2^127-1) + 1 < 2^128  当且仅当 q <= 2^127
    // 因此模数须 <= 2^127（与 mulMod 同一约束）。2^128 本身不是本函数的
    // 模数——Z_{2^128} 的运算就是自然回绕的加乘，见 add/sub/mul。
    if (q > kPow2_127) {
        throw std::invalid_argument(
            "field::reduce: 模数 q 必须 <= 2^127（逐位约减的中间量需要 2q 可表示）");
    }
    uint128_t r = 0;
    for (int bit = 127; bit >= 0; --bit) {
        const unsigned b = static_cast<unsigned>((v >> bit) & 1u);
        r = (r << 1) | b;  // 由上述约束保证不回绕
        if (r >= q) {
            r -= q;
        }
    }
    return r;
}

uint128_t addMod(uint128_t a, uint128_t b, uint128_t q) {
    if (q == 0) {
        throw std::invalid_argument("field::addMod: 模数 q 不能为 0");
    }
    a = reduce(a, q);
    b = reduce(b, q);
    // a,b < q <= 2^128-1，直接相加可能溢出；改用条件判断避免回绕。
    if (kMax - a < b) {
        return a - (q - b);
    }
    const uint128_t s = a + b;
    return s >= q ? s - q : s;
}

uint128_t subMod(uint128_t a, uint128_t b, uint128_t q) {
    if (q == 0) {
        throw std::invalid_argument("field::subMod: 模数 q 不能为 0");
    }
    a = reduce(a, q);
    b = reduce(b, q);
    return a >= b ? a - b : a + (q - b);
}

uint128_t modInversePow2(uint128_t a, unsigned k) {
    if (k == 0 || k > 128) {
        throw std::invalid_argument("field::modInversePow2: k 必须在 1..128");
    }
    if ((a & 1u) == 0) {
        throw std::invalid_argument("field::modInversePow2: a 必须为奇数");
    }
    // 牛顿迭代：x_{n+1} = x * (2 - a*x)，每轮的精度翻倍。
    // 起点必须满足 a*x ≡ 1 (mod 2)；对奇数 a 取 x = 1 恒成立。
    // （若以 x = a 起手，对 a = 2 会得到 x = 0：2*(2-4) = -4 ≡ 2^128-4，
    //   再乘 2 回绕为 0，迭代不收敛。）
    // 精度序列 2 → 4 → 8 → 16 → 32 → 64 → 128，7 轮足够。
    uint128_t x = 1;
    for (int i = 0; i < 7; ++i) {
        x = x * (static_cast<uint128_t>(2) - a * x);
    }
    if (k == 128) {
        return x;
    }
    return x & ((static_cast<uint128_t>(1) << k) - 1);
}

uint128_t modInverse(uint128_t a, uint128_t m) {
    if (m == 0) {
        throw std::invalid_argument("field::modInverse: 模数 m 不能为 0");
    }
    if (m == 1) {
        return 0;
    }
    a = reduce(a, m);
    if (a == 0) {
        throw std::invalid_argument("field::modInverse: 0 在模 m 下不可逆");
    }

    // 扩展欧几里得，系数用"signed magnitude"表示：uint128 幅值 + 1 bit 符号。
    //
    // 关键陷阱：系数不能简单地按模 2^128 做补码回绕。回绕只在模数整除
    // 2^128 时才与真实整数运算一致（例如 m = 7 时，s*3 与 (s+2^128)*3 的
    // 模 7 余数可以相差 3），因此回绕会得到错误的逆元。
    // 这里改为在 2^128 的幅值空间里做精确的有符号加减，全程不丢失精度。
    //
    // 由 |s_{i-1}| <= m/2 与 q_i >= 1 可保证 q_i*|s_{i-1}| 不超过 2^128，
    // 因此下面的幅值运算不会回绕。
    struct Signed {
        uint128_t mag = 0;
        bool neg = false;
    };
    const auto signedFrom = [](uint128_t v) {
        return Signed{v, false};
    };
    // a - b，精确到 2^128 幅值
    const auto signedSub = [](const Signed& x, const Signed& y) -> Signed {
        if (x.neg != y.neg) {
            // 同号相加：幅值相加（由界保证不回绕）
            return Signed{x.mag + y.mag, x.neg};
        }
        if (x.mag >= y.mag) {
            return Signed{x.mag - y.mag, x.neg};
        }
        return Signed{y.mag - x.mag, !x.neg};
    };
    const auto signedMul = [&](uint128_t k, const Signed& x) -> Signed {
        // k * |x| 由界保证不超过 2^128；仍加一层断言式检查
        if (x.mag != 0 && k > kMax / x.mag) {
            throw std::runtime_error("field::modInverse: 系数溢出 128 位");
        }
        return Signed{x.mag * k, x.neg};
    };

    uint128_t r0 = a, r1 = m;
    Signed s0 = signedFrom(1), s1 = signedFrom(0);
    int guard = 0;
    while (r1 != 0) {
        if (++guard > 512) {
            throw std::runtime_error("field::modInverse: 欧几里得迭代未收敛");
        }
        uint128_t qq = 0, r2 = r0;
        Signed s2 = s0;
        if (r0 >= r1) {
            qq = r0 / r1;
            r2 = r0 - qq * r1;
            s2 = signedSub(s0, signedMul(qq, s1));
        }
        r0 = r1;
        r1 = r2;
        s0 = s1;
        s1 = s2;
    }
    if (r0 != 1) {
        throw std::invalid_argument("field::modInverse: a 与 m 不互素，逆元不存在");
    }
    // s0 是满足 s0*a ≡ 1 (mod m) 的系数；负数时取 m - (|s0| mod m)
    const uint128_t magMod = reduce(s0.mag, m);
    if (!s0.neg) {
        return magMod;
    }
    return magMod == 0 ? 0 : (m - magMod);
}

uint128_t mulMod(uint128_t a, uint128_t b, uint128_t q) {
    if (q == 0) {
        throw std::invalid_argument("field::mulMod: 模数 q 不能为 0");
    }
    // 中间量以 128 位累加，需要 2q <= 2^128 才能保证 addMod(rem,rem,q) 不回绕。
    if (q > kPow2_127) {
        throw std::invalid_argument(
            "field::mulMod: 模数 q 必须 <= 2^127（否则 256 位模约减会溢出）");
    }
    a = reduce(a, q);
    b = reduce(b, q);

    // 128×128 → 256 位：按 64 位拆分成四个部分积，避免直接相乘丢高位。
    const uint64_t a0 = low64(a), a1 = high64(a);
    const uint64_t b0 = low64(b), b1 = high64(b);

    const uint128_t p00 = static_cast<uint128_t>(a0) * b0;
    const uint128_t p01 = static_cast<uint128_t>(a0) * b1;
    const uint128_t p10 = static_cast<uint128_t>(a1) * b0;
    const uint128_t p11 = static_cast<uint128_t>(a1) * b1;

    // 累加到 256 位的 (hi, lo)
    const uint128_t mid = (p00 >> 64) + (p01 & kLo64Mask) + (p10 & kLo64Mask);
    const uint128_t lo = (p00 & kLo64Mask) | (mid << 64);
    const uint128_t hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);

    if (hi == 0) {
        return reduce(lo, q);
    }

    // 逐位做 256 位模约减：从 (hi, lo) 的最低位起扫描
    uint128_t rem = 0;
    for (int bit = 255; bit >= 0; --bit) {
        rem = addMod(rem, rem, q);
        const bool set = bit >= 128 ? ((hi >> (bit - 128)) & 1u) != 0
                                    : ((lo >> bit) & 1u) != 0;
        if (set) {
            rem = addMod(rem, static_cast<uint128_t>(1), q);
        }
    }
    return rem;
}

void toBytesLE(uint128_t v, uint8_t out[kUint128Bytes]) {
    for (size_t i = 0; i < kUint128Bytes; ++i) {
        out[i] = static_cast<uint8_t>(v >> (8 * i));
    }
}

uint128_t fromBytesLE(const uint8_t in[kUint128Bytes]) {
    uint128_t v = 0;
    for (size_t i = 0; i < kUint128Bytes; ++i) {
        v |= static_cast<uint128_t>(in[i]) << (8 * i);
    }
    return v;
}

std::vector<uint8_t> toBytes(uint128_t v) {
    std::vector<uint8_t> out(kUint128Bytes);
    toBytesLE(v, out.data());
    return out;
}

uint128_t fromBytes(const uint8_t* data, size_t len) {
    if (len < kUint128Bytes) {
        // 高位补零，便于处理被截断的输入
        uint8_t buf[kUint128Bytes] = {0};
        std::memcpy(buf, data, len);
        return fromBytesLE(buf);
    }
    return fromBytesLE(data);
}

std::string toString(uint128_t v) {
    if (v == 0) {
        return "0";
    }
    std::string s;
    while (v > 0) {
        s.push_back(static_cast<char>('0' + static_cast<int>(v % 10)));
        v /= 10;
    }
    std::reverse(s.begin(), s.end());
    return s;
}

std::string toHex(uint128_t v) {
    char buf[35];
    std::snprintf(buf, sizeof(buf), "0x%016llx%016llx",
                  static_cast<unsigned long long>(high64(v)),
                  static_cast<unsigned long long>(low64(v)));
    return std::string(buf);
}

uint128_t ParseLiteral(const char* str) {
    if (str == nullptr || *str == '\0') {
        throw std::invalid_argument("field::parse: 空字符串");
    }
    const std::string s(str);
    return parse(s);
}

uint128_t parse(const std::string& s) {
    if (s.empty()) {
        throw std::invalid_argument("field::parse: 空字符串");
    }
    size_t i = 0;
    int base = 10;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        i = 2;
    }
    if (i >= s.size()) {
        throw std::invalid_argument("field::parse: 缺少数字: " + s);
    }

    uint128_t acc = 0;
    for (; i < s.size(); ++i) {
        const char c = s[i];
        int d;
        if (c >= '0' && c <= '9') {
            d = c - '0';
        } else if (base == 16 && c >= 'a' && c <= 'f') {
            d = c - 'a' + 10;
        } else if (base == 16 && c >= 'A' && c <= 'F') {
            d = c - 'A' + 10;
        } else {
            throw std::invalid_argument("field::parse: 非法字符 '" + std::string(1, c) +
                                        "' in " + s);
        }
        if (d >= base) {
            throw std::invalid_argument("field::parse: 数字超出进制范围: " + s);
        }
        // 溢出检测
        if (acc > (kMax - static_cast<uint128_t>(d)) / static_cast<uint128_t>(base)) {
            throw std::invalid_argument("field::parse: 数值超出 128-bit 范围: " + s);
        }
        acc = acc * static_cast<uint128_t>(base) + static_cast<uint128_t>(d);
    }
    return acc;
}

}  // namespace tsb
