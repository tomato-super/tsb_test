#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace tsb {

// 128-bit 无符号整数。本项目两个协议的秘密共享元素都是 128-bit
// （VMPQ 的 RSS over Z_{2^128}；MPRAQ 的属性值元素）。
#if !defined(__SIZEOF_INT128__)
#error "本项目依赖 128-bit 整数扩展 (__int128)；请使用 GCC/Clang 编译。"
#endif

using uint128_t = unsigned __int128;

constexpr size_t kUint128Bytes = 16;

// ---------------------------------------------------------------------------
// Z_{2^128} 环运算（自然溢出即模 2^128）
// ---------------------------------------------------------------------------

inline uint128_t add(uint128_t a, uint128_t b) { return a + b; }
inline uint128_t sub(uint128_t a, uint128_t b) { return a - b; }
inline uint128_t neg(uint128_t a) { return static_cast<uint128_t>(0) - a; }
inline uint128_t mul(uint128_t a, uint128_t b) { return a * b; }

// 2 的幂环中的"乘以 2^127"。
//
// ⚠️ 这不是除法！2 在 Z_{2^128} 中不可逆（gcd(2, 2^128) = 2），
// 所以不存在 2^{-1}。本函数只是"乘 2^127"，只在极少数情形下恰好等于 /2
// （例如 x == 2 时结果为 1）。真正的除以 2 请用 shr(a, 1)（仅对偶数有意义）。
//
// 保留此函数是为了显式暴露 SecureMul 中 e*d*2^{-1} 这一项的代数问题：
// 论文公式要求 2 可逆，见 TASK_PLAN.md §7.6 Q1。
inline uint128_t mulBy2Pow127(uint128_t a) {
    return a * (static_cast<uint128_t>(1) << 127);
}

// 2^127。注意它是偶数，在 Z_{2^128} 中不可逆，且是零因子（2^127 * 2 == 0）。
inline uint128_t pow2_127() { return static_cast<uint128_t>(1) << 127; }

// 兼容旧命名（语义同上，不是逆元）
inline uint128_t mulHalf(uint128_t a) { return mulBy2Pow127(a); }
inline uint128_t inv2Pow2k() { return pow2_127(); }

// ---------------------------------------------------------------------------
// 位操作（显式，避免移位量 >= 宽度导致的 UB）
// ---------------------------------------------------------------------------

inline uint64_t high64(uint128_t v) { return static_cast<uint64_t>(v >> 64); }
inline uint64_t low64(uint128_t v) { return static_cast<uint64_t>(v); }
inline uint128_t from64(uint64_t hi, uint64_t lo) {
    return (static_cast<uint128_t>(hi) << 64) | static_cast<uint128_t>(lo);
}

// v << n，n 可为 0..127（n >= 128 返回 0）
inline uint128_t shl(uint128_t v, unsigned n) {
    if (n == 0) return v;
    if (n >= 128) return 0;
    return v << n;
}

// v >> n，n 可为 0..127（n >= 128 返回 0）
inline uint128_t shr(uint128_t v, unsigned n) {
    if (n == 0) return v;
    if (n >= 128) return 0;
    return v >> n;
}

// ---------------------------------------------------------------------------
// 模 q 运算（q 为任意 128-bit 模数，用于 MPRAQ 的属性值算术）
// ---------------------------------------------------------------------------

uint128_t addMod(uint128_t a, uint128_t b, uint128_t q);
uint128_t subMod(uint128_t a, uint128_t b, uint128_t q);

// 模乘。结果等价于 (a*b) mod q，但用 256 位中间量计算，
// 因此 mod q 下的大数相乘不会因 128 位回绕而丢高位。
uint128_t mulMod(uint128_t a, uint128_t b, uint128_t q);

// 将 v 归约到 [0, q)。要求 q > 0。
uint128_t reduce(uint128_t v, uint128_t q);

// ---------------------------------------------------------------------------
// 2 的幂模数下的逆元（用于 SPDZ 风格的 2^{-1}）
// ---------------------------------------------------------------------------

// 返回 a 在模 2^k 下的逆元。要求 a 为奇数。k 必须为 1..128。
// 使用牛顿迭代：x_{n+1} = x_n * (2 - a * x_n)，模 2^{2^n} 收敛。
uint128_t modInversePow2(uint128_t a, unsigned k);

// 扩展欧几里得求逆（任意模数，a 与 m 互素）。m 必须 > 0。
// 用于 MPRAQ 若采用素数域时的除法。
uint128_t modInverse(uint128_t a, uint128_t m);

// ---------------------------------------------------------------------------
// 序列化：小端序，固定 16 字节
// ---------------------------------------------------------------------------

void toBytesLE(uint128_t v, uint8_t out[kUint128Bytes]);
uint128_t fromBytesLE(const uint8_t in[kUint128Bytes]);
std::vector<uint8_t> toBytes(uint128_t v);
uint128_t fromBytes(const uint8_t* data, size_t len);

// ---------------------------------------------------------------------------
// 调试/日志用渲染
// ---------------------------------------------------------------------------

// 十进制字符串
std::string toString(uint128_t v);

// 十六进制字符串，带 0x 前缀，固定 32 位十六进制数字
std::string toHex(uint128_t v);

// 解析十进制或 0x 前缀的十六进制字符串；非法输入抛 std::invalid_argument
uint128_t parse(const std::string& s);

// ---------------------------------------------------------------------------
// 用户自定义字面量，便于测试书写 128-bit 常量
//   auto x = 12345678901234567890_k;
//   auto y = 0xdeadbeefcafebabeULL;  // 普通字面量也可直接赋给 uint128_t
// ---------------------------------------------------------------------------

uint128_t ParseLiteral(const char* str);

inline namespace literals {
inline uint128_t operator"" _k(const char* s) { return ParseLiteral(s); }
}  // namespace literals

}  // namespace tsb
