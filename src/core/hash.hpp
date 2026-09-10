#pragma once

// 哈希与消息认证码。
//
// 对应 MPRAQ 论文 §preliminaries 的 "Hash Function and MAC"：
//   * 哈希函数 H: {0,1}^* -> {0,1}^ell
//   * MAC 实例化为 HMAC_k(m) = HMAC(k, m)
//   * 记录 i 的值 v 的 MAC 为  MAC_k(i, v) = HMAC_k(domain || i || v)
//
// 域分隔字符串 domain 由所有参与方约定，作用是把不同用途的 MAC 隔离开，
// 防止跨上下文伪造。

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "core/field.hpp"

namespace tsb {

// SHA-256 摘要长度
constexpr size_t kSha256Bytes = 32;

// 我们统一使用的 MAC 标签长度。
//
// V-OO-PIR 的 Mset-XOR-Hash 需要把标签 XOR 进 128 位的 hint parity，
// 因此标签取 128 位。HMAC-SHA256 的输出被截断到前 16 字节——
// 截断一个 PRF 的输出仍是 PRF，安全性约为 128 位。
constexpr size_t kMacTagBytes = 16;

using MacTag = std::array<uint8_t, kMacTagBytes>;
using Digest = std::array<uint8_t, kSha256Bytes>;

// ---------------------------------------------------------------------------
// 域分隔常量
//
// ⚠️ 所有使用 MAC 的地方都必须显式传 domain，禁止省略或复用不同用途的域。
// ---------------------------------------------------------------------------
namespace domain {

// V-OO-PIR / VMPQ：单条记录的 MAC（对应 Mset-XOR-Hash 的元素标签）
inline constexpr const char* kRecord = "TSB-V1-RECORD";

// MPRAQ：LCTE 编码特征值相关
inline constexpr const char* kFeature = "TSB-V1-FEATURE";

// MPRAQ：属性值相关
inline constexpr const char* kAttribute = "TSB-V1-ATTRIBUTE";

}  // namespace domain

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

Digest Sha256(const uint8_t* data, size_t len);
Digest Sha256(const std::vector<uint8_t>& data);
Digest Sha256(const std::string& data);

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------

// 原始 HMAC-SHA256，输出完整 32 字节。key 可为任意长度。
Digest HmacSha256(const uint8_t* key, size_t key_len, const uint8_t* msg,
                  size_t msg_len);

// 截断到 kMacTagBytes 的 HMAC，用于 MAC 与多集哈希。
MacTag HmacTag(const uint8_t* key, size_t key_len, const uint8_t* msg,
               size_t msg_len);

// ---------------------------------------------------------------------------
// 论文定义的 MAC_k(i, v) = HMAC_k(domain || i || v)
// ---------------------------------------------------------------------------

// 规范编码：domain(字节串) || index(8 字节小端) || value(16 字节小端)
std::vector<uint8_t> EncodeMacMessage(const std::string& domain, uint64_t index,
                                      uint128_t value);

// 计算 MAC 标签
MacTag ComputeMac(const uint8_t* key, size_t key_len, const std::string& domain,
                  uint64_t index, uint128_t value);

// 对任意字节串计算带域分隔的 MAC 标签
MacTag ComputeMacBytes(const uint8_t* key, size_t key_len,
                       const std::string& domain, const uint8_t* data,
                       size_t len);

// 常量时间比较，避免通过比较耗时泄露信息
bool ConstantTimeEquals(const uint8_t* a, const uint8_t* b, size_t len);
bool ConstantTimeEquals(const MacTag& a, const MacTag& b);

// 字节容器 -> 十六进制字符串（调试与日志用）
std::string ToHexString(const uint8_t* data, size_t len);

}  // namespace tsb
