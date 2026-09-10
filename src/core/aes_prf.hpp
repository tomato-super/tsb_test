#pragma once

// AES 伪随机函数（PRF）。
//
// 实例化方式对齐 S3PIR 官方实现与 V-OO-PIR 规格（见 doc/design/PIR_SPEC.md §3.3）：
//   * AES-128，ECB 模式，单块调用（每块 16 字节 = 128 bit）
//   * 输入块布局（小端 uint32_t[4]）：
//         in[0] = w0
//         in[1] = (domain << 16) | w1
//         in[2] = in[3] = 0
//     即 **域分隔编码在 in[1] 的高 16 位**，不是字符串拼接。
//   * 一次 AES 调用可把 128 位输出拆成 4 个 uint32 或 8 个 uint16，
//     这正是论文所说的 "break up a single 128-bit AES output into
//     four to eight pseudorandom numbers"。
//
// ⚠️ 密钥管理：两服务器方案中 PRF 密钥只与 offline server 共享，
// 绝不与在线服务器共享。禁止硬编码密钥（参考实现里的
// "1234567812345678" 仅为 artifact 用途）。

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

// Crypto++ 的 AES 与 ECB 模式。注意 CryptoPP 里 SecByteBlock 是 typedef，
// ECB_Mode 是模板别名式的类模板，因此不能用手写前置声明（会与其定义冲突），
// 必须引入真实头文件。
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/secblock.h>

#include "core/field.hpp"

namespace tsb {

// AES-128 密钥长度（字节）
constexpr size_t kAesKeyBytes = 16;

// 域分隔常量。V-OO-PIR 使用的三域（对齐官方实现）：
enum class PrfDomain : uint16_t {
    kDummyOffset = 0,  // 每次查询新生成的 dummy 分区内偏移
    kSelect = 1,       // 分区选择值 v_{j,k}
    kOffset = 2,       // 分区内偏移 r_{j,k}
};

class AesPrf {
public:
    // 用给定密钥构造。key 长度必须恰为 16 字节，否则抛 std::invalid_argument。
    explicit AesPrf(const std::array<uint8_t, kAesKeyBytes>& key);
    explicit AesPrf(const std::vector<uint8_t>& key);

    // 生成一把全新的随机密钥（使用密码学安全随机源）。
    static std::array<uint8_t, kAesKeyBytes> GenerateKey();

    // 用随机密钥构造。
    AesPrf();

    ~AesPrf();
    // 持有 ECB 上下文指针，禁止拷贝；移动需要转移所有权，暂不提供。
    AesPrf(const AesPrf&) = delete;
    AesPrf& operator=(const AesPrf&) = delete;

    // ---- 基础求值 ----

    // 对 128 位输入块求值，返回 128 位输出块。
    uint128_t Eval(uint128_t input) const;

    // 批量求值。等价于对每个输入调用 Eval，但复用 ECB 上下文。
    // out 与 in 不得重叠。count == 0 时不做任何事。
    void EvalBatch(const uint128_t* in, uint128_t* out, size_t count) const;

    // ---- 域分隔求值（V-OO-PIR / S3PIR 使用的形式）----

    // 构造输入块 in = [w0, (domain << 16) | w1, 0, 0] 并求值。
    // 要求 w1 不超过 16 位（即 w1 <= 0xFFFF），否则抛 std::invalid_argument。
    uint128_t EvalDomainU32(PrfDomain domain, uint32_t w0, uint32_t w1) const;

    // 把一次求值的输出拆成 4 个 uint32（小端）。
    void EvalSelectBatch(PrfDomain domain, uint32_t w0, uint32_t w1,
                         uint32_t out[4]) const;

    // 把一次求值的输出拆成 8 个 uint16（小端）。
    void EvalOffsetBatch(PrfDomain domain, uint32_t w0, uint32_t w1,
                         uint16_t out[8]) const;

    // ---- S3PIR 兼容的便捷封装 ----

    // 分区选择值 v_{j,k}（32-bit）。一次 AES 调用产出 4 个连续分区的值。
    // part_id 为 4 对齐的分区号（即官方实现的 partID/4）。
    void PrfBatchSelect(uint32_t hint_id, uint32_t part_id_quarter,
                        uint32_t out[4]) const;

    // 取单个分区的选择值 v_{j,k}
    uint32_t PrfSelect(uint32_t hint_id, uint32_t part_id) const;

    // 分区内偏移 r_{j,k}，未取模。一次 AES 调用产出 8 个连续分区的值。
    void PrfBatchIdx(uint32_t hint_id, uint32_t part_id_eighth,
                     uint16_t out[8]) const;

    // 取单个分区的偏移并归约到 [0, part_size)
    uint16_t PrfIdx(uint32_t hint_id, uint32_t part_id, uint32_t part_size) const;

    // dummy 偏移流：w0 = 0，域 = kDummyOffset，取第 (cnt mod 8) 个 uint16。
    // cnt 必须单调递增且绝不重用（这是 PRF 流，不是真随机）。
    uint16_t NextDummyOffset(uint64_t cnt, uint32_t part_size) const;

    // ---- 密钥访问 ----

    const std::array<uint8_t, kAesKeyBytes>& key() const { return key_; }

private:
    std::array<uint8_t, kAesKeyBytes> key_;
    // ECB 上下文的 ProcessData 非 const，故用指针 + mutable 保持 Eval 的 const 语义。
    mutable std::unique_ptr<CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption> enc_;

    void InitCipher();
    void ProcessBlock(uint8_t out[16], const uint8_t in[16]) const;
};

}  // namespace tsb
