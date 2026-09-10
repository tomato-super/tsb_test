#pragma once

// 密码学安全随机数。
//
// 两个协议的所有随机性（秘密共享的掩码、Beaver triple、iPRF 密钥、
// dummy 偏移计数器初值等）都从这里取，禁止使用 std::rand / std::mt19937。

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "core/aes_prf.hpp"
#include "core/field.hpp"

namespace tsb {
namespace random {

// 填充任意字节缓冲
void FillBytes(uint8_t* out, size_t len);
std::vector<uint8_t> Bytes(size_t len);

// 均匀随机 128 位整数
uint128_t Uint128();

// 均匀随机于 [0, bound)。bound 必须 > 0。
// 采用拒绝采样，无模偏置。
uint128_t Below(uint128_t bound);

// 随机字节数组（密钥等）
std::array<uint8_t, kAesKeyBytes> AesKey();

// ---- 确定性 PRNG（测试与可复现实验用）----
//
// ⚠️ 仅供测试/复现：生产路径必须使用上面的 CSPRNG。
// 实现为 AES-PRF 计数器流：out_i = AES_{key}(nonce || counter_i)，
// 与项目既有的 AES_PRNG 设计一致。
class DeterministicPrng {
public:
    explicit DeterministicPrng(const std::array<uint8_t, kAesKeyBytes>& key,
                               uint64_t nonce = 0);

    uint128_t Next();
    uint128_t Below(uint128_t bound);
    void FillBytes(uint8_t* out, size_t len);

    void Reset() { counter_ = 0; }

private:
    AesPrf prf_;
    uint64_t nonce_;
    uint64_t counter_;
};

}  // namespace random
}  // namespace tsb
