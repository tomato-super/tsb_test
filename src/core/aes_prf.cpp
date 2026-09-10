#include "core/aes_prf.hpp"

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>

#include <cstring>
#include <stdexcept>

namespace tsb {

namespace {
namespace cry = CryptoPP;

// 把 16 字节缓冲按小端解释为 uint32[4] / uint16[8]
void BytesToU32LE(const uint8_t in[16], uint32_t out[4]) {
    for (size_t i = 0; i < 4; ++i) {
        out[i] = static_cast<uint32_t>(in[4 * i]) |
                 (static_cast<uint32_t>(in[4 * i + 1]) << 8) |
                 (static_cast<uint32_t>(in[4 * i + 2]) << 16) |
                 (static_cast<uint32_t>(in[4 * i + 3]) << 24);
    }
}

void BytesToU16LE(const uint8_t in[16], uint16_t out[8]) {
    for (size_t i = 0; i < 8; ++i) {
        out[i] = static_cast<uint16_t>(static_cast<uint16_t>(in[2 * i]) |
                                       (static_cast<uint16_t>(in[2 * i + 1]) << 8));
    }
}

void U128ToBytesLE(uint128_t v, uint8_t out[16]) {
    for (size_t i = 0; i < 16; ++i) {
        out[i] = static_cast<uint8_t>(v >> (8 * i));
    }
}

uint128_t BytesToU128LE(const uint8_t in[16]) {
    uint128_t v = 0;
    for (size_t i = 0; i < 16; ++i) {
        v |= static_cast<uint128_t>(in[i]) << (8 * i);
    }
    return v;
}
}  // namespace

// ---------------------------------------------------------------------------
// 构造 / 析构
// ---------------------------------------------------------------------------

AesPrf::AesPrf(const std::array<uint8_t, kAesKeyBytes>& key) : key_(key) {
    InitCipher();
}

AesPrf::AesPrf(const std::vector<uint8_t>& key) {
    if (key.size() != kAesKeyBytes) {
        throw std::invalid_argument(
            "AesPrf: 密钥长度必须为 " + std::to_string(kAesKeyBytes) +
            " 字节（AES-128），实际为 " + std::to_string(key.size()));
    }
    std::memcpy(key_.data(), key.data(), kAesKeyBytes);
    InitCipher();
}

AesPrf::AesPrf() {
    key_ = GenerateKey();
    InitCipher();
}

AesPrf::~AesPrf() = default;

std::array<uint8_t, kAesKeyBytes> AesPrf::GenerateKey() {
    std::array<uint8_t, kAesKeyBytes> key{};
    cry::AutoSeededRandomPool rng;
    rng.GenerateBlock(reinterpret_cast<cry::byte*>(key.data()), key.size());
    return key;
}

void AesPrf::InitCipher() {
    // ECB_Mode 在构造时会调用 SetKey 并做自检
    enc_ = std::make_unique<cry::ECB_Mode<cry::AES>::Encryption>(
        reinterpret_cast<const cry::byte*>(key_.data()), key_.size());
}

void AesPrf::ProcessBlock(uint8_t out[16], const uint8_t in[16]) const {
    // ProcessData 语义上非 const（内部可能缓存状态），用可变上下文完成调用
    enc_->ProcessData(out, in, 16);
}

// ---------------------------------------------------------------------------
// 基础求值
// ---------------------------------------------------------------------------

uint128_t AesPrf::Eval(uint128_t input) const {
    uint8_t in[16];
    uint8_t out[16];
    U128ToBytesLE(input, in);
    ProcessBlock(out, in);
    return BytesToU128LE(out);
}

void AesPrf::EvalBatch(const uint128_t* in, uint128_t* out, size_t count) const {
    if (count == 0) {
        return;
    }
    if (in == nullptr || out == nullptr) {
        throw std::invalid_argument("AesPrf::EvalBatch: 空指针");
    }
    // 逐块处理，保证与逐次调用 Eval 的结果完全一致（ECB 无链接状态）
    for (size_t i = 0; i < count; ++i) {
        out[i] = Eval(in[i]);
    }
}

// ---------------------------------------------------------------------------
// 域分隔求值
// ---------------------------------------------------------------------------

uint128_t AesPrf::EvalDomainU32(PrfDomain domain, uint32_t w0, uint32_t w1) const {
    if (w1 > 0xFFFFu) {
        throw std::invalid_argument(
            "AesPrf::EvalDomainU32: w1 必须 <= 0xFFFF（输入块中域占高 16 位）");
    }
    uint32_t words[4] = {w0, (static_cast<uint32_t>(domain) << 16) | w1, 0, 0};
    uint8_t in[16];
    std::memcpy(in, words, 16);
    uint8_t out[16];
    ProcessBlock(out, in);
    return BytesToU128LE(out);
}

void AesPrf::EvalSelectBatch(PrfDomain domain, uint32_t w0, uint32_t w1,
                             uint32_t out[4]) const {
    const uint128_t r = EvalDomainU32(domain, w0, w1);
    uint8_t bytes[16];
    U128ToBytesLE(r, bytes);
    BytesToU32LE(bytes, out);
}

void AesPrf::EvalOffsetBatch(PrfDomain domain, uint32_t w0, uint32_t w1,
                             uint16_t out[8]) const {
    const uint128_t r = EvalDomainU32(domain, w0, w1);
    uint8_t bytes[16];
    U128ToBytesLE(r, bytes);
    BytesToU16LE(bytes, out);
}

// ---------------------------------------------------------------------------
// S3PIR 兼容封装
// ---------------------------------------------------------------------------

void AesPrf::PrfBatchSelect(uint32_t hint_id, uint32_t part_id_quarter,
                            uint32_t out[4]) const {
    EvalSelectBatch(PrfDomain::kSelect, hint_id, part_id_quarter, out);
}

uint32_t AesPrf::PrfSelect(uint32_t hint_id, uint32_t part_id) const {
    uint32_t vals[4];
    PrfBatchSelect(hint_id, part_id / 4, vals);
    return vals[part_id % 4];
}

void AesPrf::PrfBatchIdx(uint32_t hint_id, uint32_t part_id_eighth,
                         uint16_t out[8]) const {
    EvalOffsetBatch(PrfDomain::kOffset, hint_id, part_id_eighth, out);
}

uint16_t AesPrf::PrfIdx(uint32_t hint_id, uint32_t part_id,
                        uint32_t part_size) const {
    uint16_t vals[8];
    PrfBatchIdx(hint_id, part_id / 8, vals);
    return static_cast<uint16_t>(vals[part_id % 8] & (part_size - 1));
}

uint16_t AesPrf::NextDummyOffset(uint64_t cnt, uint32_t part_size) const {
    // w1 = cnt / 8 必须落在 16 位内
    const uint64_t group = cnt / 8;
    if (group > 0xFFFFu) {
        throw std::invalid_argument(
            "AesPrf::NextDummyOffset: dummy 偏移流计数超出 16 位分组范围");
    }
    uint16_t vals[8];
    EvalOffsetBatch(PrfDomain::kDummyOffset, 0, static_cast<uint32_t>(group), vals);
    return static_cast<uint16_t>(vals[cnt % 8] & (part_size - 1));
}

}  // namespace tsb
