#include "core/random.hpp"

#include <cryptopp/osrng.h>

#include <stdexcept>

namespace tsb {
namespace random {

namespace {
namespace cry = CryptoPP;

cry::AutoSeededRandomPool& Rng() {
    // AutoSeededRandomPool 内部线程安全，且复用可避免重复熵收集开销
    static thread_local cry::AutoSeededRandomPool rng;
    return rng;
}
}  // namespace

void FillBytes(uint8_t* out, size_t len) {
    if (len == 0) {
        return;
    }
    if (out == nullptr) {
        throw std::invalid_argument("random::FillBytes: 空指针");
    }
    Rng().GenerateBlock(reinterpret_cast<cry::byte*>(out), len);
}

std::vector<uint8_t> Bytes(size_t len) {
    std::vector<uint8_t> v(len);
    FillBytes(v.data(), len);
    return v;
}

uint128_t Uint128() {
    // 逐字节填充以保证与字节序无关的均匀性
    uint8_t buf[kUint128Bytes];
    FillBytes(buf, sizeof(buf));
    return fromBytesLE(buf);
}

uint128_t Below(uint128_t bound) {
    if (bound == 0) {
        throw std::invalid_argument("random::Below: bound 必须 > 0");
    }
    if (bound == 1) {
        return 0;
    }
    // 拒绝采样消除模偏置。
    // bound >= 2^127 时几乎不会拒绝，直接取模并修正即可。
    const uint128_t kMaxV = ~static_cast<uint128_t>(0);
    if (bound > (kMaxV >> 1)) {
        uint128_t v = Uint128();
        return v >= bound ? (v - bound) : v;  // 至多减一次即落入 [0,bound)
    }
    const uint128_t limit = kMaxV - (kMaxV % bound);  // 到此处为止可整除
    for (;;) {
        const uint128_t v = Uint128();
        if (v < limit) {
            return v % bound;
        }
    }
}

std::array<uint8_t, kAesKeyBytes> AesKey() { return AesPrf::GenerateKey(); }

// ---------------------------------------------------------------------------
// DeterministicPrng
// ---------------------------------------------------------------------------

DeterministicPrng::DeterministicPrng(const std::array<uint8_t, kAesKeyBytes>& key,
                                     uint64_t nonce)
    : prf_(key), nonce_(nonce), counter_(0) {}

uint128_t DeterministicPrng::Next() {
    // out = AES_key( LE64(nonce) || LE64(counter) )
    //
    // ⚠️ 这里修掉了一个**共享底座缺陷**（FND-06 的实现过程中暴露）：
    // 原实现是
    //     EvalDomainU32(kDummyOffset, (uint32_t)(nonce_ >> 32), (uint32_t)counter_)
    // 有两个问题：
    //   1. `nonce_` 的**低 32 位被静默丢弃** ⇒ (key, nonce=99) 与 (key, nonce=100)
    //      产生**完全相同**的密钥流。测试里到处写的 `DeterministicPrng(key, seed)`
    //      因此可能拿到同一份"随机"数据，D6 的"确定性可复现"名不副实。
    //   2. counter 被塞进 16 位域（w1 ≤ 0xFFFF）⇒ 流长上限 64 KiB 个块（1 MiB），
    //      超出直接抛异常。
    // 现在用完整 128 位输入块（nonce 与 counter 各占 8 字节小端），
    // 非 2 的幂/长流/确定性三件事都不再受限。
    uint8_t buf[kUint128Bytes];
    toBytesLE(static_cast<uint128_t>(nonce_), buf);
    toBytesLE(static_cast<uint128_t>(counter_++), buf + 8);
    return prf_.Eval(fromBytesLE(buf));
}

uint128_t DeterministicPrng::Below(uint128_t bound) {
    if (bound == 0) {
        throw std::invalid_argument("DeterministicPrng::Below: bound 必须 > 0");
    }
    if (bound == 1) {
        return 0;
    }
    const uint128_t kMaxV = ~static_cast<uint128_t>(0);
    if (bound > (kMaxV >> 1)) {
        const uint128_t v = Next();
        return v >= bound ? (v - bound) : v;
    }
    const uint128_t limit = kMaxV - (kMaxV % bound);
    for (;;) {
        const uint128_t v = Next();
        if (v < limit) {
            return v % bound;
        }
    }
}

void DeterministicPrng::FillBytes(uint8_t* out, size_t len) {
    size_t written = 0;
    while (written < len) {
        const uint128_t v = Next();
        uint8_t buf[kUint128Bytes];
        toBytesLE(v, buf);
        const size_t take = (len - written) < kUint128Bytes ? (len - written)
                                                            : kUint128Bytes;
        for (size_t i = 0; i < take; ++i) {
            out[written + i] = buf[i];
        }
        written += take;
    }
}

}  // namespace random
}  // namespace tsb
