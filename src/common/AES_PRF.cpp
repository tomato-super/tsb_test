#include "AES_PRF.hpp"
#include <cryptopp/osrng.h>

namespace cry = CryptoPP;
#define AES_DEFAULT_SIZE 16

AES_PRF::AES_PRF() {
    key_.resize(AES_DEFAULT_SIZE);
    cry::AutoSeededRandomPool rng;
    rng.GenerateBlock(key_, AES_DEFAULT_SIZE);
    enc_.SetKey(key_, key_.size());
}

AES_PRF::AES_PRF(const CryptoPP::SecByteBlock &prf_key) {
    key_=prf_key;
    enc_.SetKey(prf_key, prf_key.size());
}

void AES_PRF::setPrfKey(const CryptoPP::SecByteBlock &prf_key) {
    key_ = prf_key;
    enc_.SetKey(key_, key_.size());
}

uint128_t AES_PRF::eval(uint128_t x) const {
    uint128_t res;
    enc_.ProcessData(
        reinterpret_cast<cry::byte*>(&res),
        reinterpret_cast<const cry::byte*>(&x),
        sizeof(uint128_t)
    );

    return res;
}

void AES_PRF::evalBatch(const uint128_t *in, uint128_t *out, size_t count) const {
    enc_.ProcessData(
        reinterpret_cast<cry::byte *>(out),
        reinterpret_cast<const cry::byte *>(in),
        count * sizeof(uint128_t)
    );
}

uint128_t AES_PRF::evalWithDomain(uint64_t domain, uint64_t x) const {
    uint128_t input = (static_cast<uint128_t>(domain) << 64) | static_cast<uint128_t>(x);

    return eval(input);
}

const CryptoPP::SecByteBlock &AES_PRF::getKey() const {
    return key_;
}
