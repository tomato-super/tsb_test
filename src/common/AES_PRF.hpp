#include "config.hpp"
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/secblock.h>
#include <cryptopp/modes.h>

class AES_PRF 
{
public:
    AES_PRF();
    explicit AES_PRF(const CryptoPP::SecByteBlock& prf_key);

    void setPrfKey(const CryptoPP::SecByteBlock& prf_key);
    uint128_t eval(uint128_t x) const;
    void evalBatch(const uint128_t* in, uint128_t* out, size_t count) const;
    uint128_t evalWithDomain(uint64_t domain, uint64_t x) const;
    const CryptoPP::SecByteBlock& getKey() const;

private:
    CryptoPP::SecByteBlock key_;
    mutable CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc_;
};
