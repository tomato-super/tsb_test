#include "utility.hpp"
#include "AES_PRF.hpp"
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>

class AES_PRNG 
{
public:
    AES_PRNG() {
        CryptoPP::AutoSeededRandomPool rng;
        // CryptoPP::SecByteBlock key(16);
        // rng.GenerateBlock(key, key.size());
        // prf_.setPrfKey(key);
        rng.GenerateBlock(reinterpret_cast<CryptoPP::byte*>(&nonce_), sizeof(nonce_));
        counter_ = 0;
    }                                      

    uint128_t Next() {
        return prf_.evalWithDomain(nonce_, counter_++);
    }

    void NextBatch(uint128_t* out, size_t count){
        std::vector<uint128_t> indices(count);
        for (size_t i = 0; i < count; i++) {
            indices[i] = (static_cast<uint128_t>(nonce_) << 64) 
                    | (static_cast<uint128_t>(counter_) + i);
        }
        counter_ += count;
        prf_.evalBatch((uint128_t*)indices.data(), out, count);
    }   
    void Reset() {
        counter_ = 0;
    }

private:
    AES_PRF prf_;
    uint64_t counter_;
    uint64_t nonce_;
};

std::string utility::uint128ToString(uint128_t val) {
    if (val == 0) return "0";
    std::string result;
    while (val > 0) {
        result.push_back('0' + static_cast<char>(val % 10));
        val /= 10;
    }
    std::reverse(result.begin(), result.end());
    return result;
}

std::string utility::uint128ToHex(uint128_t val) {
    char buf[33];
    uint64_t hi = static_cast<uint64_t>(val >> 64);
    uint64_t lo = static_cast<uint64_t>(val);
    snprintf(buf, sizeof(buf), "%016lx%016lx", hi, lo);
    return std::string("0x") + buf;
}

void utility::numToOneHotVect(
    uint128_t val, uint32_t num_bucket, std::vector<uint128_t>& vec
)
{
    vec.assign(num_bucket, 0);      // 全部初始化为 0
    
    if (val < num_bucket) {
        vec[val] = 1;               // 对应位置设为 1
    } else {
        // val 超出范围的处理（可选）
        throw std::out_of_range("val >= num_bucket");
    }
}

uint128_t utility::randomUint128()
{
    static thread_local AES_PRNG prng;
    return prng.Next();
}

std::tuple<uint128_t, uint128_t> utility::AdditiveShare(uint128_t val)
{
    uint128_t r = randomUint128();
    return std::make_tuple(r, val - r);
}

uint128_t utility::AdditiveReconstruct(const std::tuple<uint128_t, uint128_t> &shares) {
    return std::get<0>(shares) + std::get<1>(shares);
}
