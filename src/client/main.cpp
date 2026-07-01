#include "utility.hpp"
#include <iostream>
#include <cassert>

int main() {
    // ========== 4. 加法秘密共享 ==========
    uint128_t secret = 123456789;
    auto [share0, share1] = utility::AdditiveShare(secret);

    std::cout << "secret = " << utility::uint128ToString(secret) << std::endl;
    std::cout << "share0 = " << utility::uint128ToString(share0) << std::endl;
    std::cout << "share1 = " << utility::uint128ToString(share1) << std::endl;

    // 重构
    uint128_t recovered = utility::AdditiveReconstruct(std::make_tuple(share0, share1));
    assert(recovered == secret);  // ✅

    // ========== 5. 模拟两方场景 ==========
    // 服务器0 持有 share0，服务器1 持有 share1
    // 各自无法推断 secret
    std::cout << "Server0 has share0, knows nothing about secret" << std::endl;
    std::cout << "Server1 has share1, knows nothing about secret" << std::endl;
    std::cout << "Together they reconstruct: " << utility::uint128ToString(recovered) << std::endl;

    // ========== 6. thread_local 随机数 ==========
    // utility::randomUint128() 内部用 thread_local AES_PRNG
    uint128_t rand1 = utility::randomUint128();
    uint128_t rand2 = utility::randomUint128();
    assert(rand1 != rand2);  // ✅ 每次不同

    return 0;
}
