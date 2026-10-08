#pragma once

// MPRAQ 的**运行方式（安全档位）**—— 负责人要求"保留一个半诚实运行方式，用配置文件配置"。
//
// ===========================================================================
// 本文件的作用：**预留接口**，不是实现
// ===========================================================================
// 本 gate 只做三件事：
//   ① 定义档位枚举与解析/打印（唯一权威定义处）；
//   ② 让它随 `StoreParams` **上线**，服务端据此做**显式校验**（防静默降级）；
//   ③ 让配置文件与 CLI 能读写它。
// **不改变任何现有行为**：两个档位目前走同一条（恶意档）代码路径。
//
// 需要按档位跳过的机制（**落地进度**，2026-10-08）：
//   * 恶意档（默认）：PIR 值层 xmac（每条目每 ℓ-bit chunk 一份 tag share）+ SPDZ MAC +
//     §4.5-A/B 两条纯客户端复核 + 批量逐记录校验。
//   * 半诚实档 —— **已落地（P1-A，语义分档）**：
//       - **xmac 全部不做**（不采样 γ、不生成/不存/不传 tag、不校验；存储与应答减半）；
//       - **SecureMul 不做任何验证**：跳过 SPDZ MAC 校验与 §4.5-A/B 两条纯客户端复核
//         （入口：`SecureMulClientState::security_mode()`，构造时**必须显式传档位**）。
//         实测见 `tests/test_mpraq_entry.cpp` 的 `SemiHonestSecureMulDoesNotVerify`：
//         同样的 MAC 篡改在恶意档被拒、在半诚实档**被静默接受**。
//   * 半诚实档 —— **尚未落地（P1-B，性能分档）**：帧与结构的瘦身
//       （`Phase2Response` 43 B → 27 B、`Phase2Request` 58 B → 42 B；
//        triple 由 7 个 mod q 分量降到 3 个）。⚠️ 这会改线协议（需再升版本）
//        并重设全部基线，属独立一步。
//
// ⚠️ **半诚实档"不做验证"是如实声明的边界，不是缺陷**：该档的威胁模型里服务器
//    **不会偏离协议**；若需要验证，请用恶意档（默认档）。
//
// ⚠️ **绝不能省的两条**（与打印/配置无关，属协议正确性）：
//   * hint 消费 + 每轮 `Refresh`（决策 D17）——hint 复用会向**半诚实服务器**泄露
//     查询分区 ℓ，这是针对半诚实模型的攻击，半诚实档**不能**关掉它；
//   * L14 查询预算预检（超预算 fail-loudly，绝不降级）。
//
// ===========================================================================
// 命名纪律（`TASK_PLAN.md` D40 与 §9 风险 R15）
// ===========================================================================
//   * 配置键用 **`security_mode`**，**不是** `mode` —— `bench_mpraq` 的 `--mode
//     local|grpc` 已被"传输口径"占用，同名会造成本仓库最忌讳的口径混淆。
//   * CLI 旗标同名：`--security-mode`。
//   * 非法值 **fail-loudly**（拒绝启动），不做模糊匹配、不静默回落到默认档。

#include <cstdint>
#include <ostream>
#include <stdexcept>
#include <string>

namespace tsb {
namespace mpraq {

enum class MpraqSecurityMode : uint8_t {
    kSemiHonest = 0,   // 半诚实：不做任何验证（PIR 值层与聚合层均不校验）
    kMalicious = 1,    // 恶意（默认）：xmac + SPDZ MAC + 纯客户端复核 + 逐记录校验
};

// 默认档 = 恶意档（论文主张；半诚实为显式 opt-in）。
inline constexpr MpraqSecurityMode kDefaultMpraqSecurityMode = MpraqSecurityMode::kMalicious;

// 唯一权威的字符串形式（写进 JSON / 输出 / 账目）。
inline const char* MpraqSecurityModeName(MpraqSecurityMode m) {
    return m == MpraqSecurityMode::kSemiHonest ? "semi-honest" : "malicious";
}

// 严格解析：**只**接受 "malicious" / "semi-honest"。拼错、大小写不符、带空格一律拒绝。
inline MpraqSecurityMode ParseMpraqSecurityMode(const std::string& s) {
    if (s == "malicious") return MpraqSecurityMode::kMalicious;
    if (s == "semi-honest") return MpraqSecurityMode::kSemiHonest;
    throw std::invalid_argument(
        "security_mode: 只接受 \"malicious\" 或 \"semi-honest\"（实际收到 \"" + s +
        "\"）—— 不做模糊匹配、不静默回落，见 src/mpraq/security_mode.hpp");
}

// 线上/存储来的**原始整数**是否落在一个已知档位上。
// ⚠️ 必须有这个函数：`static_cast<MpraqSecurityMode>(x)` 对任意 `x` 都能编译通过，
//    于是"线上收到 7"会变成一个**非法枚举值**并在后续比较里静默走 else 分支 ——
//    正是本仓库最忌讳的静默降级。所有从字节/整数还原档位的地方都必须先过这里。
inline bool IsKnownMpraqSecurityMode(uint32_t raw) {
    return raw == static_cast<uint32_t>(MpraqSecurityMode::kSemiHonest) ||
           raw == static_cast<uint32_t>(MpraqSecurityMode::kMalicious);
}

// 严格还原：非法整数**抛异常**（绝不回落默认档）。
inline MpraqSecurityMode MpraqSecurityModeFromRaw(uint32_t raw) {
    if (!IsKnownMpraqSecurityMode(raw)) {
        throw std::invalid_argument(
            "security_mode: 收到未知档位编码 " + std::to_string(raw) +
            "（只认 0 = semi-honest、1 = malicious）—— 拒绝静默回落到默认档");
    }
    return static_cast<MpraqSecurityMode>(raw);
}

// 便于诊断与测试断言直接打印档位（`EXPECT_EQ` 需要它）。
inline std::ostream& operator<<(std::ostream& os, MpraqSecurityMode m) {
    return os << MpraqSecurityModeName(m);
}

}  // namespace mpraq
}  // namespace tsb
