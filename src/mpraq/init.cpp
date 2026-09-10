#include "mpraq/init.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <numeric>
#include <sstream>

#include "core/iprf.hpp"

namespace tsb {
namespace mpraq {

namespace {

std::string Num(uint64_t v) { return std::to_string(v); }

std::string AttrLabel(const AttributeSchema& a) {
    return "属性 " + std::to_string(a.id) + "(\"" + a.name + "\")";
}

bool IsPowerOfTwo(uint64_t v) { return v != 0 && (v & (v - 1)) == 0; }

uint64_t NextPow2(uint64_t v) {
    uint64_t p = 1;
    while (p < v && p < (static_cast<uint64_t>(1) << 62)) p <<= 1;
    return p;
}

// v 的**奇数部分**（去掉全部因子 2）。决策 D35 的可行性判据要用它：
// ⌈N/128⌉ = 2^t·q 中只有 q 决定"列数至少要多大"。
uint64_t OddPart(uint64_t v) {
    if (v == 0) return 0;
    while ((v & 1u) == 0u) v >>= 1;
    return v;
}

// 列数升级搜索的**余量**（决策 D35）：充要条件给出的列数之上再允许 2^k 次翻倍。
// 取值 2 ⇒ 上限是最小充分列数的 4 倍；更大只会多试几个（主键 n 最小 ⇒ 不会误选大列数）。
constexpr uint64_t kColumnUpgradeSlack = 2;

// XOR/mod q 掩码流的根密钥（编译期可从 tag 推出 ⇒ 跨进程可复现，铁律 D6）。
// 独立流标签 ⇒ 与 Plinko 的流（区块密钥 / hint 子集 / 哑偏移）**互不干扰**。
std::array<uint8_t, kAesKeyBytes> MaskStreamKey(const char* tag) {
    std::array<uint8_t, kAesKeyBytes> key{};
    const size_t n = std::strlen(tag);
    for (size_t i = 0; i < kAesKeyBytes; ++i) {
        key[i] = static_cast<uint8_t>(static_cast<uint8_t>(tag[i % n]) ^
                                      static_cast<uint8_t>(0x5A + i));
    }
    return key;
}

// 属性值的 mod q 加法共享（强类型 ModShare；D11/D24 —— 绝不用 XOR 承载可加量）。
// 掩码取自确定性流，因此 `s1 = E − s0 (mod q)` 与 `s0` 都逐位可复现。
std::pair<std::vector<ModShare>, std::vector<ModShare>> ShareAttributeVector(
    const std::vector<int64_t>& values, uint128_t q, random::DeterministicPrng& prng) {
    std::vector<ModShare> s0, s1;
    s0.reserve(values.size());
    s1.reserve(values.size());
    for (int64_t v : values) {
        if (v < 0) {
            throw std::invalid_argument(
                "MPRAQ Init: 属性值出现负数（" + std::to_string(v) +
                "）—— 取值域是 [domain_min, domain_max] 且要求 domain_min >= 0；"
                "负值无法无损映射进 Z_q（本口径按无符号整数处理）。");
        }
        const uint128_t secret = reduce(static_cast<uint128_t>(v), q);
        const uint128_t mask = prng.Below(q);
        s0.push_back(ModShare{mask});
        s1.push_back(ModShare{subMod(secret, mask, q)});
    }
    return {std::move(s0), std::move(s1)};
}

double MsSince(const std::chrono::steady_clock::time_point& t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0)
        .count();
}

}  // namespace

// ---------------------------------------------------------------------------
// 最小合法几何（补齐是**本层**的事：PLINKO_SPEC §1 的注 + D15(a)）
// ---------------------------------------------------------------------------

MpraqPaddedGeometry DerivePaddedGeometry(size_t real_column_count, size_t num_records,
                                        uint32_t lambda, double prp_epsilon,
                                        bool has_explicit_w, uint64_t w_explicit) {
    if (num_records == 0) {
        throw std::invalid_argument(
            "DerivePaddedGeometry: N（记录数）必须 >= 1（N=0 时 ⌈N/128⌉=0，"
            "特征表为空 ⇒ 没有任何可检索的条目）");
    }
    if (real_column_count == 0) {
        throw std::invalid_argument("DerivePaddedGeometry: 真实列数 M 必须 >= 1");
    }
    const size_t words_per_column = (num_records + 127) / 128;
    const uint64_t real_n = static_cast<uint64_t>(real_column_count) *
                            static_cast<uint64_t>(words_per_column);

    MpraqPaddedGeometry g;
    g.real_column_count = real_column_count;

    // ---------------------------------------------------------------------
    // 列数补齐：**只补列、绝不补记录**（D15(a)），并允许 ×2 **升级搜索**（决策 D35）
    // ---------------------------------------------------------------------
    // 列数 `cols`（= PIR 的 `m`）必须是 **2 的幂**（与 `VmpqParams::PaddedEntries`
    // 同一手法），条目数 `n = cols · ⌈N/128⌉`。
    //
    // 🔴 为什么必须**升级**（D35）：设 `L = ⌈N/128⌉ = 2^t·q`（`q` 为奇）、`cols = 2^a`、
    //    `w = 2^b`。几何合法性（`PlinkoParams::Validate`）要求
    //      * `w >= L`（一个区块至少装下一整列 ⇒ `b >= t + ⌈log₂q⌉`）；
    //      * `n = c·w` 且 `c` 为**偶数**（PLINKO_SPEC §5.5）⇒ `c = 2^(a+t−b)·q`
    //        为偶 ⇔ `b <= a + t − 1`；
    //    ⇒ **存在合法 (a, b) ⇔ `a >= 1 + ⌈log₂q⌉`**（且仍需 `2^a >= M`）。
    //    只试**最小**的 `2^a = NextPow2(min_columns(w))` 在 `q > M/2` 时**必然无解**：
    //    例如 `L=13`、`M=10` ⇒ `cols=16` 时 `c` 恒为奇数（试遍所有 `w`），
    //    升到 `cols=32`、`w=16` 后 `n=416`、`c=26` 为偶 ✅。
    //    代价：服务器存储 `16·cols·L` 随升级**翻倍**（D26 口径 ⇒ 必须与"不含补齐"双报，
    //    `MPA-09` 的 bench 也把 `m0`（升级前）与 `m`（升级后）都打出来）。
    //
    // 搜索顺序（**先最小列数，无解才升级**）：
    //    对每个候选 `w`（`w = 2^⌈log₂L⌉·2^k`）从 `cols = NextPow2(min_columns(w))` 起
    //    逐个 `×2` 试到上限；每个 `w` 取**第一个**合法列数（= 该 `w` 下 `n` 最小），
    //    最后在全部候选里按 **(n 最小, w 最小)** 排序取最优（主键 = 服务器存储 `16·n`；
    //    次键 = hint 表 `H = 3λw/2`）⇒ 有解时不升级、升级时也只升到够用为止。
    //
    // 列数上限（**有文档记录**）：由上面的充要条件，`cols >= 2^max(⌈log₂M⌉, 1+⌈log₂q⌉)`
    //    时**一定**存在合法 `w`（取 `w = 2^(t+⌈log₂q⌉)` 即可），因此上限取
    //    `NextPow2(max(M, 2q)) · 2^kColumnUpgradeSlack`。
    const uint64_t odd_L = OddPart(static_cast<uint64_t>(words_per_column));

    // 真实数据需要多少个**全局列**：至少 M 个，且必须能装进 `entry_count / w` 个区块
    // （一个区块含 w 个 word，即 `w/words_per_column` 个整列）。
    const auto min_columns = [&](uint64_t w) -> uint64_t {
        const uint64_t cap = w / words_per_column;  // 一个区块覆盖多少**整列**
        if (cap == 0) return std::numeric_limits<uint64_t>::max();
        const uint64_t need = (real_column_count + cap - 1) / cap;
        return std::max<uint64_t>(need, real_column_count);
    };

    // 某个（最小）列数之上允许升到多少
    const auto cols_cap = [&](uint64_t base) -> uint64_t {
        const uint64_t need_math =
            std::max<uint64_t>(static_cast<uint64_t>(real_column_count), 2 * odd_L);
        uint64_t sufficient = NextPow2(need_math);
        for (uint64_t i = 0; i < kColumnUpgradeSlack; ++i) {
            if (sufficient > (std::numeric_limits<uint64_t>::max() >> 1)) break;
            sufficient <<= 1;
        }
        return std::max(base, sufficient);
    };

    struct Candidate {
        uint64_t w = 0;
        uint64_t n = 0;
        uint64_t cols = 0;
    };

    // 指定 (w, cols) 是否自洽。几何判据**只有** `PlinkoParams::Validate` 一处
    // （本层绝不自己重写一套、也不放宽它 —— MPA-09 任务 C 的边界纪律）。
    const auto build = [&](uint64_t w, uint64_t cols, PlinkoParams* out,
                           std::string* why) -> bool {
        const uint64_t n = cols * static_cast<uint64_t>(words_per_column);
        if (n < 4) {
            *why = "n=" + Num(n) + " < 4（最小合法几何）";
            return false;
        }
        PlinkoParams p;
        p.n = n;
        p.w = w;
        p.lambda = lambda;
        p.prp_epsilon = prp_epsilon;
        try {
            p.Validate();
        } catch (const std::exception& e) {
            *why = e.what();
            return false;
        }
        *out = p;
        return true;
    };

    // 对给定 w：最小列数 → ×2 升级，取第一个合法几何
    const auto try_w = [&](uint64_t w, Candidate* out, std::string* why) -> bool {
        const uint64_t need = min_columns(w);
        if (need == std::numeric_limits<uint64_t>::max()) {
            *why = "w 小于一列的大小（w=" + Num(w) + " < ⌈N/128⌉=" +
                   Num(words_per_column) + "）";
            return false;
        }
        const uint64_t base = NextPow2(need);
        const uint64_t cap = cols_cap(base);
        std::string tried;
        for (uint64_t cols = base;; cols <<= 1) {
            PlinkoParams p;
            std::string r;
            if (build(w, cols, &p, &r)) {
                out->w = w;
                out->n = p.n;
                out->cols = cols;
                return true;
            }
            if (!tried.empty()) tried += "；";
            tried += "cols=" + Num(cols) + "（n=" + Num(cols * words_per_column) +
                     "）：" + r;
            if (cols >= cap) break;
        }
        *why = "已尝试列数 " + Num(base) + "…" + Num(cap) + "（含 ×2 升级，上限 = " +
               Num(cap) + "）仍无合法几何 ⇒ " + tried;
        return false;
    };

    // 把选中的候选落到输出（唯一写 g 的地方；再校验一次，防"选了却没验"）
    const auto apply = [&](const Candidate& c) {
        PlinkoParams p;
        std::string why;
        if (!build(c.w, c.cols, &p, &why)) {
            throw std::logic_error(
                "MPRAQ Init: 内部一致性错误（选中的候选几何重新校验失败）：" + why);
        }
        g.column_count = static_cast<size_t>(c.cols);
        g.padding_columns = static_cast<size_t>(c.cols) - real_column_count;
        g.plinko = p;
    };

    if (has_explicit_w) {
        // 显式 w：块容量 = w 个 word/区块（D24④），**只补齐列数**（含 ×2 升级），不改 w
        if (w_explicit == 0 || !IsPowerOfTwo(w_explicit)) {
            throw std::invalid_argument(
                "MPRAQ Init: w 必须是 2 的幂（决策 D21：w 是 iPRF 的值域；"
                "非 2 的幂会让 PMNS 退化，core/iprf 直接拒绝）。实际 w = " +
                Num(w_explicit));
        }
        Candidate c;
        std::string why;
        if (!try_w(w_explicit, &c, &why)) {
            throw std::invalid_argument(
                "MPRAQ Init: 显式 w = " + Num(w_explicit) +
                " 无法通过补齐整列凑出合法的 Plinko 几何（条目数恒为 columns·⌈N/128⌉ = " +
                Num(words_per_column) + " 的整数倍；M = " + Num(real_column_count) +
                "、⌈N/128⌉ 的奇数部分 q = " + Num(odd_L) + "）：" + why +
                "。\n  处置：改用**默认派生**的 w（它在全部合法 (w, 列数) 里按 "
                "(服务器存储 16·n, hint 表 3λw/2) 取最优），或换一个 N"
                "（⌈N/128⌉ 的奇数部分越小越容易补齐）。");
        }
        apply(c);
        return g;
    }

    // 默认路径：块容量取 w_column = ⌈⌈N/128⌉⌉₂（一列 = 一个区块，让 w 落在 √n 量级，
    // 与 `PlinkoParams::Derive` 的 `w = 2^⌈log₂√n⌉` 同族）。w 是自由参数，多个取值常常
    // 都合法 ⇒ **在全部合法候选里按 (服务器存储, 提示表) 排序取最优**：
    //   * 服务器存储 = `16·n` 字节，`n = 列数·⌈N/128⌉`（`MPRAQ_IMPL.md` §1）⇒ 主键 `n`；
    //   * 提示表规模 = `H = 3λw/2` 个槽位（PLINKO_SPEC §2）⇒ 次键 `w`（更小的 w 让 hint
    //     存储与每轮成本都更低）。
    // ⚠️ 升级只在"最小列数无解"时才会被选中：升级后的 `n` 严格大于同 `w` 的最小列数候选，
    //    而主键是 `n` 最小 ⇒ 有解时行为与 D35 之前**逐位一致**（`test_mpraq_scaling` 有回归守卫）。
    const uint64_t w_column = NextPow2(static_cast<uint64_t>(words_per_column));
    std::vector<Candidate> valid;
    std::vector<std::string> reasons;
    for (uint64_t k = 0; k < 33; ++k) {
        const uint64_t w = w_column << k;
        if (w > (static_cast<uint64_t>(1) << 32)) break;
        Candidate c;
        std::string why;
        if (try_w(w, &c, &why)) {
            valid.push_back(c);
        } else {
            reasons.push_back("w=" + Num(w) + "：" + why);
        }
    }
    if (valid.empty()) {
        std::ostringstream oss;
        oss << "MPRAQ Init: 无法把 LCTE 布局（M=" << real_column_count << " 列 × ⌈N/128⌉="
            << words_per_column << " 个 word/列，即 " << real_n
            << " 个真实条目）补齐到任何合法的 Plinko 几何"
            << "（要求 w = 2^k、n = c·w、c 为偶数、n >= 4）。\n"
            << "  诊断：⌈N/128⌉ 的奇数部分 q = " << odd_L
            << " ⇒ 由「c 必须为偶数」（PLINKO_SPEC §5.5）推出的**充要条件**是 "
               "列数 >= 2q = "
            << (2 * odd_L) << "（且 >= NextPow2(M) = " << NextPow2(real_column_count)
            << "）；本层已把列数从最小候选 **×2 升级**到上限 "
            << cols_cap(NextPow2(static_cast<uint64_t>(real_column_count)))
            << "（决策 D35），每个候选 w 都升级过。\n"
            << "  试过的候选 w（每个都含列数升级）：";
        for (size_t i = 0; i < reasons.size() && i < 8; ++i) {
            oss << "\n    " << reasons[i];
        }
        if (reasons.size() > 8) {
            oss << "\n    …（其余 " << (reasons.size() - 8) << " 个候选同理）";
        }
        oss << "\n  处置：换一个 N（⌈N/128⌉ 的奇数部分越小越容易补齐；N 取 2 的幂最省）、"
               "或调整 schema（增大 M 会同时抬高 NextPow2(M)）、"
               "或检查 λ/ε（`λw` 或 `H = 3λw/2` 超过 core/iprf 的 2^32 域宽时"
               "**任何**几何都不合法）。";
        throw std::invalid_argument(oss.str());
    }
    std::sort(valid.begin(), valid.end(), [](const Candidate& a, const Candidate& b) {
        if (a.n != b.n) return a.n < b.n;   // 主键：条目数（= 服务器存储 16·n 字节）
        return a.w < b.w;                   // 次键：区块更小（H = 3λw/2 ⇒ hint 表更小）
    });
    apply(valid.front());
    return g;
}

// ---------------------------------------------------------------------------
// 输入校验（`MPRAQ_IMPL.md` §2 的第 ① 步）
// ---------------------------------------------------------------------------

namespace {

size_t ValidateInputs(const Schema& schema, const std::vector<MpraqRecord>& records) {
    if (records.empty()) {
        throw std::invalid_argument(
            "MpraqClient::Init: 记录数 N 必须 >= 1（N=0 时特征表为空，"
            "没有任何可检索的条目；⌈N/128⌉ = 0 ⇒ Plinko 的 n = 0）");
    }
    if (schema.num_attributes() == 0) {
        throw std::invalid_argument("MpraqClient::Init: schema 至少要有一个属性");
    }
    if (schema.num_attributes() > static_cast<size_t>(UINT32_MAX)) {
        throw std::invalid_argument("MpraqClient::Init: 属性数过多");
    }

    for (size_t a = 0; a < schema.num_attributes(); ++a) {
        const AttributeSchema& s = schema.attributes()[a];
        if (s.id != a) {
            throw std::invalid_argument(
                "MpraqClient::Init: 属性必须按 id = 0,1,2,... 连续编号（第 " + Num(a) +
                " 个属性的 id 是 " + Num(s.id) + "）—— 条目号与上传都要用它定位。");
        }
        ValidateLcteParams(s.lcte);
        if (s.domain_min > s.domain_max) {
            throw std::invalid_argument("MpraqClient::Init: " + AttrLabel(s) +
                                        " 的取值域倒置（domain_min > domain_max）");
        }
        if (s.domain_min < 0) {
            throw std::invalid_argument(
                "MpraqClient::Init: " + AttrLabel(s) + " 的 domain_min 必须 >= 0（实际 " +
                std::to_string(s.domain_min) +
                "）—— 取值按无符号整数映射进 Z_q。");
        }
        if (s.lcte.window_size != 0 && s.lcte.window_size != records.size()) {
            throw std::invalid_argument(
                "MpraqClient::Init: " + AttrLabel(s) + " 的 lcte.window_size = " +
                Num(s.lcte.window_size) + " 与记录数 N = " + Num(records.size()) +
                " 不一致（N 取 records.size()）");
        }
        // ---- D19-5：m >= (domain_max − domain_min) + 2 ----
        // 要精确表达闭取值域 [d_min, d_max] 上的全部比较（含右端排他上界 d_max+1），
        // R 必须比取值域多覆盖一个点：R ⊇ [d_min, d_max+1] ⇔ m >= span + 2。
        // 否则 LCTE 无法无损表达（`mpraq/lcte.hpp` §2 的推导）。
        const uint64_t span = static_cast<uint64_t>(s.domain_max - s.domain_min);
        const uint64_t need = span + 2;
        if (s.lcte.range_size < need) {
            throw std::invalid_argument(
                "MpraqClient::Init: " + AttrLabel(s) + " 的 lcte.range_size = " +
                Num(s.lcte.range_size) + " < 跨度+2 = " + Num(need) +
                "（取值域 [" + std::to_string(s.domain_min) + ", " +
                std::to_string(s.domain_max) + "]，跨度 " + Num(span) +
                "）。决策 D19-5：R ⊇ [domain_min, domain_max+1] 才能无损表达全部"
                "左阈值谓词（含 x <= domain_max 所需的 d_max+1 那一列）。");
        }
    }

    // 记录逐条校验：属性个数、逐属性取值是否落在闭取值域内
    for (size_t r = 0; r < records.size(); ++r) {
        const MpraqRecord& rec = records[r];
        if (rec.attributes.size() != schema.num_attributes()) {
            throw std::invalid_argument(
                "MpraqClient::Init: 第 " + Num(r) + " 条记录的属性个数 " +
                Num(rec.attributes.size()) + " 与 schema 的 " +
                Num(schema.num_attributes()) + " 个属性不符");
        }
        for (size_t a = 0; a < rec.attributes.size(); ++a) {
            const AttributeSchema& s = schema.attributes()[a];
            const int64_t v = rec.attributes[a];
            if (v < s.domain_min || v > s.domain_max) {
                throw std::out_of_range(
                    "MpraqClient::Init: 第 " + Num(r) + " 条记录的 " + AttrLabel(s) +
                    " 取值 " + std::to_string(v) + " 越出闭取值域 [" +
                    std::to_string(s.domain_min) + ", " + std::to_string(s.domain_max) +
                    "]");
            }
        }
    }

    // 真实列数 M = Σ_a m_a（全局列号按属性顺序拼接；`predicate.hpp` 的
    // `LcteColumnRef{attribute_id, column}` 与本层的 `global_column` 一一对应）
    size_t total = 0;
    for (const AttributeSchema& s : schema.attributes()) total += s.lcte.range_size;
    return total;
}

}  // namespace

// ---------------------------------------------------------------------------
// MpraqQuery / MpraqQueryBatch
// ---------------------------------------------------------------------------

const PlinkoAnswer& MpraqQuery::answer0() const {
    if (!answered_) {
        throw std::logic_error("MpraqQuery::answer0: 尚未 Run（服务器 0 未应答）");
    }
    return answer0_;
}

const PlinkoAnswer& MpraqQuery::answer1() const {
    if (!answered_) {
        throw std::logic_error("MpraqQuery::answer1: 尚未 Run（服务器 1 未应答）");
    }
    return answer1_;
}

const PlinkoAnswer& MpraqQuery::answer() const {
    if (!answered_) {
        throw std::logic_error("MpraqQuery::answer: 尚未 Run（两台服务器都未应答）");
    }
    return answer_;
}

uint128_t MpraqQuery::value() const {
    if (!answered_) {
        throw std::logic_error(
            "MpraqQuery::value: 尚未 Run —— 明文值只有在两台服务器应答并 ClientRecon 之后才存在");
    }
    return value_;
}

MpraqQuery& MpraqQueryBatch::at(size_t i) {
    if (i >= queries_.size()) {
        throw std::out_of_range("MpraqQueryBatch::at: 下标越界 " + Num(i) + "（共 " +
                                Num(queries_.size()) + " 条查询）");
    }
    return queries_[i];
}

const MpraqQuery& MpraqQueryBatch::at(size_t i) const {
    if (i >= queries_.size()) {
        throw std::out_of_range("MpraqQueryBatch::at: 下标越界 " + Num(i) + "（共 " +
                                Num(queries_.size()) + " 条查询）");
    }
    return queries_[i];
}

std::vector<uint128_t> MpraqQueryBatch::Run() {
    if (owner_ == nullptr) {
        throw std::logic_error("MpraqQueryBatch::Run: 批次没有归属的客户端");
    }
    return owner_->RunBatch(*this);
}

// ---------------------------------------------------------------------------
// MpraqClient：Init
// ---------------------------------------------------------------------------

std::unique_ptr<MpraqClient> MpraqClient::Init(const Schema& schema,
                                               const std::vector<MpraqRecord>& records,
                                               const MpraqInitParams& params) {
    const auto t_total = std::chrono::steady_clock::now();
    auto client = std::unique_ptr<MpraqClient>(new MpraqClient());
    client->schema_ = schema;
    client->init_params_ = params;
    client->rng_ = std::make_unique<random::DeterministicPrng>(
        MaskStreamKey("tsb:mpraq/init-mask"), params.seed);

    const size_t real_cols = ValidateInputs(schema, records);

    // ---------- ① 参数校验 + 补齐到合法几何 ----------
    const MpraqPaddedGeometry g =
        DerivePaddedGeometry(real_cols, records.size(), params.lambda, params.prp_epsilon,
                             params.has_explicit_w, params.w);

    client->store_ = StoreParams{};
    client->store_.num_records = records.size();
    client->store_.words_per_column = (records.size() + 127) / 128;
    client->store_.real_column_count = real_cols;
    client->store_.column_count = g.column_count;
    client->store_.plinko = g.plinko;
    client->store_.attrs.clear();
    for (const AttributeSchema& a : schema.attributes()) {
        client->store_.attrs.push_back(
            StoreAttribute{a.name, a.id, a.lcte, a.domain_min, a.domain_max});
    }
    // ⚠️ 这里就是"补齐后的 n 满足 PlinkoParams 几何（c 偶数、w = 2^k）"的**断言点**：
    //    `StoreParams::Validate` 会核对 plinko.n == column_count·⌈N/128⌉ 并跑
    //    `PlinkoParams::Validate`（w 是 2 的幂、n = c·w、c 为偶数）。
    client->store_.Validate();

    client->timings_.records = records.size();
    client->timings_.words_per_column = client->store_.words_per_column;
    client->timings_.column_count = g.column_count;
    client->timings_.padding_columns = g.padding_columns;
    client->timings_.entry_count = g.plinko.n;
    client->timings_.block_count = g.plinko.block_count();
    client->timings_.block_size = g.plinko.w;

    // ---------- ② LCTE 编码 + 位打包 + 列主序展平 ----------
    client->BuildPlainTable(records);

    // ---------- ③ 共享掩码 + ④ HintInit + ⑥ α ----------
    client->PrepareShares(params);

    // 单进程仿真：自建两台节点与两条本地通道
    client->owned_nodes_.reserve(2);
    client->owned_channels_.reserve(2);
    for (int i = 0; i < 2; ++i) {
        client->owned_nodes_.push_back(std::make_unique<MpraqNode>());
        client->owned_channels_.push_back(
            std::make_unique<LocalMpraqChannel>(*client->owned_nodes_.back()));
        client->channels_[i] = client->owned_channels_.back().get();
    }
    client->owns_nodes_ = true;

    // ---------- ⑤ 上传 ----------
    client->DistributeUpload();

    client->timings_.total_ms = MsSince(t_total);
    return client;
}

std::unique_ptr<MpraqClient> MpraqClient::InitWithChannels(
    const Schema& schema, const std::vector<MpraqRecord>& records,
    const MpraqInitParams& params, IMpraqChannel& channel0, IMpraqChannel& channel1) {
    const auto t_total = std::chrono::steady_clock::now();
    if (&channel0 == &channel1) {
        throw std::invalid_argument(
            "MpraqClient::InitWithChannels: 两台服务器必须是**不同的**通道"
            "（同一对象会让两半共享落在同一台服务器上，XOR 重建立刻暴露明文）");
    }
    auto client = std::unique_ptr<MpraqClient>(new MpraqClient());
    client->schema_ = schema;
    client->init_params_ = params;
    client->rng_ = std::make_unique<random::DeterministicPrng>(
        MaskStreamKey("tsb:mpraq/init-mask"), params.seed);

    const size_t real_cols = ValidateInputs(schema, records);
    const MpraqPaddedGeometry g =
        DerivePaddedGeometry(real_cols, records.size(), params.lambda, params.prp_epsilon,
                             params.has_explicit_w, params.w);

    client->store_ = StoreParams{};
    client->store_.num_records = records.size();
    client->store_.words_per_column = (records.size() + 127) / 128;
    client->store_.real_column_count = real_cols;
    client->store_.column_count = g.column_count;
    client->store_.plinko = g.plinko;
    client->store_.attrs.clear();
    for (const AttributeSchema& a : schema.attributes()) {
        client->store_.attrs.push_back(
            StoreAttribute{a.name, a.id, a.lcte, a.domain_min, a.domain_max});
    }
    client->store_.Validate();

    client->timings_.records = records.size();
    client->timings_.words_per_column = client->store_.words_per_column;
    client->timings_.column_count = g.column_count;
    client->timings_.padding_columns = g.padding_columns;
    client->timings_.entry_count = g.plinko.n;
    client->timings_.block_count = g.plinko.block_count();
    client->timings_.block_size = g.plinko.w;

    client->channels_[0] = &channel0;
    client->channels_[1] = &channel1;
    client->owns_nodes_ = false;

    client->BuildPlainTable(records);
    client->PrepareShares(params);
    client->DistributeUpload();
    client->timings_.total_ms = MsSince(t_total);
    return client;
}

// ---------------------------------------------------------------------------
// ② LCTE 编码 → 位打包 → 列主序展平
// ---------------------------------------------------------------------------

void MpraqClient::BuildPlainTable(const std::vector<MpraqRecord>& records) {
    const auto t_total = std::chrono::steady_clock::now();
    const size_t N = store_.num_records;
    const size_t words = store_.words_per_column;
    const size_t cols = store_.column_count;

    plain_features_.assign(N, 0);
    plain_attrs_.assign(store_.attrs.size(), std::vector<int64_t>(N, 0));
    for (size_t i = 0; i < N; ++i) {
        plain_features_[i] = records[i].feature;
        for (size_t a = 0; a < store_.attrs.size(); ++a) {
            plain_attrs_[a][i] = records[i].attributes[a];
        }
    }

    // 逐属性逐记录编码：LCTE 位（复用 MPA-01 的 `LcteBits`；阈值口径 r_min + i）
    std::vector<std::vector<std::vector<uint8_t>>> bits(store_.attrs.size());
    for (size_t a = 0; a < store_.attrs.size(); ++a) {
        const StoreAttribute& s = store_.attrs[a];
        bits[a].assign(N, {});
        for (size_t i = 0; i < N; ++i) {
            bits[a][i] = LcteBits(records[i].attributes[a], s.lcte);
        }
    }
    timings_.lcte_ms = MsSince(t_total);

    // 位打包 + 列主序展平：
    //   第 c 列第 w 个 word 的**条目号 = c·⌈N/128⌉ + w**（MPRAQ_IMPL.md §1 / D24④）
    //   word 的第 j 位 = 第 j 条记录；第 j >= N 的位是**尾部填充位**，恒为 0
    //   （本实现从零初始化后只置位，因此填充位天然为 0 且两台一致）。
    const auto t_pack = std::chrono::steady_clock::now();
    plain_words_.assign(cols * words, 0);
    for (size_t a = 0; a < store_.attrs.size(); ++a) {
        const size_t base = store_.column_base(static_cast<uint32_t>(a));
        const size_t m_a = store_.attrs[a].lcte.range_size;
        for (size_t col = 0; col < m_a; ++col) {
            uint128_t* words_of_col =
                plain_words_.data() + (base + col) * words;  // 列主序：本列连续 words 个
            for (size_t i = 0; i < N; ++i) {
                if ((bits[a][i][col] & 1u) != 0) {
                    words_of_col[i / 128] |= static_cast<uint128_t>(1) << (i % 128);
                }
            }
        }
    }
    // 补齐列（条目号 [real_column_count, column_count)）保持全 0 —— 明文恒为 0，
    // 因此两台服务器的共享也逐位相同（0 ⊕ 0），尾部填充位一致这一要求自动满足。
    timings_.pack_ms = MsSince(t_pack);
}

// ---------------------------------------------------------------------------
// ③ 共享 + ④ HintInit + ⑤ 上传 + ⑥ MAC 密钥
// ---------------------------------------------------------------------------

void MpraqClient::PrepareShares(const MpraqInitParams& params) {
    const auto t_total = std::chrono::steady_clock::now();
    const size_t n = static_cast<size_t>(store_.entry_count());
    const uint128_t q = kMpraqModulus;

    // ---------- ③ 共享材料 ----------
    // 特征 word：**XOR 共享**（D3/D12；parity 语义是 ⊕ ⇒ 绝不用加法共享）。
    // s0 = mask、s1 = plain ⊕ mask；两台分别上传。
    // 补齐列必须**两台同为 0**：这样"补齐位明文为 0 且两台一致"逐位成立
    // （MPRAQ_IMPL.md §1 的 ⚠️），而不是靠 mask ⊕ mask = 0 这种"结果对但分量不一致"的写法。
    feature_share0_.assign(n, 0);
    feature_share1_.assign(n, 0);
    const size_t real_cols = store_.real_column_count;
    for (size_t i = 0; i < n; ++i) {
        const size_t col = i / store_.words_per_column;
        if (col >= real_cols) {  // 补齐列：两台同为 0
            continue;
        }
        const uint128_t mask = rng_->Next();
        feature_share0_[i] = mask;
        feature_share1_[i] = static_cast<uint128_t>(plain_words_[i] ^ mask);
    }

    // 属性值：**mod q 加法共享**（强类型 `ModShare`）
    const size_t na = store_.attrs.size();
    attr_share0_.assign(na, {});
    attr_share1_.assign(na, {});
    for (size_t a = 0; a < na; ++a) {
        auto [s0, s1] = ShareAttributeVector(plain_attrs_[a], q, *rng_);
        attr_share0_[a] = std::move(s0);
        attr_share1_[a] = std::move(s1);
    }
    timings_.share_ms = MsSince(t_total);

    // ---------- ④ HintInit（客户端本地，对**明文** feature word 表）----------
    // ⚠️ 真实部署里这一步跑在**持有 DB 的 offline server** 上（PLINKO_SPEC §2 的注）；
    //    本仓库沿用单机仿真约定，hint 由客户端本地生成，两种做法结果完全相同。
    const auto t_hint = std::chrono::steady_clock::now();
    plinko_ = std::make_unique<PlinkoClient>(store_.plinko, params.seed);
    plinko_->HintInit(plain_words_);
    timings_.hint_ms = MsSince(t_hint);

    // ---------- ⑥ MAC 密钥 α（**全局一份**，Q3）----------
    // ⚠️ α 只是 SPDZ MAC 的密钥，供 `MPA-06` 的 `ShareAuthenticated` 使用；
    //    本任务**不生成任何 HMAC 验证值**（论文 :527 在共享域上不可实现，
    //    D24① / 台账 L9，机制待 §7.13 的 V1 裁决）。
    mac_keys_ = GenerateMacKey(2, kMpraqModulus);
}

void MpraqClient::DistributeUpload() {
    const auto t_up = std::chrono::steady_clock::now();
    const size_t n = static_cast<size_t>(store_.entry_count());
    size_t chunk = init_params_.upload_chunk_words;
    if (chunk == 0) {
        throw std::invalid_argument(
            "MpraqClient::Init: upload_chunk_words 必须 >= 1（分块大小为 0 时无法推进）");
    }
    chunk = std::min(chunk, n);

    for (int s = 0; s < 2; ++s) {
        channels_[s]->InitTable(store_);
    }
    // 特征 word 的 XOR 共享：**分块**上传（块大小固定常量 4096 word = 64 KiB/块；
    // 理由见 `MpraqInitParams::upload_chunk_words`）。
    const auto& s0 = feature_share0_;
    const auto& s1 = feature_share1_;
    for (size_t base = 0; base < n; base += chunk) {
        const size_t cnt = std::min(chunk, n - base);
        std::vector<uint128_t> w0(s0.begin() + static_cast<ptrdiff_t>(base),
                                  s0.begin() + static_cast<ptrdiff_t>(base + cnt));
        std::vector<uint128_t> w1(s1.begin() + static_cast<ptrdiff_t>(base),
                                  s1.begin() + static_cast<ptrdiff_t>(base + cnt));
        channels_[0]->UploadFeatureWords(base, w0, cnt);
        channels_[1]->UploadFeatureWords(base, w1, cnt);
        upload_bytes_ += 2 * static_cast<uint64_t>(cnt) * kUint128Bytes;
    }

    // 属性值的加法共享：带 attr_id 上传
    for (size_t a = 0; a < store_.attrs.size(); ++a) {
        channels_[0]->SetAttributeShares(static_cast<uint32_t>(a), attr_share0_[a]);
        channels_[1]->SetAttributeShares(static_cast<uint32_t>(a), attr_share1_[a]);
        upload_bytes_ += 2ull * store_.num_records * kUint128Bytes;
    }
    timings_.chunk_words = chunk;
    timings_.chunk_count = (n + chunk - 1) / chunk;
    timings_.upload_ms = MsSince(t_up);
}

// ---------------------------------------------------------------------------
// 状态访问
// ---------------------------------------------------------------------------

IprfKey MpraqClient::block_key(uint64_t block) const {
    const uint64_t c = store_.plinko.block_count();
    if (block >= c) {
        throw std::out_of_range("MpraqClient::block_key: 区块号越界 " + Num(block) +
                                "（c = " + Num(c) + "）");
    }
    // 与 `PlinkoClient` 内部生成的是同一批密钥：`HintInit` 调
    // `Iprf::GenBlockKeys(c, /*use_csprng=*/false, nonce_=seed)`（见 pir/plinko.cpp），
    // 因此这里用同样的 (c, false, seed) 重算 —— 不额外存一份材料，也不会不一致。
    const std::vector<IprfKey> keys =
        Iprf::GenBlockKeys(static_cast<size_t>(c), /*use_csprng=*/false, init_params_.seed);
    return keys[static_cast<size_t>(block)];
}

size_t MpraqClient::hint_slot_count() const { return plinko_->hint_slot_count(); }
size_t MpraqClient::hint_state_bytes() const { return plinko_->hint_state_bytes(); }
double MpraqClient::logical_hint_bytes() const { return plinko_->logical_hint_bytes(); }
size_t MpraqClient::backup_remaining() const { return plinko_->backup_remaining(); }
uint64_t MpraqClient::query_count() const { return plinko_->query_count(); }
std::vector<uint8_t> MpraqClient::coverage_mask() const { return plinko_->coverage_mask(); }

uint128_t MpraqClient::PlainFeatureWord(uint64_t i) const {
    if (i >= plain_words_.size()) {
        throw std::out_of_range("MpraqClient::PlainFeatureWord: 条目号越界 " + Num(i) +
                                "（n = " + Num(plain_words_.size()) + "）");
    }
    return plain_words_[static_cast<size_t>(i)];
}

uint64_t MpraqClient::ColumnWordIndex(uint32_t attr_id, uint32_t column, size_t word) const {
    // ⚠️ 唯一入口：**列主序**条目号 = 全局列号 · ⌈N/128⌉ + word 序号（D24④）。
    return store_.ColWordIndex(attr_id, column, word);
}

uint64_t MpraqClient::GlobalColumnWordIndex(size_t global_column, size_t word) const {
    return store_.ColWordIndex(global_column, word);
}

std::pair<uint64_t, uint64_t> MpraqClient::ColumnSegment(uint32_t attr_id,
                                                         uint32_t column) const {
    const uint64_t begin = store_.ColWordIndex(attr_id, column, 0);
    return {begin, begin + store_.words_per_column};
}

std::vector<uint8_t> MpraqClient::PlainColumnBits(uint32_t attr_id, uint32_t column) const {
    const uint64_t base = store_.ColWordIndex(attr_id, column, 0);
    std::vector<uint8_t> bits(store_.num_records, 0);
    for (size_t j = 0; j < store_.num_records; ++j) {
        const uint128_t word = plain_words_[static_cast<size_t>(base) + j / 128];
        bits[j] = static_cast<uint8_t>((word >> (j % 128)) & 1u);
    }
    return bits;
}

// ---------------------------------------------------------------------------
// 查询：QueryGen → 两台 ServerResp → XorAnswers → ClientRecon
// ---------------------------------------------------------------------------

MpraqQueryBatch MpraqClient::CreateQueries(const std::vector<ColumnWord>& targets) {
    if (targets.empty()) {
        throw std::invalid_argument("MpraqClient::CreateQueries: 目标不能为空");
    }
    // ⚠️ 每轮 PIR 消费 1 条常规 hint 并提升 1 条备份 hint ⇒ 一批的总数不能超过剩余备份数
    //    （D8：不做摊销式离线）。**在发出任何查询之前**先检查，避免半途抛错留下半批状态。
    const size_t backup_capacity = plinko_->backup_remaining();
    if (targets.size() > backup_capacity) {
        throw std::invalid_argument(
            "MpraqClient::CreateQueries: 本批有 " + Num(targets.size()) +
            " 条查询，超过剩余备份 hint 数 " + Num(backup_capacity) +
            "（每轮 PIR 消费 1 条常规 hint 并提升 1 条备份 hint；决策 D8 不做摊销式离线）"
            "⇒ 请分成多批，每批不超过剩余备份数。");
    }
    std::vector<uint64_t> flats;
    flats.reserve(targets.size());
    for (const ColumnWord& t : targets) {
        // ⚠️ 唯一的条目号算法：**列主序** = 全局列号 · ⌈N/128⌉ + word 序号（D24④）
        flats.push_back(store_.ColWordIndex(t.attr_id, t.column, t.word));
    }
    return CreateQueriesForIndices(flats);
}

MpraqQueryBatch MpraqClient::CreateQueriesForIndices(const std::vector<uint64_t>& flat_indices) {
    if (flat_indices.empty()) {
        throw std::invalid_argument("MpraqClient::CreateQueriesForIndices: 目标不能为空");
    }
    const uint64_t n = store_.entry_count();
    for (uint64_t flat : flat_indices) {
        if (flat >= n) {
            throw std::out_of_range("MpraqClient::CreateQueriesForIndices: 条目号越界 " +
                                    Num(flat) + "（n = " + Num(n) + "）");
        }
    }
    MpraqQueryBatch batch(*this);
    batch.queries_.reserve(flat_indices.size());
    for (uint64_t flat : flat_indices) {
        MpraqQuery q;
        q.flat_index_ = flat;
        try {
            auto [pq, h] = plinko_->QueryGen(flat);
            q.query_ = std::move(pq);
            q.handle_ = h;
        } catch (const PlinkoBackupsExhausted& e) {
            throw PlinkoBackupsExhausted(
                std::string("MpraqClient::CreateQueriesForIndices: 备份 hint 用尽：") +
                e.what());
        }
        batch.queries_.push_back(std::move(q));
    }
    return batch;
}

MpraqQueryBatch MpraqClient::CreateColumnQuery(uint32_t attr_id, uint32_t column) {
    std::vector<ColumnWord> targets;
    targets.reserve(store_.words_per_column);
    for (size_t w = 0; w < store_.words_per_column; ++w) {
        targets.push_back(ColumnWord{attr_id, column, w});
    }
    return CreateQueries(targets);
}

// 两条路径共用的**客户端本地**收尾：两台应答 XOR 起来 → `ClientRecon`。
// ⊕ 与 XOR 共享线性相容（D12/D3）⇒ 合并后的应答就是明文应答。
// （作为 `MpraqClient` 的成员以访问 `MpraqQuery` 的私有字段；不产生任何通道调用。）
uint128_t MpraqClient::FinishOne(MpraqQuery& q, const PlinkoAnswer& a0,
                                const PlinkoAnswer& a1) {
    q.answer0_ = a0;
    q.answer1_ = a1;
    q.answer_ = PlinkoClient::XorAnswers(a0, a1);
    q.value_ = plinko_->ClientRecon(q.handle_, q.answer_);
    q.answered_ = true;
    return q.value_;
}

uint128_t MpraqClient::RunQuery(MpraqQuery& q) {
    // **单条**路径：1 个查询集 ⇒ 1 次标量 `ServerResp`（= 1 次往返）。
    // 标量语义正是"只有一条查询"的退化解，因此这里**不**套用批量接口。
    const PlinkoAnswer a0 = channels_[0]->ServerResp(q.query_);
    const PlinkoAnswer a1 = channels_[1]->ServerResp(q.query_);
    ++server_resp_calls_[0];
    ++server_resp_calls_[1];
    ++server_resp_queries_[0];
    ++server_resp_queries_[1];
    return FinishOne(q, a0, a1);
}

std::vector<uint128_t> MpraqClient::RunBatch(MpraqQueryBatch& batch) {
    if (batch.owner_ != this) {
        throw std::invalid_argument(
            "MpraqClient::RunBatch: 该批次不属于本客户端（跨客户端复用会读错 hint 表）");
    }
    if (batch.queries_.empty()) {
        throw std::invalid_argument("MpraqClient::RunBatch: 批次不能为空");
    }
    // ⚠️ **Q5 / MPRAQ_IMPL.md §3 / D24④**：整批查询集走每台服务器的**一次**
    //    `ServerRespBatch` ⇒ 远程部署下一次 `AggQuery`（任意多少列 × 每列 ⌈N/128⌉ 个
    //    word）的网络往返数恒为 **1**。逐条调用 `ServerResp` 会让 N=2^14 的一列
    //    （128 个 word）变成 128 次 RPC。
    std::vector<PlinkoQuery> wire;
    wire.reserve(batch.queries_.size());
    for (const MpraqQuery& q : batch.queries_) wire.push_back(q.query_);

    // 两台服务器各自在**本方 XOR 共享**上应答（服务器之间零通信）
    const std::vector<PlinkoAnswer> ans0 = channels_[0]->ServerRespBatch(wire);
    const std::vector<PlinkoAnswer> ans1 = channels_[1]->ServerRespBatch(wire);
    ++server_resp_batch_calls_[0];
    ++server_resp_batch_calls_[1];
    server_resp_queries_[0] += wire.size();
    server_resp_queries_[1] += wire.size();
    if (ans0.size() != wire.size() || ans1.size() != wire.size()) {
        throw std::runtime_error(
            "MpraqClient::RunBatch: 服务器应答个数与查询集个数不符（" +
            Num(ans0.size()) + " / " + Num(ans1.size()) + " vs " + Num(wire.size()) +
            "）—— 通道实现必须逐条同序返回");
    }

    // 重建是**客户端本地**工作 ⇒ 逐条做（不再产生任何通道调用）
    std::vector<uint128_t> out;
    out.reserve(batch.queries_.size());
    for (size_t i = 0; i < batch.queries_.size(); ++i) {
        out.push_back(FinishOne(batch.queries_[i], ans0[i], ans1[i]));
    }
    return out;
}

// ---------------------------------------------------------------------------
// 属性共享 / 服务器 / 账目
// ---------------------------------------------------------------------------

ModShare MpraqClient::AttributeShare(uint32_t attr_id, size_t record, int server) const {
    if (server != 0 && server != 1) {
        throw std::out_of_range("MpraqClient::AttributeShare: server 必须是 0 或 1");
    }
    if (attr_id >= store_.attrs.size()) {
        throw std::out_of_range("MpraqClient::AttributeShare: 属性号越界 " + Num(attr_id));
    }
    if (record >= store_.num_records) {
        throw std::out_of_range("MpraqClient::AttributeShare: 记录号越界 " + Num(record));
    }
    return (server == 0 ? attr_share0_ : attr_share1_)[attr_id][record];
}

std::pair<ModShare, ModShare> MpraqClient::AttributeShare(uint32_t attr_id,
                                                         size_t record) const {
    return {AttributeShare(attr_id, record, 0), AttributeShare(attr_id, record, 1)};
}

std::vector<ModShare> MpraqClient::AttributeShares(uint32_t attr_id, int server) const {
    if (server != 0 && server != 1) {
        throw std::out_of_range("MpraqClient::AttributeShares: server 必须是 0 或 1");
    }
    if (attr_id >= store_.attrs.size()) {
        throw std::out_of_range("MpraqClient::AttributeShares: 属性号越界 " + Num(attr_id));
    }
    return (server == 0 ? attr_share0_ : attr_share1_)[attr_id];
}

MpraqNode& MpraqClient::node(int server_id) {
    if (server_id < 0 || server_id > 1) {
        throw std::out_of_range("MpraqClient::node: server_id 必须是 0 或 1");
    }
    if (!owns_nodes_) {
        throw std::logic_error(
            "MpraqClient::node: 远程模式下没有本地节点（请改用 channel 访问）");
    }
    return *owned_nodes_[static_cast<size_t>(server_id)];
}

const MpraqNode& MpraqClient::node(int server_id) const {
    if (server_id < 0 || server_id > 1) {
        throw std::out_of_range("MpraqClient::node: server_id 必须是 0 或 1");
    }
    if (!owns_nodes_) {
        throw std::logic_error(
            "MpraqClient::node: 远程模式下没有本地节点（请改用 channel 访问）");
    }
    return *owned_nodes_[static_cast<size_t>(server_id)];
}

IMpraqChannel& MpraqClient::channel(int server_id) {
    if (server_id < 0 || server_id > 1) {
        throw std::out_of_range("MpraqClient::channel: server_id 必须是 0 或 1");
    }
    return *channels_[server_id];
}

MpraqRpcStats MpraqClient::channel_rpc_stats(int server_id) const {
    if (server_id < 0 || server_id > 1) {
        throw std::out_of_range(
            "MpraqClient::channel_rpc_stats: server_id 必须是 0 或 1");
    }
    MpraqRpcStats s;
    s.server_resp_batch_calls = server_resp_batch_calls_[server_id];
    s.server_resp_single_calls = server_resp_calls_[server_id];
    s.queries = server_resp_queries_[server_id];
    return s;
}

uint64_t MpraqClient::channel_server_resp_calls(int server_id) const {
    return channel_rpc_stats(server_id).server_resp_single_calls;
}

uint64_t MpraqClient::storage_bytes(int server_id) const {
    return node(server_id).StorageBytes();
}

}  // namespace mpraq
}  // namespace tsb
