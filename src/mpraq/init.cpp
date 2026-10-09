#include "mpraq/init.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <numeric>
#include <sstream>

#include "core/gf128.hpp"
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

MpraqPaddedGeometry DerivePaddedGeometry(size_t levels, size_t n, uint32_t lambda,
                                         double prp_epsilon, bool has_explicit_w,
                                         uint64_t w_explicit) {
    if (n == 0) {
        throw std::invalid_argument(
            "DerivePaddedGeometry: n（记录数 = 列长）必须 >= 1（n=0 时 ⌈n/128⌉=0，"
            "条目宽度为 0 ⇒ 没有任何可检索的条目）");
    }
    if (levels == 0) {
        throw std::invalid_argument(
            "DerivePaddedGeometry: levels（真实 LCTE 层数 = Σ_a lcte.range_size）必须 >= 1");
    }
    const uint64_t entry_words = (static_cast<uint64_t>(n) + 127) / 128;

    MpraqPaddedGeometry g;
    g.levels = levels;

    // ---------------------------------------------------------------------
    // 列级补齐：**只补列、绝不补记录**
    // ---------------------------------------------------------------------
    // ⚠️ 列粒度（一个条目 = 一整列）下，Plinko 的几何要求只剩三条：
    //      * `w` 是 2 的幂（D21：w 是 iPRF 的值域）；
    //      * `m = κ·w`，即 **w | m**；
    //      * `κ = m/w` 为**偶数**（§5.5 的对称性硬要求）⇒ 等价于 **2w | m**。
    //   ⇒ 对给定的 `w`，满足条件的最小 `m` 就是 `ceil(levels / (2w)) · 2w`。
    //   🔴 **旧口径作废**：word 粒度下条目数 = 列数 × ⌈n/128⌉，且 `w >= ⌈n/128⌉`、
    //      `cols` 必须补齐到 2 的幂，于是出现了 D35 的"×2 升级搜索"。
    //      列粒度下 **m 不再需要是 2 的幂**，补齐量从"抬到 2 的幂"降到"抬到 2w 的倍数"，
    //      D35 的升级搜索因此**整体删除**（连同 `OddPart` / `kColumnUpgradeSlack`，已删）。
    //   代价只有"补齐列"（全零列；几何公开 ⇒ 不泄露），存储增量
    //   `16·(m − levels)·entry_words` B，必须与 `levels` 口径**双报**。
    struct Candidate {
        uint64_t w = 0;
        uint64_t m = 0;   // PIR 条目数（含补齐列）
    };

    // 指定 (w, m) 是否自洽。几何判据**只有** `PlinkoParams::Validate` 一处
    // （本层绝不自己重写一套、也不放宽它）。
    const auto build = [&](uint64_t w, uint64_t m, PlinkoParams* out,
                           std::string* why) -> bool {
        PlinkoParams p;
        p.m = m;
        p.entry_words = entry_words;
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

    // 给定 w：取**最小**的合法 m（>= levels 且 2w | m）
    const auto try_w = [&](uint64_t w, Candidate* out, std::string* why) -> bool {
        if (w == 0 || !IsPowerOfTwo(w)) {
            *why = "w 必须是 2 的幂";
            return false;
        }
        const uint64_t step = 2 * w;                       // κ 必须为偶数 ⇒ 2w | m
        uint64_t m = ((static_cast<uint64_t>(levels) + step - 1) / step) * step;
        if (m < 4) m = 4;                                  // 最小合法几何（w=2 ⇒ κ=2）
        if (m % step != 0) m = ((m + step - 1) / step) * step;
        PlinkoParams p;
        std::string r;
        if (build(w, m, &p, &r)) {
            out->w = w;
            out->m = m;
            return true;
        }
        *why = r;
        return false;
    };

    // 把选中的候选落到输出（唯一写 g 的地方；再校验一次，防"选了却没验"）
    const auto apply = [&](const Candidate& c) {
        PlinkoParams p;
        std::string why;
        if (!build(c.w, c.m, &p, &why)) {
            throw std::logic_error(
                "MPRAQ Init: 内部一致性错误（选中的候选几何重新校验失败）：" + why);
        }
        g.m = static_cast<size_t>(c.m);
        g.padding_columns = static_cast<size_t>(c.m) - levels;
        g.plinko = p;
    };

    if (has_explicit_w) {
        // 显式 w：只补齐列数，不改 w
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
                " 无法通过补齐整列凑出合法的 Plinko 几何（levels = " + Num(levels) +
                "、entry_words = " + Num(entry_words) + "）：" + why);
        }
        apply(c);
        return g;
    }

    // 默认路径：在全部合法 w 里按 (服务器存储 16·m·entry_words, hint 表 H = 3λw/2) 取最优。
    //   主键 = m（更小的 m ⇒ 更少补齐列、更小存储）；次键 = w（更小的 H）。
    std::vector<Candidate> valid;
    std::vector<std::string> reasons;
    for (uint64_t k = 0; k < 33; ++k) {
        const uint64_t w = static_cast<uint64_t>(1) << k;
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
        oss << "MPRAQ Init: 无法把 LCTE 布局（levels=" << levels << " 层 × entry_words="
            << entry_words << " 个字/列）补齐到任何合法的 Plinko 几何"
            << "（要求 w = 2^k、w | m、κ = m/w 为偶数、m >= 4）。\n"
            << "  诊断：对每个 w 取最小 m = ceil(levels / 2w)·2w 都被 PlinkoParams::Validate"
               " 拒绝。\n"
            << "  试过的候选 w：";
        for (size_t i = 0; i < reasons.size() && i < 8; ++i) {
            oss << "\n    " << reasons[i];
        }
        if (reasons.size() > 8) {
            oss << "\n    …（其余 " << (reasons.size() - 8) << " 个候选同理）";
        }
        oss << "\n  处置：检查 λ/ε（`λw` 或 `H = 3λw/2` 超过 core/iprf 的 2^32 域宽时"
               "**任何**几何都不合法）。";
        throw std::invalid_argument(oss.str());
    }
    // 次键选择：**w 取最接近 √m 的 2 的幂**（Plinko 的标准选择 w ≈ √m）。
    //   ⚠️ 查询成本 = κ = m/w 次**区块访问** ⇒ w 越小读得越多；`w = 1` 会让一次列查询
    //      退化成整表扫描（κ = m），彻底丧失次线性 —— 必须避免。
    //      而 hint 表规模 H = 3λw/2 随 w 增长 ⇒ 取 w ≈ √m 是"读次数 vs hint 表"的
    //      标准折中（与 `PlinkoParams::Derive` 的 `w = 2^⌈log₂√m⌉` 同族）。
    const auto log2d = [](uint64_t v) { return std::log2(static_cast<double>(v)); };
    std::sort(valid.begin(), valid.end(), [&](const Candidate& a, const Candidate& b) {
        const double da = std::fabs(log2d(a.w) - 0.5 * log2d(a.m));
        const double db = std::fabs(log2d(b.w) - 0.5 * log2d(b.m));
        if (da != db) return da < db;      // 主键：w 越接近 √m 越好
        if (a.m != b.m) return a.m < b.m;  // 次键：更少补齐列（存储更小）
        return a.w < b.w;                  // 末键：hint 表更小（H = 3λw/2）
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
            "MpraqClient::Init: 记录数 n 必须 >= 1（n=0 时特征表为空，"
            "没有任何可检索的条目 ⇒ Plinko 的 m = 0）");
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

const PlinkoEntry& MpraqQuery::value() const {
    if (!answered_) {
        throw std::logic_error(
            "MpraqQuery::value: 尚未 Run —— 明文整列只有在两台服务器应答并 ClientRecon 之后才存在");
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

std::vector<PlinkoEntry> MpraqQueryBatch::Run() {
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
    client->store_.n = records.size();
    client->store_.entry_words = (records.size() + 127) / 128;
    client->store_.levels = real_cols;
    client->store_.m = g.m;
    client->store_.plinko = g.plinko;
    client->store_.security_mode = params.security_mode;
    // Plinko 的重复查询缓存开关（默认开；关掉 ⇒ 重复查询**直接拒绝**，见 init.hpp）
    client->store_.plinko.enable_repeat_cache = params.enable_repeat_query_cache;
    client->store_.attrs.clear();
    for (const AttributeSchema& a : schema.attributes()) {
        client->store_.attrs.push_back(
            StoreAttribute{a.name, a.id, a.lcte, a.domain_min, a.domain_max});
    }
    // ⚠️ 这里就是"补齐后的 `m` 满足 PlinkoParams 几何（kappa 偶数、w = 2^k）"的**断言点**：
    //    `StoreParams::Validate` 会交叉核对 `plinko.m == m`、`plinko.entry_words == entry_words`
    //    并跑 `PlinkoParams::Validate`（w 是 2 的幂、m = kappa·w、kappa 为偶数）。
    client->store_.Validate();

    client->timings_.n = records.size();
    client->timings_.entry_words = client->store_.entry_words;
    client->timings_.m = g.m;
    client->timings_.levels = g.levels;
    client->timings_.padding_columns = g.padding_columns;
    client->timings_.blocks = g.plinko.blocks();
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
        // ⚠️ 必须把档位告诉节点：`InitTable` 会拿它和 `StoreParams.security_mode` 比对，
        //    不一致即拒绝装载（唯一的静默降级失败模式）。漏掉这一步的后果是
        //    "客户端说半诚实、本地节点按恶意档准备" —— 正是闸门要拦的情形。
        client->owned_nodes_.back()->SetSecurityMode(params.security_mode);
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
    client->store_.n = records.size();
    client->store_.entry_words = (records.size() + 127) / 128;
    client->store_.levels = real_cols;
    client->store_.m = g.m;
    client->store_.plinko = g.plinko;
    client->store_.security_mode = params.security_mode;
    // 与 `Init` 同一纪律：**两条初始化路径都必须透传这个开关**（漏掉一处会让
    // "配置说关、实际开着"这种不一致悄悄发生）。
    client->store_.plinko.enable_repeat_cache = params.enable_repeat_query_cache;
    client->store_.attrs.clear();
    for (const AttributeSchema& a : schema.attributes()) {
        client->store_.attrs.push_back(
            StoreAttribute{a.name, a.id, a.lcte, a.domain_min, a.domain_max});
    }
    client->store_.Validate();

    client->timings_.n = records.size();
    client->timings_.entry_words = client->store_.entry_words;
    client->timings_.m = g.m;
    client->timings_.levels = g.levels;
    client->timings_.padding_columns = g.padding_columns;
    client->timings_.blocks = g.plinko.blocks();
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
    const size_t N = store_.n;
    const size_t words = store_.entry_words;
    const size_t cols = store_.m;

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

    // 位打包：**一列 = 一个条目**。
    //   条目 i（= 全局列号 i）占 `[i·entry_words, (i+1)·entry_words)` 个连续 word；
    //   word 的第 j 位 = 第 j 条记录；第 j >= n 的位是**尾部填充位**（不变量 I2），
    //   本实现从零初始化后只置位 ⇒ 填充位天然为 0 且两台一致。
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
    // 补齐列（条目号 [levels, m)）保持全 0 —— 明文恒为 0，
    // 因此两台服务器的共享也逐位相同（0 ⊕ 0），列级与位级填充都自动满足不变量 I2。
    timings_.pack_ms = MsSince(t_pack);
}

// ---------------------------------------------------------------------------
// ③ 共享 + ④ HintInit + ⑤ 上传 + ⑥ MAC 密钥
// ---------------------------------------------------------------------------

void MpraqClient::PrepareShares(const MpraqInitParams& params) {
    const auto t_total = std::chrono::steady_clock::now();
    // ⚠️ 特征表是**扁平的字数组**：总量 = m 个条目 × entry_words 个字
    const size_t total_words =
        static_cast<size_t>(store_.entry_count()) * store_.entry_words;
    const uint128_t q = kMpraqModulus;

    // ---------- ③ 共享材料 ----------
    // 特征 word：**XOR 共享**（D3/D12；parity 语义是 ⊕ ⇒ 绝不用加法共享）。
    // s0 = mask、s1 = plain ⊕ mask；两台分别上传。
    // 补齐列必须**两台同为 0**：这样"补齐位明文为 0 且两台一致"逐位成立
    // （不变量 I2），而不是靠 mask ⊕ mask = 0 这种"结果对但分量不一致"的写法。
    feature_share0_.assign(total_words, 0);
    feature_share1_.assign(total_words, 0);
    const size_t real_cols = store_.levels;
    for (size_t i = 0; i < total_words; ++i) {
        const size_t col = i / store_.entry_words;   // 一列 = 一个条目（entry_words 个字）
        if (col >= real_cols) {  // 补齐列：两台同为 0
            continue;
        }
        const uint128_t mask = rng_->Next();
        feature_share0_[i] = mask;
        feature_share1_[i] = static_cast<uint128_t>(plain_words_[i] ^ mask);
    }
    // ⚠️ **不变量 I2**：末字的尾部填充位（`j >= n`）必须在**两台分片上恒为 0**，
    //    而不是"靠 mask ⊕ mask = 0 让重建结果对"—— 后者会让两台分片在填充位上
    //    **取值相同**（都等于掩码），既是文档点名的反面写法，也让"哪些位是填充"
    //    在分片层面留下结构性痕迹。这里显式把两台的高位掩掉。
    //    （列级补齐的全零列已在上面 `continue` 掉，同样是两台恒 0。）
    const size_t tail_bits = store_.n % 128;
    if (tail_bits != 0) {
        const uint128_t keep = (static_cast<uint128_t>(1) << tail_bits) - 1;
        for (size_t e = 0; e < store_.m; ++e) {
            const size_t last = e * store_.entry_words + (store_.entry_words - 1);
            feature_share0_[last] = static_cast<uint128_t>(feature_share0_[last] & keep);
            feature_share1_[last] = static_cast<uint128_t>(feature_share1_[last] & keep);
        }
    }

    // ---------- ③b xmac 的 tag 分片（**仅恶意档**）----------
    // 论文 :122-123：`mac1[i]^(c) ←$ GF(2^ℓ)`、`mac2[i]^(c) = mac1[i]^(c) ⊕ (γ ⊙ D[i]^(c))`。
    // ℓ = 128 恰好等于一个字 ⇒ **一个 chunk = 一个字**，`C = entry_words`。
    //
    // ⚠️ **半诚实档整段跳过**：不采样 γ、不生成、不存、不传、不校验（存储与应答各减半）。
    //    判定完全由 `store_.has_tags()`（= 档位）决定，**没有第二处开关**。
    //
    // ⚠️ **补齐条目（entry >= levels）两块 tag 都置 0**（与数据侧的 I2 同纪律）：
    //    按公式若 D = 0 则 `mac2 = mac1 ⊕ 0 = mac1` ⇒ **两台 tag 完全相同**，
    //    会留下"哪些条目是补齐"的结构性痕迹。置 0 后 `XOR = 0 = γ ⊙ 0` 仍然自洽，
    //    且补齐条目**不可达**（越界即抛），所以不影响任何可达查询。
    //
    // ⚠️ **尾部填充位（末字 j >= n）不做特殊处理**：tag 是对**整字**算的，
    //    `γ ⊙ D` 自然卷入那些 0 位；由于 `mac1` 是随机的，两台 tag 分片**看起来仍然随机**
    //    ⇒ 不像数据侧那样需要额外掩码，也**不该**掩（掩了反而制造痕迹）。
    if (store_.has_tags()) {
        tag_key_ = Gf128SampleNonZero(*rng_);
        const size_t total = plain_words_.size();
        tag_share0_.assign(total, 0);
        tag_share1_.assign(total, 0);
        for (size_t i = 0; i < total; ++i) {
            const size_t col = i / store_.entry_words;   // 一列 = 一个条目
            if (col >= store_.levels) continue;          // 补齐条目：两台恒 0（见上）
            const uint128_t mac1 = rng_->Next();
            tag_share0_[i] = mac1;
            tag_share1_[i] = static_cast<uint128_t>(mac1 ^ Gf128Mul(tag_key_, plain_words_[i]));
        }
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
    // ⚠️ 特征表是**扁平的字数组**：总量 = m 个条目 × entry_words 个字
    //    （旧口径下 `entry_count()` 就是字数；列粒度下必须再乘 entry_words，
    //     否则只会上传前 m 个字 ⇒ 静默少传，重建出垃圾）。
    const size_t total_words =
        static_cast<size_t>(store_.entry_count()) * store_.entry_words;
    size_t chunk = init_params_.upload_chunk_words;
    if (chunk == 0) {
        throw std::invalid_argument(
            "MpraqClient::Init: upload_chunk_words 必须 >= 1（分块大小为 0 时无法推进）");
    }
    // ⚠️ 分块必须是 entry_words 的整数倍（服务端按条目边界校验上传长度 = 不变量 I1）
    chunk = (chunk / store_.entry_words) * store_.entry_words;
    if (chunk == 0) chunk = store_.entry_words;
    chunk = std::min(chunk, total_words);

    for (int s = 0; s < 2; ++s) {
        channels_[s]->InitTable(store_);
    }
    // 特征 word 的 XOR 共享：**分块**上传（块大小默认 4096 word = 64 KiB/块，
    // 且按 entry_words 对齐；理由见 `MpraqInitParams::upload_chunk_words`）。
    const auto& s0 = feature_share0_;
    const auto& s1 = feature_share1_;
    for (size_t base = 0; base < total_words; base += chunk) {
        const size_t cnt = std::min(chunk, total_words - base);
        std::vector<uint128_t> w0(s0.begin() + static_cast<ptrdiff_t>(base),
                                  s0.begin() + static_cast<ptrdiff_t>(base + cnt));
        std::vector<uint128_t> w1(s1.begin() + static_cast<ptrdiff_t>(base),
                                  s1.begin() + static_cast<ptrdiff_t>(base + cnt));
        channels_[0]->UploadFeatureWords(base, w0, cnt);
        channels_[1]->UploadFeatureWords(base, w1, cnt);
        upload_bytes_ += 2 * static_cast<uint64_t>(cnt) * kUint128Bytes;
    }

    // xmac 的 tag 共享：**仅恶意档**上传；分块与对齐规则与特征侧完全相同
    // （tag 与条目等宽 ⇒ 同样按 `entry_words` 对齐，不变量 I5）。
    if (store_.has_tags()) {
        const auto& t0 = tag_share0_;
        const auto& t1 = tag_share1_;
        for (size_t base = 0; base < total_words; base += chunk) {
            const size_t cnt = std::min(chunk, total_words - base);
            std::vector<uint128_t> w0(t0.begin() + static_cast<ptrdiff_t>(base),
                                      t0.begin() + static_cast<ptrdiff_t>(base + cnt));
            std::vector<uint128_t> w1(t1.begin() + static_cast<ptrdiff_t>(base),
                                      t1.begin() + static_cast<ptrdiff_t>(base + cnt));
            channels_[0]->UploadFeatureTags(base, w0, cnt);
            channels_[1]->UploadFeatureTags(base, w1, cnt);
            upload_bytes_ += 2 * static_cast<uint64_t>(cnt) * kUint128Bytes;
        }
    }

    // 属性值的加法共享：带 attr_id 上传
    for (size_t a = 0; a < store_.attrs.size(); ++a) {
        channels_[0]->SetAttributeShares(static_cast<uint32_t>(a), attr_share0_[a]);
        channels_[1]->SetAttributeShares(static_cast<uint32_t>(a), attr_share1_[a]);
        upload_bytes_ += 2ull * store_.n * kUint128Bytes;
    }
    timings_.chunk_words = chunk;
    timings_.chunk_count = (total_words + chunk - 1) / chunk;
    timings_.upload_ms = MsSince(t_up);
}

// ---------------------------------------------------------------------------
// 状态访问
// ---------------------------------------------------------------------------

IprfKey MpraqClient::block_key(uint64_t block) const {
    const uint64_t c = store_.plinko.blocks();
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

uint64_t MpraqClient::client_state_bytes() const {
    // hint 表 + 重复查询缓存（都在 PlinkoClient 里，由 `hint_state_bytes()` 一并统计）
    // + 每区块一把 iPRF 密钥（`IprfKey` = 2 × AES-128 密钥 = 32 B，架构相关但稳定）。
    const uint64_t hints = static_cast<uint64_t>(plinko_ ? plinko_->hint_state_bytes() : 0);
    const uint64_t keys = 32ull * static_cast<uint64_t>(store_.plinko.blocks());
    return hints + keys;
}

uint64_t MpraqClient::client_sim_bytes() const {
    // **仅单机仿真**的额外常驻（真实部署不需要）。逐项对应 `init.hpp` 的成员声明。
    const uint64_t words = 16ull * static_cast<uint64_t>(plain_words_.size());
    const uint64_t shares = 16ull * static_cast<uint64_t>(feature_share0_.size()) +
                            16ull * static_cast<uint64_t>(feature_share1_.size());
    const uint64_t tags = 16ull * static_cast<uint64_t>(tag_share0_.size()) +
                          16ull * static_cast<uint64_t>(tag_share1_.size());
    uint64_t attrs = 8ull * static_cast<uint64_t>(plain_features_.size());
    for (const auto& col : plain_attrs_) attrs += 8ull * static_cast<uint64_t>(col.size());
    for (const auto& v : attr_share0_) attrs += 16ull * static_cast<uint64_t>(v.size());
    for (const auto& v : attr_share1_) attrs += 16ull * static_cast<uint64_t>(v.size());
    return words + shares + tags + attrs;
}
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

uint64_t MpraqClient::EntryIndex(uint32_t attr_id, uint32_t column) const {
    // ⚠️ 唯一入口：**一列 = 一个条目**，条目号就是全局列号。
    return store_.EntryIndex(attr_id, column);
}

uint64_t MpraqClient::GlobalEntryIndex(size_t global_column) const {
    return store_.EntryIndex(global_column);
}

std::vector<uint8_t> MpraqClient::PlainColumnBits(uint32_t attr_id, uint32_t column) const {
    // 不变量 I3：只暴露**恰好 n 个有效 bit**（尾部填充位绝不外泄）。
    const uint64_t entry = store_.EntryIndex(attr_id, column);
    const uint128_t* words = plain_words_.data() + static_cast<size_t>(entry) * store_.entry_words;
    std::vector<uint8_t> bits(store_.n, 0);
    for (size_t j = 0; j < store_.n; ++j) {
        bits[j] = static_cast<uint8_t>((words[j / 128] >> (j % 128)) & 1u);
    }
    return bits;
}

// ---------------------------------------------------------------------------
// 查询：QueryGen → 两台 ServerResp → XorAnswers → ClientRecon
// ---------------------------------------------------------------------------

MpraqQueryBatch MpraqClient::CreateQueries(const std::vector<ColumnEntry>& targets) {
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
    for (const ColumnEntry& t : targets) {
        // ⚠️ 唯一的条目号算法：**一列 = 一个条目**，条目号 = 全局列号
        flats.push_back(store_.EntryIndex(t.attr_id, t.column));
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
    // ⚠️ **一次列查询 = 1 个查询集**（一个条目 = 一整列），不再有 word 维度的展开。
    std::vector<ColumnEntry> targets;
    targets.push_back(ColumnEntry{attr_id, column});
    return CreateQueries(targets);
}

// 两条路径共用的**客户端本地**收尾：两台应答 XOR 起来 → `ClientRecon`。
// ⊕ 与 XOR 共享线性相容（D12/D3）⇒ 合并后的应答就是明文应答。
// （作为 `MpraqClient` 的成员以访问 `MpraqQuery` 的私有字段；不产生任何通道调用。）
// xmac 的纯校验：`M_b = γ ⊙ R_b` 逐 chunk 成立，否则抛。
// 论文 :243-245（合并式）与 :296（`ClientRecon` 里的检查）；安全界见 Lemma `lem:pir`：
// `Pr[accept ∧ δ_b ≠ 0] ≤ 1/(2^128 − 1)`。
//
// ⚠️ 三条**必须**的拒绝（任何一条缺失都会静默丢掉 xmac 的保护）：
//   ① 半诚实档调用它 ⇒ 拒绝（该档没有 γ，也没有 tag）；
//   ② 恶意档收到**空 tag** ⇒ 拒绝（绝不降级为"只校验数据"）；
//   ③ tag 宽度 ≠ 数据宽度 ⇒ 拒绝（不变量 I5）。
void MpraqClient::VerifyXmacOrThrow(const PlinkoAnswer& merged, uint8_t b) const {
    if (!store_.has_tags()) {
        throw std::logic_error(
            "MpraqClient::VerifyXmacOrThrow: 本客户端是半诚实档（不生成 γ、不校验 tag）"
            "—— 调用它是逻辑错误，绝不静默返回");
    }
    if (b > 1) {
        throw std::invalid_argument("MpraqClient::VerifyXmacOrThrow: 侧位 b 必须是 0 或 1");
    }
    const PlinkoEntry& r_b = (b == 0) ? merged.r0 : merged.r1;
    const PlinkoEntry& m_b = (b == 0) ? merged.m0 : merged.m1;
    if (m_b.empty()) {
        throw std::runtime_error(
            "MpraqClient: 恶意档下服务器**没有返回 tag** —— 拒绝（绝不降级为『只校验数据』）；"
            "说明对端按半诚实档应答或实现不一致");
    }
    if (m_b.size() != r_b.size()) {
        throw std::runtime_error(
            "MpraqClient: tag 宽度与数据宽度不一致（M_b=" + Num(m_b.size()) +
            " vs R_b=" + Num(r_b.size()) + "）—— 不变量 I5 被破坏");
    }
    for (size_t j = 0; j < r_b.size(); ++j) {
        if (m_b[j] != Gf128Mul(tag_key_, r_b[j])) {
            throw std::runtime_error(
                "MpraqClient: PIR 应答的 xmac 校验失败（第 " + Num(j) +
                " 个 chunk：M != γ⊙R）—— abort 当前查询"
                "（论文 :296：M_b = γ ⊙ R_b 不成立即拒绝；安全界 1/(2^128−1)）");
        }
    }
    ++tag_checks_;
}

PlinkoEntry MpraqClient::FinishOne(MpraqQuery& q, const PlinkoAnswer& a0,
                                  const PlinkoAnswer& a1) {
    q.answer0_ = a0;
    q.answer1_ = a1;
    q.answer_ = PlinkoClient::XorAnswers(a0, a1);   // 顺带校验两台的 tag 字段有无一致

    // ---------- xmac：逐 chunk 校验 `M_b = γ ⊙ R_b`（论文 :243-245 / :296）----------
    // ⚠️ **必须在 `ClientRecon` 之前**：先验后取 ⇒ 被篡改的应答**绝不会**被当成明文值，
    //    而且 hint 不会被消费掉（失败即 abort 当前查询）。
    // ⚠️ **校验放在应用层**（负责人批注 3）：`pir/plinko` 保持为可独立测试的检索底座，
    //    不依赖"安全档 + γ"。论文 :296 说的 "inside ClientRecon" 是**表述**差异，
    //    语义完全一致（同一条检查、同一个位置在流水线上）。
    // ⚠️ **按档位决定是否校验**：半诚实档不走校验路径（该档不生成 γ、也不该有 tag）。
    //    `VerifyXmacOrThrow` 自身对半诚实档是**拒绝**的（防误用），所以这里必须先判档位 ——
    //    漏掉这个 `if` 会让整个半诚实流程直接抛异常（重构时踩过，被
    //    `XmacRejectsTamperedAnswers` 的第 ③ 例当场抓到）。
    if (store_.has_tags()) {
        VerifyXmacOrThrow(q.answer_, q.handle_.b);
    }

    q.value_ = plinko_->ClientRecon(q.handle_, q.answer_);
    q.answered_ = true;
    return q.value_;
}

PlinkoEntry MpraqClient::RunQuery(MpraqQuery& q) {
    // **单条**路径：1 个查询集 ⇒ 1 次标量 `ServerResp`（= 1 次往返）。
    // 标量语义正是"只有一条查询"的退化解，因此这里**不**套用批量接口。
    const uint64_t rb0 = channels_[0]->recv_bytes();
    const uint64_t rb1 = channels_[1]->recv_bytes();
    const PlinkoAnswer a0 = channels_[0]->ServerResp(q.query_);
    const PlinkoAnswer a1 = channels_[1]->ServerResp(q.query_);
    server_recv_bytes_[0] += channels_[0]->recv_bytes() - rb0;
    server_recv_bytes_[1] += channels_[1]->recv_bytes() - rb1;
    ++server_resp_calls_[0];
    ++server_resp_calls_[1];
    ++server_resp_queries_[0];
    ++server_resp_queries_[1];
    return FinishOne(q, a0, a1);
}

std::vector<PlinkoEntry> MpraqClient::RunBatch(MpraqQueryBatch& batch) {
    if (batch.owner_ != this) {
        throw std::invalid_argument(
            "MpraqClient::RunBatch: 该批次不属于本客户端（跨客户端复用会读错 hint 表）");
    }
    if (batch.queries_.empty()) {
        throw std::invalid_argument("MpraqClient::RunBatch: 批次不能为空");
    }
    // ⚠️ **Q5 / MPRAQ_IMPL.md §3**：整批查询集走每台服务器的**一次** `ServerRespBatch`
    //    ⇒ 远程部署下一次 `AggQuery`（任意多少列）的网络往返数恒为 **1**。
    //    逐条调用 `ServerResp` 会让"每列 1 个查询集"退化成"每列 1 次 RPC"。
    std::vector<PlinkoQuery> wire;
    wire.reserve(batch.queries_.size());
    for (const MpraqQuery& q : batch.queries_) wire.push_back(q.query_);

    // 两台服务器各自在**本方 XOR 共享**上应答（服务器之间零通信）
    const uint64_t rb0 = channels_[0]->recv_bytes();
    const uint64_t rb1 = channels_[1]->recv_bytes();
    const std::vector<PlinkoAnswer> ans0 = channels_[0]->ServerRespBatch(wire);
    const std::vector<PlinkoAnswer> ans1 = channels_[1]->ServerRespBatch(wire);
    server_recv_bytes_[0] += channels_[0]->recv_bytes() - rb0;
    server_recv_bytes_[1] += channels_[1]->recv_bytes() - rb1;
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
    std::vector<PlinkoEntry> out;
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
    if (record >= store_.n) {
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
    s.recv_bytes = server_recv_bytes_[server_id];
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
