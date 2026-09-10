#include "shared/database.hpp"
#include "test_framework.hpp"

#include <stdexcept>
#include <vector>

using namespace tsb;

namespace {

std::vector<uint128_t> Row(std::initializer_list<uint64_t> vals) {
    std::vector<uint128_t> r;
    for (uint64_t v : vals) r.push_back(static_cast<uint128_t>(v));
    return r;
}

PlainTable MakeSampleTable(size_t rows, size_t cols) {
    PlainTable t(cols);
    for (size_t r = 0; r < rows; ++r) {
        std::vector<uint128_t> row(cols);
        for (size_t c = 0; c < cols; ++c) {
            row[c] = static_cast<uint128_t>(r * 100 + c + 1);
        }
        t.AppendRow(row);
    }
    return t;
}

}  // namespace

// ---------------------------------------------------------------------------
// PlainTable
// ---------------------------------------------------------------------------

TEST(PlainTable, ConstructsWithShape) {
    PlainTable t(4, 3);
    EXPECT_EQ(t.num_columns(), static_cast<size_t>(4));
    EXPECT_EQ(t.num_rows(), static_cast<size_t>(3));
    EXPECT_EQ(t.num_elements(), static_cast<size_t>(12));
    // 初始为全 0
    for (size_t r = 0; r < 3; ++r) {
        for (size_t c = 0; c < 4; ++c) {
            EXPECT_EQ(t.At(r, c), static_cast<uint128_t>(0));
        }
    }
}

TEST(PlainTable, AppendRowAndReadBack) {
    PlainTable t(3);
    t.AppendRow(Row({1, 2, 3}));
    t.AppendRow(Row({4, 5, 6}));
    EXPECT_EQ(t.num_rows(), static_cast<size_t>(2));
    EXPECT_EQ(t.At(0, 0), static_cast<uint128_t>(1));
    EXPECT_EQ(t.At(0, 2), static_cast<uint128_t>(3));
    EXPECT_EQ(t.At(1, 0), static_cast<uint128_t>(4));
    EXPECT_EQ(t.At(1, 2), static_cast<uint128_t>(6));
}

TEST(PlainTable, AppendRejectsWrongLength) {
    PlainTable t(3);
    EXPECT_THROW(t.AppendRow(Row({1, 2})), std::invalid_argument);
    EXPECT_THROW(t.AppendRow(Row({1, 2, 3, 4})), std::invalid_argument);
}

TEST(PlainTable, AccessOutOfRangeThrows) {
    const PlainTable t = MakeSampleTable(2, 3);
    EXPECT_THROW(t.At(2, 0), std::out_of_range);
    EXPECT_THROW(t.At(0, 3), std::out_of_range);
    EXPECT_THROW(t.Column(3), std::out_of_range);
    EXPECT_THROW(t.ColumnXor(3), std::out_of_range);
    // Set 是非 const 操作，单独用可写对象测试
    PlainTable w = MakeSampleTable(2, 3);
    EXPECT_THROW(w.Set(5, 0, 1), std::out_of_range);
    EXPECT_THROW(w.Set(0, 9, 1), std::out_of_range);
    // 合法写入应当生效
    w.Set(1, 2, 777);
    EXPECT_EQ(w.At(1, 2), static_cast<uint128_t>(777));
}

TEST(PlainTable, ColumnExtractsCorrectEntries) {
    const PlainTable t = MakeSampleTable(4, 3);
    // 行 r、列 c 的值 = r*100 + c + 1
    const auto col1 = t.Column(1);
    EXPECT_EQ(col1.size(), static_cast<size_t>(4));
    EXPECT_EQ(col1[0], static_cast<uint128_t>(2));
    EXPECT_EQ(col1[1], static_cast<uint128_t>(102));
    EXPECT_EQ(col1[2], static_cast<uint128_t>(202));
    EXPECT_EQ(col1[3], static_cast<uint128_t>(302));
}

TEST(PlainTable, ColumnXorMatchesManualXor) {
    const PlainTable t = MakeSampleTable(5, 4);
    for (size_t c = 0; c < 4; ++c) {
        uint128_t expected = 0;
        for (size_t r = 0; r < 5; ++r) {
            expected = static_cast<uint128_t>(expected ^ t.At(r, c));
        }
        EXPECT_EQ(t.ColumnXor(c), expected);
    }
}

TEST(PlainTable, OneHotColumnXorRevealsCount) {
    // one-hot 表的关键性质：某列的 XOR 等于"该列被置 1 的行数"的奇偶性
    const uint32_t num_bucket = 4;
    const std::vector<uint64_t> values = {1, 1, 3, 1, 0};  // 列 1 出现 3 次（奇）
    const auto flat = EncodeOneHotRows(values, num_bucket);
    PlainTable t(num_bucket);
    for (size_t r = 0; r < values.size(); ++r) {
        std::vector<uint128_t> row(num_bucket);
        for (uint32_t c = 0; c < num_bucket; ++c) row[c] = flat[r * num_bucket + c];
        t.AppendRow(row);
    }
    EXPECT_EQ(t.ColumnXor(1), static_cast<uint128_t>(1));  // 3 次 -> 奇
    EXPECT_EQ(t.ColumnXor(3), static_cast<uint128_t>(1));  // 1 次 -> 奇
    EXPECT_EQ(t.ColumnXor(0), static_cast<uint128_t>(1));  // 1 次 -> 奇
    EXPECT_EQ(t.ColumnXor(2), static_cast<uint128_t>(0));  // 0 次 -> 偶
}

TEST(PlainTable, ClearRowsKeepsShape) {
    PlainTable t = MakeSampleTable(3, 2);
    t.ClearRows();
    EXPECT_EQ(t.num_rows(), static_cast<size_t>(0));
    EXPECT_EQ(t.num_columns(), static_cast<size_t>(2));
    // 清空后仍可继续追加
    t.AppendRow(Row({7, 8}));
    EXPECT_EQ(t.num_rows(), static_cast<size_t>(1));
}

// ---------------------------------------------------------------------------
// ShareTable 与重建
// ---------------------------------------------------------------------------

TEST(ShareTable, SplitAndReconstructRoundTrip) {
    const PlainTable plain = MakeSampleTable(6, 5);
    auto [a, b] = ShareTableSplit(plain);
    EXPECT_EQ(a.num_rows(), plain.num_rows());
    EXPECT_EQ(a.num_columns(), plain.num_columns());
    EXPECT_EQ(b.num_rows(), plain.num_rows());

    const PlainTable back = ReconstructTable(a, b);
    for (size_t r = 0; r < plain.num_rows(); ++r) {
        for (size_t c = 0; c < plain.num_columns(); ++c) {
            EXPECT_EQ(back.At(r, c), plain.At(r, c));
        }
    }
}

TEST(ShareTable, SingleShareDiffersFromPlaintext) {
    const PlainTable plain = MakeSampleTable(3, 3);
    auto [a, b] = ShareTableSplit(plain);
    bool any_different = false;
    for (size_t r = 0; r < 3; ++r) {
        for (size_t c = 0; c < 3; ++c) {
            if (a.At(r, c).value != plain.At(r, c)) any_different = true;
        }
    }
    EXPECT_TRUE(any_different);
    // 两个共享不应相同
    EXPECT_NE(a.At(0, 0).value, b.At(0, 0).value);
}

TEST(ShareTable, XorDoesNotCommuteWithAdditiveShares) {
    // ⚠️ 重要事实：Z_{2^128} 的**加法**共享不保持 XOR 同态。
    // 记共享为 (a, s-a) 与 (b, t-b)，则
    //     (a XOR b) + ((s-a) XOR (t-b)) != s XOR t
    // 因此"服务器各自对列做 XOR、客户端再 XOR 两半"这条路径**只对
    // XOR 共享成立**，对 RingShare（加法共享）不成立。
    //
    // 这对协议设计是硬约束：V-OO-PIR 的 parity 语义是 ⊕，
    // 所以参与列 parity 的数据必须用 **XOR 共享**（等价于 Z_2 上的加法共享）。
    // 见 doc/design/PIR_SPEC.md §4.2 与 TASK_PLAN 决策 D3。
    const PlainTable plain = MakeSampleTable(6, 3);
    auto [a, b] = ShareTableSplit(plain);
    for (size_t c = 0; c < 3; ++c) {
        const uint128_t combined =
            static_cast<uint128_t>(a.ColumnXor(c).value ^ b.ColumnXor(c).value);
        EXPECT_NE(combined, plain.ColumnXor(c));
    }
}

TEST(ShareTable, ColumnXorWorksWhenEntriesAreXorShared) {
    // 正确路径：用 XOR 共享（即 Z_2 上的加法共享，值域只取 0/1）时，
    // 服务器各自 XOR、客户端再 XOR，恰好重建明文列的 XOR。
    // 这正是 V-OO-PIR 的工作方式。
    const size_t rows = 50;
    const size_t cols = 2;
    PlainTable plain(cols);
    for (size_t r = 0; r < rows; ++r) {
        std::vector<uint128_t> row(cols);
        for (size_t c = 0; c < cols; ++c) {
            row[c] = static_cast<uint128_t>((r * 7 + c * 3) % 2);  // 单比特
        }
        plain.AppendRow(row);
    }

    // 用 XOR 共享构造两台服务器的表
    ShareTable a(cols), b(cols);
    for (size_t r = 0; r < rows; ++r) {
        std::vector<RingShare> ra(cols), rb(cols);
        for (size_t c = 0; c < cols; ++c) {
            const uint8_t bit = static_cast<uint8_t>(plain.At(r, c) & 1u);
            auto [sa, sb] = ShareXorBit(bit);
            ra[c] = RingShare{sa.value};
            rb[c] = RingShare{sb.value};
        }
        a.AppendRow(ra);
        b.AppendRow(rb);
    }

    for (size_t c = 0; c < cols; ++c) {
        const uint128_t combined =
            static_cast<uint128_t>(a.ColumnXor(c).value ^ b.ColumnXor(c).value);
        EXPECT_EQ(combined, plain.ColumnXor(c));
    }

    // 注意：这里 entry 是 XOR 共享，所以重建也必须用 XOR，不能调用
    // ReconstructTable（那是加法共享的重建，会得到 2 倍的值）。
    for (size_t r = 0; r < rows; ++r) {
        for (size_t c = 0; c < cols; ++c) {
            const uint128_t back = static_cast<uint128_t>(a.At(r, c).value ^
                                                          b.At(r, c).value);
            EXPECT_EQ(back, plain.At(r, c));
        }
    }
}

TEST(ShareTable, ColumnExtractsShares) {
    const PlainTable plain = MakeSampleTable(4, 3);
    auto [a, b] = ShareTableSplit(plain);
    const auto col = a.Column(2);
    EXPECT_EQ(col.size(), static_cast<size_t>(4));
    for (size_t r = 0; r < 4; ++r) {
        EXPECT_EQ(col[r].value, a.At(r, 2).value);
    }
    EXPECT_THROW(a.Column(3), std::out_of_range);
}

TEST(ShareTable, ReconstructRejectsShapeMismatch) {
    PlainTable p1 = MakeSampleTable(3, 2);
    PlainTable p2 = MakeSampleTable(4, 2);
    auto [a1, b1] = ShareTableSplit(p1);
    auto [a2, b2] = ShareTableSplit(p2);
    EXPECT_THROW(ReconstructTable(a1, b2), std::invalid_argument);
}

TEST(ShareTable, AppendRowSharesIndependently) {
    ShareTable t(2);
    t.AppendRow({RingShare{10}, RingShare{20}});
    t.AppendRow({RingShare{30}, RingShare{40}});
    EXPECT_EQ(t.num_rows(), static_cast<size_t>(2));
    EXPECT_EQ(t.At(1, 0).value, static_cast<uint128_t>(30));
    EXPECT_EQ(t.At(1, 1).value, static_cast<uint128_t>(40));
    EXPECT_THROW(t.AppendRow({RingShare{1}}), std::invalid_argument);
}

// ---------------------------------------------------------------------------
// ShareDatabase
// ---------------------------------------------------------------------------

TEST(ShareDatabase, CreateAndLookupTables) {
    ShareDatabase db;
    EXPECT_FALSE(db.HasTable("t1"));
    db.CreateTable("t1", 4, 2);
    EXPECT_TRUE(db.HasTable("t1"));
    EXPECT_EQ(db.NumTables(), static_cast<size_t>(1));
    EXPECT_EQ(db.Table("t1").num_columns(), static_cast<size_t>(4));
    EXPECT_EQ(db.Table("t1").num_rows(), static_cast<size_t>(2));

    db.CreateTable("t2", 3);
    EXPECT_EQ(db.NumTables(), static_cast<size_t>(2));
    const auto ids = db.TableIds();
    EXPECT_EQ(ids.size(), static_cast<size_t>(2));
    // 排序保证可复现
    EXPECT_EQ(ids[0], std::string("t1"));
    EXPECT_EQ(ids[1], std::string("t2"));
}

TEST(ShareDatabase, MissingTableThrows) {
    ShareDatabase db;
    EXPECT_THROW(db.Table("nope"), std::out_of_range);
}

TEST(ShareDatabase, CreateTableOverwrites) {
    ShareDatabase db;
    db.CreateTable("t", 4, 2);
    db.CreateTable("t", 8, 5);
    EXPECT_EQ(db.Table("t").num_columns(), static_cast<size_t>(8));
    EXPECT_EQ(db.Table("t").num_rows(), static_cast<size_t>(5));
    EXPECT_EQ(db.NumTables(), static_cast<size_t>(1));
}

TEST(ShareDatabase, TotalElementsSumsAllTables) {
    ShareDatabase db;
    db.CreateTable("t1", 4, 3);   // 12
    db.CreateTable("t2", 2, 5);   // 10
    EXPECT_EQ(db.TotalElements(), static_cast<size_t>(22));
    db.Clear();
    EXPECT_EQ(db.NumTables(), static_cast<size_t>(0));
    EXPECT_EQ(db.TotalElements(), static_cast<size_t>(0));
}

TEST(ShareDatabase, ModelsVmpqStorageLayout) {
    // 论文 §V-A：每张 one-hot 表 N × 2^l 个 128 位元素
    const uint32_t window_size = 16;
    const uint32_t num_bucket = 8;  // 2^3
    const PlainTable plain(num_bucket);
    PlainTable mutable_plain = plain;
    for (uint32_t r = 0; r < window_size; ++r) {
        mutable_plain.AppendRow(MakeOneHotRow(r % num_bucket, num_bucket));
    }
    auto [a, b] = ShareTableSplit(mutable_plain);

    ShareDatabase db0, db1;
    db0.CreateTable("attr0", num_bucket);
    db1.CreateTable("attr0", num_bucket);
    for (uint32_t r = 0; r < window_size; ++r) {
        std::vector<RingShare> row0(num_bucket), row1(num_bucket);
        for (uint32_t c = 0; c < num_bucket; ++c) {
            row0[c] = a.At(r, c);
            row1[c] = b.At(r, c);
        }
        db0.Table("attr0").AppendRow(row0);
        db1.Table("attr0").AppendRow(row1);
    }
    // 元素数 = 2 * N * 2^l（两服务器合计，对应论文的 |κ|·(N + N·2^l)）
    EXPECT_EQ(db0.TotalElements(), static_cast<size_t>(window_size * num_bucket));
    EXPECT_EQ(db1.TotalElements(), static_cast<size_t>(window_size * num_bucket));
}

// ---------------------------------------------------------------------------
// one-hot 编码
// ---------------------------------------------------------------------------

TEST(Encoding, OneHotRowHasExactlyOneSetBit) {
    const uint32_t nb = 5;
    for (uint32_t v = 0; v < nb; ++v) {
        const auto row = MakeOneHotRow(v, nb);
        EXPECT_EQ(row.size(), static_cast<size_t>(nb));
        for (uint32_t c = 0; c < nb; ++c) {
            EXPECT_EQ(row[c], c == v ? static_cast<uint128_t>(1) : static_cast<uint128_t>(0));
        }
    }
}

TEST(Encoding, OneHotRejectsOutOfRange) {
    EXPECT_THROW(MakeOneHotRow(4, 4), std::out_of_range);
    EXPECT_THROW(MakeOneHotRow(100, 8), std::out_of_range);
}

TEST(Encoding, OneHotRowsFlatLayoutIsRowMajor) {
    const auto flat = EncodeOneHotRows({1, 0}, 3);
    EXPECT_EQ(flat.size(), static_cast<size_t>(6));
    // 行 0 -> 列 1
    EXPECT_EQ(flat[0], static_cast<uint128_t>(0));
    EXPECT_EQ(flat[1], static_cast<uint128_t>(1));
    EXPECT_EQ(flat[2], static_cast<uint128_t>(0));
    // 行 1 -> 列 0
    EXPECT_EQ(flat[3], static_cast<uint128_t>(1));
    EXPECT_EQ(flat[4], static_cast<uint128_t>(0));
    EXPECT_EQ(flat[5], static_cast<uint128_t>(0));
}

// ---------------------------------------------------------------------------
// LCTE 编码
// ---------------------------------------------------------------------------

TEST(Encoding, LcteBasicThresholds) {
    // 修正后的论文口径：R = {r_min, ..., r_min+m-1}，
    // 0-based 列索引 i 的阈值 = r_min + i。
    // 取 range_min = 10, range_size = 5 ⇒ R = {10, 11, 12, 13, 14}
    // （r_1 = 10 = r_min，r_m = 14 = r_min + m - 1）。
    //
    // ⚠️ 注意参数选取的变化：这里刻意让 range_min 就等于 R 的最小元素，
    // 以固化"第 0 列阈值 = range_min"（旧实现是 range_min + 1）。
    LcteParams p;
    p.range_size = 5;
    p.range_min = 10;

    // x = 9 (< r_min): 9 < 10,11,12,13,14 全部为真 -> 全 1
    const auto v9 = LcteEncode(9, p);
    for (auto b : v9) EXPECT_EQ(b, static_cast<uint128_t>(1));

    // x = 10 (= r_min = 第 0 列的阈值):
    //   10<10 假; 10<11,12,13,14 真 -> {0,1,1,1,1}
    // （旧实现下这里会错误地给出全 1，正是被修正的偏移 1 缺陷）
    const auto v10 = LcteEncode(10, p);
    EXPECT_EQ(v10[0], static_cast<uint128_t>(0));
    EXPECT_EQ(v10[1], static_cast<uint128_t>(1));
    EXPECT_EQ(v10[2], static_cast<uint128_t>(1));
    EXPECT_EQ(v10[3], static_cast<uint128_t>(1));
    EXPECT_EQ(v10[4], static_cast<uint128_t>(1));

    // x = 11 (= 第 1 列的阈值): 11<10,11 假; 11<12,13,14 真 -> {0,0,1,1,1}
    const auto v11 = LcteEncode(11, p);
    EXPECT_EQ(v11[0], static_cast<uint128_t>(0));
    EXPECT_EQ(v11[1], static_cast<uint128_t>(0));
    EXPECT_EQ(v11[2], static_cast<uint128_t>(1));
    EXPECT_EQ(v11[3], static_cast<uint128_t>(1));
    EXPECT_EQ(v11[4], static_cast<uint128_t>(1));

    // x = 14 (= r_m = r_min + m - 1): 全部为假 -> 全 0
    const auto v14 = LcteEncode(14, p);
    for (auto b : v14) EXPECT_EQ(b, static_cast<uint128_t>(0));

    // x = 100: 超出范围右侧 -> 全 0
    const auto v100 = LcteEncode(100, p);
    for (auto b : v100) EXPECT_EQ(b, static_cast<uint128_t>(0));
}

TEST(Encoding, LcteIsMonotoneNonIncreasingInValue) {
    // 关于**取值**的单调性（论文："The monotonicity of the resulting vector
    // ... reflects the cumulative nature"）：
    //   x1 < x2  ⇒  LCTE(x1) 的每个分量 ≥ LCTE(x2) 的对应分量
    // 因为对每个固定阈值 r_i 都有 [x1 < r_i] ≥ [x2 < r_i]。
    // 等价说法：1 的位置随 x 增大而整体左移。
    //
    // ⚠️ 原用例写的是"关于列索引"的形状检查，且判据 saw_one_to_zero 在合法的
    // 0...01...1 形状下恒为假，整段断言实际空转（方向也写反了：行向量关于列
    // 索引是**非减**的）。这里改为按取值域穷举、逐分量比较，属性才真正生效；
    // 列索引方向的形状断言见 LcteShapeIsPrefixOfZeros。
    LcteParams p;
    p.range_size = 8;
    p.range_min = 0;
    for (int64_t x1 = -3; x1 <= 9; ++x1) {
        for (int64_t x2 = x1 + 1; x2 <= 10; ++x2) {
            const auto a = LcteEncode(x1, p);
            const auto b = LcteEncode(x2, p);
            for (size_t i = 0; i < a.size(); ++i) {
                EXPECT_TRUE(a[i] >= b[i]);
            }
        }
    }
}

TEST(Encoding, LcteShapeIsPrefixOfZeros) {
    // 合法行的形状必然是 0...01...1：关于列索引 i **非减**（一旦变成 1 就不会
    // 再回到 0）。直观理解：阈值 r_i = range_min + i 随 i 递增，x < r_i 越来越
    // 容易成立，所以 0→1 只会发生一次。
    LcteParams p;
    p.range_size = 10;
    p.range_min = -5;  // 负数阈值：R = {-5, -4, ..., 4}
    for (int64_t x = -6; x <= 5; ++x) {
        const auto row = LcteEncode(x, p);
        bool seen_one = false;
        size_t ones = 0;
        for (auto b : row) {
            if (b == 1) {
                seen_one = true;
                ++ones;
            } else {
                EXPECT_FALSE(seen_one);  // 0 不能出现在 1 之后
            }
        }
        // 阈值 r_i = range_min + i（0-based 列索引 i），统计满足 x < r_i 的列数
        size_t expected_ones = 0;
        for (uint32_t i = 0; i < p.range_size; ++i) {
            if (x < p.range_min + static_cast<int64_t>(i)) ++expected_ones;
        }
        EXPECT_EQ(ones, expected_ones);
    }
    // 两侧边界的显式断言（x < r_min ⇒ 全 1；x >= r_max ⇒ 全 0）
    for (auto b : LcteEncode(-6, p)) EXPECT_EQ(b, static_cast<uint128_t>(1));
    for (auto b : LcteEncode(4, p)) EXPECT_EQ(b, static_cast<uint128_t>(0));
    for (auto b : LcteEncode(5, p)) EXPECT_EQ(b, static_cast<uint128_t>(0));
}

TEST(Encoding, LcteOneCountEqualsPosition) {
    // 对 x = r_k（1-based 的 r_k = range_min + k - 1），恰好有 (m - k) 个 1：
    // 列 i（0-based）的阈值是 range_min + i = r_{i+1}，x < r_{i+1} ⟺ i + 1 > k ⟺ i ≥ k。
    LcteParams p;
    p.range_size = 6;
    p.range_min = 100;  // 阈值集合 R = {100, 101, ..., 105}
    for (int64_t k = 1; k <= 6; ++k) {
        const int64_t x = p.range_min + (k - 1);  // = r_k
        const auto row = LcteEncode(x, p);
        size_t ones = 0;
        for (auto b : row) {
            if (b == 1) ++ones;
        }
        EXPECT_EQ(ones, static_cast<size_t>(6 - k));
    }
}

TEST(Encoding, LcteRowsFlatLayoutIsRowMajor) {
    LcteParams p;
    p.range_size = 2;
    p.range_min = 0;  // 阈值集合 R = {0, 1}（第 0 列阈值 0，第 1 列阈值 1）
    const auto flat = EncodeLcteRows({-1, 0, 1}, p);
    // x=-1 (< r_min): -1<0 真, -1<1 真 -> {1,1}
    // x= 0 (= r_min):  0<0 假,  0<1 真 -> {0,1}
    // x= 1 (= r_m):    1<0 假,  1<1 假 -> {0,0}
    EXPECT_EQ(flat.size(), static_cast<size_t>(6));
    EXPECT_EQ(flat[0], static_cast<uint128_t>(1));
    EXPECT_EQ(flat[1], static_cast<uint128_t>(1));
    EXPECT_EQ(flat[2], static_cast<uint128_t>(0));
    EXPECT_EQ(flat[3], static_cast<uint128_t>(1));
    EXPECT_EQ(flat[4], static_cast<uint128_t>(0));
    EXPECT_EQ(flat[5], static_cast<uint128_t>(0));
}

// ---------------------------------------------------------------------------
// 位打包
// ---------------------------------------------------------------------------

TEST(Encoding, BitPackingRoundTrip) {
    std::vector<uint8_t> bits(300);
    for (size_t i = 0; i < bits.size(); ++i) {
        bits[i] = static_cast<uint8_t>((i * 7 + 3) % 2);
    }
    const auto words = PackBitsToRing(bits);
    EXPECT_EQ(words.size(), (bits.size() + 127) / 128);
    const auto back = UnpackRingToBits(words, bits.size());
    EXPECT_EQ(back, bits);
}

TEST(Encoding, BitPackingHandlesEmpty) {
    const std::vector<uint8_t> empty;
    const auto words = PackBitsToRing(empty);
    EXPECT_EQ(words.size(), static_cast<size_t>(0));
    EXPECT_EQ(UnpackRingToBits(words, 0).size(), static_cast<size_t>(0));
}

TEST(Encoding, BitPackingBitOrder) {
    // 第 i 位应落在 word[i/128] 的第 (i%128) 位
    std::vector<uint8_t> bits(200, 0);
    bits[0] = 1;
    bits[127] = 1;
    bits[128] = 1;
    const auto words = PackBitsToRing(bits);
    EXPECT_EQ(words.size(), static_cast<size_t>(2));
    EXPECT_EQ(words[0], (static_cast<uint128_t>(1) << 127) | static_cast<uint128_t>(1));
    EXPECT_EQ(words[1], static_cast<uint128_t>(1));
}
