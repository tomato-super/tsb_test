#pragma once

// 数据库表抽象。
//
// 设计依据（VMPQ 论文 §V-A）：服务器为每张 one-hot 索引表存储
// `|κ| · N · 2^l` 的共享，即**每个 (行, 列) 单元是一个 128 位环元素**。
// PIR 检索的单位是**一列**（长度 N 的向量），而不是单单一个标量。
//
// 因此本模块把"表"建模为：
//   * 一个扁平的环元素数组（存储）
//   * 一组形状参数（行数 window_size、列数）
//   * 按 (行, 列) 与按列的访问器
//
// 本模块**只做存储与整形，不含协议语义**（决策 D10：底座对未定设计保持中立）。
// 具体的编码方式（one-hot / LCTE）由上层协议模块负责，这里只提供
// 两种布局的便捷视图与编码辅助函数。

#include <cstdint>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/field.hpp"
#include "shared/secret_sharing.hpp"

namespace tsb {

// ---------------------------------------------------------------------------
// 表参数
// ---------------------------------------------------------------------------

// one-hot 索引表：N 行 × num_bucket 列
struct OneHotParams {
    uint32_t window_size = 0;  // 行数 N
    uint32_t num_bucket = 0;   // 列数 2^l
};

// LCTE 编码表：N 条记录 × m 列（m = |R|，编码范围大小）
//
// 阈值集合（论文 §Left-Threshold Cumulative Encoding）：
//   R = {r_1, ..., r_m}，本文取 **单位间隔的连续整数**
//   R = {r_min, r_min+1, ..., r_min+m-1}。
// 1-based 的 r_i = range_min + i - 1，等价说法：
//   **0-based 列索引 i 对应的阈值是 range_min + i**。
struct LcteParams {
    uint32_t window_size = 0;  // 记录数 N（LcteEncode 本身不依赖它，供上层整形/校验用）
    uint32_t range_size = 0;   // 列数 m = |R|
    int64_t range_min = 0;     // 阈值集合左端点 r_min（R 的最小元素）
};

// ---------------------------------------------------------------------------
// 明文表（客户端侧，用于编码与验证）
// ---------------------------------------------------------------------------

class PlainTable {
public:
    PlainTable() = default;
    explicit PlainTable(size_t num_columns, size_t num_rows = 0);

    // 列数 = 每条记录的向量长度
    size_t num_columns() const { return num_columns_; }
    size_t num_rows() const { return num_rows_; }
    size_t num_elements() const { return data_.size(); }

    // 追加一行（长度必须等于 num_columns）
    void AppendRow(const std::vector<uint128_t>& row);

    // 设置/读取某个单元
    void Set(size_t row, size_t col, uint128_t v);
    uint128_t At(size_t row, size_t col) const;

    // 取整列（PIR 检索单位）
    std::vector<uint128_t> Column(size_t col) const;

    // 取整列按位 XOR（V-OO-PIR 的列 parity）
    uint128_t ColumnXor(size_t col) const;

    // 清空数据但保留形状
    void ClearRows();

    const std::vector<uint128_t>& raw() const { return data_; }

private:
    size_t Index(size_t row, size_t col) const;
    size_t num_columns_ = 0;
    size_t num_rows_ = 0;
    std::vector<uint128_t> data_;
};

// ---------------------------------------------------------------------------
// 单台服务器持有的表（共享形式）
// ---------------------------------------------------------------------------

class ShareTable {
public:
    ShareTable() = default;
    explicit ShareTable(size_t num_columns, size_t num_rows = 0);

    size_t num_columns() const { return num_columns_; }
    size_t num_rows() const { return num_rows_; }
    size_t num_elements() const { return data_.size(); }

    void AppendRow(const std::vector<RingShare>& row);
    void Set(size_t row, size_t col, const RingShare& v);
    const RingShare& At(size_t row, size_t col) const;

    // 取整列的共享（PIR 的 entry）
    std::vector<RingShare> Column(size_t col) const;

    // 服务器侧对整列做 XOR 累加（ServerResp 的核心原语）。
    //
    // ⚠️ **语义前提**：本操作只有在 entry 采用 **XOR 共享**时才与客户端侧的
    // XOR 重建相容。若 entry 是 Z_{2^128} 的**加法**共享，则
    //     (a⊕b) + ((s−a)⊕(t−b)) ≠ s⊕t
    // 两服务器的 XOR 结果无法重建明文。即：凡 parity 语义为 ⊕ 的数据，
    // 必须用 XOR 共享承载（等价于 Z_2 上的加法共享，取值仅 0/1）。
    //
    // 详见 doc/design/PIR_SPEC.md §4.2 与 TASK_PLAN 决策 D3；
    // 正反两面的测试见 tests/test_database.cpp 的
    //   XorDoesNotCommuteWithAdditiveShares /
    //   ColumnXorWorksWhenEntriesAreXorShared。
    RingShare ColumnXor(size_t col) const;

    void ClearRows();

    const std::vector<RingShare>& raw() const { return data_; }

private:
    size_t Index(size_t row, size_t col) const;
    size_t num_columns_ = 0;
    size_t num_rows_ = 0;
    std::vector<RingShare> data_;
};

// 把一个明文表共享成两台服务器的共享表
std::pair<ShareTable, ShareTable> ShareTableSplit(const PlainTable& plain);

// 由两台服务器的共享重建明文
PlainTable ReconstructTable(const ShareTable& a, const ShareTable& b);

// ---------------------------------------------------------------------------
// 多表数据库
// ---------------------------------------------------------------------------

class ShareDatabase {
public:
    // 创建（或重置）一张表。table_id 已存在时覆盖。
    void CreateTable(const std::string& table_id, size_t num_columns,
                     size_t num_rows = 0);

    bool HasTable(const std::string& table_id) const;
    ShareTable& Table(const std::string& table_id);
    const ShareTable& Table(const std::string& table_id) const;

    std::vector<std::string> TableIds() const;
    size_t NumTables() const { return tables_.size(); }

    // 删除全部表
    void Clear();

    // 总元素数（用于存储开销统计，对应论文 Table I 的存储分析）
    size_t TotalElements() const;

private:
    std::unordered_map<std::string, ShareTable> tables_;
};

// ---------------------------------------------------------------------------
// 编码辅助（两个协议共用）
// ---------------------------------------------------------------------------

// one-hot 行向量：第 onehot_index 位为 1，其余为 0。
// onehot_index >= num_bucket 时抛 std::out_of_range。
std::vector<uint128_t> MakeOneHotRow(uint64_t onehot_index, uint32_t num_bucket);

// 把一批取值编码成 one-hot 表的扁平数据（行优先）
std::vector<uint128_t> EncodeOneHotRows(const std::vector<uint64_t>& values,
                                        uint32_t num_bucket);

// LCTE 编码（论文 §Left-Threshold Cumulative Encoding）：
//   LCTE(x) = ([x < r_1], [x < r_2], ..., [x < r_m])
// 其中 1-based 的 r_i = range_min + i - 1，即 **0-based 列索引 i 的阈值为
// range_min + i**，阈值集合 R = {range_min, ..., range_min + m - 1}。
//
// 边界语义（直接由 Iverson 括号 [·] 给出）：
//   * x <  range_min          ⇒ 全 1（每一列都满足 x < r_i）
//   * x == range_min          ⇒ 第 0 列为 0，其余为 1
//   * x >= range_min + m - 1  ⇒ 全 0（即 x >= r_m，没有任何列满足）
//
// 单调性：列索引递增 ⇒ 阈值递增 ⇒ `x < r_i` 越来越难成立，
// 因此行向量形如 `0...01...1`（关于列索引**非减**）；
// 等价地，随 x 增大，1 的位置整体左移（每个分量关于 x 非增）。
//
// ⚠️ 历史缺陷已修正：本函数此前用 `range_min + i + 1` 作为第 i 列的阈值，
// 与论文的 R = {r_min, ..., r_min+m-1} 相比**整体偏移了 1**，
// 导致 x = r_min 时错误地给出全 1、x = r_max 的判定点也整体右移。
std::vector<uint128_t> LcteEncode(int64_t x, const LcteParams& params);

// 把一批取值编码成 LCTE 表的扁平数据（行优先）
std::vector<uint128_t> EncodeLcteRows(const std::vector<int64_t>& values,
                                      const LcteParams& params);

// 把 bool 向量打包成 128 位元素（用于需要按位存储的场景）
std::vector<uint128_t> PackBitsToRing(const std::vector<uint8_t>& bits);
std::vector<uint8_t> UnpackRingToBits(const std::vector<uint128_t>& words,
                                      size_t num_bits);

}  // namespace tsb
