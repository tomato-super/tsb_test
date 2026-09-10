# `config/mpraq_scale.json` —— MPRAQ 规模配置（负责人只管三个量）

> JSON 本身不支持注释（`core/config.hpp` 用的是严格 JSON 解析器），
> 因此单位与约束写在**本文件**里；`mpraq_scale.json` 只有纯字段。

## 字段

| 字段 | 单位 / 含义 | 约束 |
|---|---|---|
| `rows` | **行数 = 记录数 `N`** | **必须是 2 的幂**（非 2 的幂 ⇒ 程序**拒绝**，不静默取整）；上限 `2^32−1` |
| `columns_per_attribute` | **列数 = 每个属性的 LCTE 区间长度（列数）** | **必须是 2 的幂**且 `>= 2`（取值域 = `[0, 列数−2]`，见下） |
| `attributes` | 属性数（每个属性**各自**一组列） | `>= 1` |
| `predicates` | **谓词数量 `k`**（谓词内容由程序自动生成） | `>= 1` |
| `lambda` | Plinko 的安全参数 λ（失败概率 `2^-λ`） | `>= 1`，默认 80 |
| `eps` | iPRF 的 PRP 目标 ε（决策 D22-1） | `(0, 1)`，默认 `1e-4` |
| `seed` | 合成数据与 `Init` 的确定性种子（铁律 D6） | 任意 `uint64`，默认 7 |

命令行**逐项覆盖**（不给 `--config` 时用本文件的同值默认值）：

```
--rows N            行数（记录数）
--columns C         列数（每属性 LCTE 列数）
--attributes A      属性数
--predicates K      谓词数
--lambda L --eps E --seed S
```

## 派生（全部由程序算，不写进配置）

```
L = ⌈N/128⌉                             每列 word 数
M = attributes × columns_per_attribute   真实列数（每个属性各自一组列）
m = 补齐到 2 的幂（含 D35 的 ×2 升级）    Plinko 的列数口径
n = m · L                                PIR 条目数（word 数，不是记录数）
去重列数 = min(k, M)                     每个谓词恰好归约到 1 列
查询集数 = 去重列数 × L
每台 RPC = 1                             一次 RunBatch ⇒ 一次 ServerRespBatch
服务器存储/台 = 16·m·L + 16·N·attributes   （双报：把 m 换成 M 即"不含补齐"口径）
q = λw/2（备份 hint）、n = m·L（新鲜索引池）⇒ L14 预算 = 去重列数 × L ≤ min(q, n)
```

超预算 / 非 2 的幂 / 未知字段 / 几何无解一律**可读报错并拒绝运行**（fail-loudly，绝不降级）。

## 示例

```bash
# 用文件里的规模
./build/bin/mpraq_client --server0 127.0.0.1:P0 --server1 127.0.0.1:P1 \
    --config config/mpraq_scale.json

# 只改三个量（其余仍按配置/默认）
./build/bin/mpraq_client --server0 127.0.0.1:P0 --server1 127.0.0.1:P1 \
    --config config/mpraq_scale.json --rows 2048 --columns 16 --predicates 5
```
