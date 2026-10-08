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
| `security_mode` | **运行方式（安全档位）** —— **接口预留**，见 `src/mpraq/security_mode.hpp` | `"malicious"`（默认）或 `"semi-honest"`；**严格解析**，其它值拒绝启动 |

命令行**逐项覆盖**（不给 `--config` 时用本文件的同值默认值）：

```
--rows N            行数（记录数）
--columns C         列数（每属性 LCTE 列数）
--attributes A      属性数
--predicates K      谓词数
--lambda L --eps E --seed S
--security-mode malicious|semi-honest
```

⚠️ **`security_mode` 的纪律**（D41 阶段的接口预留）：

* 键名是 **`security_mode`**，**不是** `mode` —— `bench_mpraq` 的 `--mode local|grpc` 已被"传输口径"占用，同名会造成本仓库最忌讳的口径混淆。
* 它随 `StoreParams` **上线**：服务器在 `InitTable` 里做**一致性校验**，客户端报的档位与本机不同就**拒绝装载**（fail-loudly）。这是唯一会**静默降级安全性**的失败模式，因此必须在装载阶段拦下。
* **本阶段不改变任何行为**：两档目前走同一条（恶意档）代码路径。按档位跳过 xmac / SPDZ MAC / §4.5-A/B / 逐记录校验的落地见 `security_mode.hpp` 的文件头。
* ⚠️ **绝不能随档位省掉的两条**：hint 消费 + 每轮 `Refresh`（D17；hint 复用会向**半诚实**服务器泄露查询分区 ℓ），以及查询预算预检（超预算 fail-loudly，不降级）。
## 派生（全部由程序算，不写进配置）

```
entry_words = ⌈n/128⌉                     条目宽度（字）
levels = attributes × columns_per_attribute  真实层数（每个属性各自一组列）
m = ceil(levels/(2w))·2w                 PIR 条目数（补齐后；只需 2w | m）
w = 2^j（最接近 √m）                      块大小（**条目**/块）
kappa = m / w                            块数（偶数）
去重列数 = min(k, levels)                 每个谓词恰好归约到 1 列
查询集数 = 去重列数                       一列 = 一个条目 = 1 个查询集
每台 RPC = 1                             一次 RunBatch ⇒ 一次 ServerRespBatch
服务器存储/台 = 16·m·entry_words + 16·n·attributes
              （双报：把 m 换成 levels 即"不含补齐"口径）
N_T = λw/2（备份 hint）、池 = m（新鲜索引池）⇒ 预算 = 去重列数 ≤ min(N_T, m)
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
