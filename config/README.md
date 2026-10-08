# `config/`：示例 JSON 配置（VMPQ）

> ✅ **MPRAQ 现在有配置了（规模配置层，`CFG-01`）**：负责人只关心 **行数 / 列数 / 谓词数量** 三个量，其余全部自动派生。
> 见 **`config/mpraq_scale.json`**（纯字段）与 **`config/mpraq_scale.md`**（单位、约束、派生公式 —— JSON 不支持注释所以写在 md 里）：
> ```json
> { "rows": 4096, "columns_per_attribute": 32, "attributes": 2,
>   "predicates": 3, "lambda": 80, "eps": 0.0001, "seed": 7 }
> ```
> 命令行逐项覆盖（CLI 优先）：
> ```bash
> ./build/bin/mpraq_client --config config/mpraq_scale.json --rows 8192 --predicates 5
> ./build/bin/bench_mpraq  --columns-per-attribute 16 --attributes 3 --predicates 4 --rows 2048
> ```
> 派生链（程序会打印，供手算核对）：`levels = 属性数×每属性列数` → `m` 补齐到 `2w` 的倍数 → **去重列 = min(k, levels)** → **查询集 = 去重列**（一列 = 一个条目） → **每台 RPC 恒 1**；
> ⚠️ 约束：`rows` 与每属性列数**必须都是 2 的幂**（否则程序**拒绝**，不静默取整）；超 **L14** 预算也会**拒绝运行**。
> ⚠️ 查询**仍不**用 JSON 表达（`TASK_PLAN.md` §7.7 已裁决作废）：查询由 API（`Predicate` + `CountPredicates` + `SumOverFilter`）或规模层自动生成的谓词表达。

命名约定：**`<系统>_<角色>[_<序号>].json`**（统一后；旧名见文末对照表）。

| 文件 | 谁读 | 关键字段 | 说明 |
|---|---|---|---|
| `vmpq_server_0.json` | `vmpq_server`（第 1 个参数） | `server_id`、`host_port` | 服务器 0，监听 `:50051` |
| `vmpq_server_1.json` | `vmpq_server` | `server_id`、`host_port` | 服务器 1，监听 `:50052` |
| `vmpq_client.json` | `vmpq_client` | `servers[]`（`id`+`address`）、`params.window_size`、`params.attr_sizes`、`params.lambda` | 客户端：两条服务器地址 + 查询参数 |
| `mpraq_scale.json` | `mpraq_client` / `bench_mpraq`（`--config`） | `rows`、`columns_per_attribute`、`attributes`、`predicates`、`lambda`、`eps`、`seed` | **MPRAQ 规模配置**：只填行数/列数/谓词数，其余自动派生（见 `mpraq_scale.md`） |

加载方式：`VmpqConfig::FromFile(path)`（`src/core/config.hpp`）。

```bash
# VMPQ gRPC 双进程 demo（三个终端）
./build/bin/vmpq_server config/vmpq_server_0.json
./build/bin/vmpq_server config/vmpq_server_1.json
./build/bin/vmpq_client config/vmpq_client.json
```

字段说明（当前 schema）：
- `params.window_size`：**N**（记录数）；
- `params.attr_sizes`：各属性的 LCTE 取值域大小（非空时**优先**于 `num_bucket`）；
- `params.num_bucket`：单属性场景的 `2^l`；**仅为向后兼容保留**，新配置请用 `attr_sizes`；
- `params.lambda`：安全参数（默认 80）。

## 改名对照（2026-09-10 工程整理）

| 旧名 | 现名 | 处置 |
|---|---|---|
| `client_vmpq.json` | **`vmpq_client.json`** | 重命名（统一命名约定） |
| `server_vmpq_0.json` / `server_vmpq_1.json` | **`vmpq_server_0.json`** / **`vmpq_server_1.json`** | 重命名 |
| `client_cfg.json` | — | **删除**：无任何代码/文档引用，且 schema 早于 `attr_sizes`/`lambda`（被 `client_vmpq.json` 取代） |
| `server_cfg_0.json` / `server_cfg_1.json` | — | **删除**：同上（内容与新版逐字重复，仅 JSON 空格风格不同） |

### `enable_repeat_query_cache`（布尔，**默认 `true`**）

Plinko 的**重复查询缓存**开关（`Q`，论文 Fig 7 的 `Query`）。

| 取值 | 重复查询的行为 | 后果 |
|---|---|---|
| `true`（默认） | 另挑一个**从未查过**的索引做 PIR，返回缓存里的值 | 服务器看到的索引序列**永不重复** ⇒ 访问模式不可关联 |
| `false` | **直接拒绝**（抛 `PlinkoRepeatedQueryRejected`） | 更严格；**绝不**退化成"对同一索引再查一次"（那会让访问模式可关联，是静默的隐私降级） |

对应 CLI：`--repeat-query-cache on|off`（严格解析，只认 `on/off/true/false/1/0`）。

⚠️ **关掉它要求上层不对同一列重复查询**。当前 MPRAQ 的 `RunBatch` **不做跨查询去重**
⇒ 同一列出现在两个谓词里（例如 demo 的 `q0` 与 `q1` 都用到 `attr0`）时，第二次会**失败**。
这是**如实行为，不是缺陷**：宁可报错，也不让服务器看到重复索引。
（`config/mpraq_scale.json` 的默认 workload 就会触发它 —— 若要在此 workload 下关缓存，
须先给上层加列去重。）

⚠️ 它**不延长查询额度**：每条查询仍消耗 1 条备份 hint（`N_T` 上限不变）。
⚠️ 关掉后**省下** `m · entry_words · 16` 字节（该档不分配明文缓存值数组）。
