# TSB：VMPQ 与 MPRAQ 双服务器隐私聚合查询

本仓库实现两套**双服务器（two-server）隐私聚合查询**系统：

| 系统 | 安全模型 | 说明 |
|---|---|---|
| **VMPQ** | 半诚实（honest-but-curious） | 复现已发表方案的基线实现（V-OO-PIR + 在线阶段 + 逐列 PIR） |
| **MPRAQ** | **恶意（malicious）**（默认）/ 半诚实 | 自研方案：**Plinko PIR** + LCTE 编码 + **xmac** 值层完整性 + SPDZ MAC 聚合 |

两者跑在同一套底座上（AES-PRF、秘密共享、SecureMul 与验证、gRPC 传输），
因此可以用同一批查询、同一套账目口径相互对照。

---

## 1. 快速开始

```bash
scripts/run.sh build        # 配置 + 全量构建（Release，-Wall -Wextra）
scripts/run.sh test         # ctest：5 个套件 / 45 个用例
scripts/run.sh mpraq        # MPRAQ 两进程 demo（恶意档）
scripts/run.sh vmpq         # VMPQ 两进程 demo
```

`scripts/run.sh` 是统一入口，它会**自己起服务器、读端口、跑客户端、清理进程与临时文件**，
并在最后打印 `MPRAQ PASS` / `VMPQ PASS`（退出码即结果，可直接当 CI 冒烟测试）。

| 子命令 | 说明 |
|---|---|
| `build` | 配置 + 全量构建 |
| `test` | `ctest --output-on-failure` |
| `mpraq [选项]` | MPRAQ 两进程 demo（`--security-mode` / `--config` / `--verbose` / `--rows` / `--columns` / `--attributes` / `--predicates` / `--keep-stale`） |
| `vmpq` | VMPQ 两进程 demo（自动生成临时配置 + 空闲端口） |
| `all [--skip-build]` | build + test + vmpq + mpraq |

> ⚠️ **并行跑多份**要加 `--keep-stale`：脚本启动前会 `pkill` 残留服务器（这是必要的，
> 否则上一轮的进程会抢端口、让新结果看起来像代码错了），而那个清理会连带杀掉并行实例。
> `--keep-stale` 跳过它；端口本身用临时端口，不会撞。

---

## 2. 环境要求

| 依赖 | 本仓库验证过的版本 |
|---|---|
| CMake | **3.22.1**（`cmake_minimum_required` = 3.20） |
| 编译器 | GCC **11.4.0**（C++17） |
| protobuf / protoc | **31.1** |
| gRPC | **1.78.1** |
| Crypto++ | **8.9.0** |

Crypto++ / protobuf / gRPC 默认装在 **`~/.local`**。

> ⚠️ **`protoc` 的路径是钉死的**：`proto/CMakeLists.txt` 写死
> `$ENV{HOME}/.local/bin/protoc` 与 `$ENV{HOME}/.local/bin/grpc_cpp_plugin`。
> 系统自带的 protobuf（3.12.4）**不兼容**，PATH 或前缀混用会硬失败。
> 换机器请先改这两行，或把工具装到对应路径。

构建产物在 `build/bin/`；`build/`、`build_*/`、`proto/gen/` 都不入库。

---

## 3. 项目结构

```
CMakeLists.txt     顶层构建（默认 Release；已开 -Wall -Wextra）
README.md          本文件
LICENSE
scripts/
  run.sh                       统一入口：build / test / mpraq / vmpq / all
  run_mpraq_grpc_online.sh     在线测试脚本（真实网卡、可跨机器）
config/                        运行配置（示例，可直接改）
  mpraq_scale.json / .md       MPRAQ 规模配置 + 单位与派生公式说明
  vmpq_{client,server_0,server_1}.json
proto/
  mpraq.proto / vmpq.proto     gRPC 接口与消息
  gen/                         构建时生成（不入库）
src/
  core/      基础原语：AES-PRF、哈希、**GF(2^128)**（xmac 的域）、模运算、iPRF、
             确定性随机源、JSON 配置解析
  shared/    秘密共享（三套强类型共享）、SecureMul 与 SPDZ MAC 验证、数据库抽象
  pir/       PIR 原语：V-OO-PIR（voo_pir）、**Plinko 六算法**（plinko）+ hint 生命周期
  vmpq/      VMPQ 协议层
  mpraq/     MPRAQ 协议层（见 §5）
  net/       传输层（见 §6）
  apps/      可执行入口：{vmpq,mpraq}_{server,client}
tests/       5 个套件 / 45 个用例 + `support/`（测试框架、明文基准、集群夹具）
bench/       bench_vmpq.cpp / bench_mpraq.cpp（参数与复杂度扫描，支持 --json）
third_parts/json/json.hpp     JSON 解析（已入库，新克隆可构建）
```

> ⚠️ **`doc/` 不在版本控制里**（`.gitignore` 排除，负责人的决定）。
> 也就是说**新克隆里没有 `doc/`**，其中包括 `doc/TASK_PLAN.md`（决策台账）、
> `doc/design/`（设计规格与评审）、`doc/evidence/`（实测原始输出）、`doc/paper/`。
> 本文件的其余部分**不依赖** `doc/`，可独立阅读。

---

## 4. 两个协议

### VMPQ（半诚实）

- PIR 条目 = **一整列**（`entry_words = ⌈N/128⌉` 个 128 位字），PIR index = 列索引；
- 一次列查询 = **1 个查询集** = 每台服务器 **1 次** RPC；
- 入口：`vmpq_server config/vmpq_server_{0,1}.json` + `vmpq_client config/vmpq_client.json`。

### MPRAQ（恶意，默认）

`src/mpraq/` 按任务号组织：

| 文件 | 任务 | 职责 |
|---|---|---|
| `lcte.{hpp,cpp}` | MPA-01 | LCTE 编码：阈值谓词 ⇒ 列；阈值对齐 |
| `predicate.{hpp,cpp}` | MPA-02 | 谓词解析：操作符 → 列索引 + 取反；本地布尔组合（De Morgan） |
| `init.{hpp,cpp}` | MPA-03 | 客户端 `Init`（离线七步）：LCTE → 位打包 → 共享 → 上传 |
| `node.{hpp,cpp}` | MPA-03 | 服务器侧存储 + 与传输无关的通道抽象 |
| `aggquery.{hpp,cpp}` | MPA-04 | **`Count`**（六步） |
| `secure_mul_flow.{hpp,cpp}` | MPA-05 | **SecureMul 三方消息流** |
| `aggvalue.{hpp,cpp}` | MPA-06 | **`Sum` / `Avg`**（批量 SecureMul） |
| `verification.{hpp,cpp}` | MPA-07 | 验证边界：把"实际具备的验证能力"固化成可断言的代码 |
| `scale_config.{hpp,cpp}` | MPA-08 | 规模配置：三个量 ⇒ 其余全自动派生 + 预估/实测对照 |
| `security_mode.hpp` | — | 安全档位（恶意 / 半诚实） |

> ⚠️ 命名空间是 **`tsb::mpraq`**（不是顶层 `tsb`）：`core/config.hpp` 已在 `tsb` 里
> 定义了同名的 `PredicateOp` / `Predicate`。

**三条主线**：

```
Init ① 参数校验 → ② LCTE+位打包 → ③ 属性值 mod q 共享 → ④ HintInit
     → ⑤ 分块上传（特征 XOR 共享 + tag）→ ⑥ st（hint/密钥/α/γ）→ ⑦ ❌ 不生成 HMAC
Count ① 谓词解析 → ② 每列 = 1 个查询集 → ③ 服务器分组 XOR 累加 → ④ 客户端重建整列
     → ⑤ 本地布尔组合 → ⑥ Count = popcount(filter)
Sum/Avg ① 离线 Beaver triple → ② 第 1 轮（N 条一个帧）→ ③ 重建 e
     → ④ 第 2 轮 → ⑤ 逐记录校验（必须传 ctx）→ ⑥ ok 把关，任一失败即 abort
```

---

## 5. 跑 MPRAQ

### 5.1 规模配置：只管三个量

```jsonc
// config/mpraq_scale.json
{
  "rows": 4096,                    // 记录数 n —— 必须是 2 的幂
  "columns_per_attribute": 32,     // 每属性 LCTE 列数 —— 必须是 2 的幂（≥ 2）
  "attributes": 2,                 // 属性数
  "predicates": 3,                 // 谓词数
  "lambda": 80, "eps": 0.0001, "seed": 7,
  "security_mode": "malicious",    // malicious（默认）| semi-honest
  "enable_repeat_query_cache": true
}
```

其余全部自动派生并打印。**约束不满足即拒绝运行，绝不静默取整**
（`rows` / 每属性列数必须是 2 的幂）。

命令行可**逐项覆盖**：`--rows` / `--columns` / `--attributes` / `--predicates` /
`--lambda` / `--eps` / `--seed` / `--prng-seed` / `--sum-attr` / `--security-mode` /
`--repeat-query-cache on|off` / `--verbose`。

### 5.2 安全档位

| | **恶意**（默认） | **半诚实** |
|---|---|---|
| xmac（PIR 值层完整性） | ✅ 每条目每 chunk 一份 tag，逐 chunk 校验 `M_b = γ ⊙ R_b` | ❌ **什么都不做**（不采样 γ、不存、不传、不校验） |
| SecureMul 的 SPDZ MAC 与 §4.5-A/B 复核 | ✅ 全部执行 | ❌ **全部跳过** |
| 存储 / 应答 | 含 tag ⇒ 数据表 ×2 | 减半 |
| 可见证据 | `tag_checks = 查询集数` | `tag_checks=0`、`storage` 少 `16·m·entry_words` B |

> ⚠️ **半诚实档下服务器篡改会被静默接受** —— 这是**如实声明的边界**，不是缺陷：
> 该档的威胁模型里服务器不偏离协议。要验证请用恶意档（默认档）。
> ⚠️ 两条**绝不随档位省掉**的：hint 消费 + 每轮 `Refresh`（D17）、查询预算预检。

### 5.3 重复查询缓存开关

| 取值 | 重复查询的行为 |
|---|---|
| `true`（默认） | 另挑一个**从未查过**的索引做 PIR，返回缓存里的值 ⇒ 访问模式**永不重复** |
| `false` | **直接拒绝**（抛 `PlinkoRepeatedQueryRejected`）—— 绝不退化成"对同一索引再查一次" |

⚠️ 关掉它**要求上层不对同一列重复查询**。当前 `RunBatch` **不做跨查询去重**
⇒ 同一列出现在两个谓词里时第二次会**失败**（如实行为）。
实测：`--repeat-query-cache off` 时 `q0` 通过、`q1` fail-loudly。

### 5.4 输出字段

```
scale n=4096 C=32 A=2 levels=64 m=64 k=3 qsets=3 rpc=1 security=malicious
query name=q0 phi=attr0 > 0 count=3973 count_matches_baseline=1 sum=59675 avg=15 \
      columns=1 query_sets=1 rpc0=1 rpc1=1 retrieve_ms=2.5 sum_ms=143.8
accounts storage_bytes_per_server=196608 query_sets=4 pir_rpc0=2 pir_rpc1=2 \
      sm_rounds=4 sm_wire_messages=32768 install_rounds=4 install_frames=4 \
      tag_checks=4 pir_cache=on
result baseline_match=1 rpc_per_batch=1 sm_rounds=2 storage_formula_match=1
```

| 字段 | 含义 |
|---|---|
| `n` | 记录数 = 列长（bit） |
| `C` / `A` | 每属性列数 / 属性数 |
| `levels` | **真实** LCTE 层数 = `A × C` |
| `m` | **PIR 条目数**（= 补齐后的层数） |
| `entry_words` | `⌈n/128⌉` —— 一个条目（= 一整列）的宽度（128 位字） |
| `w` / `kappa` | 区块大小 / 区块数 `κ = m/w`（**必须偶数**） |
| `lw` / `N_T` / `H` | 常规 hint 数 `λw` / 备份 hint 数 `λw/2` / 槽位数 `λw+N_T` |
| `k` / `qsets` | 谓词数 / **查询集数**（= 去重列数；**一列 = 一个条目 = 1 个查询集**） |
| `rpc` | 每台服务器的 RPC 次数，**恒为 1**（整批一次请求） |
| `storage_bytes_per_server` | `16·m·entry_words`（数据）+ **`16·m·entry_words`（tag，仅恶意档）** + `16·n·A`（属性值） |
| `tag_checks` | 已通过 xmac 校验的查询集数（恶意档 = 查询集数，半诚实档 = 0） |
| `pir_cache` | 重复查询缓存是否开启 |
| **查询预算** | `查询集 ≤ min(N_T, m)`，超出则**拒绝运行**（加大 `--lambda` 可放宽） |

---

## 6. 传输层

三层，**只有最下一层碰真网络**：

```
应用语义     mpraq/*、vmpq/*        只发"不透明字节"，不碰 socket
传输抽象     net/transport.hpp      ITransportClient / ITransportServer，Payload = 字节
真实实现     net/local_transport.*  进程内（测试与 bench 默认路径）
             gRPC                   真实 socket / HTTP2
```

| 文件 | 作用 |
|---|---|
| `net/transport.hpp` | 传输抽象（`Submit` / `Collect` / `SetHandler`） |
| `net/grpc_mpraq.*` | MPRAQ 数据通道（线协议 **v3**） |
| `net/grpc_transport.*` | 通用 **Relay**（SecureMul 四条腿，opaque 字节） |
| `net/mpraq_remote_securemul.*` | 两进程 SecureMul（14 字节封套 + 原样批量帧） |
| `net/grpc_vmpq.*` | VMPQ 数据通道 |
| `net/grpc_limits.hpp` | **收包上限**（gRPC 默认 4 MiB，必须显式放宽） |

**本仓库没有手写的 socket 代码** —— 网络 I/O 全部交给 gRPC。

**结构性保证：服务器之间零通信。** 每台服务器是独立的 `grpc::Server` +
独立的 `RelayServiceImpl`，只持有**自己那一个** handler ⇒ 一台服务器**没有任何句柄**
能触达另一台（真实双进程部署时物理成立）。

---

## 7. 跑 VMPQ

```bash
scripts/run.sh vmpq
```

等价于（脚本会自动选空闲端口并生成临时配置，避免固定 50051 冲突）：

```bash
./build/bin/vmpq_server config/vmpq_server_0.json   # :50051
./build/bin/vmpq_server config/vmpq_server_1.json   # :50052
./build/bin/vmpq_client config/vmpq_client.json
```

预期：`result all_match=1 mismatch=0`
⚠️ VMPQ 用**固定端口**，两份不能同时跑（脚本生成临时配置就是为绕开这一点）。

---

## 8. 基准

```bash
# MPRAQ：进程内口径
./build/bin/bench_mpraq --exp all --rows 1024,2048,4096,8192

# MPRAQ：真实 gRPC 两进程口径（未给端点时自动拉起同目录的 mpraq_server）
./build/bin/bench_mpraq --exp sum --rows 4096 --mode grpc

# 机器可读：每行一条 JSON 到 stdout（人读表到 stderr），并落盘完整文档
./build/bin/bench_mpraq --exp all --rows 1024,2048,4096 --json --json-out /tmp/exp.json

# VMPQ
./build/bin/bench_vmpq --quick      # 不加 --quick 为完整扫描
```

主要旗标：`--exp online|sum|init-w|storage|tradeoff|all`、`--mode local|grpc`、
`--rows`、`--columns-per-attribute`、`--attributes`、`--predicates`、`--lambda`、`--eps`、
`--w`、`--security-mode`、`--repeat`、`--json` / `--json-out`、`--quick`。

每个实验都会断言 **`all_accounting_assertions_passed=1`**（公式 = 实测）。

---

## 9. 测试

```bash
scripts/run.sh test          # 等价于 ctest --test-dir build --output-on-failure
```

**5 个套件 / 45 个用例**（每个用例有 `TIMEOUT 300`）：

| 套件 | 用例 | 覆盖 |
|---|---|---|
| `test_mpraq_entry` | 13 | MPRAQ 条目/档位契约：四组不变量、列粒度、存储公式、档位接口、tag 存储、**篡改必拒**、协议版本拒绝、半诚实档不校验 |
| `test_plinko_contract` | 10 | Plinko 底座：几何自洽、精确重建、XOR 线性、**hint 生命周期**、重复查询重采样、备份耗尽、`Verify` 恒抛、确定性、**缓存开关** |
| `test_gf128` | 6 | `GF(2^128)`：位序与约简多项式（**独立可推导**）、域公理、逆元与单射、XOR 同态、**不可约性严格证明** |
| `test_aggvalue` | 6 | `Sum`/`Avg`：明文基准一致、`Avg` 口径、**篡改 ⇒ 整体 abort（绝不返回部分和）**、长度校验、确定性、两档 |
| `test_grpc_mpraq` | 10 | **真实 gRPC 线协议**（`InProcessMpraqNode`）：几何往返、档位不一致拒绝、上传校验、批量一次 RPC、tag 字段存在性、**> 4 MiB 应答**、错误传播 |

> ⚠️ `test_grpc_mpraq` **会起真实 gRPC 服务器**（`127.0.0.1:0` 临时端口），
> 因此用例被挂住的风险是真实的 —— `TIMEOUT 300` 就是为它准备的（把"挂死"变成"失败"）。

---

## 10. 已知边界（如实声明）

| # | 边界 | 说明 |
|---|---|---|
| 1 | **半诚实档不做任何验证** | 设计如此；篡改被静默接受。要验证请用恶意档 |
| 2 | **缓存关掉后当前 workload 会报错** | 上层不做列去重（负责人裁定），同一列出现在两个谓词里时第二次 fail-loudly |
| 3 | **VMPQ 未在 `N ≥ 2^17` 做 e2e 确认** | 收包上限已放宽（`net/grpc_vmpq.cpp`），依据是代码核对 + 解析界；MPRAQ 侧有 `test_grpc_mpraq` 的 8 MiB 用例 |
| 4 | **`bench_mpraq` 不单列"PIR 应答字节"** | 恶意档应答翻倍但账目里看不到 |
| 5 | **`protoc` 路径钉死在 `~/.local`** | 换机器要改 `proto/CMakeLists.txt` |
| 6 | **两台共谋与元数据信道在模型之外** | 中转 `e` 的隐信道（≈127 bit/记录，需共谋）、时序信道、abort 下标信道 |
| 7 | **摊销式离线未实现**（D8） | 查询额度 = `min(m, N_T)`，用完须重跑 `HintInit` |
| 8 | **`doc/` 不在版本控制内** | 设计文档与实测证据只存在于本机 |

论文侧待改的 6 条见 `doc/design/mparq_review/FINAL_ADJUDICATION.md`（本机文件）。

---

## 11. 术语与约定（改代码前必读）

| 约定 | 内容 |
|---|---|
| **条目粒度** | 一个 PIR 条目 = **一整列**（`entry_words = ⌈n/128⌉` 个字），PIR index = 列索引。**不是一个 word** |
| **几何规则** | `m = κ·w`、`w` 是 2 的幂、**`κ` 必须偶数**、`m ≥ levels`。`m` **不再要求是 2 的幂** |
| **符号** | `n` 记录数 / `m` 条目数 / `entry_words` 条目宽度 / `levels` 真实层数 / `w` 区块大小 / `κ` 区块数 / `N_T` 备份 hint 数 |
| **不变量 I1–I5** | I1 宽度自洽 / I2 尾部填充位两台恒 0 / I3 恰好暴露 `n` bit / I4 宽度不符即拒 / I5 tag 宽度 = 条目宽度 |
| **档位来源** | `StoreParams::has_tags()` **由 `security_mode` 推出**，不另设字段（避免自相矛盾）。半诚实档 = **什么都不做**，没有"按档位分支"的开关 |
| **两个代数设定** | PIR 层用 `GF(2^128)`（xmac）；MPC 层用 `Z_q`，`q = 2^127−1`（Mersenne 素数）。**符号绝不混用** |
| **线协议版本** | 当前 **v3**（1 = word 粒度 / 2 = 列粒度 / 3 = 列粒度 + xmac tag）。版本不匹配**直接拒绝** |

---

## 12. 常用命令速查

```bash
scripts/run.sh build                                  # 构建
scripts/run.sh test                                   # 全部测试
scripts/run.sh mpraq                                  # MPRAQ demo（恶意档）
scripts/run.sh mpraq --security-mode semi-honest      # 半诚实档
scripts/run.sh mpraq --verbose --rows 8192            # 换规模 + 全量账目
scripts/run.sh vmpq                                   # VMPQ demo
scripts/run.sh all                                    # 一条龙

# 手工起 MPRAQ（不想用脚本时）—— 注意用完要 kill
./build/bin/mpraq_server --id 0 --port-file /tmp/p0 &
./build/bin/mpraq_server --id 1 --port-file /tmp/p1 &
./build/bin/mpraq_client --server0 127.0.0.1:$(cat /tmp/p0) \
                         --server1 127.0.0.1:$(cat /tmp/p1) \
                         --config config/mpraq_scale.json
```
