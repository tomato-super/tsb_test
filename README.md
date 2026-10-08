# TSB：VMPQ 与 MPRAQ 双服务器隐私聚合查询

本仓库实现两套**双服务器（two-server）隐私聚合查询**系统：

| 系统 | 安全模型 | 说明 |
|---|---|---|
| **VMPQ** | 半诚实（honest-but-curious） | 复现已发表方案的基线实现（V-OO-PIR + 在线阶段），可端到端双进程运行 |
| **MPRAQ** | **恶意（malicious）** | 本项目的自研方案实现（Plinko PIR + LCTE 编码 + SPDZ MAC 聚合 + 恶意路径验证） |

两者跑在同一套底座上（AES-PRF、秘密共享、SecureMul 与验证、gRPC 传输），因此可以用同一批查询、同一套账目口径相互对照。

---

## 1. 项目结构

```
CMakeLists.txt            顶层构建入口（默认 Release）
TASK_PLAN.md              项目文档：设计决策、实测数据、里程碑与全部实验记录
README.md                 本文件（结构 / 编译 / 跑实验）

config/                   运行配置（示例，可直接改）
  vmpq_server_0.json         VMPQ 服务器 0（server_id / host_port）
  vmpq_server_1.json         VMPQ 服务器 1
  vmpq_client.json           VMPQ 客户端（服务器地址 + window_size / attr_sizes / lambda）
  mpraq_scale.json           MPRAQ 规模配置：只填 行数 / 每属性列数 / 属性数 / 谓词数 / λ / ε / seed
  mpraq_scale.md             上述配置的单位、约束与派生公式（JSON 不支持注释，故写在 md 里）

proto/                    gRPC 协议
  vmpq.proto                 VMPQ：InitTable / UploadEntries / PirQuery
  mpraq.proto                MPRAQ：InitTable / UploadFeatureWords / SetAttributeShares / ServerResp / Relay
  gen/                       构建时生成的代码（不入库）

src/
  core/       基础原语：AES-PRF（aes_prf）、哈希（hash）、Mset-XOR-Hash、模运算（field）、
              可逆 PRF / iPRF（iprf）、确定性随机源（random）、JSON 配置解析（config）
  shared/     秘密共享与 MPC：三套强类型共享（secret_sharing）、SecureMul 与验证（mpc / verify）、数据库
  pir/        PIR 原语：V-OO-PIR（voo_pir）、Plinko 六算法（plinko）、hint 机制
  vmpq/       VMPQ 协议层：参数（params）、服务器节点（node）、协议主流程（vmpq）
  mpraq/      MPRAQ 协议层：LCTE 编码（lcte）、谓词解析（predicate）、初始化与分片上传（init）、
              服务器节点与通道接口（node）、Count（aggquery）、SecureMul 逐记录流程（secure_mul_flow）、
              Sum/Avg 批量层（aggvalue）、恶意路径验证边界（verification）、规模配置层（scale_config）
  net/        传输层：接口与进程内实现（transport / local_transport）、
              VMPQ gRPC 通道（grpc_vmpq）、MPRAQ gRPC 通道（grpc_mpraq）、
              通用 gRPC 传输（grpc_transport）、MPRAQ 两进程链路（mpraq_remote_securemul）
  apps/       可执行入口：vmpq_server / vmpq_client、mpraq_server / mpraq_client

tests/        自检测试与测试夹具（support/：明文基准 mpraq_baseline.hpp、集群夹具 test_cluster.hpp）
bench/        基准与实验：bench_vmpq.cpp（VMPQ）、bench_mpraq.cpp（MPRAQ 参数与复杂度扫描，支持 --json）

doc/
  design/     设计规格与评审报告（PIR_SPEC、PLINKO_SPEC、MPRAQ_IMPL 等）
  evidence/   实测原始输出（VMPQ 基准与 demo 输出、MPRAQ 实验 JSON 与表格）
  refs/       参考资料（S3PIR 规格中译、官方参考实现）
  paper/      论文（MPARQ.tex 与参考 PDF）
```

---

## 2. 编译

依赖：CMake ≥ 3.16、C++17 编译器、**Crypto++**、**protobuf / gRPC**。

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j          # 内存较小的机器请用 -j2
ctest --test-dir build          # 可选自检：应全部通过
```

构建产物在 `build/bin/`：`mpraq_server`、`mpraq_client`、`bench_mpraq`、`vmpq_server`、`vmpq_client`、`bench_vmpq`，以及各测试程序。
构建目录不入库（`.gitignore` 覆盖 `build/` 与 `build_*/`）。

---

## 3. 跑实验

### 3.1 MPRAQ：按规模跑（只需填三个量）

**只需要关心三个量：行数、列数、谓词数量**；其余（真实列数、补齐列数、区块大小、hint、存储、查询预算）全部自动派生并打印出来。

`config/mpraq_scale.json`：
```json
{ "rows": 4096,                 // 行数 N —— 必须是 2 的幂
  "columns_per_attribute": 32,   // 列数（每个属性的 LCTE 列数）—— 必须是 2 的幂
  "attributes": 2,               // 属性数
  "predicates": 3,               // 谓词数量
  "lambda": 80, "eps": 0.0001, "seed": 7 }
```
单位、约束与派生公式见 **`config/mpraq_scale.md`**。命令行可**逐项覆盖**（CLI 优先于配置文件）：

```bash
# 两进程端到端：先起两个服务器进程，再跑客户端
./build/bin/mpraq_server --id 0 --port-file /tmp/p0 &
./build/bin/mpraq_server --id 1 --port-file /tmp/p1 &
./build/bin/mpraq_client --server0 127.0.0.1:$(cat /tmp/p0) \
                         --server1 127.0.0.1:$(cat /tmp/p1) \
                         --config config/mpraq_scale.json

# 逐项覆盖（示例：8192 行、每属性 16 列、5 个谓词）
./build/bin/mpraq_client ... --rows 8192 --columns 16 --predicates 5
```

客户端会打印一条**换算链**和全套账目：

```
本次规模：N=…、每属性列数=…、属性数=…、M=…、m=…、谓词数=… ⇒ 去重列数=…、查询集数=…、每台 RPC=1
```

| 输出量 | 含义 |
|---|---|
| `n` | 行数（记录数 = 列长 bit） |
| 每属性列数 | 每个属性的 LCTE 列数；**所有属性同形状，但各自拥有一组列** |
| `levels` | **真实层数** = 属性数 × 每属性列数 |
| `m` | **PIR 条目数**（= 补齐后的层数；服务器特征表按 `m` 计，输出里同时给出 `levels` 口径） |
| `entry_words` | `⌈n/128⌉` —— 一个条目（= 一整列）的宽度（128 位字） |
| `k` | 谓词数量（谓词内容自动生成，落在互不相同的列上） |
| **去重列数** | `min(k, levels)` —— **在线成本由它决定，不是谓词数量** |
| **查询集数** | **= 去重列数**（**一列 = 一个条目 = 1 个查询集**） |
| **每台 RPC** | 恒为 **1**（整批一次请求），与查询集数无关 |
| 存储/台 | `16·m·entry_words`（特征表）+ `16·n·属性数`（属性值共享） |
| 查询预算 | `查询集 ≤ min(N_T = λw/2, m)`，超出则**拒绝运行** |

约束（不满足即**拒绝**，不会静默取整）：`rows` 与每属性列数**必须都是 2 的幂**；`λ` 决定预算上限（默认配置下允许 `k ≤ 40`，要跑更多谓词请加大 `--lambda`）。

### 3.2 MPRAQ：复杂度与参数扫描（支持机器可读输出）

```bash
# 进程内口径：在线查询 / Sum·Avg / 离线 Init / 存储 / λ·ε 权衡
./build/bin/bench_mpraq --exp all --rows 1024,2048,4096,8192

# 真实 gRPC 两进程口径（未给端点时自动拉起同目录的 mpraq_server）
./build/bin/bench_mpraq --exp sum --rows 4096 --mode grpc

# 用规模配置层的同一套旋钮
./build/bin/bench_mpraq --columns-per-attribute 16 --attributes 3 --predicates 4 --rows 2048

# 机器可读：每行一条 JSON 到 stdout（人读表同时到 stderr），并落盘完整文档
./build/bin/bench_mpraq --exp all --rows 1024,2048,4096 --json --json-out /tmp/mpraq_exp.json
```
主要旗标：`--exp online|sum|init-w|storage|tradeoff|all`、`--mode local|grpc`、`--rows`、`--lambda`、`--eps`、`--w`、`--repeat`、
`--config` / `--columns-per-attribute` / `--attributes` / `--predicates`、`--json` / `--json-out`、`--quick`。

### 3.3 VMPQ：基准与双进程 demo

```bash
./build/bin/bench_vmpq --quick                       # 基准（不加 --quick 为完整扫描）

# gRPC 双进程 demo（三个终端）
./build/bin/vmpq_server config/vmpq_server_0.json    # :50051
./build/bin/vmpq_server config/vmpq_server_1.json    # :50052
./build/bin/vmpq_client config/vmpq_client.json
```

### 3.4 实验结果的留存位置

- 历史实验的原始输出在 **`doc/evidence/`**（VMPQ 基准与 demo 输出、MPRAQ 实验的 JSON / 表格）；
- `--json-out` 可把本次实验写成完整 JSON 文档（含配置、每个数据点与汇总），便于自行绘图；
- 逐条实测数字、参数选择理由与结论记录在 **`TASK_PLAN.md`** 的 §7 各节。
