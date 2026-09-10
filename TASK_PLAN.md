# 隐私聚合查询系统 —— 任务规划与上手须知

> 本文档是本仓库的**权威上手文档**。任何新对话/新成员请先完整读完本文，再动手改代码。
> 维护规则：任务状态变化时同步更新第 9 节的看板；重大设计决策变更时同步更新第 5 节并在文末追加变更记录。

---

## 0. 当前进展（截至 2026-09-10）

| 指标 | 数值 |
|---|---|
| 测试 | **14 个测试程序、317 项用例，`ctest` 全绿**（约 1.6 s） |
| 代码 | 实现 6087 行（`src/`）、测试 5746 行（`tests/`） |
| 任务 | **24 / 38 完成**；共享底座与 VMPQ 两层全部完成 |
| 里程碑 | M1 ✅、M2 ✅、**M4 ✅（VMPQ 端到端跑通）**；M3 🟡、M5 ⬜ |

**已经能跑起来的东西**：
```bash
cd build && cmake --build . && ctest          # 全量测试
./build/bin/bench_vmpq                        # VMP-07 基准
./build/bin/vmpq_server config/server_vmpq_0.json   # VMP-08 demo（另开两个终端）
./build/bin/vmpq_server config/server_vmpq_1.json
./build/bin/vmpq_client config/client_vmpq.json
```

**VMPQ 半诚实版本已完成**：`Init → 单/多谓词 Count → SUM → AVG/Var/矩` 四条链路
在真实 gRPC 双进程下端到端验证，全部与明文基准一致（见 §7.11）。

**MPRAQ 尚未开工**（负责人指示暂缓）。其 `MPA-01`/`MPA-02` 不依赖 Q9，可随时启动；
`MPA-03` 起依赖 Plinko（`PIR-04`），而 Plinko 阻塞于 **Q9（iPRF 可行性）**。

---

## 1. 一句话背景

我们在实现**两个基于双服务器秘密共享的隐私聚合查询系统**：

| 系统 | 状态 | 我们的目标 | 论文 |
|---|---|---|---|
| **VMPQ** | 已发表（IEEE TKDE 2026） | **只做半诚实版本**，作为对比基线 | `doc/paper/VMPQ_...pdf` |
| **MPRAQ** | 我们自己的论文，**未完工** | **完整实现**（含恶意模型下的验证） | `doc/paper/MPARQ.tex` |

两个系统形态相近（都是双服务器、不共谋、客户端持有本地状态、支持多谓词 + 聚合），但**密码学底座不同**，这决定了架构必须分层共享、协议层分离。

> ⚠️ **命名提醒**：论文源文件叫 `MPARQ.tex`（标题：*Multi-Pridicate Range Aggregation Query with Verification over Timestamp Database*），而口头/任务里称 **MPRAQ**。本文档统一用 **MPRAQ**，代码目录命名请沿用 `mpraq`。**注意论文标题里 "Pridicate" 是笔误，应为 "Predicate"，投稿前需修正。**

---

## 2. 两个协议的技术画像（决定模块划分）

### 2.1 VMPQ（半诚实版要做的事）

- **秘密共享**：论文称两方 RSS（加法共享 over `Z_{2^k}`）。**但实测（决策 D12）表明
  参与 PIR parity 的 one-hot 比特必须用 XOR 共享**，否则两服务器的 XOR 结果无法重建明文。
  本实现即按此分层：**one-hot 比特走 XOR 共享，属性值走加法共享**。
- **数据组织**：每个属性一张 **one-hot 索引表**，尺寸 `N × 2^{l_a}`。本实现把一列
  **按 128 位打包**成 `⌈N/128⌉` 个 word（论文口径是每个 (行,列) 单元一个 16 字节环元素）。
- **检索层（核心创新）**：**V-OO-PIR**，五个算法 `Hint / Query / Answer / Refresh / Verify`，
  子线性复杂度。规格见 `doc/design/PIR_SPEC.md`。
- **⚠️ 半诚实版本移除全部 proof（决策 D16）**：论文用 Mset-XOR-Hash 做 hint 证明，
  但客户端不持有服务器共享、HMAC 又非线性（`C_0 ⊕ C_1 ≠ C`），该用法不成立；
  半诚实模型下服务器默认不篡改，故 proof 全部去除。移除后 `HintInit` 快约 3.6 倍。
- **多谓词**：`Multiply` 协议（RSS-based 两方安全乘法，Beaver triple 形式，用户中转消除服务器间通信）。
- **聚合**：`Count` 由 hint 的 parity 直接得到（`β_i`）；`Sum` 在 count 基础上多一步与属性值 `E` 的 join（`e = E - b`）；`Avg/Var/Std` 由 sum/count 本地推导。
- **服务端存储**：`|κ|·(N + N·2^l)`（属性值 N 个 + one-hot 索引 N×2^l 个，每个 κ=16 字节）。
- **半诚实版本的取舍**：**保留** Hint/Query/Answer/Refresh 与 Multiply 的完整计算链路；**关闭/跳过** Verify 的判定分支与恶意行为检测（但要**保留接口**，便于后续开开关）。

### 2.2 MPRAQ（要完整实现）

- **秘密共享（两套并用，务必区分）**：
  - **XOR 秘密共享** `[x]_i` → 用于 **LCTE 编码后的特征比特**。服务端应答是 XOR 累加，客户端 `v = v1 ⊕ v2`。
  - **加法秘密共享** `⟨x⟩_i mod q` → 用于 **属性值**（128-bit 元素）。
- **编码**：**LCTE（Left-Threshold Cumulative Encoding）**，`LCTE(x) = ([x<r_1], ..., [x<r_m])`，阈值集合 `R = {r_min, ..., r_min+m-1}` 连续整数。范围查询 `[t_a, t_b)` 拆成两个点查询 `¬P_a(t) ∧ P_b(t)`；多区间用 De Morgan 优化成 `Φ = ¬(∨ P_{i0}(l_i)) ∧ (∧ P_{i1}(r_i))`。
- **检索层**：**Plinko**（iPRF 为核心，`M = λ√n` 个主 hint + `M/2` 备份 hint），六个算法 `HintInit / GetHint / QueryGen / ServerResp / ClientRecon / Verify`。**查询复杂度 `O(n/r)`**。
- **验证**：两套机制并用 —— (a) HMAC-based 多集证明 `F ⊕ C = MAC_target ⊕ MAC_filler`；(b) SPDZ 风格 MAC `mac = α·z`。
- **聚合**：`Count` 客户端本地数 filter 向量中 1 的个数；`Sum` 用 `SecureMul`（Beaver triple + SPDZ MAC）；`Avg = Sum/Count`。
- **威胁模型**：**恶意服务器**，服务器可任意偏离协议并篡改应答，检测到即 abort。

### 2.3 关键差异对照（写代码时最容易踩的地方）

| 维度 | VMPQ | MPRAQ |
|---|---|---|
| 检索原语 | V-OO-PIR（SimPraPir2 变体） | Plinko |
| PRF 类型 | 普通 PRF（分区选择 + 偏移） | **iPRF**（可逆：`IF` 与 `IF⁻¹` 都要） |
| 特征共享 | 加法共享 over `Z_{2^128}` | **XOR 共享**（比特级） |
| 属性共享 | 加法共享（16 字节） | 加法共享（`mod q`） |
| 数据布局 | one-hot 表（每属性一列族） | 特征列 + 属性列 |
| 多谓词实现 | 服务器端 `Multiply`（每加入一个谓词一次乘法） | **客户端本地布尔组合**（因为 LCTE 列只有 N bit，传输成本可忽略） |
| 验证 | Mset-XOR-Hash（可先关掉） | HMAC 多集证明 + SPDZ MAC |
| 服务器间通信 | **无**（用户中转 `[d],[e]`） | **无**（同上） |

**注意**：MPRAQ 的多谓词在客户端本地做布尔运算，这是与 VMPQ 最大的结构性差异。MPRAQ 的服务器仍然要参与 `Sum` 的 `SecureMul`，只有 `Count` 完全不需要服务器做乘法。

---

## 3. 当前代码实现状况（务必先看，避免重复劳动与踩坑）

### 3.1 现状总览

**旧代码已按决策 D9 全部删除**（`src/common`、`src/client`、`src/server` 及旧 `proto/pir_comm.proto`）。
其功能已由新模块取代，迁移对照见 §3.3。当前结构：

```
src/
├── core/     ✅ 环运算、AES-PRF、SHA-256/HMAC、Mset-XOR-Hash、随机、配置
├── shared/   ✅ XOR/加法秘密共享、表抽象、SecureMul、验证机制
├── pir/      ✅ V-OO-PIR（五算法全部实现并验证）
├── vmpq/     ✅ VMPQ 半诚实版本（参数、服务器节点、通道抽象、客户端）
├── net/      ✅ 传输抽象（进程内 + 真实 gRPC）
└── apps/     ✅ vmpq_server / vmpq_client 可执行入口
proto/vmpq.proto          ✅ 当前唯一协议（InitTable / UploadEntries / PirQuery）
bench/bench_vmpq.cpp      ✅ VMP-07 基准
```

### 3.2 历史缺陷（**已随旧代码删除而消失，保留作为"重写时别重蹈覆辙"的对照**）

| 原位置 | 问题 | 新实现如何规避 |
|---|---|---|
| `src/server/vmpq_server.cpp:32` | `updateBatchVarList` 无边界检查，可堆越界写 | `VmpqNode::UploadEntries` / `PirQuery` 全部做范围校验并抛异常 |
| 同上 | `var_list_[id]` 对不存在的 key 隐式创建空 vector | 改为显式 `initialized()` 状态检查，未 Init 即报错 |
| `src/server/vmpq_server.cpp:15` | `initTable` 与 varlist 上传使用两套 id 语义 | 新设计用扁平条目号 + schema 推导的属性基址，无隐式约定 |
| `src/server/vmpq_server.cpp:46` | `updateBatchTable` 是追加语义，重复上传静默累积 | 上传按 `base_index` **覆盖式**写入，语义明确 |
| `src/client/query_client.cpp` | 分块大小硬编码魔数，可能撞 gRPC 4MB 上限 | `Init` 分块上传按固定的 4096 条目/块 |

### 3.3 已有资产与迁移对照（不用重写）

| 旧资产 | 新位置 | 说明 |
|---|---|---|
| `common/AES_PRF` | `core/aes_prf` | 补齐了域分隔 API、批量/单点一致性测试，并用 **FIPS-197 向量**验证 |
| `utility::AdditiveShare` | `shared/secret_sharing` | 扩展为**三套强类型**共享（Ring/Mod/XorBit），编译期阻止混用 |
| `utility::numToOneHotVect` | `shared/database` + `vmpq` | 单热编码 + 128 位按位打包 |
| `utility::uint128ToString/Hex` | `core/field` | 加上解析、序列化、模逆等 |
| `QueryClient` / `VMPQServer` | `apps/vmpq_client` / `vmpq_server` | 重写为基于新协议的真实 gRPC 双进程 |

**新增的关键能力**（旧代码完全没有）：
`core/hash`（HMAC-SHA256，RFC 4231 验证）、`core/mset_hash`、`shared/mpc`（Beaver triple）、
`shared/verify`、`pir/voo_pir`（V-OO-PIR 五算法）、`net/grpc_vmpq`。

### 3.4 构建与运行

```bash
# 依赖：~/.local/cryptopp（静态库）、~/.local/bin/protoc、~/.local/bin/grpc_cpp_plugin
# 第三方 json：third_parts/json/json.hpp（单头文件，v3.12.0）

cd build && cmake --build . && ctest      # 构建 + 全量测试（14 个程序、317 项用例）

# VMP-07 基准
./build/bin/bench_vmpq

# VMP-08 端到端 demo（需要三个终端）
./build/bin/vmpq_server config/server_vmpq_0.json   # :50051
./build/bin/vmpq_server config/server_vmpq_1.json   # :50052
./build/bin/vmpq_client config/client_vmpq.json
```

**已知坑（已修复，务必别再犯）**：
- `third_parts/` 曾叫 `third_part/`，改名后 `src/server/CMakeLists.txt` 的 include 路径没同步 → 编译失败。**改目录名前先 grep 全仓库引用。**
- `third_parts/json/json.hpp` 曾被下载中断截断成 512KB（恰好 524288 字节），报错却是 `unterminated #ifndef` + `/usr/include/c++/11/fstream:52 expected '='` 这类极具误导性的级联错误。**遇到 fstream 报错先怀疑第三方头文件完整性。**

---

## 4. 架构（**已落地**，与计划一致）

**同一仓库，共享底座 + 协议模块 + 可执行入口**。下图标注了每个模块的实际状态：

```
tsb_test/
├── proto/
│   └── vmpq.proto                  ✅ 唯一协议：InitTable / UploadEntries / PirQuery
├── src/
│   ├── core/                       ✅ 第 1 层：纯工具，无协议语义
│   │   ├── field.{hpp,cpp}         #   Z_{2^128} / mod q 环运算、逆元、序列化
│   │   ├── aes_prf.{hpp,cpp}       #   AES-PRF（FIPS-197 向量验证）
│   │   ├── hash.{hpp,cpp}          #   SHA-256 / HMAC-SHA256（RFC 4231 验证）
│   │   ├── mset_hash.{hpp,cpp}     #   Mset-XOR-Hash ※VMPQ 半诚实路径已不使用（D16）
│   │   ├── random.{hpp,cpp}        #   CSPRNG + 确定性 PRNG（复现实验用）
│   │   ├── config.{hpp,cpp}        #   JSON 配置与校验
│   │   └── iprf.{hpp,cpp}          ❌ 未实现，阻塞于 Q9
│   ├── shared/                     ✅ 第 2 层：两协议共用
│   │   ├── secret_sharing.{hpp,cpp}#   Ring / Mod / XorBit 三套强类型共享
│   │   ├── database.{hpp,cpp}      #   表抽象 + one-hot/LCTE 编码辅助
│   │   ├── mpc.{hpp,cpp}           #   SecureMul（Beaver + SPDZ MAC，q=2^127−1）
│   │   └── verify.{hpp,cpp}        #   HMAC 多集证明、SPDZ MAC 校验
│   ├── pir/
│   │   ├── voo_pir.{hpp,cpp}       ✅ V-OO-PIR 五算法（含 Refresh 与压力测试）
│   │   └── plinko.{hpp,cpp}        ❌ 未实现，阻塞于 Q9
│   ├── vmpq/                       ✅ 第 3 层：协议 A（半诚实）
│   │   ├── params.hpp              #   schema、PIR 参数推导、2 的幂补齐
│   │   ├── node.{hpp,cpp}          #   服务器节点 + IVmpqChannel 抽象
│   │   └── vmpq.{hpp,cpp}          #   客户端：Init/Append/Count/SUM/AVG
│   ├── net/                        ✅ 传输
│   │   ├── transport.hpp           #   进程内传输抽象（opaque payload）
│   │   ├── local_transport.cpp     #   进程内实现（延迟/篡改注入）
│   │   └── grpc_vmpq.{hpp,cpp}     #   真实 gRPC 通道 + 服务端
│   ├── apps/                       ✅ vmpq_server / vmpq_client
│   └── mpraq/                      ❌ 第 3 层：协议 B（完整）—— 尚未开工
├── tests/                          ✅ 14 个测试程序、317 项用例
├── bench/                          ✅ bench_vmpq（VMP-07）
└── TASK_PLAN.md                    # 本文档
```

**与最初计划的偏差**（均已记录在 §5 决策台账）：

| 计划 | 实际 | 原因 |
|---|---|---|
| `core/iprf` | 未实现 | 阻塞于 Q9 |
| `net/grpc_transport.cpp` | → `net/grpc_vmpq.cpp` | 通道接口是 VMPQ 专属的 `IVmpqChannel`，比泛化的 opaque transport 更直接 |
| `shared/database` 含"滑动窗口" | 已移除 | 决策 D8：不支持数据库更新 |
| `mpc`/`verify` 被 VMPQ 使用 | VMPQ 不引用它们 | 决策 D16：半诚实版移除全部 proof；这两个模块留给 MPRAQ |

**旧 `src/common`、`src/client`、`src/server` 已按决策 D9 删除**（迁移对照见 §3.3）。
删除的触发点是新 `vmpq_server` 与旧目标重名导致 CMake 冲突——正好是清理的时机。

## 5. 关键技术决策（已定，附理由 —— 变更需在此追加记录）

**D1. 共享底座先行的分层架构。**
理由：两个系统共享「环运算 + 秘密共享 + PRF + 传输 + MPC」约 60% 基础设施。先做底座可避免重复实现，且底座有独立测试，后续两条协议线可并行推进。

**D2. 传输层从「单向表上传」改为「请求-应答」，并提供进程内实现。**
理由：两个协议的核心都是 `查询 → 应答`（V-OO-PIR 的 Query/Answer、Plinko 的 QueryGen/ServerResp）。现有代码只有上传通道，无法承载。
**进程内 transport 是关键工程决策**：单进程可起"客户端 + 两台服务器"，并可注入延迟/丢包/恶意篡改。这让绝大多数开发和测试无需起真实 gRPC 服务，迭代速度提升一个数量级。

**D3. XOR 共享与加法共享两套并存，绝不混用。**
- VMPQ：加法共享 over `Z_{2^128}`（用于 one-hot 索引与属性值）。
- MPRAQ：**XOR 共享**用于 LCTE 特征比特（服务端应答是 XOR 累加），**加法共享**用于属性值。
理由：MPRAQ 的 PIR 应答结构与 XOR 代数一致（`v = v1 ⊕ v2`），而 `SecureMul` 需要加法共享。两者必须在类型/命名上严格区分，**建议用不同返回类型或强类型包装，让混用在编译期就报错**。现有 `AdditiveShare` 只覆盖加法，XOR 共享需新增。

**D4. VMPQ 的验证机制保留接口、默认关闭。**
理由：半诚实版本无需验证；但接口保留后，后续开启验证即可作为"恶意模型"的扩展实验，不需要重构。

**D5. 参数全部走配置，禁止硬编码。**
理由：论文实验要扫参数（`l`、`N`、`λ`、`P` 谓词数），硬编码无法完成评测。

**D6. 测试用已知答案验证，不只验"跑通"。**
理由：密码学协议最危险的失败模式是**结果沉默地错误**。每个算法都必须有确定性随机源下的期望值测试。

**D7. 阈值规则以 S3PIR 的 `FindCutoff` 为准，不采用 VMPQ 论文的 median。**
理由：S3PIR 有官方参考实现可逐行对照，工程风险最低；负责人已确认 VMPQ 论文自身存在若干问题（见 `PIR_SPEC.md` §0）。VMPQ 特有的验证层仍然实现，作为可选开关。
**推论**：论文表述与已裁决实现不一致时，**以实现为准**，并在代码注释里标注论文原文与差异原因。

**D8. 不支持数据库更新 / 滑动窗口，数据库一次性装载。**
理由：S3PIR 论文本身将数据库更新列为开放问题，自行推导增量方案会引入未经证实的正确性假设。装载时按预期最大规模预留 `N = P·s`。
**推论**：`VMP-06` 删除；`Append` 仅指一次性写入。
⚠️ **但 hint 的在线 `Refresh` 不属于此列，必须实现** —— 它是协议正确性的组成部分。

**D9. 允许推翻既有代码：旧代码只作参考，不做兼容性包袱。**
理由：负责人确认 `src/common`、`src/client`、`src/server` 是早期探索产物，且 MPRAQ 的设计尚未定稿。新架构按 §4 重建，只把有价值的组件（AES_PRF、uint128 工具、CryptoPP PRNG）**迁移**而非适配。
**推论**：越界写、table_id/varlist_id 双 ID 语义、硬编码分块大小等历史问题**通过重写消除，不再单独修复**。
**已执行**：三个旧目录与旧协议已于 `VMP-08` 收尾时删除（迁移对照见 §3.3）。

**D10. 共享底座必须对 MPRAQ 的未定设计保持中立。**
理由：负责人尚有多个 MPRAQ 设计点未决（见 §7.6）。底座若过早绑定某一具体选择，后续改设计会造成大范围返工。
**推论**：`core/` 与 `net/` 只提供机制不提供策略；`shared/` 的 `SecureMul` 等接口需同时容纳"每查询现生成 Beaver triple"与"离线预处理批量预生成"两种实现路径。

**D11. ⚠️ 已证实：`2^{-1}` 在 `Z_{2^128}` 中不存在，SecureMul 的论文公式在 2 的幂环上不成立。**
发现过程：`FND-02` 的单测在实现 `inv2Pow2k()` / `mulHalf()` 时暴露。数学事实：
- `gcd(2, 2^128) = 2 ≠ 1` ⇒ **2 在 `Z_{2^128}` 中不可逆**，不存在 `2^{-1}`；
- `2^127` 不是 `2^{-1}`：它本身是**偶数**，是**零因子**（`2^127 · 2 = 2^128 ≡ 0`）；
- 因此 `x · 2^127` 并非"除以 2"：连 `x = 2` 都得到 0，只有极特殊输入才碰巧等于 `x/2`。

**影响**：MPRAQ 论文 Algorithm 5（`SecureMul`）的
`z_p = ⟨c⟩_p + d·⟨b⟩_p + e·⟨a⟩_p + e·d·2^{-1}`
在 `Z_{2^k}` 上**对奇数 `e·d` 无法正确重建**（约一半的输入会算错）。论文把共享取在"128-bit ring"上，这一项是数学上的漏洞。

**处置**：`core/field` 已将事实固化为带注释的 API ——
- `modInversePow2(a, k)` 对偶数**显式抛异常**（不再静默返回错值）；
- `mulHalf()` 更名为主名 `mulBy2Pow127()`，注释明确它不是除法；旧名保留为兼容别名；
- 单测 `Pow2_127IsEvenZeroDivisorNotInverse`、`OddNumbersCannotBeHalvedInPow2Ring` 固化该结论。

**待决**：这直接决定 §7.6 **Q1**（`SecureMul` 的代数结构）必须选**奇模数**。倾向 `q = 2^127 - 1`（梅森素数）：`core/field` 的 `mulMod/addMod/subMod/modInverse/reduce` 已全部在该模数下测试通过，且 `2^{-1} = 2^{126}` 存在。**`MPA-05` 仍建议等 Q1 正式确认后再做。**
⚠️ VMPQ 的 `Multiply` 协议不用 `2^{-1}`，不受此影响。
⚠️ 若最终选素数域，属性值共享的表示会与 `Z_{2^128}` 的 one-hot 共享不同，需评估是否引入域转换开销。

**D12. ⚠️ 已证实：加法共享不保持 XOR 同态，凡 parity 语义为 ⊕ 的数据必须用 XOR 共享承载。**
发现过程：`FND-12`（`shared/database`）实现 `ShareTable::ColumnXor` 时暴露。数学事实：
- 记两记录为 s、t，其 Z_{2^128} 加法共享为 (a, s−a) 与 (b, t−b)，则
  `(a ⊕ b) + ((s−a) ⊕ (t−b)) ≠ s ⊕ t`（已用 Python 独立验证）。
- 因此"两服务器各自对列做 XOR、客户端再把两半 XOR"这条路径**只对 XOR 共享成立**。

**影响 VMPQ**：V-OO-PIR 的 parity 语义是 ⊕（论文 Algorithm 1 的 `P_j = ⊕_{i∈S} D[i]`），
所以参与列 parity 的数据必须用 **XOR 共享**——等价于 **Z_2 上的加法共享**（取值仅 0/1）。
这与论文"single-bit parity"的说法自洽：**单比特是必要条件**，因为只有 Z_2 上加法与 XOR 才重合。
实现时务必区分：VMPQ 的 one-hot 列共享走 XOR/Z_2，而属性值 E 的共享走 Z_{2^128} 加法。

**影响 MPRAQ**：无冲突——MPRAQ 本来就用 XOR 共享承载 LCTE 比特、加法共享承载属性值（决策 D3）。

**处置**：`ShareTable::ColumnXor` 已加注释说明该前提；测试 `XorDoesNotCommuteWithAdditiveShares`（反例）
与 `ColumnXorWorksWhenEntriesAreXorShared`（正例）双向固化。**这是 `PIR-01` 的首要集成风险点，务必先写小规模验证用例。**

**D13. 验证等式的两侧（F 与 C）必须是纯 XOR，不得掺入 Mset-XOR-Hash 的基准值 H(0,r)。**
发现过程：`FND-14` 写 `PIRVerifier::VerifyRelation` 的第一组测试时暴露。
- 验证等式为 `F ⊕ C = MAC(x,v) ⊕ MAC(fill, v_fill)`。
- 该等式成立的代数依据是：**F 与 C 分别是各自集合上元素标签的纯 XOR**，
  于是两集合的交集在 ⊕ 中两两抵消，只剩**对称差**。
- 若任一侧多带一个基准项（或多带任何公共项），两侧就无法抵消，验证恒失败。

**协议模型（务必按此理解 `fill` 的含义）**：
```
客户端预存  F = ⊕ tag(hint 覆盖集合 X)
查询子集    S = X ∪ {目标项 x, 填充项 fill}
服务器返回  C = ⊕ tag(S)
⇒ F ⊕ C = tag(x) ⊕ tag(fill)
```
**目标项与填充项都不属于 hint 覆盖集合 X**——它们是查询时额外引入的两项：
目标项用于取出 `DB[x]`，填充项让两组子集结构对称、掩护目标。

**处置**：`ComputeHintProof` 实现为纯 XOR；`BaseTag()` 保留但注释明确禁止混入 F/C；
新增测试 `HintProofIsPureXorOfItemTags`（含"掺入基准值必须不同"的防回归断言）、
`HintProofAndSubsetValueAgreeOnSameSet`、`SymmetricDifferenceProperty`（直接验证对称差性质）。
**`PIR-01` 实现 `ServerResp` 时必须遵循同一约定。**

> 适用范围更新（见 D16）：D13 只对**启用验证**的路径有意义。VMPQ 半诚实版本已移除全部 proof，因此该约定在 VMPQ 路径上不再适用。

**D14. 🔴 勘误：MPRAQ 论文 Algorithm 5 的 SPDZ MAC 公式有误，照抄会导致校验恒失败。**
发现过程：`FND-13` 实现 `SecureMul` 时，值重建完全正确（`z = x·y` 全部通过），但
`mac == α·z` **恒不成立**。经符号化推导 + Python 独立验证确认是论文公式错误，而非实现问题。

论文原文（Algorithm 5）：
```
⟨z⟩_p   = ⟨c⟩_p + d·⟨b⟩_p + e·⟨a⟩_p + e·d·2^{-1}
⟨mac⟩_p = ⟨αc⟩_p + d·⟨αb⟩_p + e·⟨αa⟩_p + ⟨α⟩_p·e·d·2^{-1}     ← 末项多了 2^{-1}
```
**正确形式**：
```
⟨z⟩_p   = ⟨c⟩_p + d·⟨b⟩_p + e·⟨a⟩_p + e·d·2^{-1}      （此项正确）
⟨mac⟩_p = ⟨αc⟩_p + d·⟨αb⟩_p + e·⟨αa⟩_p + ⟨α⟩_p·e·d    ← 末项不应再乘 2^{-1}
```

**推导**：`z = c + d·b + e·a + e·d/2`，故正确 MAC 应为
`α·z = αc + d·(αb) + e·(αa) + α·e·d/2`。
论文把末项写成 `⟨α⟩_p·e·d·2^{-1}`，即又额外乘了一次 `2^{-1}`，
于是重建出的 `mac = αc + d·αb + e·αa + α·e·d/4 ≠ α·z`，校验必然失败。

**验证方式**：用符号化的 Python 脚本分别计算两种公式，各跑 3 轮随机取值，
论文公式 `correct=False`、修正公式 `correct=True`（见下表）。C++ 侧另有 15 项单测兜底。

| 公式 | 结果 |
|---|---|
| 论文 MAC 公式 | `mac ≠ α·z`（3/3 失败） |
| 修正 MAC 公式 | `mac = α·z`（3/3 通过） |

**处置**：`SecureMulServerPhase2` 按**修正公式**实现，源码注释里标注了论文原文与勘误原因。
**MPRAQ 论文投稿前必须修正 Algorithm 5。** 该错误源于 `2^{-1}` 的记账：
`z` 的末项已经含 `2^{-1}`，MAC 是 `α·z`，因此不应再有第二个 `2^{-1}`。

**D15. 🔴 V-OO-PIR 的三条工程约束（`VMP-01` 落地时暴露，都会静默削弱安全性/正确性）。**
发现过程：把 V-OO-PIR 接到 VMPQ 上时，单谓词 Count 大面积报「找不到 hint」。
逐层排查后确认不是协议 bug，而是三条此前未意识到的约束：

**(1) PIR 数据库大小必须是 2 的幂。** `part_num × part_size == n` 且两者都是 2 的幂
⇒ `n` 本身必须是 2 的幂。VMPQ 的真实条目数 `Σ_a 2^{l_a} × words_per_column` 一般不是，
**必须向上补齐**（补齐位填 0，不参与语义）。已实现 `VmpqParams::PaddedEntries()`。

**(2) `part_num` 必须足够大（>= 16），否则 `FindCutoff` 大量失效。**
过滤区间 `[1/2−1/16, 1/2+1/16]` 只占值域 1/8，区间内元素数常常不足 `P/2`。
实测 **P=6 时 hint 有效率仅 8%**（9/118）。`DerivePirParams` 现在对 `P < 16`
**显式抛错**，而不是静默产生一堆无效 hint。

**(3) ⚠️ `M = λ√n` 必须指「有效 hint 数」，不是「尝试次数」。**
这条最隐蔽：`FindCutoff` 会丢弃 35%~60% 的 hint。若只尝试 M 次，有效 hint 只剩
`0.4M~0.65M`，**等效安全参数从 λ 掉到约 0.5λ**，而未覆盖索引数按 `n·e^{−λ_eff/2}`
指数上升。
- 实测：λ=24、M=768 次尝试 → 仅 324 条有效 → λ_eff≈10 → 未覆盖 7/1024（与理论吻合）
- 改为「**持续生成直到攒够 M 条有效 hint**」后：768/768 有效，λ_eff=24，**未覆盖 0/1024**

**影响**：任何基于 V-OO-PIR 的实现都必须处理这三点，否则会出现「大部分时候能用、
偶尔查不到」的间歇性故障——正是最难定位的那类问题。

> 附注：这印证了决策 D11 的价值——若沿用 `Z_{2^k}`（2 不可逆），
> 这个 `2^{-1}` 记账错误会以"约一半输入算错"的形式出现，比现在更难定位。


**D16. ✅ VMPQ 半诚实版本移除全部 proof；论文用 Mset-XOR-Hash 的方式是错的。**
依据：负责人明确指示——半诚实模型下**默认服务器不会篡改应答**，因此 hint 证明 `F_j`
没有任何用处；论文把 Mset-XOR-Hash 用在这里本身也不成立。

**论文用法为何不成立**：客户端并不持有服务器的秘密共享，无法对**共享数据**预计算标签；
而 HMAC 不是线性的，因此 `C_0 ⊕ C_1 ≠ C(明文)`——验证等式在共享域上无法成立。
（这与决策 D13 是同一根源的两面：D13 说等式两侧必须是纯 XOR，而共享数据上根本得不到纯 XOR 的 C。）

**处置**：
- `VooPirClient` 的证明计算改为**可选且默认关闭**：两参数构造 ⇒ 不计算任何证明；
  只有显式传入 `mac_key` 才计算。`proof()` 在未启用时**抛异常**而非返回零标签。
- `VmpqClient` 的构造**不再接收 MAC 密钥**（半诚实路径不需要），API 上直接消除误用可能。
- `Refresh` 不再维护 proof。
- `core/mset_hash` 与 `shared/verify` 保留（MPRAQ 侧可能用得上），但**VMPQ 路径不引用**。

**实测收益**（window=1024, 768 hints, P=32/σ=32）：

| | HintInit 耗时 |
|---|---|
| 含 proof（论文做法） | 32.8 ms |
| **无 proof（半诚实）** | **9.0 ms** |

⇒ **约 3.6× 加速**；整个测试套件从 2.61 s 降到 0.88 s（约 3×）。

---

## 6. 任务分解

标记说明：`[ ]` 待办 · `[~]` 进行中 · `[x]` 完成 · `[!]` 阻塞

### 第 1 层：共享底座（✅ 全部完成）

| ID | 任务 | 产出/验收标准 | 依赖 |
|---|---|---|---|
| `[x]` FND-01 | 清理与骨架搭建 | 建立 §4 目录结构与 CMake target；旧代码保持可编译。**已完成**（旧目录保留待 FND-03 迁移后删除） | — |
| `[x]` FND-02 | `core/field`：环运算 | `Z_{2^128}` 加减乘、模 q 运算、逆元、序列化；**34 项单测全绿**。⚠️ 实现中发现 `2^{-1}` 语义问题，见决策 **D11** | FND-01 |
| `[x]` FND-03 | `core/aes_prf`：迁移与补强 | **已完成**。AES-128 ECB，输入块 `[w0,(dom<<16)\|w1,0,0]`（对齐 S3PIR 官方实现）。19 项单测，含 **FIPS-197 C.1** 向量验证与域分隔测试 | FND-01 |
| `[x]` FND-04 | `core/hash`：HMAC 与常量 | **已完成**。SHA-256 + HMAC-SHA256 + `MAC_k(i,v)=HMAC_k(domain‖i‖v)`；域常量集中在 `domain::` 命名空间。21 项单测，含 **RFC 4231 TC1/TC2** 与 **FIPS 180-2** 向量 | FND-01 |
| `[x]` FND-05 | `core/mset_hash`：Mset-XOR-Hash | **已完成**。`H(0,r) ⊕ ⊕H(1,x_i)`，验证了增量性、顺序无关、自逆（移除=再 XOR）、多集语义（重复项抵消） | FND-04 |
| `[ ]` FND-06 | `core/iprf`：可逆 PRF | `Gen / IF / IF^{-1}`；**关键测试：对任意 `(k, β)`，`IF(IF^{-1}(k,β))` 往返一致，且输出落在 `[0, n)`**。⚠️ 阻塞于 §7.6 **Q9** 的可行性确认 | FND-03 |
| `[x]` FND-07 | `shared/secret_sharing` | **已完成**。`RingShare`（Z_{2^128}）/ `ModShare`（Z_q）/ `XorBitShare` 三套**强类型**共享，编译期阻止混用。26 项单测 | FND-02 |
| `[x]` FND-08 | `net/transport` 接口 + 进程内实现 | **已完成**。`ITransportClient/Server` + `LocalTransport`（进程内、支持多阶段 relay、延迟注入、篡改/丢包钩子、请求日志）。15 项单测 | FND-01 |
| `[x]` FND-09 | 双服务器仿真测试框架 | **已完成**。`tests/support/test_cluster.hpp`：单进程 1 客户端 + 2 服务器，`DistributeVarList`/`DistributeOneHotTable`/`MakeMalicious`/`MakeUnresponsive`。10 项单测 | FND-08 |
| `[x]` FND-10 | gRPC transport + proto 重设计 | **已完成**。新协议 `proto/vmpq.proto`（InitTable / UploadEntries / PirQuery，移除早期表上传接口）；`net/grpc_vmpq` 提供 `GrpcChannel`（实现 `IVmpqChannel`）与 `VmpqServiceImpl`。旧的 `proto/pir_comm.proto` 已随之删除 | FND-08, Q5 |
| `[x]` FND-11 | 配置系统 | **已完成**。`core/config`：`JsonConfig/JsonValue`（带类型与范围校验、错误信息指出**完整路径**与实际类型）、`VmpqConfig`（含 `num_bucket` 必须是 2 的幂等校验）、`ServerConfig`、`QueryConfig`。26 项单测 | FND-01 |

**里程碑 M1**：✅ **已达成**（2026-09-10）。`ctest` 全绿（13 个测试可执行文件）；`TestCluster` 完成了"共享 → 传输 → 重建"的完整往返（见 `test_cluster.cpp` 的 `EndToEndShareTransportReconstruct`）。

**测试设施**：
- `tests/support/test_framework.hpp`：最小依赖的自研测试框架（不引入 gtest/catch2，避免外部依赖）。
- `tests/support/test_cluster.hpp`：双服务器仿真环境，复用 `shared/database` 的表抽象。
- 支撑代码编成 `tsb_test_support` 静态库，PUBLIC 依赖自动传递给各测试。
- 运行：`ctest`（全部）或 `./build/bin/test_<模块> [过滤串]`。

### 第 2 层：共享服务（✅ 全部完成）

| ID | 任务 | 产出/验收标准 | 依赖 |
|---|---|---|---|
| `[x]` FND-12 | `shared/database` 表抽象 | **已完成**。`PlainTable`/`ShareTable`/`ShareDatabase`，按 (行,列) 与按列访问、`ColumnXor`、one-hot 与 LCTE 编码辅助、位打包。31 项单测。⚠️ 暴露 XOR 语义问题，见决策 **D12** | FND-07 |
| `[x]` FND-13 | `shared/mpc`：SecureMul | **已完成**。Beaver triple + SPDZ MAC 的两阶段实现；模数为显式参数并强制奇数（D11）。15 项单测。⚠️ **发现并修正论文公式错误，见 D14** | FND-12, FND-14 |
| `[x]` FND-14 | `shared/verify` | **已完成**。`PIRVerifier`（V-OO-PIR 多集证明）、`MacVerifier`（单条 HMAC 校验 + 批量聚合）、SPDZ MAC（`GenerateMacKey`/`ShareAuthenticated`/`VerifyMac`）。29 项单测，含正反两面。⚠️ 暴露 F/C 必须为纯 XOR，见决策 **D13** | FND-05, FND-12 |
| `[x]` FND-15 | 恶意行为注入测试集 | **已完成**。`tests/test_adversary.cpp`：逐比特/逐字节篡改矩阵、重放、跨域重放、共享错配、退化参数、端到端传输篡改。22 项测试 | FND-14 |

**里程碑 M2**：`SecureMul` 与验证机制在恶意注入下全部检出，无误报。

### 第 3 层：检索原语（🟡 2/5）

| ID | 任务 | 产出/验收标准 | 依赖 |
|---|---|---|---|
| `[x]` PIR-01 | **V-OO-PIR 五算法** | **已完成**。`Hint`/`Query`/`Answer`/`Reconstruct`/`Refresh` 全部实现并验证（25 项）。含**全量扫描 1024/1024 零错误**与**300 轮持续 查询→刷新 压力测试** | FND-03, FND-12 |
| `[ ]` PIR-02 | V-OO-PIR 参数与批量优化 | 支持 `λ=80`、32-bit `V_j` 元素；单列（one-hot 的一列）hint parity 为 1 bit 的优化 | PIR-01 |
| `[x]` PIR-03 | V-OO-PIR 隐私性测试 | **已完成**。结构不变量、两种命中方式（case A/B）的查询形状不可区分、dummy 偏移每轮新鲜、请求中不含目标索引痕迹。4 项测试 | PIR-01 |
| `[ ]` PIR-04 | **Plinko 六算法** | `HintInit / GetHint / QueryGen / ServerResp / ClientRecon / Verify`（MPRAQ 论文 §III-C/§III-D 的六个算法）；`M=λ√n`，`q=M/2`，主 hint 选 `r/2+1` 分区、备份选 `r/2` | FND-06, FND-12 |
| `[ ]` PIR-05 | Plinko 备份 hint 与 Refresh | 备份 hint 提升（promotion）、swap_flag 处理、hint 刷新后仍可正确查询 | PIR-04 |

**里程碑 M3**：两个 PIR 原语都能在 `n` 达 `2^14` 规模下稳定完成随机点查询，结果 100% 正确。

### 第 4 层：VMPQ（半诚实）（✅ 全部完成）

| ID | 任务 | 产出/验收标准 | 依赖 |
|---|---|---|---|
| `[x]` VMP-01 | `Init` / `Append` | **已完成**。one-hot 编码 + 128 位打包 + XOR 共享分发 + 属性值加法共享；按 schema 分配服务器存储 | PIR-01 |
| `[x]` VMP-02 | 单谓词 Count | **已完成**。逐 word 走 V-OO-PIR 取回整列后本地数比特；对照明文计数逐取值验证 | VMP-01 |
| `[x]` VMP-03 | 多谓词 `Multiply` | **已完成（实现方式不同，见 §7.9 G4）**。`CountMultiPredicate`：逐列 PIR 取回后在客户端本地按位与再计数。等价且无需 MPC——本实现的检索粒度是整列，客户端本就拿得到列向量 | VMP-02 |
| `[x]` VMP-04 | Sum 聚合 | **已完成（实现方式不同，见 §7.9 G5）**。`SumWithFilter`：利用「每个属性都是 one-hot 索引、取值域为 2^l」这一模型，`SUM = Σ_v v·Count(filter ∧ attr==v)`，完全复用 Count 链路 | VMP-03 |
| `[x]` VMP-05 | Avg / Var / Std | **已完成**。`AvgWithFilter` 与精确整数矩 `Aggregate{count,sum,sum_sq}`；方差/标准差由调用方从矩推导，**不引入浮点误差**（设计目标要求结果精确） | VMP-04 |
| `[x]` VMP-06 | 半诚实开关 | **已完成（按 D16 重新定义）**。半诚实版本**直接移除全部 proof**，而非"跳过 Verify 分支"。`VmpqClient` 不再接收 MAC 密钥；`VooPirClient` 的证明默认关闭。验证接口保留在 PIR 层供将来恶意模型使用 | VMP-02 |
| `[x]` VMP-07 | 基准测试 | **已完成**。`bench/bench_vmpq.cpp`，输出 Init/Count/多谓词/SUM 延迟、服务端与 hint 存储、单次查询的 PIR 次数与请求字节。实测结果见 §7.10 | VMP-05 |
| `[x]` VMP-08 | 端到端 demo | **已完成**。`apps/vmpq_server` + `apps/vmpq_client`，两台独立进程 + 真实 gRPC，跑通 Init→Count→多谓词→SUM，全部与明文一致。输出存于 `doc/design/demo_vmpq.txt` | VMP-07, FND-10 |

**里程碑 M4**：VMPQ 半诚实版本端到端跑通，Count/Sum/Avg 结果与明文一致，基准数据出表。

### 第 5 层：MPRAQ（完整）（⬜ 未开始）

| ID | 任务 | 产出/验收标准 | 依赖 |
|---|---|---|---|
| `[ ]` MPA-01 | **LCTE 编码** | `LCTE(x) = ([x<r_1],...,[x<r_m])`；边界：`x < r_1` 全 1、`x ≥ r_m` 全 0；阈值对齐检查（阈值不在 R 内时按论文"调整到最近值或 abort"） | FND-02 |
| `[ ]` MPA-02 | 谓词解析 | 谓词公式 → LCTE 列索引；支持 `∧ ∨ ¬`；De Morgan 优化形式 `Φ = ¬(∨P_{i0}) ∧ (∧P_{i1})` | MPA-01 |
| `[ ]` MPA-03 | `Init` | 论文 Algorithm 3：LCTE 编码 → HintInit → XOR 分片特征 + 加法分片属性 + HMAC 验证值 → 上传 | PIR-04, MPA-01 |
| `[ ]` MPA-04 | `AggQuery` - Count | 论文 Algorithm 4：逐列 PIR 检索 → 验证 → 本地布尔组合 → 数 1 的个数 | MPA-03 |
| `[ ]` MPA-05 | `SecureMul` | 论文 Algorithm 5：Beaver triple + SPDZ MAC；含客户端与两服务器三方的消息流 | FND-13, FND-14 |
| `[ ]` MPA-06 | `AggQuery` - Sum / Avg | Sum 逐记录 `SecureMul(f_i, E_i)` 后累加；Avg = Sum/Count；任一验证失败即 abort | MPA-04, MPA-05 |
| `[ ]` MPA-07 | 恶意模型验证路径 | 默认开启验证；篡改注入必须 100% 检出并 abort | MPA-06, FND-15 |
| `[ ]` MPA-08 | 端到端 demo | `mpraq_client` / `mpraq_server` 跑通范围查询 + 多谓词 + 三种聚合 | MPA-07, FND-10 |
| `[ ]` MPA-09 | 参数与复杂度验证 | 实测 `O(n/r)` 在线查询、`O(log n)` 更新、`O(r)` 客户端存储三条曲线 | MPA-08 |
| `[ ]` MPA-10 | 论文补全 | 补 `abstract` / `introduction` / `evaluate` / `conclusion`（当前全是 "my xxx" 占位）；修正标题 "Pridicate" 笔误 | MPA-09 |

**里程碑 M5**：MPRAQ 端到端跑通，恶意服务器注入全部检出，实验数据支撑论文 §evaluate。

---

## 7. 接口契约（冻结，降低并行开发冲突）

新对话开工前请确认自己负责的模块落在哪个契约面上。**契约变更需在本节同步更新并在文末记录。**

### 7.1 秘密共享（`shared/secret_sharing.hpp`）
```cpp
// 加法共享：Z_{2^128}（VMPQ 全用；MPRAQ 用于属性值）
std::pair<uint128_t, uint128_t> AdditiveShare(uint128_t v);
uint128_t AdditiveReconstruct(uint128_t s0, uint128_t s1);

// XOR 共享：比特级（MPRAQ 用于 LCTE 特征比特）—— 新增
template<typename T> std::pair<T,T> XorShare(T v);   // s0 = rand, s1 = v ^ s0
template<typename T> T XorReconstruct(T s0, T s1);
```
> **禁止**把 XOR 共享的结果喂给 `AdditiveReconstruct`（反之亦然）。建议用强类型标签在编译期拦截。

### 7.2 传输（`net/transport.hpp`）
```cpp
struct Message { std::vector<uint8_t> payload; };

class ClientTransport {                        // 客户端 → 指定服务器
  virtual Message Send(int server_id, const Message&) = 0;
};
class ServerTransport {                        // 服务器 → 客户端
  virtual void Register(std::function<Message(const Message&)>) = 0;
};
```
- `LocalTransport`：进程内直连，支持 `setLatencyMs()` 与 `tamperHook()`。
- `GrpcTransport`：部署用，消息分块需按**字节数**计算，尊重 gRPC 默认 4MB 上限。

### 7.3 V-OO-PIR（`pir/voo_pir.hpp`）
```cpp
HintSet  HintInit(uint32_t lambda, uint64_t n, const Database& D);
QuerySet Query(const HintSet& T, uint64_t x, uint64_t n);           // → (S, S')
Answer   ServerAnswer(const QuerySet& q, const DBShares& share);      // → (P, P')
Result   ClientRecon(const Answer& a0, const Answer& a1, const HintSet& T, uint64_t x);
HintSet  Refresh(const HintSet& T, uint64_t x, const Result&, uint64_t n);
bool     Verify(uint64_t x, const Proof&, const Answer&, const HintSet& T, uint64_t n);
```

### 7.4 Plinko（`pir/plinko.hpp`）
```cpp
HintSet  HintInit(uint32_t lambda, uint64_t n, const Database& D);
Hint     GetHint(const HintSet& hs, uint32_t alpha, uint32_t beta);   // 内部工具
Query    QueryGen(uint64_t x, const ClientState& st);
Answer   ServerResp(const Query& q, const DBShares& share, const Key& k);
std::tuple<Value, C, Value> ClientRecon(const Answer& a0, const Answer& a1,
                                        const HintSet&, const Recoinfo& h, const Key& k);
bool     Verify(Value v, C c, Proof F, Value v_fill,
                uint64_t x, uint64_t fill, const Key& k);
```

### 7.5 SecureMul（`shared/mpc.hpp`）
```cpp
struct BeaverTriple { uint128_t a, b, c; };
struct MulResult { uint128_t z; uint128_t mac; };   // mac = alpha * z，验证用
MulResult SecureMul(uint128_t f,                       // 客户端持有的 filter bit
                    uint128_t E_share_server0,
                    uint128_t E_share_server1,
                    const BeaverTriple& triple,
                    uint128_t alpha);
```

### 7.6 MPRAQ 待定设计决策（**需负责人拍板，阻塞第 5 层**）

负责人已确认：MPRAQ 的多个设计点尚未定稿。以下每项都列出了选项与**我的推荐**。这些决定会显著影响 `core/` 与 `shared/` 的接口形态，请在开工第 5 层前明确。未决期间共享底座按 D10 保持中立，不阻塞第 1–4 层。

| # | 问题 | 选项 | 我的推荐 | 影响面 |
|---|---|---|---|---|
| **Q1** | ⚠️ **`SecureMul` 与 SPDZ MAC 在哪个代数结构上运算？**（已由 D11 证明必须选奇模数） | (a) `Z_{2^128}`（现有代码与论文所述）<br>(b) 奇模数，推荐 `q = 2^127 - 1`（梅森素数） | **(b)**。D11 已证实：`Z_{2^128}` 中 2 不可逆，论文公式 `e·d·2^{-1}` 对奇数 `e·d` 必然算错（约一半输入）。`q = 2^127-1` 下 `2^{-1} = 2^{126}` 存在，且 `core/field` 的 `mulMod/addMod/subMod/modInverse/reduce` 均已在该模数下测试通过。<br>⚠️ 代价：MPRAQ 属性值共享的表示将与 VMPQ 的 one-hot 共享不同，需评估转换开销 | `core/field`、`shared/mpc`、`MPA-05` || ✅ | **实现已按 (b) 完成并验证**：`shared/mpc` 用 `q = 2^127−1` 实现，15 项测试全绿（含对照明文乘法、奇数积、篡改检出）。**待负责人正式确认后可将 Q1 标记为已裁决** |
| **Q2** | Beaver triple 何时生成？ | (a) 每查询现生成<br>(b) 离线预处理批量预生成（RandBit/RandInt 式） | **先 (a) 正确性优先，接口预留 (b)**。论文 §Aggregation 用的是 (a) 的表述 | `shared/mpc` 接口、`MPA-05/06` |
| **Q3** | SPDZ 的 MAC 密钥 `α` 是全局一份还是每查询一份？ | (a) 全局<br>(b) 每查询 | **(a) 全局**，在 `Init` 阶段生成并存于客户端 `st`；实现最简单且与论文"global MAC key"表述一致 | `shared/verify`、`MPA-03` |
| **Q4** | 范围查询 `[t_a, t_b)` 怎么映射到 LCTE 列？ | (a) 检索两列（下界、上界）本地做 `¬P_a ∧ P_b`<br>(b) 每列单独一次 PIR 往返 | **(a)+(b)**：语义用 (a)，传输上用**批量 PIR**（见 Q5） | `mpraq/lcte`、`MPA-01/02` |
| **Q5** | ⚡ **一次查询要检索很多列（`2^l` 列中的多列），PIR 怎么组织？** | (a) 每列一次独立 PIR 往返<br>(b) **一次往返批量检索多列**（同一 hint 集、服务器一遍扫描算多个 parity）<br>(c) 打包成宽 entry | **(b)** —— 这是 MPRAQ 性能的**决定性设计**。多谓词查询需检索 `2n` 列（n 个区间），逐列往返会让延迟和通信量线性膨胀。S3PIR 的服务器应答是纯 XOR 线性结构，天然可并行算多个 parity | 影响 `pir/plinko` 与 `net/transport` 的**接口形态**，**建议优先定这一项** |
| ✅ | **Q5 已裁决（负责人）**：VMPQ 论文的 PIR 一次查询产生一个查询集，无法避免"把所有谓词的列都发过去"；因此**就把所有谓词全部发过去，客户端在本地做谓词组合**。暂不做批量 PIR。 | 影响 `VMP-02/03/04`（已按此实现）、`FND-10` proto 形态（按"一次性发送全部谓词查询集"设计） |
| **Q6** | 特征值超出 LCTE 域 `R` 时怎么办？ | (a) 调整到最近有效值<br>(b) abort | **(a)** 论文 §Multi-Predicate Filtering 二者都提了。倾向 (a) 并记警告日志，避免因边缘数据导致查询失败；同时在**装载期**就校验数据落在 `R` 内并告警 | `mpraq/lcte`、`MPA-01/02` |
| **Q7** | 谓词操作符支持范围？ | 论文只定义左阈值 `x < θ` | **MVP 支持 `eq / lt / le / gt / ge / range`**，全部归约到左阈值：`gt`/`ge` 用"列上方全 0 区"判定（需确认 LCTE 单调性支撑），`eq` 用 `[v, v+1)` 两次左阈值 | `mpraq/lcte`、`MPA-02` |
| **Q8** | 布尔组合支持 `∧ ∨ ¬` 到什么程度？ | 论文提了三种但 De Morgan 优化只覆盖 AND-of-ranges | **MVP 只做 AND（合取）**，`∨`/`¬` 接口预留。论文的 `Φ = ¬(∨P_{i0}) ∧ (∧P_{i1})` 本质仍是合取形式 | `MPA-02/04` |
| **Q9** | iPRF 怎么构造？ | (a) 基于 AES-PRF 加可逆层<br>(b) 现成库 | **(a)** 复用 `core/aes_prf`。⚠️ **这是 `FND-06` 的最大技术风险**，需先做可行性验证（Plinko 的 `IF`/`IF⁻¹` 要求双向可计算，不是任意 PRF 都能直接加逆） | `core/iprf`、`FND-06`、`PIR-04` |
| **Q10** | Plinko 参数怎么取？ | `n`、客户端存储 `r`、分区数 | 先按论文 `M = λ√n`、`q = M/2` 实现，参数走配置；`r` 的具体取值待 benchmark 后定 | `PIR-04`、`MPA-09` |
| **Q11** | MPRAQ 聚合类型范围？ | 论文正文提 COUNT/SUM/AVG，另讨论 VAR/STD | **MVP 做 COUNT / SUM / AVG**，VAR/STD 作为扩展（按论文可由 SUM/COUNT 与平方和推导） | `MPA-06` |

**关键路径提示**：**Q5（批量 PIR）与 Q9（iPRF 可行性）是两项最高风险**。建议在开工第 5 层前，先各做一个最小验证原型——Q5 决定传输层接口，Q9 决定检索层能否落地。

### 7.7 MPRAQ 查询配置 schema（`config/mpraq_query.json`）
计划支持（待负责人确认字段命名）：
```json
{
  "time_range": { "start": 1700000000, "end": 1700086400, "end_inclusive": false },
  "filters": [
    { "attribute": "patient_id", "op": "eq", "value": 3 },
    { "attribute": "heart_rate", "op": "range", "min": 60, "max": 100 }
  ],
  "combine": "and",
  "aggregate": "avg",
  "aggregate_attribute": "blood_glucose"
}
```
支持的操作符目标集合：`eq / neq / lt / le / gt / ge / range`，`combine ∈ {and, or, not}`。

---

### 7.8 遗留问题台账（开工前必读）

| # | 位置 | 问题 | 状态 |
|---|---|---|---|
| ~~L1~~ | `src/pir/voo_pir.cpp` `Refresh` | ✅ **已解决**。对齐官方 `TwoSVClient::Online` 的 replenish 部分与 `TwoSVServer::replenishHint` 后修复。关键三点：(1) parity **要**包含 extra 项（官方 server.cpp:109 在累加真实半区前先 XOR 进 extra）；(2) 刷新时 indicator = !(sel(ℓ)<c)，即取**不含 ℓ** 的半区再换入目标项；(3) 查询时哑组用**全新随机偏移**（哑组项不在 parity 中，无需相消）。验证：同一索引连续 200 轮刷新全部正确、全量扫描 1024/1024 零错误 |
| ~~L2~~ | `RefreshMaterial` | ✅ **已解决**（随 L1）。`GenerateRefreshMaterial` 现按官方 `replenishHint` 语义返回两个半区的 parity（含 ℓ、不含 extra） |
| L3 | `VooPirClient::proof` / `Refresh` 的 proof 维护 | **对 VMPQ 已不适用**（决策 D16：半诚实版本移除全部 proof）。PIR 层的证明接口保留为可选，仅在显式传入 `mac_key` 时启用；启用后 `Refresh` 不会更新证明，该缺口留给将来的恶意模型扩展 | 不阻塞 VMPQ；MPRAQ 若要用需补齐 |

> ✅ **台账已清空**：L1/L2 在 `Refresh` 修复后关闭；L3 因决策 D16（半诚实版移除 proof）
> 对 VMPQ 不再适用。当前**没有任何阻塞 VMPQ 的遗留缺陷**。

---

### 7.9 VMPQ 实现与论文的已知工程差异

| # | 差异 | 原因 / 影响 |
|---|---|---|
| G1 | **检索粒度**：论文把「一整列」作为一次 PIR 检索的 entry（hint parity remains a single bit），本实现把一列按 128 位打包成若干 word，**每个 word 一次 PIR**，故一次列查询需 ⌈N/128⌉ 次 PIR | 为复用已验证的标量 entry PIR 层而不改动其接口。代价：hint 消耗按 word 数放大。优化方向：把 V-OO-PIR 泛化为向量 entry |
| G2 | **属性值 E 的 SUM 链路尚未接入**（VMP-04） | 需要 SecureMul（已实现于 `shared/mpc`）。下一批任务补齐 |
| G3 | **验证默认关闭**（决策 D4） | 半诚实版本不需要；`VMP-06` 提供开关 |
| G4 | **多谓词 Count 不用 Multiply 协议**：直接本地按位与 | 论文的 `Answer` 只返回单个计数值 `[β]_p`，客户端拿不到整列，故合取需要 MPC；本实现的检索粒度是**整列**（逐 word PIR），客户端本就重建出两个列向量，本地与运算等价且更简单。**代价差异**：论文的 `Multiply` 每加一个谓词多一轮 Beaver triple 交互；本实现每个谓词多 ⌈N/128⌉ 次 PIR |
| G5 | **SUM 不用 SecureMul**：`SUM = Σ_v v·Count(filter ∧ attr==v)` | VMPQ 模型里每个属性都是 one-hot 索引、取值域有限，因此 SUM 可归约为若干 Count。**代价**：需 `|domain(attr)|` 次 Count 查询（每次 ⌈N/128⌉ 次 PIR）；论文的 Multiply 是 O(1) 次查询但需要 Beaver triple。此处取"正确优先、复用已验证链路" |

---

### 7.10 VMP-07 实测数据

环境：本机 GCC 11 / `-O3`，单线程；λ=24，单属性域 2^6=64，双属性同域。
运行：`./build/bin/bench_vmpq`（完整输出存于 `doc/design/bench_vmpq.txt`）。

| N | P | σ | M(hints) | Init (ms) | Count×1 (ms) | Count×2 (ms) | SUM (ms) | PIR/查询 | 服务端 (KB) | hint (KB) | 请求 (B) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 512 | 32 | 16 | 544 | 6.6 | 0.06 | 0.10 | 6.5 | 4 | 32 | 19 | 272 |
| 1024 | 32 | 32 | 768 | 9.1 | 0.14 | 0.25 | 16.2 | 8 | 64 | 27 | 544 |
| 2048 | 64 | 32 | 1087 | 18.4 | 0.48 | 0.82 | 53.8 | 16 | 128 | 39 | 2176 |
| 4096 | 64 | 64 | 1536 | 26.1 | 1.20 | 2.22 | 136.4 | 32 | 256 | 55 | 4352 |

论文取值 λ=80、N=1024：M=2560、Init=30.1 ms、hint=92 KB、服务端=64 KB。

**可验证的伸缩规律**：
- `PIR/查询 = ⌈N/128⌉`，即**按位打包把每列的 PIR 次数压到 N/128**。
- **多谓词开销严格随谓词数线性增长**（Cnt2 ≈ 2×Cnt1），与「所有谓词列一次取回」的口径一致。
- **SUM 开销 = |domain| × 2 × Count**（N=1024 时实测比值 116 ≈ 64×2），
  这是 §7.9 G5「SUM 归约为 Count」的直接代价，也是后续最值得优化的点。
- 服务端存储按位打包后为 `|κ|·N·2^l/128`，比论文口径小 128 倍。

⚠️ **与论文数值不可直接对比**：论文把整列作为一次 PIR 的 entry，本实现是每 word 一次，
请求次数是 ⌈N/128⌉ 倍但每次规模更小（见 §7.9 G1）。此处只报告本实现的绝对量级与伸缩趋势。

---

### 7.11 VMP-08 真实 gRPC 端到端 demo 结果

两台**独立进程**的服务器 + 一个客户端，走真实 gRPC（TCP 回环 + protobuf 序列化）。
完整输出：`doc/design/demo_vmpq.txt`。

```
./build/bin/vmpq_server config/server_vmpq_0.json   # :50051
./build/bin/vmpq_server config/server_vmpq_1.json   # :50052
./build/bin/vmpq_client config/client_vmpq.json
```

| 阶段 | 结果 |
|---|---|
| 连接 | 两台服务器均就绪 |
| Init（编码 + XOR 共享 + 上传 + 离线 hint） | 13.2 ms |
| 单谓词 Count ×8 | 24.9 ms，**与明文 0 处不一致** |
| 多谓词 Count(p0=3 ∧ p1=5) | 一致；**PirQuery RPC 次数 = 1**（Q5 在网络层得到验证） |
| SUM(filter p0=2, 求和 p1) | 一致；117 ms（= |domain|×2 倍 Count，见 §7.10） |
| 服务器账目 | 每台 86 次 RPC / 1184 个查询集（两次运行累计），两台**完全对称** |

**Q5 在网络层的验证**：`GrpcVmpq.MultiPredicateSendsAllQueriesInOneRpc` 断言
"2 个谓词 ⇒ 1 次 RPC 但携带 2×⌈N/128⌉ 个查询集"，实测通过。
这正是"把所有谓词的列一次性发过去、客户端本地组合"在协议上的落地。

---

## 8. 论文参数与基线（写 bench 时对照用）

### VMPQ 实验设置（论文 §V-B）
- 安全参数 `λ = 80`；`V_j` 元素 32-bit（`|v| = 32`）。
- 服务端数据库值大小固定 **16 字节**。
- 列数 `2^l`，实验中 `l = 14, 20, 28`。**`l = 14`（16384 列）时在线查询开销与 Waldo 相当**，是最有参考价值的对比点。
- 窗口 `N` 最大 `2^18`（受本地算力限制）。
- 单谓词查询检索的是 shared one-hot index 的**一行**（`N = 1`）。
- 服务端存储：`|κ|·(N + N·2^l)`；论文报告范围 **48KB ~ 12MB**。
- 客户端 hint 存储：`λ√(2^l)(|j|+|v̂_j|+|e_j|+|P_j|+|F_j|) + 0.5λ√(2^l)(|j|+|v̂_j|+|P'_j|+|F'_j|)`。
- 在线查询时间：V-OO-PIR **0.074 ms ~ 0.996 ms**；DPF-PIR 基线 0.042 ms ~ 0.817 ms。
  > ⚠️ 注意：DPF-PIR 在线更快，VMPQ 的优势在**通信量的子线性**与**服务器数从 3 降到 2**。bench 报告时不要误读成"处处更快"。
- 流式更新：hint parity/proof 用 XOR 增量更新，开销恒定，上限 **420 KB**。
- 实验负载比例：**90% append / 10% query**。

### S3PIR 官方实验数据（V-OO-PIR 的检索底座，bench 对照用）
单线程 / AWS m5.8xlarge / λ=80 / entry 32B（完整表见 `doc/design/PIR_SPEC.md` §7.2）：
- `N=2²⁰`：两服务器在线 2.26 KB / 0.12 ms，客户端存储 3.76 MB。
- `N=2²⁴`：两服务器在线 8.64 KB / 0.54 ms，客户端存储 15.04 MB。
- `N=2²⁸`：两服务器在线 34.1 KB / **2.7 ms**，客户端存储 60.16 MB，离线 842 s。

> ⚠️ 再次提醒对照 VMPQ 的实验结论：V-OO-PIR 在线时间 0.074–0.996 ms **慢于** DPF-PIR 基线的 0.042–0.817 ms。VMPQ 的优势在**通信量的子线性**与**服务器数 3→2**，不是在线延迟。

### 复杂度对照（论文 Table I）
| 阶段 | VMPQ 通信 | VMPQ 计算 |
|---|---|---|
| Query | `2√(2^l)·|v|` | `2√(2^l)·Cmp + (√(2^l)/2)·Prf` |
| Answer | `N` | `(N·2^l)·Xor` |
| Verify | `|κ|·N` | `(N·2^l)·Xor` |

### MPRAQ 效率目标（论文 §goals）
- 在线查询时间与通信 `O(n/r)`；更新 `O(log n)`；客户端存储 `O(r)`；离线预处理 `O(n)`。
- `r` = 客户端存储位数（Plinko 参数），`n` = 记录数。

---

## 9. 任务看板（最新状态，请随时更新）

```
第 1 层 共享底座                              ✅ 全部完成（11/11）
  FND-01 目录与 CMake 骨架                      [x] 完成
  FND-02 core/field                             [x] 完成（34 项测试）
  FND-03 core/aes_prf                           [x] 完成（19 项，含 FIPS-197 向量）
  FND-04 core/hash                              [x] 完成（21 项，含 RFC 4231 向量）
  FND-05 core/mset_hash                         [x] 完成
  FND-06 core/iprf                              [!] 阻塞于 Q9
  FND-07 shared/secret_sharing                  [x] 完成（26 项）
  FND-08 net/transport + 进程内                  [x] 完成（15 项）
  FND-09 双服务器仿真框架                        [x] 完成（10 项）
  FND-10 gRPC transport + proto 重设计           [x] 完成
  FND-11 配置系统                                [x] 完成（26 项）
第 2 层 共享服务                              ✅ 全部完成（4/4）
  FND-12 shared/database                        [x] 完成（31 项）
  FND-13 shared/mpc SecureMul                   [x] 完成（15 项）
  FND-14 shared/verify                          [x] 完成（29 项）
  FND-15 恶意行为注入测试                        [x] 完成（22 项）
第 3 层 检索原语                              🟡 2/5（Plinko 阻塞于 Q9）
  PIR-01 V-OO-PIR 五算法                        [x] 完成（25 项，含压力测试）
  PIR-02 参数与批量优化                          [ ] 未开始
  PIR-03 隐私性结构检查                          [x] 完成（4 项）
  PIR-04 ~ PIR-05  Plinko                       [ ] 未开始
第 4 层 VMPQ                                  ✅ 全部完成（8/8）
  VMP-01 Init/Append                            [x] 完成
  VMP-02 单谓词 Count                            [x] 完成
  VMP-03 多谓词 Count                            [x] 完成
  VMP-04 Sum 聚合                                [x] 完成
  VMP-05 Avg/Var/Std                             [x] 完成
  VMP-06 半诚实开关（移除 proof）                [x] 完成
  VMP-07 benchmark                              [x] 完成（见 §7.10）
  VMP-08 端到端 gRPC demo                       [x] 完成（见 §7.11）
第 5 层 MPRAQ                                 ⬜ 未开始（0/10），负责人指示暂缓
  MPA-01 ~ MPA-10                               [ ] 未开始
```

## 9.1 里程碑总览

| 里程碑 | 内容 | 状态 |
|---|---|---|
| **M1** | 共享底座 + 双服务器仿真框架；`ctest` 全绿 | ✅ 达成 |
| **M2** | SecureMul 与验证机制在恶意注入下全部检出 | ✅ 达成（`FND-13/14/15`） |
| **M3** | 两个 PIR 原语在 n≈2^14 下稳定完成随机点查询 | 🟡 V-OO-PIR 已完成；Plinko 阻塞于 Q9 |
| **M4** | **VMPQ 半诚实版本端到端跑通** | ✅ **达成**（`VMP-01`~`VMP-08`，真实 gRPC 双进程 demo） |
| **M5** | MPRAQ 端到端 + 恶意服务器注入全部检出 | ⬜ 未开始（`MPA-01` 起；MPA-03+ 依赖 Q9） |

**下一步（新对话直接从这里接着干）**——按建议优先级排列：

1. **`PIR-02`（参数与批量优化）** — 不依赖任何未决项。§7.10 显示 **SUM 的开销是
   `|domain| × 2 × Count`**，是最值得优化的点；批量 PIR 也能显著降低往返次数。
2. **MPRAQ `MPA-01` / `MPA-02`（LCTE 编码 + 谓词解析）** — **不依赖 Q9**，可立即开工。
   ⚠️ 开工时须一并修正已知缺陷：`src/shared/database.cpp` 的 `LcteEncode` 阈值比论文的
   `R = {r_min, …, r_min+m-1}` **偏移了 1**（当前用 `r_min+i+1`），并更新 `test_database.cpp`
   的对应断言。
3. **Q9（iPRF 可行性验证）** — 阻塞 `FND-06` → Plinko（`PIR-04/05`）→ 整个 MPRAQ 检索层
   （`MPA-03` 起）。这是 MPRAQ 能否落地的关键，建议优先做一个最小可行性原型。
4. **`FND-06` 之后的 `MPA-03` ~ `MPA-10`** — 需 Plinko 就绪。

**已解冻**：`FND-10`（gRPC transport）随 Q5 裁决完成；`FND-13`（SecureMul）按 D11/D14
用 `q = 2^127−1` 实现并通过测试。

构建与测试：`cd build && cmake --build . && ctest`（14 个测试程序、317 项用例）。

> 📄 **`doc/design/PIR_SPEC.md`**：V-OO-PIR 的工程实现规格（已就绪）。配套 S3PIR 论文精读全文 `doc/design/S3PIR_spec_zh.md`，以及官方参考实现源码 `doc/design/ref_s3pir/`。
>
> ✅ **阈值规则分歧已裁决**（2026-09-10）：以 S3PIR 的 `FindCutoff` 为准，**不采用 median**。理由：S3PIR 有官方实现可逐行对照；负责人已确认 VMPQ 论文自身存在若干问题，不作为逐字复现依据。**注**：VMPQ 特有的验证层（`F_j` / `Verify`）在 PIR 层保留为可选开关，但 **VMPQ 半诚实路径已全部移除**（决策 D16）。
>
> ❌ **数据库更新明确不做**（2026-09-10）：两系统均不支持追加/滑动窗口/增量 parity 更新，数据库一次性装载。`VMP-06`（原 Hint Refresh 与窗口滑动）已删除。⚠️ 但 hint 的 **`Refresh`（在线查询后补充被消耗的 hint）仍必须实现** —— 那是协议正确性的一部分，别一起砍掉。

---

## 10. 给新对话 / 子 agent 的开工提示词（可直接复制）

> 仓库：`/home/topman/test/tsb_test`。实现两个双服务器隐私聚合查询系统：
> **VMPQ**（IEEE TKDE 2026，只做半诚实版本，作对比基线）与 **MPRAQ**
> （我们自己的论文 `doc/paper/MPARQ.tex`，要完整实现含恶意模型验证）。
>
> **第一步：完整读 `TASK_PLAN.md`**（本文档，为冷启动而写）。重点看 §0 当前进展、
> §3 现状、§5 决策台账 D1–D16、§7 接口契约与未定设计、§9 看板与里程碑。
> 改检索层前必读 `doc/design/PIR_SPEC.md`。论文在 `doc/paper/`。
> （文件都在磁盘上，与本仓库的 git 状态无关。）

### 当前状态（2026-09-10）

- **14 个测试程序、317 项用例，`ctest` 全绿**（约 1.6 s）；`rm -rf build` 后可
  从零重建（已实测验证）。
- **VMPQ 半诚实版本已完成**：`VMP-01`~`VMP-08`。`Init → 单/多谓词 Count → SUM →
  AVG/Var/矩` 四条链路已在**真实 gRPC 双进程**下端到端验证，结果全部与明文一致（§7.11）。
- **MPRAQ 尚未开工**（负责人指示暂缓）。`src/mpraq/` 为空。

### 必须遵守的已定口径（别自行推翻）

1. **半诚实版移除全部 proof**（D16）：不使用 Mset-XOR-Hash、不需要 MAC 密钥。
   论文用 Mset 的方式本身不成立——客户端不持有服务器共享，而 HMAC 非线性
   （`C_0 ⊕ C_1 ≠ C`）。移除后 `HintInit` 快约 3.6 倍。
2. **parity 语义为 ⊕ 的数据必须用 XOR 共享**（D12）：加法共享不保持 XOR 同态。
   VMPQ 的 one-hot 比特走 XOR 共享，属性值才走加法共享。
3. **V-OO-PIR 的三条工程约束**（D15，都会**静默**削弱安全性/正确性）：
   (a) PIR 数据库大小必须**补齐到 2 的幂**；
   (b) `part_num ≥ 16`，否则 `FindCutoff` 大量失效（P=6 时有效率仅 8%）；
   (c) **`M = λ√n` 指"有效 hint 数"而非尝试次数**，否则等效 λ 掉一半。
4. **查询口径（Q5）**：VMPQ 的 PIR 无法避免"把所有谓词发过去"，因此
   **一次 RPC 携带全部谓词的全部查询集**，客户端在本地做谓词组合。
5. **SecureMul 用 `q = 2^127−1`**（D11/D14）。`Z_{2^128}` 中 2 不可逆
   （是零因子），论文公式里的 `e·d·2^{-1}` 无定义。
6. 不做数据库更新/滑动窗口（D8）；阈值规则以 S3PIR 的 `FindCutoff` 为准（D7）。

### 下一步（按优先级）

1. **`PIR-02`** 参数与批量优化 —— 不依赖任何未决项。§7.10 显示
   **SUM 开销 = `|domain| × 2 × Count`**，是最值得优化的点。
2. **MPRAQ `MPA-01` / `MPA-02`**（LCTE 编码 + 谓词解析）—— **不依赖 Q9**，可立即开工。
   ⚠️ 开工时须一并修正已知缺陷：`src/shared/database.cpp` 的 `LcteEncode` 阈值比论文的
   `R = {r_min, …, r_min+m-1}` **偏移了 1**（当前用 `r_min+i+1`），并更新 `test_database.cpp`。
3. **Q9（iPRF 可行性原型）** —— 阻塞 `FND-06` → Plinko（`PIR-04/05`）→ 整个 MPRAQ 检索层。

### 构建与运行

```bash
cd build && cmake --build . && ctest       # 构建 + 全量测试
./build/bin/bench_vmpq                     # VMP-07 基准（输出格式见 §7.10）

# VMP-08 端到端 demo（需要三个终端）
./build/bin/vmpq_server config/server_vmpq_0.json    # :50051
./build/bin/vmpq_server config/server_vmpq_1.json    # :50052
./build/bin/vmpq_client config/client_vmpq.json
```

动手前请确认：你负责的任务 ID、依赖是否就绪、产出如何验收。
**每个算法都要有确定性随机源下的期望值测试**——本项目已多次靠测试抓出实现 bug
（`Refresh` 三处语义、`reduce` 位长差溢出）与**论文本身的错误**（D11/D14）。

## 11. 变更记录

| 日期 | 变更 | 原因 |
|---|---|---|
| 2026-09-10 | 初版：确立分层架构、30 项任务分解、接口契约、论文参数基线 | 项目启动，需为新对话提供统一上手文档 |
| 2026-09-10 | 新增 `doc/design/PIR_SPEC.md`（V-OO-PIR 工程规格）+ `doc/design/ref_s3pir/`（官方参考实现）；标注 2 处待决分歧：阈值规则 median vs cutoff、数据库更新支持度 | S3PIR 论文精读完成，为 `PIR-01` 提供实现依据，同时暴露与 VMPQ 论文的规格差异 |
| 2026-09-10 | **解除 `PIR-01` 阻塞**：阈值规则裁决为以 S3PIR 的 `FindCutoff` 为准（D7）。**删除 `VMP-06`** 并明确不做数据库更新（D8）。新增 D9（允许推翻旧代码）、D10（底座对未定设计保持中立）。新增 §7.6 MPRAQ 待定设计决策 Q1–Q11 | 负责人决策：赞同以 S3PIR 为准；两系统均不考虑数据库更新；允许修改全部代码以更合适的方式实现；MPRAQ 尚有多项设计未定 |
| 2026-09-10 | **`FND-01`、`FND-02` 完成**：建立 `src/{core,net,shared,pir,vmpq,mpraq}` 与 `tests/`、`bench/` 骨架；`core/field` 实现并通过 34 项单测；引入自研最小测试框架；`ctest` 接入。新增决策 **D11**（`2^{-1}` 在 `Z_{2^128}` 不存在，SecureMul 公式在 2 的幂环上不成立） | 共享底座开工。D11 是在实现 `2^{-1}` 时由单测暴露的数学漏洞，直接影响 §7.6 Q1，必须在实现 `MPA-05` 前解决 |
| 2026-09-10 | **`FND-03`~`FND-09` 完成，里程碑 M1 达成**：`core/aes_prf`（FIPS-197 向量验证）、`core/hash`（RFC 4231 / FIPS 180-2 向量验证）、`core/mset_hash`、`core/random`、`shared/secret_sharing`（三套强类型共享）、`net/transport`（进程内 + 恶意注入钩子）、`tests/support/test_cluster`（双服务器仿真）。**6 个测试可执行文件、125 项用例全绿** | 底座主体完成，具备实现检索原语与协议层的全部基础设施 |
| 2026-09-10 | **`FND-11`、`FND-12` 完成**：`shared/database`（表抽象 + one-hot/LCTE 编码辅助 + 位打包，31 项单测）、`core/config`（JSON 校验层 + VMPQ/查询/服务端配置，26 项单测）。新增决策 **D12**（加法共享不保持 XOR 同态；凡 parity 语义为 ⊕ 的数据必须用 XOR 共享承载） | 第 2 层开工。D12 是 `ColumnXor` 实现时由单测暴露的语义约束，直接决定 `PIR-01` 的数据表示 |
| 2026-09-10 | **`FND-14` 完成**：`shared/verify`（V-OO-PIR 多集证明 + 单条 HMAC 校验 + SPDZ MAC），29 项单测。新增决策 **D13**（验证等式两侧 F/C 必须是纯 XOR，不得掺基准值；并明确 `fill` 是查询时额外引入的填充项） | 实现验证逻辑时由测试暴露的代数约束，直接决定 `PIR-01` 的 `ServerResp` 与 `Verify` 写法 |
| 2026-09-10 | **`FND-15` 完成**：`tests/test_adversary.cpp`（22 项）。含**逐比特/逐字节全矩阵**篡改检出验证（128 位标签的每一位、每个字节的三种掩码全部检出且零误报）、重放、跨域重放、值/MAC 共享错配、退化参数拒绝、端到端传输篡改 | 系统化验证恶意服务器的各类偏离均被检出，而非零散补几个篡改用例 |
| 2026-09-10 | **`FND-13` 完成**：`shared/mpc`（Beaver triple + SPDZ MAC 两阶段实现），15 项单测。🔴 **发现并修正 MPRAQ 论文 Algorithm 5 的 MAC 公式错误**——论文末项多乘了一个 `2^{-1}`，导致 `mac ≠ α·z` 恒不成立（决策 **D14**，符号化验证 3/3 确认） | SecureMul 是 VMPQ 与 MPRAQ 的共用核心。值重建全部正确但 MAC 恒失败，追查后确认是论文公式错误 |
| 2026-09-10 | **`PIR-01` 完成**：`src/pir/voo_pir`（`HintInit`/`Query`/`Answer`/`Reconstruct` + `FindCutoff`），23 项测试通过，含**全量扫描零错误**（1024 个索引中所有被覆盖者均正确重建）。⚠️ **`Refresh` 未实现正确**，测试以 `#if 0` 停用并记录于新增的 §7.8 遗留问题台账 | 检索层是 VMPQ 的核心。刷新路径反复推导仍未对齐，选择如实记录而非弱化断言 |
| 2026-09-10 | **`PIR-01` 的 `Refresh` 修复完成**：按上一轮的建议直接对照官方实现（`doc/design/ref_s3pir/`），发现三处此前推错的语义 —— parity 需含 extra、刷新取不含 ℓ 的半区、查询哑组用新随机偏移。修复后同一索引连续 200 轮刷新全部正确、全量扫描 1024/1024 零错误；新增 300 轮持续压力测试。§7.8 的 L1/L2 标记为已解决 | 上一轮如实记录了 Refresh 未解并建议改用参考实现；本轮照做后一次通过 |
| 2026-09-10 | **`PIR-03` 完成**：新增 4 项隐私性结构检查（每分区恰好一个偏移、case A/B 查询形状不可区分、dummy 偏移每轮新鲜、请求不含目标索引痕迹） | 把「服务器看到什么」也纳入回归测试，而非只测正确性 |
| 2026-09-10 | **`VMP-01`、`VMP-02` 完成**：`src/vmpq/vmpq`（one-hot 编码 + 128 位打包 + XOR 共享分发；单谓词 Count 走 V-OO-PIR）。21 项测试，含逐取值对照明文计数。新增决策 **D15**（V-OO-PIR 三条工程约束：数据库须补齐到 2 的幂、P>=16、M 必须指有效 hint 数）与 §7.9（与论文的工程差异） | 把 PIR 接到 VMPQ 时暴露「偶尔查不到 hint」的间歇性故障，逐层排查后确认为几何/统计约束而非协议 bug |
| 2026-09-10 | **`VMP-03`/`VMP-04`/`VMP-05` 完成**：多谓词 Count（本地按位与）、SUM（归约为 Count）、AVG 与精确整数矩。32 项 VMPQ 测试，全部对照明文基准。§7.9 新增 G4/G5 记录与论文的两处实现方式差异及代价对比 | 半诚实 VMPQ 的查询链路现已完整：Init → 单/多谓词 Count → SUM/AVG/Var/Std |
| 2026-09-10 | **按负责人指示移除 VMPQ 半诚实版本的 proof（决策 D16）**：`VooPirClient` 证明改为可选且默认关闭、`VmpqClient` 不再接收 MAC 密钥、`Refresh` 不再维护 proof。实测 HintInit **32.8 ms → 9.0 ms（约 3.6×）**，测试套件 2.61 s → 0.88 s。记录论文 Mset-XOR-Hash 用法不成立的原因（客户端不持有共享，HMAC 非线性 ⇒ `C_0⊕C_1 ≠ C`）。`VMP-06` 结案 | 负责人指出半诚实模型默认服务器不篡改，proof 无用且论文用法有误 |
| 2026-09-10 | **`VMP-07` 完成**：`bench/bench_vmpq`，实测 Init/Count/多谓词/SUM 延迟、存储、PIR 次数与请求字节；结论写入 §7.10。验证了"多谓词开销随谓词数线性"与"SUM = |domain|×2×Count"两条伸缩规律 | 产出可复现的基准数据，并为 SUM 的优化方向提供依据 |
| 2026-09-10 | **`FND-10`、`VMP-08` 完成，VMPQ 半诚实版本全部收尾**：新协议 `proto/vmpq.proto`、`net/grpc_vmpq`（GrpcChannel + 服务端）、`apps/vmpq_{server,client}` 真实双进程 gRPC demo，全部查询与明文一致。**按决策 D9 删除 src/common、src/client、src/server 与旧 proto**，构建从零重配成功。记录 §7.11 实测数据 | Q5 裁决后 FND-10 解冻；VMPQ 四条查询链路（单/多谓词 Count、SUM、AVG/矩）已全部在真实网络下端到端验证 |
| 2026-09-10 | **文档全面刷新**：新增 §0「当前进展」摘要；§2.1 按实际实现重写 VMPQ 技术画像（XOR 共享、按位打包、移除 proof）；§3 重写为现状/迁移对照/历史缺陷三部分；§4 架构图标注逐模块状态并列出与最初计划的偏差；看板补全层级完成度；「下一步」按优先级重写 | VMPQ 收尾后多项描述已过时，会让新对话读到错误前提 |
