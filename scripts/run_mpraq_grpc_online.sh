#!/usr/bin/env bash
# ===========================================================================
# MPRAQ 真实网络在线测试：**两个独立的 mpraq_server 进程 + 客户端走 gRPC**
# ===========================================================================
#
# 与 `--mode local`（进程内 LocalTransport）的区别：
#   * 服务器是**独立进程**，客户端通过 gRPC（HTTP/2 + protobuf）通信；
#   * 每次 `RunBatch` 恒 1 次 `ServerResp` RPC/台，延迟里包含真实 socket/序列化；
#   * 服务器进程退出时打印**实测账目**（受理查询集、word 读取、Relay 帧数），
#     用来自证"应答确实经过服务器"，而不是客户端本地算出来的。
#
# 用法：
#   scripts/run_mpraq_grpc_online.sh                        # 本机、绑真实网卡 IP
#   scripts/run_mpraq_grpc_online.sh --rows 4096 --predicates 3
#   scripts/run_mpraq_grpc_online.sh --bind 127.0.0.1       # 强制 loopback
#   scripts/run_mpraq_grpc_online.sh --bench --repeat 3     # 额外跑在线基准
#   scripts/run_mpraq_grpc_online.sh --verbose              # 打印客户端/服务器的全量账目
#                                                           # （默认只打一屏摘要）
#
# 跨两台真实机器（服务器在 A/B，客户端在 C）：
#   # A: ./build/bin/mpraq_server --id 0 --listen 0.0.0.0:50051
#   # B: ./build/bin/mpraq_server --id 1 --listen 0.0.0.0:50052
#   scripts/run_mpraq_grpc_online.sh --server0 A:50051 --server1 B:50052
#
# 产物：`build/netrun/`（gitignored）——客户端输出、两个服务器的日志、端口文件。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/build/bin"

BIND_IP=""
SERVER0=""
SERVER1=""
VERBOSE=0
ROWS=4096
# ⚠️ **不要把这个变量叫 `COLUMNS`**：它是 bash 的特殊变量，`BASHOPTS` 里的
#    `checkwinsize` 会被子 shell 继承 ⇒ 在带 tty 的终端里 bash 会按终端宽度刷新它，
#    把脚本设的值覆盖掉（实测：终端 109 列 ⇒ 变成 `--columns 109`，规模层 fail-loudly
#    报"不是 2 的幂"）。已改名 `COLS_PER_ATTR`。
COLS_PER_ATTR=32
ATTRIBUTES=2
PREDICATES=3
PRNG_SEED=11
SUM_ATTR=""
OUTDIR="$ROOT/build/netrun"
RUN_BENCH=0
REPEAT=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bind)       BIND_IP="$2"; shift 2 ;;
        --server0)    SERVER0="$2"; shift 2 ;;
        --server1)    SERVER1="$2"; shift 2 ;;
        --rows)       ROWS="$2"; shift 2 ;;
        --columns)    COLS_PER_ATTR="$2"; shift 2 ;;
        --attributes) ATTRIBUTES="$2"; shift 2 ;;
        --predicates) PREDICATES="$2"; shift 2 ;;
        --prng-seed)  PRNG_SEED="$2"; shift 2 ;;
        --sum-attr)   SUM_ATTR="$2"; shift 2 ;;
        --outdir)     OUTDIR="$2"; shift 2 ;;
        --bench)      RUN_BENCH=1; shift ;;
        --verbose|-v) VERBOSE=1; shift ;;
        --repeat)     REPEAT="$2"; shift 2 ;;
        -h|--help)    sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "未知参数: $1" >&2; exit 2 ;;
    esac
done

[[ -x "$BIN/mpraq_server" && -x "$BIN/mpraq_client" ]] || {
    echo "缺少二进制：请先 cmake --build build" >&2; exit 1; }

# 远程模式 = 两个端点都由外部给出（跨机测试）。否则本机起两个进程。
REMOTE=0
if [[ -n "$SERVER0" && -n "$SERVER1" ]]; then
    REMOTE=1
elif [[ -n "$SERVER0" || -n "$SERVER1" ]]; then
    echo "--server0/--server1 必须同时给出" >&2; exit 2
fi

mkdir -p "$OUTDIR"
PIDS=()
cleanup() {
    local rc=$?
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true
    done
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
    done
    exit $rc
}
trap cleanup EXIT INT TERM

if [[ $REMOTE -eq 0 ]]; then
    # 默认走真实网卡：取第一个非 loopback 的 IPv4（拿不到才退回 127.0.0.1）
    if [[ -z "$BIND_IP" ]]; then
        BIND_IP="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^127\.' | head -1 || true)"
        [[ -n "$BIND_IP" ]] || BIND_IP="127.0.0.1"
    fi
    # ⚠️ **先删旧端口文件**：否则等待循环会看到上一轮遗留的非空文件而立刻通过，
    #    客户端就连到上一轮的端口（实测：新服务器在 42235、客户端连 42455 ⇒ 0 次 RPC）。
    rm -f "$OUTDIR/p0" "$OUTDIR/p1"
    SRV_VERBOSE=(); [[ $VERBOSE -eq 1 ]] && SRV_VERBOSE=(--verbose)
    echo "== 启动 2 个 mpraq_server 进程（绑定 $BIND_IP:0，内核分配端口）=="
    "$BIN/mpraq_server" --id 0 --listen "$BIND_IP:0" --port-file "$OUTDIR/p0" \
        "${SRV_VERBOSE[@]}" >"$OUTDIR/server0.log" 2>&1 &
    PIDS+=($!)
    "$BIN/mpraq_server" --id 1 --listen "$BIND_IP:0" --port-file "$OUTDIR/p1" \
        "${SRV_VERBOSE[@]}" >"$OUTDIR/server1.log" 2>&1 &
    PIDS+=($!)

    for _ in $(seq 1 100); do
        [[ -s "$OUTDIR/p0" && -s "$OUTDIR/p1" ]] && break
        sleep 0.1
    done
    [[ -s "$OUTDIR/p0" && -s "$OUTDIR/p1" ]] || {
        echo "服务器未就绪，日志：" >&2; cat "$OUTDIR"/server*.log >&2; exit 1; }
    SERVER0="$BIND_IP:$(tr -d '[:space:]' <"$OUTDIR/p0")"
    SERVER1="$BIND_IP:$(tr -d '[:space:]' <"$OUTDIR/p1")"
    # 两个端点必须不同（同端口 = 一台服务器冒充两台）
    [[ "$SERVER0" != "$SERVER1" ]] || {
        echo "两个服务器端点相同（$SERVER0）—— 端口文件异常" >&2; exit 1; }
fi

echo "== 端点 =="
echo "  server0 = $SERVER0    server1 = $SERVER1"
echo "  （进程模型：$( [[ $REMOTE -eq 1 ]] && echo '外部/远程进程' || echo "本机 2 个独立进程 pid ${PIDS[0]} / ${PIDS[1]}" )）"
echo

# ---------------------------------------------------------------------------
# 客户端：Init（离线）+ 在线 Count / 多谓词 / Sum / Avg，全部与明文基准逐值对照
# ---------------------------------------------------------------------------
CLIENT_ARGS=(--server0 "$SERVER0" --server1 "$SERVER1"
             --rows "$ROWS" --columns "$COLS_PER_ATTR" --attributes "$ATTRIBUTES"
             --predicates "$PREDICATES" --prng-seed "$PRNG_SEED")
[[ -n "$SUM_ATTR" ]] && CLIENT_ARGS+=(--sum-attr "$SUM_ATTR")
[[ $VERBOSE -eq 1 ]] && CLIENT_ARGS+=(--verbose)

# 把**有效规模**显式带出来：这样"脚本变量被环境改写"这类问题一眼可见
echo "== 客户端（gRPC；rows=$ROWS 每属性列数=$COLS_PER_ATTR 属性数=$ATTRIBUTES 谓词数=$PREDICATES）=="
set +e
"$BIN/mpraq_client" "${CLIENT_ARGS[@]}" 2>&1 | tee "$OUTDIR/client.log"
CLIENT_RC=${PIPESTATUS[0]}
set -e
echo
echo "客户端退出码 = $CLIENT_RC"

# ---------------------------------------------------------------------------
# 可选：在线基准（同一个 gRPC 口径；显式给端点 ⇒ bench 不再自己拉进程）
# ---------------------------------------------------------------------------
if [[ $RUN_BENCH -eq 1 ]]; then
    echo
    echo "== bench_mpraq --exp online --mode grpc（显式端点）=="
    "$BIN/bench_mpraq" --exp online --mode grpc --server0 "$SERVER0" --server1 "$SERVER1" \
        --rows "$ROWS" --columns-per-attribute "$COLS_PER_ATTR" --attributes "$ATTRIBUTES" \
        --predicates "$PREDICATES" --repeat "$REPEAT" 2>&1 | tee "$OUTDIR/bench_online.log"
fi

# ---------------------------------------------------------------------------
# 收尾：停服务器并把它们的实测账目打出来（自证应答经过服务器）
# ---------------------------------------------------------------------------
if [[ $REMOTE -eq 0 ]]; then
    echo
    echo "== 关闭服务器并取回实测账目 =="
    for pid in "${PIDS[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
    for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
    PIDS=()
    for f in "$OUTDIR/server0.log" "$OUTDIR/server1.log"; do
        echo "---- $f ----"
        # 默认只匹配「READY + 一行关闭摘要」；`--verbose` 时把全量账目也带出来
        grep -E 'READY|关闭：|实测账目|服务侧|node 层|Relay' "$f" || cat "$f"
    done
fi

echo
echo "产物目录：$OUTDIR"
[[ $CLIENT_RC -eq 0 ]] || exit "$CLIENT_RC"
