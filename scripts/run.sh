#!/usr/bin/env bash
# ===========================================================================
# 统一启动脚本：构建 / 测试 / 跑 VMPQ / 跑 MPRAQ（两进程真实 gRPC）
# ===========================================================================
#
# 用法：
#   scripts/run.sh build                        # 配置 + 全量构建
#   scripts/run.sh test                         # ctest（5 个套件 / 45 用例）
#   scripts/run.sh mpraq                        # MPRAQ demo（恶意档，默认）
#   scripts/run.sh mpraq --security-mode semi-honest
#   scripts/run.sh mpraq --verbose --rows 8192 --predicates 5
#   scripts/run.sh vmpq                         # VMPQ demo
#   scripts/run.sh all                          # build + test + mpraq + vmpq
#   scripts/run.sh all --skip-build             # 已构建过时用
#   scripts/run.sh mpraq --keep-stale           # 并行跑多份时**必须**加（见下 ①/②）
#
# 设计要点（都是踩过的坑，别改回去）：
#
#   ① **启动前清理残留进程**。本项目反复出现"上一轮的 `mpraq_server` 没被杀掉、
#      抢答了端口"，让新跑的结果看起来是**代码错了**（实测过一次：6 个残留进程里
#      有一个是**改动前编译的**）。所以本脚本启动前显式 `pkill -x`（`-x` = 精确
#      进程名；**不要**用 `pkill -f` —— 它会匹配到脚本自己的命令行，把自己杀掉）。
#
#   ② **MPRAQ 用临时端口**：服务器 `--port-file` 绑 `127.0.0.1:0` 并把实际端口写回
#      文件，脚本轮询该文件。⇒ **端口**上不会撞。
#      ⚠️ 但①的残留清理会杀掉并行实例的服务器 ⇒ **要并行跑多份必须加 `--keep-stale`**。
#
#   ③ **VMPQ 只吃配置文件**（没有端口参数）⇒ 脚本**生成临时配置**并选空闲端口，
#      顺手获得同样的并行安全性（仓库里的 `config/vmpq_server_*.json` 写死了 50051/50052，
#      同时跑两份会绑定失败）。
#
#   ④ `trap` 收尾：无论成功、失败还是 Ctrl-C，都会杀掉子进程并删掉临时文件。
#
#   ⑤ 结果**校验**：抓客户端的 `result ...` 行，检查关键字段，最后打印 PASS/FAIL
#      并以此作为脚本退出码 ⇒ 可以直接用在 CI 里当冒烟测试。
#
# 产物：`build/run/`（gitignored）—— 客户端输出与两个服务器的日志。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/build/bin"
OUT="$ROOT/build/run"
KEEP_STALE=0          # 见 `clean_stale`：置 1（`--keep-stale`）可并行跑多份

# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 收尾（**脚本级**，必须如此 —— 见下面 kill_pids 的 ⚠️）
# ---------------------------------------------------------------------------
#
# ⚠️ **踩过的真 bug**：trap 若装在**函数内部**并引用该函数的 `local` 变量，
#    函数 `return` 之后那些 `local` 就**出作用域**了；EXIT 触发时 `$p0` 已 unset
#    ⇒ `kill` 拿到空串 ⇒ **服务器根本没被杀掉**（成功路径因为显式 kill 过，
#    完全看不出来；只有**失败路径**会稳定泄漏进程 —— 实测失败后 2 秒仍有 2 个残留）。
#    ⇒ 正确做法：PID 与临时路径都放**脚本级**变量，trap 也在脚本级装一次。
SRV_P0=""
SRV_P1=""
TMP_PATHS=()

die() { echo "错误： $*" >&2; exit 1; }
info() { printf '  %s\n' "$*"; }
step() { printf '\n=== %s ===\n' "$*"; }

need_bins() {
    local missing=()
    for b in "$@"; do
        [ -x "$BIN/$b" ] || missing+=("$b")
    done
    if [ ${#missing[@]} -ne 0 ]; then
        die "缺少可执行文件：${missing[*]}
      先构建：  scripts/run.sh build"
    fi
}

# 启动前清残留。⚠️ 精确进程名（`-x`），绝不用 `-f`：`-f` 会匹配到本脚本自己的
# 命令行（它含有 "mpraq_server" 这个字符串）从而把自己杀掉。
# ⚠️ **本函数会杀掉机器上所有 `mpraq_server` / `vmpq_server`** —— 包括**另一份并行实例的**。
#    它解决的是真实问题（残留进程抢端口，让新结果看起来像代码错了），代价是不容忍并发。
#    ⇒ **要并行跑多份，必须加 `--keep-stale`**（否则后启动的那份会把先启动的服务器杀掉；
#      实测两份都 PASS 只是时机凑巧，不是真的并行安全）。
clean_stale() {
    [ "${KEEP_STALE:-0}" -eq 1 ] && { info "--keep-stale：跳过残留清理"; return 0; }
    local killed=0
    for name in mpraq_server vmpq_server; do
        if pkill -x "$name" 2>/dev/null; then
            killed=1
        fi
    done
    [ "$killed" -eq 1 ] && info "已清理上一轮残留的服务器进程"
    sleep 0.3
    return 0
}

# 选一个空闲端口（TOCTOU 竞态对 demo 可接受）
free_port() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
    else
        # 退路：在 [20000,60000) 里挑一个当前没人监听的
        local p
        for p in $(seq 20000 20050); do
            if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then echo "$p"; return; fi
        done
        die "找不到空闲端口（且没有 python3）"
    fi
}

# 收尾：杀掉服务器并清理临时文件。读**脚本级**变量（理由见文件头上面的 ⚠️）。
#
# ⚠️ 必须 `wait`：服务器要先打印收尾账目才退出；不等的话脚本返回后它们还在，
#    立刻 `pgrep` 会数到残留（实测数到 2、2 秒后才归 0），很容易被误判成"没收尾"。
srv_cleanup() {
    local pid p
    for pid in "$SRV_P0" "$SRV_P1"; do
        if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi
    done
    for pid in "$SRV_P0" "$SRV_P1"; do
        if [ -n "$pid" ]; then wait "$pid" 2>/dev/null || true; fi
    done
    SRV_P0=""; SRV_P1=""
    for p in ${TMP_PATHS[@]+"${TMP_PATHS[@]}"}; do rm -rf "$p"; done
    TMP_PATHS=()
    return 0
}
# 脚本级安装一次，覆盖**成功、失败、Ctrl-C** 三条路径
trap srv_cleanup EXIT INT TERM

# 等待端口文件被服务器写入
wait_port_file() {
    local f="$1" tries="${2:-80}"
    local i=0
    while [ "$i" -lt "$tries" ]; do
        [ -s "$f" ] && return 0
        sleep 0.25
        i=$((i + 1))
    done
    return 1
}

# 校验客户端输出里的关键字段
check_result() {
    local log="$1"; shift
    local line
    line="$(grep -E '^result ' "$log" | tail -1 || true)"
    if [ -z "$line" ]; then
        echo "失败：客户端没有输出 'result' 行 —— 看 $log" >&2
        return 1
    fi
    echo "  $line"
    local field
    for field in "$@"; do
        case " $line " in
            *" $field "*|*" $field"*) ;;
            *) echo "失败：结果里缺少 '$field'" >&2; return 1 ;;
        esac
    done
    return 0
}

# ---------------------------------------------------------------------------
# build / test
# ---------------------------------------------------------------------------

cmd_build() {
    step "配置 + 全量构建"
    cmake -S "$ROOT" -B "$ROOT/build" -DCMAKE_BUILD_TYPE=Release
    cmake --build "$ROOT/build" -j"$(nproc 2>/dev/null || echo 4)"
    info "构建完成（0 error / 0 warning 是本仓库的常态，有输出请查）"
}

cmd_test() {
    step "ctest"
    need_bins test_mpraq_entry
    ctest --test-dir "$ROOT/build" --output-on-failure
}

# ---------------------------------------------------------------------------
# MPRAQ（两进程真实 gRPC）
# ---------------------------------------------------------------------------

cmd_mpraq() {
    local mode="malicious" cfg="$ROOT/config/mpraq_scale.json" verbose=0 rows=""
    local cols="" attrs="" preds=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --security-mode) mode="${2:?}"; shift 2 ;;
            --config)        cfg="${2:?}"; shift 2 ;;
            --rows)          rows="${2:?}"; shift 2 ;;
            --columns)       cols="${2:?}"; shift 2 ;;
            --attributes)    attrs="${2:?}"; shift 2 ;;
            --predicates)    preds="${2:?}"; shift 2 ;;
            --verbose|-v)    verbose=1; shift ;;
            --keep-stale)    KEEP_STALE=1; shift ;;
            *) die "mpraq: 未知参数 $1" ;;
        esac
    done
    need_bins mpraq_server mpraq_client
    clean_stale
    mkdir -p "$OUT"

    local pf0 pf1 c0 c1
    pf0="$(mktemp)"; pf1="$(mktemp)"; rm -f "$pf0" "$pf1"
    c0="$(mktemp)"; c1="$(mktemp)"; rm -f "$c0" "$c1"

    TMP_PATHS+=("$pf0" "$pf1" "$c0" "$c1")
    "$BIN/mpraq_server" --id 0 --security-mode "$mode" --port-file "$pf0" >"$OUT/mpraq_server0.log" 2>&1 &
    SRV_P0=$!
    "$BIN/mpraq_server" --id 1 --security-mode "$mode" --port-file "$pf1" >"$OUT/mpraq_server1.log" 2>&1 &
    SRV_P1=$!

    step "MPRAQ：等两台服务器就绪"
    wait_port_file "$pf0" || die "服务器 0 未写出端口文件（看 $OUT/mpraq_server0.log）"
    wait_port_file "$pf1" || die "服务器 1 未写出端口文件（看 $OUT/mpraq_server1.log）"
    info "server0 = 127.0.0.1:$(cat "$pf0")   server1 = 127.0.0.1:$(cat "$pf1")"

    local -a extra=()
    [ "$verbose" -eq 1 ] && extra+=(--verbose)
    [ -n "$rows" ]  && extra+=(--rows "$rows")
    [ -n "$cols" ]  && extra+=(--columns "$cols")
    [ -n "$attrs" ] && extra+=(--attributes "$attrs")
    [ -n "$preds" ] && extra+=(--predicates "$preds")

    step "MPRAQ：客户端（security_mode=$mode）"
    set +e
    "$BIN/mpraq_client" \
        --server0 "127.0.0.1:$(cat "$pf0")" \
        --server1 "127.0.0.1:$(cat "$pf1")" \
        --config "$cfg" --security-mode "$mode" "${extra[@]+"${extra[@]}"}" \
        >"$OUT/mpraq_client.log" 2>&1
    local rc=$?
    set -e
    echo "  --- 客户端输出（节选；完整见 $OUT/mpraq_client.log）---"
    grep -E '^(scale|query|accounts|result|\[FAIL)' "$OUT/mpraq_client.log" || true
    if [ "$rc" -ne 0 ]; then
        echo "失败：客户端退出码 $rc —— 完整输出见 $OUT/mpraq_client.log" >&2
        return "$rc"
    fi

    check_result "$OUT/mpraq_client.log" "baseline_match=1" "storage_formula_match=1" \
        || return 1
    # （`accounts` 行上面已经打过了：那行里的 `storage_bytes_per_server` 与 `tag_checks`
    #   正是"分档确实生效"的证据 —— 恶意档含 tag 表、半诚实档不含。）

    srv_cleanup
    echo "MPRAQ PASS"
}

# ---------------------------------------------------------------------------
# VMPQ（两进程真实 gRPC；配置是**临时生成**的，端口空闲）
# ---------------------------------------------------------------------------

cmd_vmpq() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --keep-stale) KEEP_STALE=1; shift ;;
            *) die "vmpq: 未知参数 $1" ;;
        esac
    done
    need_bins vmpq_server vmpq_client
    clean_stale
    mkdir -p "$OUT"

    local pa pb tmp
    pa="$(free_port)"; pb="$(free_port)"
    [ "$pa" != "$pb" ] || die "两次取到同一个端口（$pa），重跑一次"
    tmp="$(mktemp -d)"
    TMP_PATHS+=("$tmp")

    # 生成临时配置：server_id / host_port / 客户端的两条地址
    printf '{\n  "server_id": 0,\n  "host_port": "%s"\n}\n' "$pa" >"$tmp/s0.json"
    printf '{\n  "server_id": 1,\n  "host_port": "%s"\n}\n' "$pb" >"$tmp/s1.json"
    sed -e "s/localhost:50051/127.0.0.1:$pa/" -e "s/localhost:50052/127.0.0.1:$pb/" \
        "$ROOT/config/vmpq_client.json" >"$tmp/client.json"

    step "VMPQ：起两台服务器（端口 $pa / $pb）"
    "$BIN/vmpq_server" "$tmp/s0.json" >"$OUT/vmpq_server0.log" 2>&1 &
    SRV_P0=$!
    "$BIN/vmpq_server" "$tmp/s1.json" >"$OUT/vmpq_server1.log" 2>&1 &
    SRV_P1=$!
    sleep 2

    step "VMPQ：客户端"
    set +e
    "$BIN/vmpq_client" "$tmp/client.json" >"$OUT/vmpq_client.log" 2>&1
    local rc=$?
    set -e
    grep -E '^(result|rpc|client_accounts)' "$OUT/vmpq_client.log" || true
    srv_cleanup
    if [ "$rc" -ne 0 ]; then
        echo "失败：客户端退出码 $rc —— 完整输出见 $OUT/vmpq_client.log" >&2
        return "$rc"
    fi

    check_result "$OUT/vmpq_client.log" "all_match=1" || return 1
    echo "VMPQ PASS"
}

# ---------------------------------------------------------------------------
# all
# ---------------------------------------------------------------------------

cmd_all() {
    local skip_build=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --skip-build) skip_build=1; shift ;;
            *) die "all: 未知参数 $1" ;;
        esac
    done
    [ "$skip_build" -eq 1 ] || cmd_build
    cmd_test
    cmd_vmpq
    cmd_mpraq
}

# ---------------------------------------------------------------------------

usage() {
    sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

case "${1:-}" in
    build) shift; cmd_build "$@" ;;
    test)  shift; cmd_test  "$@" ;;
    mpraq) shift; cmd_mpraq "$@" ;;
    vmpq)  shift; cmd_vmpq  "$@" ;;
    all)   shift; cmd_all   "$@" ;;
    ""|-h|--help|help) usage ;;
    *) die "未知子命令 '$1'（可用：build / test / mpraq / vmpq / all）" ;;
esac
