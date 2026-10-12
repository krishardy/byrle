#!/usr/bin/env bash
# Install times through the proxy against installs direct from the registries.
#
# One large npm set and one large PyPI set, each installed from a lockfile in five cases:
# direct with an empty and a filled client cache, and through the proxy fresh (nothing
# analysed), after `byrle warm`, and with the client's cache filled. Each case runs
# BYRLE_BENCH_RUNS times (default 3) and the median is reported, in seconds.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
port="${BYRLE_PORT:-8761}"
runs="${BYRLE_BENCH_RUNS:-3}"
npm_packages=(next react react-dom eslint typescript vite vitest)
pypi_packages=(pandas scikit-learn matplotlib)
workdir="$(mktemp -d)"
proxy_pid=""
proxy="http://127.0.0.1:${port}"

cleanup() {
    [[ -n "$proxy_pid" ]] && kill "$proxy_pid" 2>/dev/null || true
    rm -rf "$workdir"
}
trap cleanup EXIT

cargo build --release --quiet --manifest-path "$repo_root/Cargo.toml"
binary="$repo_root/target/release/byrle"

start_proxy() {
    stop_proxy
    rm -rf "$workdir/spool"
    BYRLE_REQUIRE_TOKEN=0 BYRLE_SPOOL_DIR="$workdir/spool" BYRLE_LISTEN="127.0.0.1:${port}" \
        "$binary" daemon >"$workdir/proxy.log" 2>&1 &
    proxy_pid=$!
    for _ in $(seq 1 60); do
        grep -q "byrle listening" "$workdir/proxy.log" && return 0
        sleep 0.5
    done
    echo "proxy did not start"; exit 1
}

stop_proxy() {
    [[ -n "$proxy_pid" ]] || return 0
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
    proxy_pid=""
}

# Seconds the command took, or FAIL.
seconds() {
    local start end
    start="$(date +%s.%N)"
    if ! "$@" >"$workdir/last.out" 2>&1; then echo FAIL; return 0; fi
    end="$(date +%s.%N)"
    awk -v s="$start" -v e="$end" 'BEGIN { printf "%.1f", e - s }'
}

median() { tr ' ' '\n' | grep -v '^$' | sort -g | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }

npm_ci() { (cd "$workdir/npm" && rm -rf node_modules && npm ci --registry="$1" --cache "$2" \
    --no-audit --no-fund --loglevel=error); }
uv_install() { rm -rf "$workdir/venv" && uv venv -q "$workdir/venv" \
    && UV_CACHE_DIR="$2" uv pip install -q --python "$workdir/venv" --index-url "$1" \
        -r "$workdir/pypi/requirements.txt"; }

# One row: the median of each case for `install <registry> <cache>`, with the lockfile
# and the direct registry given.
row() {
    local name="$1" install="$2" direct="$3" through="$4" lockfile="$5"
    local d_cold="" d_warm="" p_cold="" p_warmed="" p_warm="" warm_time=""
    for _ in $(seq 1 "$runs"); do
        rm -rf "$workdir/cache"
        d_cold+=" $(seconds "$install" "$direct" "$workdir/cache")"
        d_warm+=" $(seconds "$install" "$direct" "$workdir/cache")"
        start_proxy
        rm -rf "$workdir/cache"
        p_cold+=" $(seconds "$install" "$through" "$workdir/cache")"
        start_proxy
        warm_time+=" $(seconds "$binary" warm --lockfile "$lockfile" --proxy "$proxy")"
        rm -rf "$workdir/cache"
        p_warmed+=" $(seconds "$install" "$through" "$workdir/cache")"
        p_warm+=" $(seconds "$install" "$through" "$workdir/cache")"
        stop_proxy
    done
    printf '| %s | %s | %s | %s | %s | %s | %s |\n' "$name" \
        "$(echo "$d_cold" | median)" "$(echo "$d_warm" | median)" \
        "$(echo "$p_cold" | median)" "$(echo "$warm_time" | median)" \
        "$(echo "$p_warmed" | median)" "$(echo "$p_warm" | median)"
}

mkdir -p "$workdir/npm" "$workdir/pypi"
(cd "$workdir/npm" && printf '{"name":"bench","version":"1.0.0","private":true}\n' >package.json \
    && npm install "${npm_packages[@]}" --package-lock-only --no-audit --no-fund --loglevel=error)
npm_count="$(grep -c '"node_modules/' "$workdir/npm/package-lock.json")"
(cd "$workdir/pypi" && printf '%s\n' "${pypi_packages[@]}" >requirements.in \
    && uv pip compile -q requirements.in -o requirements.txt --python-version 3.12)
pypi_count="$(grep -cE '^[a-z0-9]' "$workdir/pypi/requirements.txt")"

echo "Median of $runs runs, in seconds. $(npm --version | sed 's/^/npm /'), $(uv --version)."
echo
echo "| Set | direct, cold | direct, warm cache | proxy, cold | byrle warm | proxy, analysed | proxy, warm cache |"
echo "|---|---|---|---|---|---|---|"
row "npm: $npm_count packages" npm_ci https://registry.npmjs.org/ "$proxy/" \
    "$workdir/npm/package-lock.json"
row "pypi: $pypi_count packages" uv_install https://pypi.org/simple "$proxy/simple/" \
    "$workdir/pypi/requirements.txt"
