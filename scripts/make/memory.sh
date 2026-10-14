#!/usr/bin/env bash
# The proxy's memory under four loads, each on a fresh process, run as a team deploys it
# (scripts/make/lib/deployed.sh): an `npm ci` and a `uv pip install` of the `make bench`
# sets through a cold proxy, 8 simultaneous requests for vite's full document, the
# largest measured, and 24 for the 8 largest documents 3 times each.
#
# Each row is the peak RSS (VmHWM), the median of RSS sampled every 0.2 s while the load
# runs, and RSS 30 s after it ends, in MB.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
port="${BYRLE_PORT:-8762}"
pg_port="${BYRLE_PG_PORT:-55438}"
idle_seconds="${BYRLE_MEMORY_IDLE_SECONDS:-30}"
largest=(typescript @types/node react next @angular/core eslint webpack aws-sdk)
workdir="$(mktemp -d)"
sampler_pid=""
# shellcheck source=scripts/make/lib/deployed.sh
. "$repo_root/scripts/make/lib/deployed.sh"

cleanup() {
    [[ -n "$sampler_pid" ]] && kill "$sampler_pid" 2>/dev/null || true
    stop_proxy
    stop_postgres
    rm -rf "$workdir"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }

# A field of the proxy's /proc status, such as VmRSS, in MB.
status_mb() { awk -v f="$1:" '$1 == f { printf "%.0f", $2 / 1024 }' "/proc/$proxy_pid/status"; }

# GET each package's document through the proxy, all at once. Waits for these requests
# only: a bare `wait` would wait for the proxy too.
documents() {
    local name pids=() pid
    for name in "$@"; do
        curl -sf -o /dev/null -m 300 -H "authorization: Bearer $token" "$proxy/$name" &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" || return 1
    done
}

# One row: run the load $2... on a fresh proxy, named $1.
measure() {
    local name="$1" median
    shift
    start_proxy
    : >"$workdir/samples"
    while sleep 0.2; do status_mb VmRSS >>"$workdir/samples"; echo >>"$workdir/samples"; done &
    sampler_pid=$!
    "$@" >"$workdir/load.out" 2>&1 || fail "$name failed: $(tail -10 "$workdir/load.out")"
    kill "$sampler_pid"
    wait "$sampler_pid" 2>/dev/null || true
    sampler_pid=""
    median="$(grep -v '^$' "$workdir/samples" | sort -n \
        | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }')"
    sleep "$idle_seconds"
    printf '| %s | %s | %s | %s |\n' "$name" "$(status_mb VmHWM)" "$median" "$(status_mb VmRSS)"
    stop_proxy
}

deployed_setup memory
deployed_sets
discover

echo "In MB. Each load on a fresh proxy; idle is ${idle_seconds} s after the load ends."
echo
echo "| Load | peak | median while loaded | idle |"
echo "|---|---|---|---|"
measure "npm ci, $npm_count packages, cold proxy" npm_ci "$npm_through" "$workdir/cache-npm"
measure "uv pip install, $pypi_count packages, cold proxy" \
    uv_install "$pypi_through" "$workdir/cache-pypi"
measure "8 at once: vite's full document" documents vite vite vite vite vite vite vite vite
measure "24 at once: the 8 largest documents, 3 times each" \
    documents "${largest[@]}" "${largest[@]}" "${largest[@]}"
