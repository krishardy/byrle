#!/usr/bin/env bash
# Install times through the proxy against installs direct from the registries.
#
# One large npm set and one large PyPI set, each installed from a lockfile in five cases:
# direct with an empty and a filled client cache, and through the proxy fresh (nothing
# analysed), after `byrle warm`, and with the client's cache filled. Each case runs
# BYRLE_BENCH_RUNS times (default 3) and the median is reported, in seconds.
#
# The proxy runs as deployed: a token required, intel from a `byrle refresh` into a
# disposable Postgres, a policy of every default, and each request's usage recorded. A
# version the defaults refuse would stop the install, so a discovery pass installs through
# the proxy first and adds an exception for each refusal; the table lists them.
#
# The latency budget, set by the user 2026-10-13: a median over it exits 1. Through an
# analysed proxy at most 1.5 times the direct cold install, through a cold one at most 2
# times, and with the client's cache filled at most 1 s over the same direct. Since
# 2026-10-14 the first two are also allowed 3 s over direct, whichever is larger: a 1.6 s
# direct install left the proxy 0.8 s.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
port="${BYRLE_PORT:-8761}"
pg_port="${BYRLE_PG_PORT:-55437}"
runs="${BYRLE_BENCH_RUNS:-3}"
analysed_ratio="${BYRLE_BENCH_ANALYSED_RATIO:-1.5}"
cold_ratio="${BYRLE_BENCH_COLD_RATIO:-2}"
warm_cache_seconds="${BYRLE_BENCH_WARM_CACHE_SECONDS:-1}"
allowance="${BYRLE_BENCH_ALLOWANCE_SECONDS:-3}"
over_budget=()
workdir="$(mktemp -d)"
# shellcheck source=scripts/make/lib/deployed.sh
. "$repo_root/scripts/make/lib/deployed.sh"

cleanup() {
    stop_proxy
    stop_postgres
    rm -rf "$workdir"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }

deployed_setup bench

# Seconds the command took, or FAIL. The first failure's output goes to stderr.
seconds() {
    local start end
    start="$(date +%s.%N)"
    if ! "$@" >"$workdir/last.out" 2>&1; then
        if [[ ! -e "$workdir/failed" ]]; then
            touch "$workdir/failed"
            { echo "--- first failure: $* ---"; tail -15 "$workdir/last.out"
              echo "--- proxy log, refusals and errors ---"
              grep -E "refused|ERROR" "$workdir/proxy.log" | sed -E 's/\x1b\[[0-9;]*m//g' \
                  | cut -c1-400 | tail -10; } >&2
        fi
        echo FAIL
        return 0
    fi
    end="$(date +%s.%N)"
    awk -v s="$start" -v e="$end" 'BEGIN { printf "%.1f", e - s }'
}

median() { tr ' ' '\n' | grep -v '^$' | sort -g | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }

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
        warm_time+=" $(BYRLE_TOKEN="$token" seconds "$binary" warm --lockfile "$lockfile" \
            --proxy "$proxy")"
        rm -rf "$workdir/cache"
        p_warmed+=" $(seconds "$install" "$through" "$workdir/cache")"
        p_warm+=" $(seconds "$install" "$through" "$workdir/cache")"
        stop_proxy
    done
    local direct cached cold analysed warm
    direct="$(echo "$d_cold" | median)"
    cached="$(echo "$d_warm" | median)"
    cold="$(echo "$p_cold" | median)"
    analysed="$(echo "$p_warmed" | median)"
    warm="$(echo "$p_warm" | median)"
    printf '| %s | %s | %s | %s | %s | %s | %s |\n' "$name" "$direct" "$cached" "$cold" \
        "$(echo "$warm_time" | median)" "$analysed" "$warm"
    within "$name, proxy analysed" "$analysed" \
        "larger($direct * $analysed_ratio, $direct + $allowance)" \
        "${analysed_ratio}x direct or direct + ${allowance}s"
    within "$name, proxy cold" "$cold" "larger($direct * $cold_ratio, $direct + $allowance)" \
        "${cold_ratio}x direct or direct + ${allowance}s"
    within "$name, proxy warm cache" "$warm" "$cached + $warm_cache_seconds" \
        "direct + ${warm_cache_seconds}s"
}

# Record case $1 as over budget when its median $2 is FAIL, or over the expression $3,
# described as $4. A FAIL in $3 makes it over budget too.
within() {
    local limit
    if [[ "$3" == *FAIL* ]]; then
        limit=FAIL
    else
        limit="$(awk "function larger(a, b) { return a > b ? a : b }
            BEGIN { printf \"%.1f\", $3 }")"
    fi
    if [[ "$2" == FAIL || "$limit" == FAIL ]] \
        || awk -v m="$2" -v l="$limit" 'BEGIN { exit !(m > l) }'; then
        over_budget+=("$1: $2 s, budget $limit s, $4")
    fi
}

deployed_sets
discover

echo "Median of $runs runs, in seconds. $(npm --version | sed 's/^/npm /'), $(uv --version)."
echo
echo "| Set | direct, cold | direct, warm cache | proxy, cold | byrle warm | proxy, analysed | proxy, warm cache |"
echo "|---|---|---|---|---|---|---|"
row "npm: $npm_count packages" npm_ci https://registry.npmjs.org/ "$npm_through" \
    "$workdir/npm/package-lock.json"
row "pypi: $pypi_count packages" uv_install https://pypi.org/simple "$pypi_through" \
    "$workdir/pypi/requirements.txt"
echo
if [[ -s "$workdir/exceptions.txt" ]]; then
    echo "Refused under the defaults, and released by an exception for the measurement:"
    sort -u "$workdir/reasons.txt"
else
    echo "Nothing was refused under the defaults."
fi
echo
if [[ ${#over_budget[@]} -gt 0 ]]; then
    echo "Over the latency budget:"
    printf '    %s\n' "${over_budget[@]}"
    exit 1
fi
echo "Within the latency budget."
