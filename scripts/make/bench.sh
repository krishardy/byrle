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
# times, and with the client's cache filled at most 1 s over the same direct.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/make/lib/postgres.sh
. "$repo_root/scripts/make/lib/postgres.sh"
# shellcheck source=scripts/make/lib/token.sh
. "$repo_root/scripts/make/lib/token.sh"
port="${BYRLE_PORT:-8761}"
pg_port="${BYRLE_PG_PORT:-55437}"
runs="${BYRLE_BENCH_RUNS:-3}"
analysed_ratio="${BYRLE_BENCH_ANALYSED_RATIO:-1.5}"
cold_ratio="${BYRLE_BENCH_COLD_RATIO:-2}"
warm_cache_seconds="${BYRLE_BENCH_WARM_CACHE_SECONDS:-1}"
over_budget=()
npm_packages=(next react react-dom eslint typescript vite vitest)
pypi_packages=(pandas scikit-learn matplotlib)
workdir="$(mktemp -d)"
proxy_pid=""
proxy="http://127.0.0.1:${port}"

cleanup() {
    [[ -n "$proxy_pid" ]] && kill "$proxy_pid" 2>/dev/null || true
    stop_postgres
    rm -rf "$workdir"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }

require_free_ports "$port" || fail "the proxy's port is taken"
cargo build --release --quiet --manifest-path "$repo_root/Cargo.toml"
binary="$repo_root/target/release/byrle"

start_postgres "byrle-bench-pg-$$" "$pg_port" || fail "postgres did not start"
# start_postgres sets its own EXIT trap; cleanup stops Postgres as well as the rest.
trap cleanup EXIT
export BYRLE_DATABASE_URL
BYRLE_DATABASE_URL="$(postgres_url "$pg_port")"
# Exit 1 is an optional stream that did not load, such as GitHub's without a token.
"$binary" refresh >"$workdir/refresh.out" 2>&1 || [[ $? -le 1 ]] \
    || fail "byrle refresh failed: $(tail -5 "$workdir/refresh.out")"
token="$(issue_token "$BYRLE_DATABASE_URL" bench)"
printf 'version: 1\n' >"$workdir/policy.yaml"

start_proxy() {
    stop_proxy
    rm -rf "$workdir/spool"
    BYRLE_POLICY="$workdir/policy.yaml" BYRLE_SPOOL_DIR="$workdir/spool" \
        BYRLE_AUDIT_LOG="$workdir/audit.jsonl" \
        BYRLE_LISTEN="127.0.0.1:${port}" "$binary" daemon >"$workdir/proxy.log" 2>&1 &
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
    within "$name, proxy analysed" "$analysed" "$direct * $analysed_ratio" \
        "${analysed_ratio}x direct"
    within "$name, proxy cold" "$cold" "$direct * $cold_ratio" "${cold_ratio}x direct"
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
        limit="$(awk "BEGIN { printf \"%.1f\", $3 }")"
    fi
    if [[ "$2" == FAIL || "$limit" == FAIL ]] \
        || awk -v m="$2" -v l="$limit" 'BEGIN { exit !(m > l) }'; then
        over_budget+=("$1: $2 s, budget $limit s, $4")
    fi
}

# Resolved as of 8 days ago, past the policy's default 7-day cooldown, so the proxy serves
# every version the lockfile names.
before="$(date -u -d '8 days ago' +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p "$workdir/npm" "$workdir/pypi"
(cd "$workdir/npm" && printf '{"name":"bench","version":"1.0.0","private":true}\n' >package.json \
    && npm install "${npm_packages[@]}" --package-lock-only --before "$before" \
        --no-audit --no-fund --loglevel=error)
# Scoped to the proxy, so the direct installs send nothing.
printf '//127.0.0.1:%s/:_authToken=%s\n' "$port" "$token" >"$workdir/npm/.npmrc"
npm_count="$(grep -c '"node_modules/' "$workdir/npm/package-lock.json")"
(cd "$workdir/pypi" && printf '%s\n' "${pypi_packages[@]}" >requirements.in \
    && uv pip compile -q requirements.in -o requirements.txt --python-version 3.12 \
        --exclude-newer "$before")
pypi_count="$(grep -cE '^[a-z0-9]' "$workdir/pypi/requirements.txt")"

npm_through="$proxy/"
pypi_through="http://bench:${token}@127.0.0.1:${port}/simple/"

# Install both sets through the proxy until neither is refused, adding an exception for
# each version the audit log shows refused. Each round finds at least one, or stops.
discover() {
    local round
    : >"$workdir/exceptions.txt"
    for round in $(seq 1 20); do
        start_proxy
        rm -rf "$workdir/cache"
        if npm_ci "$npm_through" "$workdir/cache" >"$workdir/discover.out" 2>&1 \
            && uv_install "$pypi_through" "$workdir/cache" >"$workdir/discover.out" 2>&1; then
            stop_proxy
            return 0
        fi
        stop_proxy
        sed -E 's/\x1b\[[0-9;]*m//g' "$workdir/proxy.log" | grep "refused by policy" \
            | sed -E 's/.*claimed_purl=([^ ]+) .*policy.reasons=\[([^]]*)\].*/    \1: \2/' \
            >>"$workdir/reasons.txt" || true
        python3 "$repo_root/scripts/make/bench_exceptions.py" "$workdir/audit.jsonl" \
            "$workdir/policy.yaml" >"$workdir/exceptions.txt"
        cmp -s "$workdir/exceptions.txt" "$workdir/exceptions.before" \
            && fail "round $round failed with no new refusal: $(tail -10 "$workdir/discover.out")"
    done
    fail "still refused after $round rounds"
}
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
