#!/usr/bin/env bash
# Where npm, pnpm and yarn diverge when installing through the proxy.
#
# The proxy only sees what a client chooses to send it, and the clients do not agree.
# This measures, per client: how many packuments arrived, how many artifacts arrived, and
# how many artifacts were digest-verified.
#
# The number that matters is artifacts. A client that fetches `dist.tarball` at the
# absolute URL the packument gives goes straight to the origin registry, so the proxy
# never sees the bytes and verifies nothing.
#
# Clients that are not installed are reported and skipped rather than failing the run.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
port="${WAHAROA_PORT:-8732}"
registry="http://127.0.0.1:${port}/"
package="${WAHAROA_SMOKE_PACKAGE:-lodash}"
workdir="$(mktemp -d)"
proxy_pid=""

cleanup() {
    [[ -n "$proxy_pid" ]] && kill "$proxy_pid" 2>/dev/null || true
    rm -rf "$workdir"
}
trap cleanup EXIT

if ss -ltn 2>/dev/null | grep -q ":${port} "; then
    echo "port ${port} is already in use; set WAHAROA_PORT to something free"
    exit 1
fi

start_proxy() {
    local log="$1"
    WAHAROA_LISTEN="127.0.0.1:${port}" \
        cargo run --quiet --manifest-path "$repo_root/Cargo.toml" >"$log" 2>&1 &
    proxy_pid=$!
    for _ in $(seq 1 60); do
        grep -q "waharoa listening" "$log" && return 0
        kill -0 "$proxy_pid" 2>/dev/null || { echo "proxy exited during startup"; exit 1; }
        sleep 1
    done
    echo "proxy did not start within 60s"
    exit 1
}

stop_proxy() {
    [[ -n "$proxy_pid" ]] && kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
    proxy_pid=""
}

# A count that is zero is a result, not an error, so every grep tolerates no match.
count() { grep -c "$1" "$2" 2>/dev/null || true; }

measure() {
    local client="$1"; shift
    if ! command -v "$client" >/dev/null 2>&1; then
        printf '  %-6s NOT INSTALLED, skipped\n' "$client"
        return 0
    fi

    local dir="$workdir/$client" log="$workdir/$client.log"
    mkdir -p "$dir/cache"
    printf '{"name":"waharoa-smoke","version":"1.0.0","private":true}\n' >"$dir/package.json"
    start_proxy "$log"
    local rc=0
    (cd "$dir" && "$@") >"$dir/out" 2>&1 || rc=$?
    stop_proxy
    sed -i -E 's/\x1b\[[0-9;]*m//g' "$log"

    local packuments artifacts verified
    packuments="$(count 'packument normalized' "$log")"
    artifacts="$(grep -coE 'proxied .*path=/[^ ]+\.tgz' "$log" 2>/dev/null || true)"
    verified="$(count 'artifact digest verified' "$log")"

    local verdict="artifacts reach the proxy"
    if [[ "$artifacts" -eq 0 && "$packuments" -gt 0 ]]; then
        verdict="ARTIFACTS BYPASS THE PROXY"
    elif [[ "$packuments" -eq 0 ]]; then
        verdict="nothing reached the proxy"
    fi
    printf '  %-6s exit=%-2s packuments=%-4s artifacts=%-4s verified=%-4s %s\n' \
        "$client" "$rc" "$packuments" "$artifacts" "$verified" "$verdict"
}

echo "==> installing '$package' through the proxy with each client"
measure npm npm install "$package" --registry "$registry" \
    --cache "$workdir/npm/cache" --no-audit --no-fund --loglevel=error
measure pnpm pnpm add "$package" --registry "$registry" \
    --store-dir "$workdir/pnpm/cache" --reporter=silent
measure yarn yarn add "$package" --registry "$registry" \
    --cache-folder "$workdir/yarn/cache" --no-lockfile --silent

cat <<'NOTE'

Measured Sept 2026 with npm 9.9.4, pnpm 10.33.0, yarn 1.22.22:

  npm   rewrites dist.tarball to the configured registry, so artifacts arrive.
  pnpm  fetches dist.tarball at its absolute URL. Artifacts bypass the proxy.
  yarn  fetches dist.tarball at its absolute URL. Artifacts bypass the proxy.

For pnpm and yarn the proxy sees metadata and never the bytes, so nothing is
digest-verified and artifact analysis has nothing to analyse. Metadata policy still
applies, because both fetch packuments through the proxy.

Closing it means rewriting dist.tarball in the packument to point at the proxy, which
plan section 4 decided against. See docs/engineering_decisions/ for the open question.
NOTE
