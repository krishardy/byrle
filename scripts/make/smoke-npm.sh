#!/usr/bin/env bash
# End-to-end check of the Stage 1 proxy against a real npm client.
#
# This is a manual verification script, not the project's test strategy: picking that
# is still an open TODO item. It exists because Stage 1's exit criterion is stated in
# terms of real client behavior, so it has to be checked with a real client.
#
# Asserts, in order:
#   1. a plain install completes through the proxy
#   2. every installed package, transitive ones included, was fetched through us
#   3. a hardcoded block returns 403 and fires before any tarball is fetched
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
port="${WAHAROA_PORT:-8731}"
registry="http://127.0.0.1:${port}/"
workdir="$(mktemp -d)"
log="$workdir/proxy.log"
proxy_pid=""

cleanup() {
    [[ -n "$proxy_pid" ]] && kill "$proxy_pid" 2>/dev/null || true
    rm -rf "$workdir"
}
trap cleanup EXIT

command -v npm >/dev/null || { echo "npm is required for this check"; exit 1; }

if ss -ltn 2>/dev/null | grep -q ":${port} "; then
    echo "port ${port} is already in use; set WAHAROA_PORT to something free"
    exit 1
fi

fail() { echo "FAIL: $*"; echo "--- proxy log ---"; cat "$log"; exit 1; }

start_proxy() {
    WAHAROA_LISTEN="127.0.0.1:${port}" WAHAROA_BLOCK="${1:-}" \
        cargo run --quiet --manifest-path "$repo_root/Cargo.toml" >"$log" 2>&1 &
    proxy_pid=$!
    for _ in $(seq 1 60); do
        grep -q "waharoa listening" "$log" && return 0
        kill -0 "$proxy_pid" 2>/dev/null || fail "proxy exited during startup"
        sleep 1
    done
    fail "proxy did not start within 60s"
}

stop_proxy() {
    [[ -n "$proxy_pid" ]] && kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
    proxy_pid=""
}

# A fresh cache per install, since npm serves from its cache without consulting the
# registry and would otherwise skip enforcement entirely. That bypass is a real one
# (see plan §7); here it would just invalidate the check.
npm_install() {
    local dir="$1"; shift
    mkdir -p "$dir/cache"
    (cd "$dir" && npm install "$@" \
        --registry "$registry" --cache "$dir/cache" \
        --no-audit --no-fund --loglevel=error)
}

echo "==> 1/3  install completes through the proxy"
start_proxy ""
npm_install "$workdir/basic" lodash >/dev/null 2>&1 || fail "npm install lodash failed"
[[ -d "$workdir/basic/node_modules/lodash" ]] || fail "lodash was not installed"
echo "    ok"

echo "==> 2/3  every package, transitive included, came through the proxy"
npm_install "$workdir/deps" express >/dev/null 2>&1 || fail "npm install express failed"
on_disk="$(find "$workdir/deps/node_modules" -maxdepth 1 -mindepth 1 -not -name '.*' -printf '%f\n' | sort)"
fetched="$(sed -E 's/\x1b\[[0-9;]*m//g' "$log" \
    | grep -oE 'path=/[^ ]+\.tgz' | sed -E 's|path=/||; s|/-/.*||' | sort -u)"
missed="$(comm -23 <(echo "$on_disk") <(echo "$fetched") || true)"
[[ -z "$missed" ]] || fail "these packages never came through the proxy: $(echo "$missed" | tr '\n' ' ')"
echo "    ok ($(echo "$on_disk" | wc -l) packages, all intercepted)"
stop_proxy

echo "==> 3/3  hardcoded block returns 403 before any tarball is fetched"
# `ms` is a transitive dependency of `debug`, never a direct install target, so this
# also proves the block reaches packages the user never named.
start_proxy "ms"
if npm_install "$workdir/blocked" debug >/dev/null 2>&1; then
    fail "install succeeded but should have been blocked"
fi
sed -E 's/\x1b\[[0-9;]*m//g' "$log" | grep -q 'blocked.*path=/ms.*status=403' \
    || fail "no 403 recorded for the blocked package"
if sed -E 's/\x1b\[[0-9;]*m//g' "$log" | grep -qE 'proxied.*path=/ms/-/'; then
    fail "a tarball for the blocked package was fetched; the block came too late"
fi
echo "    ok (403 on the packument, no tarball fetched)"

echo
echo "PASS: Stage 1 proxy behaves as the exit criterion requires."
