#!/usr/bin/env bash
# Whether upstream traffic honours the forward proxy variables, checked with the binary.
#
# Plain HTTP throughout: a local registry, a local forward proxy that logs what it
# carries, and the proxy's npm upstream pointed at the registry. Asserts, in order:
#   1. HTTP_PROXY set: the request goes through the forward proxy, and startup says so
#   2. HTTP_PROXY pointing at nothing: 502
#   3. NO_PROXY naming the registry: the request goes direct
#   4. only HTTPS_PROXY set: an http upstream goes direct
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
registry_port="${WAHAROA_REGISTRY_PORT:-8751}"
forward_port="${WAHAROA_FORWARD_PORT:-8752}"
port="${WAHAROA_PORT:-8753}"
workdir="$(mktemp -d)"
pids=()

cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    rm -rf "$workdir"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

mkdir -p "$workdir/registry"
printf '{"name":"widget","versions":{}}' >"$workdir/registry/widget"
python3 -m http.server "$registry_port" --bind 127.0.0.1 --directory "$workdir/registry" \
    >/dev/null 2>&1 &
pids+=("$!")
python3 "$repo_root/scripts/make/lib/forward_proxy.py" "$forward_port" "$workdir/carried.log" &
pids+=("$!")
cargo build --quiet --manifest-path "$repo_root/Cargo.toml"
binary="$repo_root/target/debug/waharoa"

# Runs the proxy with the given variables, asks it for /widget, and sets `status`.
# Every proxy variable is set, so none leaks in from the calling shell.
ask() {
    local log="$workdir/proxy-$1.log"; shift
    env HTTPS_PROXY= https_proxy= HTTP_PROXY= http_proxy= NO_PROXY= no_proxy= "$@" \
        WAHAROA_UPSTREAM_NPM="http://127.0.0.1:${registry_port}" \
        WAHAROA_SPOOL_DIR="$workdir/spool" WAHAROA_LISTEN="127.0.0.1:${port}" \
        "$binary" daemon >"$log" 2>&1 &
    local pid=$!
    for _ in $(seq 1 60); do
        grep -q "waharoa listening" "$log" && break
        kill -0 "$pid" 2>/dev/null || fail "proxy exited during startup: $(cat "$log")"
        sleep 0.5
    done
    status="$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 --noproxy '*' \
        "http://127.0.0.1:${port}/widget")"
    kill "$pid"; wait "$pid" 2>/dev/null || true
}

carried() {
    [[ -f "$workdir/carried.log" ]] || { echo 0; return; }
    grep -c "widget" "$workdir/carried.log" || true
}
forward="http://127.0.0.1:${forward_port}"

echo "==> 1/4  HTTP_PROXY set: the request goes through the forward proxy"
ask through HTTP_PROXY="$forward"
[[ "$status" == 200 ]] || fail "answered $status"
[[ "$(carried)" == 1 ]] || fail "the forward proxy carried $(carried) requests, not 1"
sed -E 's/\x1b\[[0-9;]*m//g' "$workdir/proxy-through.log" \
    | grep -q "upstream traffic goes through a forward proxy waharoa.forward_proxy.https=\"none\" waharoa.forward_proxy.http=\"$forward/\"" \
    || fail "startup did not name the forward proxy"
echo "    ok (200, carried by the forward proxy, named at startup)"

echo "==> 2/4  HTTP_PROXY pointing at nothing: 502"
ask dead HTTP_PROXY="http://127.0.0.1:1"
[[ "$status" == 502 ]] || fail "answered $status"
echo "    ok (502)"

echo "==> 3/4  NO_PROXY naming the registry: the request goes direct"
ask exempt HTTP_PROXY="$forward" NO_PROXY=127.0.0.1
[[ "$status" == 200 ]] || fail "answered $status"
[[ "$(carried)" == 1 ]] || fail "the forward proxy carried an exempt request"
echo "    ok (200, not carried)"

echo "==> 4/4  only HTTPS_PROXY set: an http upstream goes direct"
ask https-only HTTPS_PROXY="$forward"
[[ "$status" == 200 ]] || fail "answered $status"
[[ "$(carried)" == 1 ]] || fail "the forward proxy carried an http request under HTTPS_PROXY"
echo "    ok (200, not carried)"

echo
echo "PASS: upstream traffic honours HTTP_PROXY, HTTPS_PROXY and NO_PROXY."
