#!/usr/bin/env bash
# Where npm, pnpm and yarn diverge when installing through the proxy.
#
# The proxy only sees what a client chooses to send it, and the clients do not agree about
# `dist.tarball`: npm rewrites it to the configured registry, pnpm 10 and yarn 1 use it
# verbatim. The proxy therefore rewrites artifact URLs to point at itself, so that every
# client in the ecosystem behaves the same way.
#
# This asserts that. Per client: packuments seen, artifacts seen, artifacts verified. An
# artifact count of zero means that client is fetching bytes the proxy never sees, which
# is the condition this whole mechanism exists to prevent.
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

# yarn 2+ is selected by a project rather than installed on PATH, so it needs a little
# setting up: corepack shims in a directory of our own, a packageManager field, and
# permission to talk to a plain http registry, which berry refuses by default.
#
# It also needs node 18 or later. corepack itself calls URL.canParse, which node 16 does
# not have, so on an older node this is skipped rather than failing confusingly.
prepare_yarn_berry() {
    local dir="$1"
    command -v corepack >/dev/null 2>&1 || return 1
    command -v node >/dev/null 2>&1 || return 1
    [[ "$(node --version | sed -E 's/^v([0-9]+).*/\1/')" -ge 18 ]] || return 1

    mkdir -p "$workdir/shims"
    corepack enable --install-directory "$workdir/shims" >/dev/null 2>&1 || return 1
    printf '{"name":"waharoa-smoke","version":"1.0.0","private":true,"packageManager":"yarn@4.9.1"}\n' \
        >"$dir/package.json"
    # globalFolder and enableMirror, not just enableGlobalCache. Measured: with only
    # enableGlobalCache off, berry copied the package out of its global mirror and the
    # proxy saw a packument and no artifact. Every client here has a cache that skips the
    # proxy, and every one of them has to be pointed somewhere disposable.
    cat >"$dir/.yarnrc.yml" <<YML
nodeLinker: node-modules
enableGlobalCache: false
enableMirror: false
globalFolder: "$dir/cache"
unsafeHttpWhitelist:
  - 127.0.0.1
YML
}

measure() {
    local client="$1"; shift
    local runner="$1"
    [[ "$client" == "yarn-berry" ]] && runner="corepack"
    if ! command -v "$runner" >/dev/null 2>&1; then
        printf '  %-10s NOT INSTALLED, skipped\n' "$client"
        return 0
    fi

    local dir="$workdir/$client" log="$workdir/$client.log"
    mkdir -p "$dir/cache"
    printf '{"name":"waharoa-smoke","version":"1.0.0","private":true}\n' >"$dir/package.json"

    if [[ "$client" == "yarn-berry" ]]; then
        if ! prepare_yarn_berry "$dir"; then
            printf '  %-10s needs corepack and node 18 or later, skipped\n' "$client"
            return 0
        fi
    fi
    start_proxy "$log"
    local rc=0
    (cd "$dir" && "$@") >"$dir/out" 2>&1 || rc=$?
    stop_proxy
    sed -i -E 's/\x1b\[[0-9;]*m//g' "$log"

    local packuments artifacts verified
    packuments="$(count 'packument normalized' "$log")"
    artifacts="$(grep -coE 'proxied .*path=/[^ ]+\.tgz' "$log" 2>/dev/null || true)"
    verified="$(count 'artifact digest verified' "$log")"

    printf '  %-10s exit=%-2s packuments=%-4s artifacts=%-4s verified=%-4s\n' \
        "$client" "$rc" "$packuments" "$artifacts" "$verified"

    if [[ "$rc" -ne 0 ]]; then
        echo "FAIL: $client could not install through the proxy"
        sed -n '1,20p' "$dir/out"
        failed=1
        return 0
    fi
    if [[ "$artifacts" -eq 0 ]]; then
        echo "FAIL: $client fetched no artifacts through the proxy, so it is fetching them"
        echo "      somewhere the proxy cannot see. Check dist.tarball rewriting."
        failed=1
        return 0
    fi
    if [[ "$verified" -ne "$artifacts" ]]; then
        echo "FAIL: $client fetched $artifacts artifacts but only $verified were verified"
        failed=1
    fi
    if grep -q 'UNINSPECTED' "$log"; then
        echo "FAIL: something went unexamined for $client:"
        grep 'UNINSPECTED' "$log" | head -3
        failed=1
    fi
}

failed=0

echo "==> installing '$package' through the proxy with each client"
measure npm npm install "$package" --registry "$registry" \
    --cache "$workdir/npm/cache" --no-audit --no-fund --loglevel=error
measure pnpm pnpm add "$package" --registry "$registry" \
    --store-dir "$workdir/pnpm/cache" --reporter=silent
measure yarn yarn add "$package" --registry "$registry" \
    --cache-folder "$workdir/yarn/cache" --no-lockfile --silent

# `yarn-berry` is not a binary. The runner is the corepack shim, picked up from PATH, and
# the project's packageManager field decides the version.
measure yarn-berry env "PATH=$workdir/shims:$PATH" COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    "YARN_NPM_REGISTRY_SERVER=$registry" yarn add "$package"

# --cache-dir, or bun serves from its global cache and never contacts the proxy. Measured:
# without it, zero packuments and zero artifacts reached the proxy and the install still
# succeeded, which is the same bypass npm's cache produces.
measure bun bun add "$package" --registry "$registry" --cache-dir "$workdir/bun/cache"

if [[ "$failed" -ne 0 ]]; then
    echo
    echo "FAIL: see above."
    exit 1
fi

cat <<'NOTE'

All clients fetch artifacts through the proxy, because artifact URLs are rewritten to
point at it. Without that, measured Sept 2026 against a registry whose dist.tarball named
a host where the package does not exist:

  npm 9.9.4        rewrites dist.tarball to the configured registry, so artifacts arrive.
  pnpm 10.33.0     uses the URL as written. Artifacts bypass the proxy.
  yarn 1.22.22     the same.
  yarn 4.9.1       the same, and records the URL in its lockfile when it is off-registry.
  bun 1.3.14       the same.

npm is the only one of the five that rewrites, which is why the proxy does it for all of
them rather than per client.

Every client also has a cache that skips the proxy entirely, and this script points each
one at a disposable directory. Without that, bun and yarn 4 both installed successfully
having asked the proxy for nothing.

See docs/engineering_decisions/packument-tarball-url-rewriting.md.
NOTE
