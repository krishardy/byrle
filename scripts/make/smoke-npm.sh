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
#   3. every one of them was normalized to a PURL, at the version on disk
#   4. every tarball's digest was known before the fetch and verified on the way past
#   5. `npm ci`, which requests no packuments at all, still verifies every artifact
#   6. policy filters a denied version on resolution and refuses it on a pinned fetch
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/make/lib/node.sh
. "$repo_root/scripts/make/lib/node.sh"
waharoa_use_latest_node

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
    WAHAROA_SPOOL_DIR="$workdir/spool" WAHAROA_LISTEN="127.0.0.1:${port}" WAHAROA_POLICY="${1:-}" \
        cargo run --quiet --manifest-path "$repo_root/Cargo.toml" -- daemon >"$log" 2>&1 &
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

echo "==> 1/6  install completes through the proxy"
start_proxy ""
npm_install "$workdir/basic" lodash >/dev/null 2>&1 || fail "npm install lodash failed"
[[ -d "$workdir/basic/node_modules/lodash" ]] || fail "lodash was not installed"
echo "    ok"

echo "==> 2/6  every package, transitive included, came through the proxy"
# @babel/code-frame is here for its scope: a scoped name becomes a percent-encoded purl
# namespace, and that is the part of the identity type most likely to regress.
npm_install "$workdir/deps" express @babel/code-frame >/dev/null 2>&1 \
    || fail "npm install failed"
on_disk="$(find "$workdir/deps/node_modules" -maxdepth 1 -mindepth 1 -not -name '.*' -printf '%f\n' \
    | grep -v '^@' | sort)"
scoped="$(find "$workdir/deps/node_modules" -maxdepth 2 -mindepth 2 -path '*/@*' -printf '%P\n' 2>/dev/null | sort)"
on_disk="$(printf '%s\n%s\n' "$on_disk" "$scoped" | grep -v '^$' | sort)"
fetched="$(sed -E 's/\x1b\[[0-9;]*m//g' "$log" \
    | grep -oE 'url.path=/[^ ]+\.tgz' | sed -E 's|url.path=/||; s|/-/.*||' | sort -u)"
missed="$(comm -23 <(echo "$on_disk") <(echo "$fetched") || true)"
[[ -z "$missed" ]] || fail "these packages never came through the proxy: $(echo "$missed" | tr '\n' ' ')"
echo "    ok ($(echo "$on_disk" | wc -l) packages, all intercepted)"

echo "==> 3/6  every installed package was normalized to a PURL at the version on disk"
clean_log="$workdir/clean.log"
sed -E 's/\x1b\[[0-9;]*m//g' "$log" >"$clean_log"

# What npm actually resolved, as purls: the scope's `@` is percent-encoded, matching
# what `identity::PackageRef` renders.
expected_purls="$(
    find "$workdir/deps/node_modules" -mindepth 2 -maxdepth 3 -name package.json \
        -not -path '*/node_modules/*/node_modules/*' -print0 \
    | xargs -0 -r jq -r 'select(.name and .version) | "pkg:npm/\(.name)@\(.version)"' \
    | sed 's|pkg:npm/@|pkg:npm/%40|' | sort -u
)"
[[ -n "$expected_purls" ]] || fail "could not read any installed package versions"

observed_purls="$(grep -oE 'waharoa.package.claimed_purl=[^ ]+' "$clean_log" | cut -d= -f2- | sort -u)"
unnormalized="$(comm -23 <(echo "$expected_purls") <(echo "$observed_purls") || true)"
[[ -z "$unnormalized" ]] \
    || fail "installed but never normalized to a purl: $(echo "$unnormalized" | tr '\n' ' ')"

# The packument side: every package had its document parsed, and no version inside any
# of those documents was skipped. A skip means a shape the normalizer cannot read.
grep -q 'packument normalized.*waharoa.package.purl=pkg:npm/%40babel/code-frame' "$clean_log" \
    || fail "the scoped packument was never normalized"
if grep -oE 'packument normalized.*skipped=[0-9]+' "$clean_log" | grep -qv 'skipped=0'; then
    fail "a packument had versions the normalizer could not read:
$(grep -E 'packument normalized.*skipped=[0-9]+' "$clean_log" | grep -v 'skipped=0')"
fi
normalized_count="$(grep -c 'packument normalized' "$clean_log")"
echo "    ok ($(echo "$expected_purls" | wc -l) purls, $normalized_count packuments, 0 versions skipped)"

echo "==> 4/6  every tarball digest was known before the fetch and verified"
# The digest comes from a packument seen earlier in the same run, which is what makes
# cache-hit-versus-miss decidable before a byte is fetched (plan section 5).
# A tarball nothing has analysed is deferred with a 503 until its analysis has finished,
# under any policy, and served on npm's retry. Every request logs the digest; only the
# served one is proxied.
known="$(grep -c 'digest known' "$clean_log" || true)"
deferred="$(grep -c 'deferred: the artifact has not been analysed' "$clean_log" || true)"
verified="$(grep -c 'artifact digest verified' "$clean_log" || true)"
tarballs="$(grep -coE 'proxied .*url.path=/[^ ]+\.tgz' "$clean_log" || true)"

[[ "$((known - deferred))" -eq "$tarballs" ]] \
    || fail "$tarballs tarballs fetched but only $((known - deferred)) had a digest from their packument"
[[ "$verified" -eq "$tarballs" ]] \
    || fail "$tarballs tarballs fetched but only $verified were verified"
if grep -q 'MISMATCH' "$clean_log"; then
    fail "a tarball did not match the digest its packument published:
$(grep 'MISMATCH' "$clean_log")"
fi
grep -q 'not served' "$clean_log" \
    && fail "a tarball could not be assessed: $(grep 'not served' "$clean_log" | head -1)"

# No false positives on the real registry: every artifact it publishes has to look like
# one the proxy will see. A warning here against registry.npmjs.org is a bug in the
# check, not a finding.
if grep -q 'PUBLISHED OFF' "$clean_log"; then
    fail "the offsite-artifact check fired against the real registry:
$(grep 'PUBLISHED OFF' "$clean_log")"
fi
echo "    ok ($tarballs tarballs, all with a known digest, all verified, none offsite, $deferred deferred for analysis)"
stop_proxy

echo "==> 5/6  npm ci verifies every artifact although it requests no packuments"
# npm ci reads `resolved` and `integrity` from package-lock.json and asks for no
# packuments at all. Measured before the proxy fetched them itself: 69 tarballs, zero
# packument requests, nothing verified. A fresh proxy and a fresh npm cache here, so the
# only way a digest can be known is the proxy fetching the packument on its own behalf.
[[ -f "$workdir/deps/package-lock.json" ]] || fail "step 2 produced no lockfile"
rm -rf "$workdir/deps/node_modules" "$workdir/deps/cache"
mkdir -p "$workdir/deps/cache"
start_proxy ""
(cd "$workdir/deps" && npm ci \
    --registry "$registry" --cache "$workdir/deps/cache" \
    --no-audit --no-fund --loglevel=error) >/dev/null 2>&1 || fail "npm ci failed"

sed -E 's/\x1b\[[0-9;]*m//g' "$log" >"$clean_log"
ci_tarballs="$(grep -coE 'proxied .*url.path=/[^ ]+\.tgz' "$clean_log" || true)"
ci_verified="$(grep -c 'artifact digest verified' "$clean_log" || true)"
ci_fetched="$(grep -c 'on our own behalf' "$clean_log" || true)"
[[ "$ci_tarballs" -gt 0 ]] || fail "npm ci fetched no tarballs through the proxy"
[[ "$ci_verified" -eq "$ci_tarballs" ]] \
    || fail "npm ci fetched $ci_tarballs tarballs but only $ci_verified were verified"
echo "    ok ($ci_tarballs tarballs, $ci_fetched packuments fetched by the proxy, all verified)"
stop_proxy

echo "==> 6/6  policy refuses a version, both ways decision #4 says it should"
# `ms` is a transitive dependency of `debug`, never a direct install target, so this also
# proves policy reaches packages the user never named. 2.1.3 is a long-published version,
# so the denial names something the registry really serves.
cat >"$workdir/deny.yaml" <<'YAML'
version: 1
cooldown_days: 0
denials:
  - purl: pkg:npm/ms@2.1.3
    reason: smoke test, so the refusal is a real policy answer and not a hardcoded one
YAML
start_proxy "$workdir/deny.yaml"

# On resolution: the version is gone from the document, and the answer is still a 200.
# A 4xx here would read as a broken registry to every client.
packument_status=$(curl -s -o "$workdir/ms.json" -w '%{http_code}' "http://127.0.0.1:${port}/ms")
[[ "$packument_status" == "200" ]] \
    || fail "filtering answered $packument_status; it has to be a 200 with fewer versions"
if python3 -c "import json,sys; sys.exit(0 if '2.1.3' in json.load(open(sys.argv[1]))['versions'] else 1)" \
    "$workdir/ms.json"; then
    fail "the denied version is still in the packument, so a resolver can still pick it"
fi
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if len(d['versions'])>0 else 1)" \
    "$workdir/ms.json" || fail "every version was removed; only 2.1.3 is denied"

# On a pinned fetch: there is no resolution left to influence, so it refuses.
tarball_status=$(curl -s -o "$workdir/ms.out" -w '%{http_code}' \
    "http://127.0.0.1:${port}/ms/-/ms-2.1.3.tgz")
[[ "$tarball_status" == "403" ]] || fail "pinned fetch of a denied version answered $tarball_status"
grep -q 'pkg:npm/ms@2.1.3' "$workdir/ms.out" \
    || fail "the refusal does not name the package it refused"
grep -q 'denials' "$workdir/ms.out" || fail "the refusal does not say which check fired"

if sed -E 's/\x1b\[[0-9;]*m//g' "$log" | grep -qE 'proxied.*url.path=/ms/-/ms-2\.1\.3\.tgz'; then
    fail "the denied artifact was fetched upstream; the refusal came too late"
fi
echo "    ok (filtered on resolution, 403 on the pinned fetch, artifact never fetched)"

echo
echo "PASS: Stage 1 proxy behaves as the exit criterion requires."
