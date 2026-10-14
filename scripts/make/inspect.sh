#!/usr/bin/env bash
# Send one packument request and one artifact request as each package manager, and print
# the responses side by side with what the registry originally served.
#
# For looking, not for asserting. `make smoke-clients` is the one that fails a build;
# this one exists so the rewriting, the encoding narrowing and the digest check can be
# seen rather than inferred from a log.
#
# The requests are simulated with curl rather than run through the real clients, so that
# one exact request is visible at a time. The headers are the ones the real clients send,
# captured from npm 9.9.4, pnpm 10.33.0 and yarn 1.22.22 against a recording server.
#
# Usage:
#   make inspect                      lodash, through a proxy this starts
#   make inspect PACKAGE=@babel/core  a scoped package
#   BYRLE_PROXY=http://host:8080 make inspect      an already running proxy
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

# shellcheck source=scripts/make/lib/node.sh
. "$repo_root/scripts/make/lib/node.sh"
byrle_use_latest_node

package="${PACKAGE:-lodash}"
upstream="${BYRLE_UPSTREAM_NPM:-https://registry.npmjs.org}"
port="${BYRLE_PORT:-8733}"
workdir="$(mktemp -d)"
proxy_pid=""

cleanup() {
    if [[ -n "$proxy_pid" ]]; then kill "$proxy_pid" 2>/dev/null || true; fi
    rm -rf "$workdir"
}
trap cleanup EXIT

for tool in curl jq openssl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required"; exit 1; }
done

# npm percent-encodes the scope separator, and so does this.
encoded="${package/\//%2f}"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
field() { printf '    %-20s %s\n' "$1" "$2"; }

if [[ -n "${BYRLE_PROXY:-}" ]]; then
    proxy="${BYRLE_PROXY%/}"
    echo "using the proxy already running at $proxy"
else
    proxy="http://127.0.0.1:${port}"
    if ss -ltn 2>/dev/null | grep -q ":${port} "; then
        echo "port ${port} is already in use; set BYRLE_PORT, or BYRLE_PROXY to use it"
        exit 1
    fi
    log="$workdir/proxy.log"
    BYRLE_REQUIRE_TOKEN=0 BYRLE_SPOOL_DIR="$workdir/spool" BYRLE_LISTEN="127.0.0.1:${port}" BYRLE_PROXY_URL="$proxy" BYRLE_UPSTREAM_NPM="$upstream" \
        cargo run --quiet --manifest-path "$repo_root/Cargo.toml" -- daemon >"$log" 2>&1 &
    proxy_pid=$!
    for _ in $(seq 1 60); do
        grep -q "byrle listening" "$log" && break
        kill -0 "$proxy_pid" 2>/dev/null || { echo "proxy exited during startup"; cat "$log"; exit 1; }
        sleep 1
    done
    echo "started a proxy at $proxy, upstream $upstream"
fi
echo

# What the registry itself serves, so the rewriting is visible as a difference rather
# than as an assertion.
bold "=== $upstream, direct, for comparison ==="
direct="$workdir/direct.json"
curl -sS -H 'Accept: application/vnd.npm.install-v1+json' -H 'Accept-Encoding: gzip' \
    --compressed "$upstream/$encoded" -o "$direct"
version="$(jq -r '."dist-tags".latest // (.versions | keys | last) // empty' "$direct")"
[[ -n "$version" ]] || { echo "could not find a version of $package to inspect"; exit 1; }
field "name" "$(jq -r .name "$direct")"
field "version inspected" "$version"
field "versions" "$(jq -r '.versions | length' "$direct")"
original_tarball="$(jq -r --arg v "$version" '.versions[$v].dist.tarball' "$direct")"
original_integrity="$(jq -r --arg v "$version" '.versions[$v].dist.integrity // "(none)"' "$direct")"
field "dist.tarball" "$original_tarball"
field "dist.integrity" "$original_integrity"
echo

# The headers each client actually sends. pnpm is the one that offers br, which the
# registry will serve if it is asked for, and which the proxy narrows away so it has one
# decompressor to maintain rather than three.
inspect_client() {
    local name="$1" agent="$2" accept="$3" encoding="$4"

    bold "=== as $name ==="
    field "user-agent" "$agent"
    field "accept" "$accept"
    field "accept-encoding" "$encoding"
    echo

    local head="$workdir/$name.head" body="$workdir/$name.json"
    curl -sS -D "$head" -o "$body" --compressed \
        -A "$agent" -H "Accept: $accept" -H "Accept-Encoding: $encoding" \
        "$proxy/$encoded"

    header() {
        grep -i "^$1:" "$head" | tail -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'
    }
    echo "  packument response"
    field "status" "$(head -1 "$head" | tr -d '\r')"
    local content_type
    content_type="$(header content-type)"
    field "content-type" "$content_type"
    case "$content_type" in
        application/vnd.npm.install-v1+json*)
            field "document" "abbreviated, what an install asks for" ;;
        application/json*)
            field "document" "full, which carries publish times, maintainers and repository" ;;
        *)  field "document" "neither packument media type, so not read" ;;
    esac
    field "content-encoding" "$(header content-encoding)"
    field "content-length" "$(header content-length)"
    field "etag" "$(header etag)"

    if ! jq -e . "$body" >/dev/null 2>&1; then
        field "body" "not JSON, shown raw below"
        head -c 400 "$body"; echo
        return 0
    fi

    local served_tarball served_integrity
    served_tarball="$(jq -r --arg v "$version" '.versions[$v].dist.tarball // "(version not in the document)"' "$body")"
    served_integrity="$(jq -r --arg v "$version" '.versions[$v].dist.integrity // "(none)"' "$body")"
    field "versions" "$(jq -r '.versions | length' "$body")"
    field "dist-tags.latest" "$(jq -r '."dist-tags".latest // "(none)"' "$body")"
    field "dist.tarball" "$served_tarball"
    if [[ "$served_tarball" == "$original_tarball" ]]; then
        field "" "unchanged from the registry"
    else
        field "" "rewritten, was $original_tarball"
    fi
    field "dist.integrity" "$served_integrity"
    if [[ "$served_integrity" == "$original_integrity" ]]; then
        field "" "unchanged, which is what npm checks the download against"
    else
        field "" "CHANGED, which would break the client's own integrity check"
    fi
    echo

    if [[ "$served_tarball" != http* ]]; then
        echo "  no artifact to fetch for $version"
        echo
        return 0
    fi

    local tarball="$workdir/$name.tgz" thead="$workdir/$name.thead"
    curl -sS -D "$thead" -o "$tarball" -A "$agent" "$served_tarball" || true
    echo "  artifact response, from the URL the packument gave"
    field "url" "$served_tarball"
    field "status" "$(head -1 "$thead" | tr -d '\r')"
    field "bytes" "$(wc -c <"$tarball" | tr -d ' ')"

    # Hashed here rather than trusting the proxy's own report, so the check is
    # independent of the thing being checked.
    if [[ "$original_integrity" == sha512-* && -s "$tarball" ]]; then
        local actual
        actual="sha512-$(openssl dgst -sha512 -binary "$tarball" | openssl base64 -A)"
        field "sha512 of what arrived" "$actual"
        if [[ "$actual" == "$original_integrity" ]]; then
            field "" "matches what the registry published"
        else
            field "" "DOES NOT MATCH what the registry published"
        fi
    fi
    echo
}

inspect_client npm "npm/9.9.4 node/v16.20.1 linux x64 workspaces/false" \
    'application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*' \
    'gzip,deflate'

inspect_client pnpm "pnpm/10.33.0 npm/? node/v20.11.1 linux x64" \
    'application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*' \
    'gzip,deflate,br'

inspect_client yarn "yarn/1.22.22 npm/? node/v16.20.1 linux x64" \
    'application/json' \
    'gzip, deflate'

if [[ -n "$proxy_pid" ]]; then
    bold "=== what the proxy logged ==="
    sed -E 's/\x1b\[[0-9;]*m//g' "$workdir/proxy.log" \
        | grep -E 'packument normalized|digest verified|digest known|REFUSED|UNINSPECTED|MISMATCH' \
        | sed 's/^/    /'
    echo
fi

cat <<'NOTE'
What to look for:

  dist.tarball rewritten to the proxy for every client, which is what makes pnpm and
  yarn fetch artifacts through it at all. They use the URL as written; only npm resolves
  it against the configured registry.

  dist.integrity unchanged. npm checks the bytes it downloads against it, and the
  registry signature covers name@version:integrity, so a rewrite that touched it would
  break both.

  content-encoding gzip even where the client offered br. The proxy narrows the request
  it makes upstream so it has one decompressor rather than three, and still answers with
  something the client asked for. pnpm is the client that offers br.

  etag marked with a byrle prefix, because the body is no longer the registry's and a
  304 on the registry's own tag would hand the client a document this proxy never saw.

  the document each client gets. npm and pnpm ask for the abbreviated packument; yarn 1
  asks for application/json and gets the full one, which carries publish times,
  maintainers and repository. Which one arrived is what qualifies every absent field on a
  record, so it is worth seeing rather than assuming.
NOTE
