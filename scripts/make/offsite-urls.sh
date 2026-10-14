#!/usr/bin/env bash
# Which URLs in a packument does each client actually fetch?
#
# The origin policy guards `dist.tarball` and nothing else. That is right for npm because
# pacote discards the host of `dist.attestations.url` and resolves it against the
# configured registry instead (`lib/registry.js`, "Always fetch attestations from the
# current registry host"). It is pacote's behaviour, not protocol, so it says nothing
# about pnpm, yarn or bun.
#
# This measures it. A registry serves a working package whose every non-tarball URL points
# at a second server, which answers 404 and logs what was asked for. A request that
# reaches the recorder is a URL the client used as written, and therefore a URL the proxy
# would never see. Silence is the result that confirms the current policy.
#
# Clients that are not installed are reported and skipped rather than failing the run.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/make/lib/node.sh
. "$repo_root/scripts/make/lib/node.sh"
byrle_use_latest_node

registry_port="${BYRLE_OFFSITE_REGISTRY_PORT:-8734}"
recorder_port="${BYRLE_OFFSITE_RECORDER_PORT:-8735}"
registry="http://127.0.0.1:${registry_port}/"
workdir="$(mktemp -d)"
servers_pid=""
recorded="$workdir/recorded.log"
asked="$workdir/registry.log"

cleanup() {
    if [[ -n "$servers_pid" ]]; then kill "$servers_pid" 2>/dev/null || true; fi
    rm -rf "$workdir"
}
trap cleanup EXIT

for port in "$registry_port" "$recorder_port"; do
    if ss -ltn 2>/dev/null | grep -q ":${port} "; then
        echo "port ${port} is already in use; set BYRLE_OFFSITE_REGISTRY_PORT or"
        echo "BYRLE_OFFSITE_RECORDER_PORT to something free"
        exit 1
    fi
done

: >"$recorded"
: >"$asked"
python3 "$repo_root/scripts/make/lib/offsite_registry.py" \
    "$registry_port" "$recorder_port" "$recorded" "$asked" >"$workdir/servers.log" 2>&1 &
servers_pid=$!

for _ in $(seq 1 30); do
    curl -fsS -o /dev/null "${registry}widget" 2>/dev/null && break
    kill -0 "$servers_pid" 2>/dev/null || { echo "servers exited during startup"; cat "$workdir/servers.log"; exit 1; }
    sleep 0.5
done

prepare_yarn_berry() {
    local dir="$1"
    command -v corepack >/dev/null 2>&1 || return 1
    command -v node >/dev/null 2>&1 || return 1
    [[ "$(node --version | sed -E 's/^v([0-9]+).*/\1/')" -ge 18 ]] || return 1

    mkdir -p "$workdir/shims"
    corepack enable --install-directory "$workdir/shims" >/dev/null 2>&1 || return 1
    printf '{"name":"byrle-offsite","version":"1.0.0","private":true,"packageManager":"yarn@4.9.1"}\n' \
        >"$dir/package.json"
    cat >"$dir/.yarnrc.yml" <<YML
nodeLinker: node-modules
enableGlobalCache: false
enableMirror: false
globalFolder: "$dir/cache"
unsafeHttpWhitelist:
  - 127.0.0.1
YML
}

runner_for() {
    case "$1" in
        yarn-berry) echo corepack ;;
        *) echo "$1" ;;
    esac
}

# Every client gets a cache of its own. A warm cache would install without asking for the
# packument at all, and the row would report silence that means nothing.
client_command() {
    local client="$1" dir="$2"
    case "$client" in
        npm) printf '%s\n' npm install widget --registry "$registry" \
            --cache "$dir/cache" --no-audit --no-fund --loglevel=error ;;
        pnpm) printf '%s\n' env "npm_config_cache_dir=$dir/metadata" \
            pnpm add widget --registry "$registry" --store-dir "$dir/cache" --reporter=silent ;;
        yarn) printf '%s\n' yarn add widget --registry "$registry" \
            --cache-folder "$dir/cache" --no-lockfile --silent ;;
        bun) printf '%s\n' bun add widget --registry "$registry" --cache-dir "$dir/cache" ;;
        yarn-berry) printf '%s\n' env "PATH=$workdir/shims:$PATH" \
            COREPACK_ENABLE_DOWNLOAD_PROMPT=0 "YARN_NPM_REGISTRY_SERVER=${registry%/}" \
            yarn add widget ;;
    esac
}

failed=0
echo "==> installing a package whose non-tarball URLs all point somewhere else"
echo "    attestations, signatures, homepage, repository and bugs point at the recorder."
echo

for client in npm pnpm yarn yarn-berry bun; do
    runner="$(runner_for "$client")"
    if ! command -v "$runner" >/dev/null 2>&1; then
        printf '  %-11s NOT INSTALLED, skipped\n' "$client"
        continue
    fi

    dir="$workdir/$client"
    mkdir -p "$dir/cache"
    printf '{"name":"byrle-offsite","version":"1.0.0","private":true}\n' >"$dir/package.json"
    if [[ "$client" == "yarn-berry" ]] && ! prepare_yarn_berry "$dir"; then
        printf '  %-11s needs corepack and node 18 or later, skipped\n' "$client"
        continue
    fi

    before="$(wc -l <"$recorded")"
    mapfile -t cmd < <(client_command "$client" "$dir")
    rc=0
    (cd "$dir" && timeout 120 "${cmd[@]}") >"$dir/out" 2>&1 || rc=$?
    after="$(wc -l <"$recorded")"
    fetched=$((after - before))

    installed=no
    [[ -e "$dir/node_modules/widget/package.json" ]] && installed=yes

    printf '  %-11s exit=%-3s installed=%-4s offsite requests=%s\n' \
        "$client" "$rc" "$installed" "$fetched"

    if [[ "$fetched" -gt 0 ]]; then
        tail -n "$fetched" "$recorded" | sed 's/^/               /'
        failed=1
    fi
    # An install that did not happen proves nothing about what the client would fetch.
    if [[ "$installed" != yes ]]; then
        echo "               WARNING: nothing installed, so this row measures nothing."
        sed -n '1,5p' "$dir/out" | sed 's/^/               /'
        failed=1
    fi
done

# The install path is the one that matters and is measured above. `npm audit signatures`
# is the command that would fetch attestations, and it is run here for what it shows about
# where npm looks: it asks the *configured registry* for its verification keys and never
# contacts the host the packument named.
#
# It does not reach the attestations fetch itself. npm stops at EMISSINGSIGNATUREKEY,
# because doing better would mean a real signing key and a real signature in this fixture.
# So this narrows where npm looks without settling what it would do with a valid one; the
# source is still the basis for that half (pacote `lib/registry.js`, "Always fetch
# attestations from the current registry host").
echo
echo "==> npm audit signatures, for where npm looks rather than what it fetches"
if command -v npm >/dev/null 2>&1 && [[ -d "$workdir/npm/node_modules/widget" ]]; then
    before="$(wc -l <"$recorded")"
    (cd "$workdir/npm" && timeout 120 npm audit signatures \
        --registry "$registry" --cache "$workdir/npm/cache") >"$workdir/npm/audit" 2>&1 || true
    after="$(wc -l <"$recorded")"
    printf '  offsite requests: %s\n' "$((after - before))"
    if [[ "$((after - before))" -gt 0 ]]; then
        tail -n "$((after - before))" "$recorded" | sed 's/^/    /'
        failed=1
    fi
    printf '  asked the registry for: %s\n' \
        "$(cut -f1 "$asked" | sort -u | tr '\n' ' ')"
    # Printed rather than matched against an expected string: npm's error codes are not
    # a contract, and a check for one would go quiet if it changed rather than saying so.
    echo "  npm said:"
    grep -E 'npm (error|warn)' "$workdir/npm/audit" | sed 's/^/    /' | head -4
else
    echo "  skipped: npm is absent or its install did not complete"
fi

echo
if [[ "$failed" -ne 0 ]]; then
    cat <<'NOTE'
FAIL: a client fetched a URL the packument named, or did not install at all.

A URL used as written is a URL the proxy does not see. If it is a real fetch, the origin
policy has to cover that field as well as `dist.tarball`, and `filter_unservable_versions`
has to consider it when deciding whether a version can be served.
NOTE
    exit 1
fi

cat <<'NOTE'
OK: no client fetched any of the five fields. Of the packument URLs that could plausibly
route an install, `dist.tarball` is the one that does, for every client measured rather
than for npm alone, so the origin policy covering it alone is not an npm-specific
accident.

Two things this does not cover:
  - Other URL-bearing fields in a packument. Five were tested, not all of them.
  - A dependency specified as a git or http(s) URL rather than a version range. That is
    fetched from wherever the manifest names, touches no packument, and is a different
    path from `dist.tarball`.
NOTE
