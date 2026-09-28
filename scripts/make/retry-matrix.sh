#!/usr/bin/env bash
# What each package manager does when the proxy defers a request: npm, pnpm, yarn 1,
# yarn 4 and bun installing from npm, and pip and uv installing from PyPI.
#
# §5 defers rather than refuses when the proxy is not ready to answer: warming, or an
# artifact still under analysis. Which status code says that is an open decision, and it
# turns on what the clients actually do with 429 and 503. None of them document it and
# they do not agree, so this measures it.
#
# Two runs per cell, because they answer different questions:
#
#   unbounded  the deferral never lifts. Attempts and elapsed time measure the client's
#              retry budget, which is what `Retry-After` has to land inside.
#   bounded    the deferral lifts after a few seconds, like a proxy finishing its warm-up.
#              Whether the install then completes is the thing operators will care about.
#
# Every client is pointed at a disposable cache directory. Without that, a warm cache
# serves the install and the proxy is never asked anything, so the row would report a
# retry budget that was never exercised. A cell showing zero attempts is a broken harness,
# not a finding.
#
# Rows are labelled with the user-agent the proxy saw as well as the client invoked. They
# are not the same thing: yarn 4 identifies itself as `got`, so a per-client table keyed
# on the user-agent needs the right-hand column, not the left.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/make/lib/node.sh
. "$repo_root/scripts/make/lib/node.sh"
# shellcheck source=scripts/make/lib/python.sh
. "$repo_root/scripts/make/lib/python.sh"
waharoa_use_latest_node

port="${WAHAROA_PORT:-8733}"
registry="http://127.0.0.1:${port}/"
index="http://127.0.0.1:${port}/simple/"
package="${WAHAROA_RETRY_PACKAGE:-lodash}"
# One wheel and no dependencies, so every deferred request is the one being measured.
pypi_package="${WAHAROA_RETRY_PYPI_PACKAGE:-idna}"
npm_clients=(npm pnpm yarn yarn-berry bun)
pypi_clients=(pip uv)
# How long a bounded deferral lasts. Long enough that a client which gives up straight
# away is not credited with waiting, short enough to run five clients through it.
bounded_seconds="${WAHAROA_RETRY_BOUNDED_SECONDS:-8}"
# A ceiling on one client's run, so a client that retries forever does not hang the target.
budget_seconds="${WAHAROA_RETRY_BUDGET_SECONDS:-120}"
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

# Debug build: WAHAROA_DEFER_TEST is compiled out of a release binary on purpose.
start_proxy() {
    local log="$1" spec="$2"
    WAHAROA_SPOOL_DIR="$workdir/spool" WAHAROA_LISTEN="127.0.0.1:${port}" WAHAROA_DEFER_TEST="$spec" \
        cargo run --quiet --manifest-path "$repo_root/Cargo.toml" -- daemon >"$log" 2>&1 &
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

# A count of zero is a result, not an error.
count() { grep -c "$1" "$2" 2>/dev/null || true; }

prepare_yarn_berry() {
    local dir="$1"
    command -v corepack >/dev/null 2>&1 || return 1
    command -v node >/dev/null 2>&1 || return 1
    [[ "$(node --version | sed -E 's/^v([0-9]+).*/\1/')" -ge 18 ]] || return 1

    mkdir -p "$workdir/shims"
    corepack enable --install-directory "$workdir/shims" >/dev/null 2>&1 || return 1
    printf '{"name":"waharoa-retry","version":"1.0.0","private":true,"packageManager":"yarn@4.9.1"}\n' \
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

# A venv for pip or uv to install into, made before the proxy starts so the timing is the
# install's alone.
prepare_python() {
    local client="$1" dir="$2"
    case "$client" in
        pip) python3 -m venv "$dir/venv" >/dev/null 2>&1 ;;
        uv) uv venv -q "$dir/venv" >/dev/null 2>&1 ;;
    esac
}

# The install command for one client, into a cache directory nothing else shares.
client_command() {
    local client="$1" dir="$2"
    case "$client" in
        npm) printf '%s\n' npm install "$package" --registry "$registry" \
            --cache "$dir/cache" --no-audit --no-fund --loglevel=error ;;
        # npm_config_cache_dir, not just --store-dir. pnpm keeps packument metadata in a
        # cache of its own, keyed by registry host and port, which --store-dir does not
        # cover. Measured: a second run at the same port resolved lodash from
        # ~/.cache/pnpm/metadata-v1.3/127.0.0.1+8733 and reported a retry budget it had
        # never needed to spend.
        pnpm) printf '%s\n' env "npm_config_cache_dir=$dir/metadata" \
            pnpm add "$package" --registry "$registry" \
            --store-dir "$dir/cache" --reporter=silent ;;
        yarn) printf '%s\n' yarn add "$package" --registry "$registry" \
            --cache-folder "$dir/cache" --no-lockfile --silent ;;
        bun) printf '%s\n' bun add "$package" --registry "$registry" --cache-dir "$dir/cache" ;;
        yarn-berry) printf '%s\n' env "PATH=$workdir/shims:$PATH" \
            COREPACK_ENABLE_DOWNLOAD_PROMPT=0 "YARN_NPM_REGISTRY_SERVER=${registry%/}" \
            yarn add "$package" ;;
        pip) waharoa_pip_command "$dir/venv" "$index" "$pypi_package" ;;
        uv) waharoa_uv_command "$dir/venv" "$index" "$pypi_package" ;;
    esac
}

runner_for() {
    case "$1" in
        yarn-berry) echo corepack ;;
        pip) echo python3 ;;
        *) echo "$1" ;;
    esac
}

# One client against one deferral spec. Prints the row.
run_cell() {
    local client="$1" spec="$2" expect="$3"
    local runner; runner="$(runner_for "$client")"
    if ! command -v "$runner" >/dev/null 2>&1; then
        printf '  %-11s NOT INSTALLED, skipped\n' "$client"
        return 0
    fi

    local dir="$workdir/$client-$expect" log="$workdir/$client-$expect.log"
    mkdir -p "$dir/cache"
    printf '{"name":"waharoa-retry","version":"1.0.0","private":true}\n' >"$dir/package.json"
    if [[ "$client" == "yarn-berry" ]] && ! prepare_yarn_berry "$dir"; then
        printf '  %-11s needs corepack and node 18 or later, skipped\n' "$client"
        return 0
    fi
    if [[ "$client" == pip || "$client" == uv ]] && ! prepare_python "$client" "$dir"; then
        printf '  %-11s could not create a venv, skipped\n' "$client"
        return 0
    fi

    mapfile -t cmd < <(client_command "$client" "$dir")
    start_proxy "$log" "$spec"
    local rc=0 started elapsed
    started=$(date +%s.%N)
    (cd "$dir" && timeout "$budget_seconds" "${cmd[@]}") >"$dir/out" 2>&1 || rc=$?
    elapsed=$(awk -v s="$started" -v e="$(date +%s.%N)" 'BEGIN { printf "%.1f", e - s }')
    stop_proxy
    sed -i -E 's/\x1b\[[0-9;]*m//g' "$log"

    local served ua
    served="$(count 'proxied' "$log")"
    ua="$(grep -oE 'user_agent.original=[^ ]+( \([^)]*\))?' "$log" | head -1 | sed 's/^user_agent.original=//')"

    # Per path, because npm asks for `/npm` as well as the package on every round. See
    # scripts/make/lib/retry_gaps.py.
    local measured attempts gaps
    measured="$(grep 'deferred by the defer test' "$log" \
        | sed -E 's/^([^ ]+) .*url.path=([^ ]+) .*/\1 \2/' \
        | python3 "$repo_root/scripts/make/lib/retry_gaps.py")"
    attempts="${measured%% *}"
    gaps="${measured#* }"

    printf '  %-11s attempts=%-3s gaps=%-16s served=%-3s exit=%-4s %5ss  ua=%s\n' \
        "$client" "$attempts" "$gaps" "$served" "$rc" "$elapsed" "${ua:--}"

    if [[ "$attempts" -eq 0 ]]; then
        echo "       WARNING: the proxy deferred nothing, so this row measures nothing."
        echo "       A cache served the install, or the client never reached the proxy."
    fi
}

clients=("${npm_clients[@]}" "${pypi_clients[@]}")
echo "==> deferral matrix: ${package} from npm and ${pypi_package} from PyPI through the proxy, ${#clients[@]} clients"
echo "    Retry-After is 1 second throughout. Gaps are the seconds between the attempts"
echo "    the proxy saw, so a client that honours the header shows gaps near 1."
echo

for scope in metadata artifact; do
    for status in 429 503; do
        echo "--- ${status} on the ${scope}, never lifting (measures the retry budget)"
        for client in "${clients[@]}"; do
            run_cell "$client" "${status}:1:${scope}" "unbounded-${status}-${scope}"
        done
        echo
    done
done

echo "--- 503 on everything, lifting after ${bounded_seconds}s (measures whether a warm-up is waited out)"
for client in "${clients[@]}"; do
    run_cell "$client" "503:1:all:${bounded_seconds}" "bounded-${client}"
done
echo

cat <<'NOTE'
Reading this:
  attempts  how many times the client reissued one request, counted per path because
            npm also asks for `/npm` on every round. 1 means it did not retry.
  gaps      seconds between those attempts. Near 1 means Retry-After was honoured;
            anything else is the client's own backoff.
  served    requests answered normally. In the bounded run this is the install
            completing after the deferral lifted.
  exit      the client's exit code. 0 in an unbounded run means it installed from
            somewhere the proxy did not see.
  ua        the user-agent the proxy saw, which is the key a per-client code table
            would use. yarn 4 sends `got`, not `yarn`.
  metadata  an npm packument or a PyPI index; artifact, an npm tarball or a PyPI file.
NOTE
