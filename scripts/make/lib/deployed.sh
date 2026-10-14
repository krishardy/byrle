#!/usr/bin/env bash
# The proxy as a team deploys it, for `make bench` and `make memory`: a token required,
# intel from a `byrle refresh` into a disposable Postgres, a policy of every default, and
# each request's usage recorded.
#
# Sourced, not executed. The caller sets `repo_root`, `workdir`, `port` and `pg_port`, and
# defines `fail` and a `cleanup` that calls `stop_proxy` and `stop_postgres`.
# `deployed_setup` sets `binary`, `account` and `token`; `start_proxy` sets `proxy_pid`; `deployed_sets`
# writes the npm and PyPI sets and sets `npm_through`, `pypi_through` and their counts.

# The caller's variables, named for shellcheck, which does not follow them here.
: "${repo_root:?}" "${workdir:?}" "${port:?}" "${pg_port:?}"

# shellcheck source=scripts/make/lib/postgres.sh
. "$repo_root/scripts/make/lib/postgres.sh"
# shellcheck source=scripts/make/lib/token.sh
. "$repo_root/scripts/make/lib/token.sh"

proxy_pid=""
proxy="http://127.0.0.1:${port}"
npm_packages=(next react react-dom eslint typescript vite vitest)
pypi_packages=(pandas scikit-learn matplotlib)

# OSV's bundles, kept under the user's cache directory and downloaded again when a day
# old, so each run's refresh does not fetch them. The URLs are `bundle::NPM_BUNDLE` and
# `bundle::PYPI_BUNDLE` in src/intel/providers/osv/bundle.rs.
osv_cache="${XDG_CACHE_HOME:-$HOME/.cache}/byrle/osv"
mirror_port="${BYRLE_MIRROR_PORT:-$((port + 1000))}"

# Download each OSV bundle older than a day. A failed download keeps the copy held.
cache_osv() {
    local ecosystem bundle
    for ecosystem in npm PyPI; do
        bundle="$osv_cache/$ecosystem/all.zip"
        mkdir -p "$(dirname "$bundle")"
        [[ -n "$(find "$bundle" -mmin -1440 2>/dev/null)" ]] && continue
        if curl -sSf -o "$bundle.part" \
            "https://osv-vulnerabilities.storage.googleapis.com/$ecosystem/all.zip"; then
            mv "$bundle.part" "$bundle"
        elif [[ -f "$bundle" ]]; then
            echo "OSV's $ecosystem bundle did not download; using the one from $(date -r "$bundle")"
        else
            fail "OSV's $ecosystem bundle did not download, and none is cached"
        fi
    done
}

# `byrle refresh`, with OSV's bundles served from the cache on loopback.
refresh_from_cache() {
    local mirror_pid status=0
    cache_osv
    python3 -m http.server "$mirror_port" --bind 127.0.0.1 --directory "$osv_cache" \
        >"$workdir/mirror.log" 2>&1 &
    mirror_pid=$!
    for _ in $(seq 1 20); do
        curl -s -o /dev/null "http://127.0.0.1:$mirror_port/" && break
        sleep 0.25
    done
    BYRLE_STREAM_URLS="osv/npm=http://127.0.0.1:$mirror_port/npm/all.zip,osv/pypi=http://127.0.0.1:$mirror_port/PyPI/all.zip" \
        "$binary" refresh >"$workdir/refresh.out" 2>&1 || status=$?
    kill "$mirror_pid" 2>/dev/null || true
    wait "$mirror_pid" 2>/dev/null || true
    # Exit 1 is an optional stream that did not load, such as GitHub's without a token.
    [[ "$status" -le 1 ]] || fail "byrle refresh failed: $(tail -5 "$workdir/refresh.out")"
}

# Build, start Postgres, refresh into it, and issue a token for account $1.
deployed_setup() {
    require_free_ports "$port" "$mirror_port" || fail "a port this needs is taken"
    cargo build --release --quiet --manifest-path "$repo_root/Cargo.toml"
    binary="$repo_root/target/release/byrle"
    start_postgres "byrle-$1-pg-$$" "$pg_port" || fail "postgres did not start"
    # start_postgres sets its own EXIT trap; the caller's cleanup stops Postgres too.
    trap cleanup EXIT
    export BYRLE_DATABASE_URL
    BYRLE_DATABASE_URL="$(postgres_url "$pg_port")"
    refresh_from_cache
    account="$1"
    # shellcheck disable=SC2034  # read by the caller
    token="$(issue_token "$BYRLE_DATABASE_URL" "$account")"
    [[ -f "$workdir/policy.yaml" ]] || printf 'version: 1\n' >"$workdir/policy.yaml"
}

# Start a fresh proxy with an empty spool, and wait until it listens.
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
    fail "the proxy did not start"
}

stop_proxy() {
    [[ -n "$proxy_pid" ]] || return 0
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
    proxy_pid=""
}

npm_ci() { (cd "$workdir/npm" && rm -rf node_modules && npm ci --registry="$1" --cache "$2" \
    --no-audit --no-fund --loglevel=error); }
uv_install() { rm -rf "$workdir/venv" && uv venv -q "$workdir/venv" \
    && UV_CACHE_DIR="$2" uv pip install -q --python "$workdir/venv" --index-url "$1" \
        -r "$workdir/pypi/requirements.txt"; }

# Resolved as of 8 days ago, past the policy's default 7-day cooldown, so the proxy serves
# every version the lockfile names.
# shellcheck disable=SC2034  # the counts are read by the caller
deployed_sets() {
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
    pypi_through="http://${account}:${token}@127.0.0.1:${port}/simple/"
}

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
        cp "$workdir/exceptions.txt" "$workdir/exceptions.before"
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
