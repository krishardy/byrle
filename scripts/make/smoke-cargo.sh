#!/usr/bin/env bash
# End-to-end check of the proxy against real cargo. See docs/cargo-plan.md.
#
# Asserts, in order:
#   1. `cargo build` of a project using itoa and serde with derive completes through the
#      proxy, and every crate in its Cargo.lock was fetched through it and verified; then
#      `cargo install` of hello-cli 0.2.2, a binary, whose crate is verified too
#   2. a denial of itoa 1.0.18 removes its line, cargo resolves 1.0.17, and the download
#      of 1.0.18 answers 403
#   3. a cooldown covering itoa's newest version makes cargo resolve an older one
#   4. under `install_scripts: block`, serde, which has a build script, and serde_derive,
#      a proc-macro, are refused once their .crate files are read, and cargo fetch fails;
#      under `allow` it fetches
#   5. with Postgres, after a refresh: rustls 0.23.45, whose four RUSTSEC advisories score
#      2.3 to 4.0, is refused under `max_cvss: 3.9`, and 0.23.46, which fixes them, resolves
#   6. under the default `max_cvss` and `install_scripts: allow`, rustls 0.23.45 is served
#      with an `advisory_vulnerability` signal, and tempdir 0.3.7, unmaintained, with an
#      `advisory_unmaintained` one
#   7. with tokens required, config.json asks for one, and cargo sends it alone
# Steps 1 to 4 run with no Postgres, and so with BYRLE_REQUIRE_TOKEN=0.
# Client cargo runs get their own CARGO_HOME, so the proxy's own `cargo run` is untouched.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/make/lib/postgres.sh
. "$repo_root/scripts/make/lib/postgres.sh"
# shellcheck source=scripts/make/lib/token.sh
. "$repo_root/scripts/make/lib/token.sh"

port="${BYRLE_PORT:-8736}"
base="http://127.0.0.1:${port}"
workdir="$(mktemp -d)"
log="$workdir/proxy.log"
proxy_pid=""
database_url=""
require_token=0
client_token=""

cleanup() {
    if [[ -n "$proxy_pid" ]]; then kill "$proxy_pid" 2>/dev/null || true; fi
    rm -rf "$workdir"
}
trap cleanup EXIT

if grep -q ":${port} " < <(ss -ltn 2>/dev/null); then
    echo "port ${port} is already in use; set BYRLE_PORT to something free"
    exit 1
fi

fail() { echo "FAIL: $*"; echo "--- proxy log ---"; cat "$log"; exit 1; }

start_proxy() {
    BYRLE_SPOOL_DIR="$workdir/spool" BYRLE_LISTEN="127.0.0.1:${port}" \
    BYRLE_PROXY_URL="$base" BYRLE_POLICY="${1:-}" \
    BYRLE_DATABASE_URL="$database_url" BYRLE_REQUIRE_TOKEN="$require_token" \
        cargo run --quiet --manifest-path "$repo_root/Cargo.toml" -- daemon >"$log" 2>&1 &
    proxy_pid=$!
    for _ in $(seq 1 60); do
        grep -q "byrle listening" "$log" && return 0
        kill -0 "$proxy_pid" 2>/dev/null || fail "proxy exited during startup"
        sleep 1
    done
    fail "proxy did not start within 60s"
}

stop_proxy() {
    if [[ -n "$proxy_pid" ]]; then kill "$proxy_pid" 2>/dev/null || true; fi
    wait "$proxy_pid" 2>/dev/null || true
    proxy_pid=""
}

clean_log() { sed -E 's/\x1b\[[0-9;]*m//g' "$log"; }

# Whether the proxy log has a line matching $1. Not `clean_log | grep -q`: under pipefail
# that fails when grep stops at its match while sed is still writing.
logged() { grep -q -- "$1" < <(clean_log); }

# A project in $1 depending on the Cargo.toml dependency lines in $2, with a fresh
# CARGO_HOME pointed at the proxy, as the startup line says.
project() {
    local dir="$1" deps="$2"
    rm -rf "$dir"
    mkdir -p "$dir/src" "$dir/home"
    printf '[package]\nname = "probe"\nversion = "0.1.0"\nedition = "2021"\n[dependencies]\n%s\n' \
        "$deps" >"$dir/Cargo.toml"
    printf 'fn main() { println!("{}", itoa::Buffer::new().format(42)); }\n' >"$dir/src/main.rs"
    printf '[source.crates-io]\nreplace-with = "byrle"\n[registries.byrle]\nindex = "sparse+%s/cargo/"\ncredential-provider = "cargo:token"\n' \
        "$base" >"$dir/home/config.toml"
}

# cargo $2... in project $1, through the proxy, with the token when one is set.
client() {
    local dir="$1"
    shift
    (cd "$dir" && CARGO_HOME="$dir/home" CARGO_REGISTRIES_BYRLE_TOKEN="$client_token" \
        timeout 600 cargo "$@")
}

# The version of crate $2 in project $1's Cargo.lock.
locked() {
    python3 -I -c '
import sys, tomllib
lock = tomllib.load(open(sys.argv[1], "rb"))
print(next(p["version"] for p in lock["package"] if p["name"] == sys.argv[2]))' \
        "$1/Cargo.lock" "$2"
}

# The status a download of crate $1 at $2 answers, once the proxy stops deferring it
# with 503 while the .crate is read.
download() {
    local auth=() status
    if [[ -n "$client_token" ]]; then auth=(-H "authorization: $client_token"); fi
    for _ in $(seq 1 30); do
        status="$(curl -s -o "$workdir/download.out" -w '%{http_code}' "${auth[@]}" \
            "$base/cargo/crates/$1/$2/download")"
        [[ "$status" == "503" ]] || break
        sleep 1
    done
    echo "$status"
}

echo "==> 1/7  cargo build and cargo install through the proxy, every crate verified"
start_proxy ""
project "$workdir/build" $'itoa = "1"\nserde = { version = "1", features = ["derive"] }'
printed="$(client "$workdir/build" run --quiet 2>"$workdir/build.err")" \
    || fail "cargo run failed: $(tail -5 "$workdir/build.err")"
[[ "$printed" == "42" ]] || fail "the program printed $printed"
crates="$(python3 -I -c '
import sys, tomllib
lock = tomllib.load(open(sys.argv[1], "rb"))
print("\n".join("{}@{}".format(p["name"], p["version"]) for p in lock["package"] if "source" in p))' \
    "$workdir/build/Cargo.lock")"
count=0
while read -r crate; do
    name="${crate%@*}" version="${crate#*@}"
    logged "artifact digest verified.*pkg:cargo/${name,,}@${version}" \
        || fail "$crate was not verified through the proxy"
    count=$((count + 1))
done <<<"$crates"
project "$workdir/install" 'itoa = "1"'
client "$workdir/install" install --quiet --locked hello-cli@0.2.2 --root "$workdir/install/bin" \
    2>"$workdir/install.err" || fail "cargo install failed: $(tail -5 "$workdir/install.err")"
[[ -x "$workdir/install/bin/bin/hello" ]] || fail "cargo install wrote no hello binary"
logged "artifact digest verified.*pkg:cargo/hello-cli@0.2.2" \
    || fail "hello-cli was not verified through the proxy"
echo "    ok ($count crates, each verified; hello-cli installed and verified)"
stop_proxy

echo "==> 2/7  a denied version is not resolved, and its download is 403"
printf 'version: 1\ncooldown_days: 0\ndenials:\n  - purl: pkg:cargo/itoa@1.0.18\n    reason: smoke-cargo\n' \
    >"$workdir/deny.yaml"
start_proxy "$workdir/deny.yaml"
project "$workdir/deny" 'itoa = "1"'
client "$workdir/deny" generate-lockfile --quiet || fail "cargo generate-lockfile failed"
[[ "$(locked "$workdir/deny" itoa)" == "1.0.17" ]] \
    || fail "itoa resolved to $(locked "$workdir/deny" itoa), not 1.0.17"
[[ "$(download itoa 1.0.18)" == "403" ]] || fail "the download of itoa 1.0.18 was not refused"
echo "    ok (resolved 1.0.17; 1.0.18 is 403)"
stop_proxy

echo "==> 3/7  a cooldown covering itoa's newest version resolves an older one"
newest="$(curl -s https://index.crates.io/it/oa/itoa | python3 -I -c '
import sys, json, datetime
lines = [json.loads(l) for l in sys.stdin if l.strip()]
last = lines[-1]
age = datetime.datetime.now(datetime.UTC) - datetime.datetime.fromisoformat(last["pubtime"])
print(last["vers"], age.days + 1)')"
read -r newest_version cooldown <<<"$newest"
printf 'version: 1\ncooldown_days: %s\n' "$cooldown" >"$workdir/cooldown.yaml"
start_proxy "$workdir/cooldown.yaml"
project "$workdir/cooldown" 'itoa = "1"'
client "$workdir/cooldown" generate-lockfile --quiet || fail "cargo generate-lockfile failed"
resolved="$(locked "$workdir/cooldown" itoa)"
[[ "$resolved" != "$newest_version" ]] \
    || fail "itoa $newest_version resolved under cooldown_days: $cooldown"
echo "    ok (cooldown_days: $cooldown; resolved $resolved, not $newest_version)"
stop_proxy

echo "==> 4/7  install_scripts refuses a build script and a proc-macro, read from the .crate"
printf 'version: 1\ncooldown_days: 0\n' >"$workdir/default.yaml"
printf 'version: 1\ncooldown_days: 0\ninstall_scripts: allow\n' >"$workdir/allow.yaml"
start_proxy "$workdir/default.yaml"
for crate in "serde 1.0.229" "serde_derive 1.0.229"; do
    read -r name version <<<"$crate"
    [[ "$(download "$name" "$version")" == "403" ]] || fail "$name $version was not refused"
    grep -q "install_scripts" "$workdir/download.out" \
        || fail "the refusal of $name $version does not name install_scripts"
done
project "$workdir/blocked" 'serde = { version = "=1.0.229", features = ["derive"] }'
if client "$workdir/blocked" fetch --quiet 2>/dev/null; then
    fail "cargo fetched serde under install_scripts: block"
fi
stop_proxy
start_proxy "$workdir/allow.yaml"
project "$workdir/allowed" 'serde = { version = "=1.0.229", features = ["derive"] }'
client "$workdir/allowed" fetch --quiet || fail "cargo fetch failed under install_scripts: allow"
echo "    ok (serde and serde_derive 403 naming install_scripts; fetched under allow)"
stop_proxy

echo "==> 5/7  an osv/cargo advisory over max_cvss is refused, and the fix resolves"
if ! choose_postgres >/dev/null; then
    echo "    skipped (neither docker nor initdb and pg_ctl are available)"
    echo "==> 6/7  skipped (no snapshot to read advisories from)"
    echo "==> 7/7  skipped (no Postgres to keep the accounts and tokens in)"
    echo "PASS: the proxy serves cargo, without the steps that need Postgres."
    exit 0
fi
pg_port="${BYRLE_PG_PORT:-55437}"
start_postgres "byrle-smoke-cargo-pg-$$" "$pg_port" || fail "postgres did not start"
trap 'stop_postgres; cleanup' EXIT
database_url="$(postgres_url "$pg_port")"
# Exit 1 is an optional stream that did not load, such as GitHub's without a token.
set +e
BYRLE_DATABASE_URL="$database_url" cargo run --quiet --manifest-path "$repo_root/Cargo.toml" \
    -- refresh >"$workdir/refresh.out" 2>&1
refresh_status=$?
set -e
[[ "$refresh_status" -le 1 ]] || fail "byrle refresh exited $refresh_status:
$(tail -20 "$workdir/refresh.out")"
printf 'version: 1\ncooldown_days: 0\nmax_cvss: 3.9\n' >"$workdir/strict.yaml"
start_proxy "$workdir/strict.yaml"
ready=$(curl -s -o /dev/null -w '%{http_code}' "$base/-/byrle/ready")
[[ "$ready" == "200" ]] || fail "the proxy is not ready after the refresh ($ready)"
project "$workdir/vulnerable" 'rustls = { version = "=0.23.45", default-features = false }'
if client "$workdir/vulnerable" generate-lockfile --quiet 2>/dev/null; then
    fail "rustls 0.23.45 resolved under max_cvss: 3.9"
fi
[[ "$(download rustls 0.23.45)" == "403" ]] || fail "the download of rustls 0.23.45 was not refused"
grep -q "max_cvss" "$workdir/download.out" || fail "the refusal of rustls 0.23.45 does not name max_cvss"
project "$workdir/fixed" 'rustls = { version = "=0.23.46", default-features = false }'
client "$workdir/fixed" generate-lockfile --quiet || fail "rustls 0.23.46 did not resolve"
echo "    ok (0.23.45 not resolved and 403 naming max_cvss; 0.23.46 resolved)"
stop_proxy

echo "==> 6/7  under the default max_cvss, advisories are signals with their own weights"
# rustls has a build script, which the default install_scripts: block refuses.
start_proxy "$workdir/allow.yaml"
for crate in "rustls 0.23.45 advisory vulnerability" "tempdir 0.3.7 advisory unmaintained"; do
    read -r name version _ kind <<<"$crate"
    [[ "$(download "$name" "$version")" == "200" ]] || fail "$name $version was not served"
    logged "signals reported.*pkg:cargo/${name}@${version}.*advisory ${kind}" \
        || fail "$name $version reported no advisory_${kind} signal"
done
echo "    ok (rustls 0.23.45 and tempdir 0.3.7 served, each with its signal)"
stop_proxy

echo "==> 7/7  a token is required, and cargo sends it alone"
client_token="$(issue_token "$database_url" smoke-cargo)"
require_token=1
start_proxy "$workdir/default.yaml"
status=$(curl -s -o /dev/null -w '%{http_code}' "$base/cargo/config.json")
[[ "$status" == "401" ]] || fail "config.json without a token answered $status"
project "$workdir/token" 'itoa = "1"'
client "$workdir/token" fetch --quiet || fail "cargo fetch with a token failed"
saved="$client_token"
client_token=""
project "$workdir/no-token" 'itoa = "1"'
if client "$workdir/no-token" generate-lockfile --quiet 2>/dev/null; then
    fail "cargo resolved without a token"
fi
client_token="$saved"
echo "    ok (401 without a token; fetched with one)"
stop_proxy

echo "PASS: the proxy serves cargo as Stage 6 requires."
