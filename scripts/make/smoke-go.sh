#!/usr/bin/env bash
# End-to-end check of the proxy against the real go command, behind nginx on TLS: go sends
# a token only over https. See docs/go-plan.md.
#
# Asserts, in order:
#   1. `go build` of a program using rsc.io/quote v1.5.2 completes through the proxy, run
#      again after each first fetch the proxy answers 503, and every zip in its go.sum is
#      verified
#   2. a denial of golang.org/x/text's newest version: @latest resolves an older one, and
#      the denied zip answers 403
#   3. a cooldown covering x/text's newest version resolves an older one
#   4. GOTOOLCHAIN=go1.26.0 downloads that Go release through the proxy, verified
#   5. with Postgres, after a refresh: golang.org/x/crypto v0.30.0, which osv/go scores
#      over the default max_cvss, is left out of @v/list and its zip is 403 naming max_cvss
#   6. with tokens required, a request without one is 401, and go sends one from GOPROXY
# Steps 1 to 4 run with no Postgres, and so with BYRLE_REQUIRE_TOKEN=0.
# Each go run has its own GOPATH, and GOENV=off, so this user's go settings are not read.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/make/lib/recognised.sh
. "$repo_root/scripts/make/lib/recognised.sh"
# shellcheck source=scripts/make/lib/postgres.sh
. "$repo_root/scripts/make/lib/postgres.sh"
# shellcheck source=scripts/make/lib/token.sh
. "$repo_root/scripts/make/lib/token.sh"
# shellcheck source=scripts/make/lib/tls_front.sh
. "$repo_root/scripts/make/lib/tls_front.sh"
# shellcheck source=scripts/make/lib/port.sh
. "$repo_root/scripts/make/lib/port.sh"
# shellcheck source=scripts/make/lib/cooldown.sh
. "$repo_root/scripts/make/lib/cooldown.sh"

port="${BYRLE_PORT:-8738}"
front_port="${BYRLE_FRONT_PORT:-8739}"
base="http://127.0.0.1:${port}"
front="https://localhost:${front_port}"
workdir="$(mktemp -d)"
log="$workdir/proxy.log"
proxy_pid=""
front_pid=""
database_url=""
require_token=0
goproxy="$front/go"
toolchain=local
rp_key="$(openssl rand -hex 32)"

cleanup() {
    if [[ -n "$proxy_pid" ]]; then kill "$proxy_pid" 2>/dev/null || true; fi
    if [[ -n "$front_pid" ]]; then kill "$front_pid" 2>/dev/null || true; fi
    # go extracts a toolchain read-only, -modcacherw or not.
    chmod -R u+w "$workdir" 2>/dev/null || true
    rm -rf "$workdir"
}
trap cleanup EXIT

for needed in go nginx openssl; do
    if ! command -v "$needed" >/dev/null 2>&1; then
        echo "FAIL: $needed is not on PATH. Run 'make dev-setup'."
        exit 1
    fi
done
for taken in "$port" "$front_port"; do
    if port_taken "$taken" >/dev/null; then
        echo "port ${taken} is already in use; set BYRLE_PORT and BYRLE_FRONT_PORT to free ones"
        exit 1
    fi
done

fail() { echo "FAIL: $*"; echo "--- proxy log ---"; cat "$log"; exit 1; }

make_certificates "$workdir"
mkdir -p "$workdir/nginx"
nginx_conf "$front_port" "$workdir/nginx" "$workdir" "$port" "$rp_key" >"$workdir/nginx/nginx.conf"
nginx -p "$workdir/nginx" -c "$workdir/nginx/nginx.conf" -g 'daemon off;' \
    >"$workdir/nginx/front.log" 2>&1 &
front_pid=$!

start_proxy() {
    BYRLE_SPOOL_DIR="$workdir/spool" BYRLE_LISTEN="127.0.0.1:${port}" BYRLE_RP_KEY="$rp_key" \
    BYRLE_PROXY_URL="$front" BYRLE_POLICY="${1:-}" \
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
    recognised "$log"
}

clean_log() { sed -E 's/\x1b\[[0-9;]*m//g' "$log"; }

# Whether the proxy log has a line matching $1. Not `clean_log | grep -q`: under pipefail
# that fails when grep stops at its match while sed is still writing.
logged() { grep -q -- "$1" < <(clean_log); }

# A module in $1, requiring the go.mod lines in $2.
project() {
    local dir="$1" requires="$2"
    rm -rf "$dir"
    mkdir -p "$dir"
    printf 'module example.test/probe\n\ngo 1.24\n\n%s\n' "$requires" >"$dir/go.mod"
}

# go $2... in module $1, through the front, trusting the test CA.
client() {
    local dir="$1"
    shift
    (cd "$dir" && GOENV=off GOPATH="$dir/gopath" GOFLAGS=-modcacherw GOPROXY="$goproxy" \
        GOSUMDB=sum.golang.org GONOPROXY='' GONOSUMDB='' GOPRIVATE='' GOTOOLCHAIN="$toolchain" \
        SSL_CERT_FILE="$workdir/ca.pem" NO_PROXY="localhost,127.0.0.1${NO_PROXY:+,$NO_PROXY}" \
        timeout 600 go "$@")
}

# client $1 $2..., run again while it fails on a 503 from the proxy: go does not retry one.
# Prints how many runs it took; fails after 20.
retried() {
    local dir="$1" runs
    shift
    for runs in $(seq 1 20); do
        if client "$dir" "$@" >"$workdir/go.out" 2>"$workdir/go.err"; then
            echo "$runs"
            return 0
        fi
        grep -q "503 Service Unavailable" "$workdir/go.err" \
            || fail "go $* failed: $(tail -5 "$workdir/go.err")"
        sleep 2
    done
    fail "go $* still answered 503 after $runs runs"
}

# The version `go list -m` resolves $2 to, in module $1.
resolved() {
    client "$1" list -m -f '{{.Version}}' "$2" 2>"$workdir/list.err" \
        || fail "go list -m $2 failed: $(tail -3 "$workdir/list.err")"
}

# The status the proxy answers for path $1, once it stops deferring it with 503.
fetched() {
    local status
    for _ in $(seq 1 120); do
        status="$(curl -s --noproxy '*' --cacert "$workdir/ca.pem" -o "$workdir/fetched.out" \
            -w '%{http_code}' "$front$1")"
        [[ "$status" == "503" ]] || break
        sleep 1
    done
    echo "$status"
}

# x/text's newest version and when it was published, from proxy.golang.org.
newest="$(curl -s https://proxy.golang.org/golang.org/x/text/@latest | python3 -I -c '
import sys, json
latest = json.load(sys.stdin)
print(latest["Version"], latest["Time"])')"
read -r newest_text published <<<"$newest"
text_age="$(cooldown_covering "$published")"
printf 'version: 1\ncooldown_days: 0\n' >"$workdir/default.yaml"

echo "==> 1/6  go build through the proxy on TLS, each 503 run again, every zip verified"
start_proxy "$workdir/default.yaml"
project "$workdir/build" 'require rsc.io/quote v1.5.2'
printf 'package main\n\nimport (\n\t"fmt"\n\n\t"rsc.io/quote"\n)\n\nfunc main() { fmt.Println(quote.Hello()) }\n' \
    >"$workdir/build/main.go"
tidy_runs="$(retried "$workdir/build" mod tidy)"
build_runs="$(retried "$workdir/build" build -o probe .)"
printed="$("$workdir/build/probe")"
[[ "$printed" == *world* ]] || fail "the program printed $printed"
count=0
while read -r module version _; do
    [[ "$version" == */go.mod ]] && continue
    logged "artifact digest verified.*pkg:golang/${module}@${version}" \
        || fail "$module $version was not verified through the proxy"
    count=$((count + 1))
done <"$workdir/build/go.sum"
[[ "$count" -gt 0 ]] || fail "go.sum names no zip"
runs=$((tidy_runs + build_runs))
[[ "$runs" -gt 2 ]] || fail "no first fetch was answered 503 ($runs runs)"
echo "    ok ($count zips, each verified; $runs runs of go, as each first fetch is 503)"
stop_proxy

echo "==> 2/6  a denied version is not resolved, and its zip is 403"
printf 'version: 1\ncooldown_days: 0\ndenials:\n  - purl: pkg:golang/golang.org/x/text@%s\n    reason: smoke-go\n' \
    "$newest_text" >"$workdir/deny.yaml"
start_proxy "$workdir/deny.yaml"
project "$workdir/deny" ''
denied_to="$(resolved "$workdir/deny" golang.org/x/text@latest)"
[[ "$denied_to" != "$newest_text" ]] || fail "x/text resolved to the denied $newest_text"
[[ "$(fetched "/go/golang.org/x/text/@v/${newest_text}.zip")" == "403" ]] \
    || fail "the zip of x/text $newest_text was not refused"
if client "$workdir/deny" mod download "golang.org/x/text@${newest_text}" 2>/dev/null; then
    fail "go downloaded the denied x/text $newest_text"
fi
echo "    ok (resolved $denied_to; $newest_text is 403)"
stop_proxy

echo "==> 3/6  a cooldown covering x/text's newest version resolves an older one"
printf 'version: 1\ncooldown_days: %s\n' "$text_age" >"$workdir/cooldown.yaml"
start_proxy "$workdir/cooldown.yaml"
project "$workdir/cooldown" ''
cooled_to="$(resolved "$workdir/cooldown" golang.org/x/text@latest)"
[[ "$cooled_to" != "$newest_text" ]] \
    || fail "x/text $newest_text resolved under cooldown_days: $text_age"
echo "    ok (cooldown_days: $text_age; resolved $cooled_to, not $newest_text)"
stop_proxy

echo "==> 4/6  a Go toolchain is downloaded through the proxy"
start_proxy "$workdir/default.yaml"
project "$workdir/toolchain" ''
toolchain=go1.26.0
toolchain_runs="$(retried "$workdir/toolchain" version)"
toolchain=local
grep -q "^go version go1.26.0 " "$workdir/go.out" || fail "go printed $(cat "$workdir/go.out")"
platform="$(go env GOOS)-$(go env GOARCH)"
logged "artifact digest verified.*pkg:golang/golang.org/toolchain@v0.0.1-go1.26.0.${platform}" \
    || fail "the go1.26.0 toolchain was not verified through the proxy"
echo "    ok (go1.26.0 for $platform verified, in $toolchain_runs runs)"
stop_proxy

echo "==> 5/6  an osv/go advisory over max_cvss is refused"
if ! choose_postgres >/dev/null; then
    echo "    skipped (neither docker nor initdb and pg_ctl are available)"
    echo "==> 6/6  skipped (no Postgres to keep the accounts and tokens in)"
    recognised "$log"
    echo "PASS: the proxy serves Go, without the steps that need Postgres."
    exit 0
fi
pg_port="${BYRLE_PG_PORT:-55438}"
start_postgres "byrle-smoke-go-pg-$$" "$pg_port" || fail "postgres did not start"
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
start_proxy "$workdir/default.yaml"
ready=$(curl -s -o /dev/null -w '%{http_code}' "$base/-/byrle/ready")
[[ "$ready" == "200" ]] || fail "the proxy is not ready after the refresh ($ready)"
[[ "$(fetched /go/golang.org/x/crypto/@v/list)" == "200" ]] || fail "x/crypto's @v/list was not served"
if grep -qx "v0.30.0" "$workdir/fetched.out"; then
    fail "x/crypto's @v/list still names v0.30.0"
fi
[[ "$(fetched /go/golang.org/x/crypto/@v/v0.30.0.zip)" == "403" ]] \
    || fail "the zip of x/crypto v0.30.0 was not refused"
grep -q "max_cvss" "$workdir/fetched.out" || fail "the refusal of x/crypto v0.30.0 does not name max_cvss"
echo "    ok (v0.30.0 left out of @v/list, and 403 naming max_cvss)"
stop_proxy

echo "==> 6/6  a token is required, and go sends it from GOPROXY's userinfo"
token="$(issue_token "$database_url" smoke-go)"
require_token=1
start_proxy "$workdir/default.yaml"
assert_unauthorized "$base/go/rsc.io/quote/@v/list"
project "$workdir/token" ''
goproxy="https://smoke-go:${token}@localhost:${front_port}/go"
resolved "$workdir/token" rsc.io/quote@latest >/dev/null
goproxy="$front/go"
if client "$workdir/token" list -m rsc.io/quote@latest >/dev/null 2>&1; then
    fail "go resolved rsc.io/quote without a token"
fi
assert_token_absent "$token" "$log"
echo "    ok (401 without a token; resolved with one)"
stop_proxy

recognised "$log"

echo "PASS: the proxy serves Go as Stage 6 requires."
