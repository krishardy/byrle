#!/usr/bin/env bash
# The Stage 4.9 exit test, docs/admin-plan.md §9: real npm and pip installs, each with its
# own account's token, read back through the console's API with the account that made
# them; a test MAL- record loaded after an install raising an alert; status degraded with
# no snapshot; every route but health refusing an account without the role; and logins by
# password and through Dex.
#
# Needs Postgres (docker, or initdb and pg_ctl), Dex (docker, or Go to build it), node,
# python3 and curl. The OSV streams are served from loopback with BYRLE_STREAM_URLS, so the
# advisories are the test's own.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/make/lib/postgres.sh
. "$repo_root/scripts/make/lib/postgres.sh"
# shellcheck source=scripts/make/lib/dex.sh
. "$repo_root/scripts/make/lib/dex.sh"
# shellcheck source=scripts/make/lib/token.sh
. "$repo_root/scripts/make/lib/token.sh"
# shellcheck source=scripts/make/lib/node.sh
. "$repo_root/scripts/make/lib/node.sh"
byrle_use_latest_node

port="${BYRLE_PORT:-8790}"
pg_port="${BYRLE_PG_PORT:-55436}"
dex_port="${BYRLE_DEX_PORT:-5592}"
mirror_port="${BYRLE_MIRROR_PORT:-8791}"
workdir="$(mktemp -d)"
console="http://127.0.0.1:${port}/admin"
registry="http://127.0.0.1:${port}/registry/"
issuer="http://127.0.0.1:${dex_port}/dex"
password="correct horse battery staple"
proxy_pid=""
mirror_pid=""

cleanup() {
    local pid
    for pid in "$proxy_pid" "$mirror_pid"; do
        [[ -n "$pid" ]] || continue
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    stop_dex
    stop_postgres
    rm -rf "$workdir"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*"
    [[ -f "$workdir/proxy.log" ]] && { echo "--- proxy log ---"; tail -40 "$workdir/proxy.log"; }
    exit 1
}
step() { echo "==> $*"; }

# JSON on stdin, the Python expression $1 applied to it as `d`, printed.
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

require_free_ports "$port" "$pg_port" "$dex_port" "$mirror_port" || fail "a port this test uses is taken"
cargo build --release --quiet --manifest-path "$repo_root/Cargo.toml"
binary="$repo_root/target/release/byrle"

start_postgres "byrle-smoke-console-pg-$$" "$pg_port" || fail "postgres did not start"
# start_postgres sets its own EXIT trap; cleanup stops Postgres as well as the rest.
trap cleanup EXIT
database_url="$(postgres_url "$pg_port")"
export BYRLE_DATABASE_URL="$database_url"
export BYRLE_ACCOUNT_EVENT_LOG="$workdir/events.jsonl"

# An OSV bundle for each ecosystem: one MAL record for a package nobody installs, and with
# `with_is_number`, one for is-number 7.0.0 as well.
bundles() {
    python3 "$repo_root/scripts/make/smoke-console-bundles.py" "$workdir/mirror" "$1"
}
mkdir -p "$workdir/mirror"
bundles no
python3 -m http.server "$mirror_port" --bind 127.0.0.1 --directory "$workdir/mirror" \
    >"$workdir/mirror.log" 2>&1 &
mirror_pid=$!
export BYRLE_STREAM_URLS="osv/npm=http://127.0.0.1:${mirror_port}/npm.zip,osv/pypi=http://127.0.0.1:${mirror_port}/pypi.zip"

secret="$(head -c 24 /dev/urandom | base64 | tr -d '/+=')"
cat >"$workdir/dex.yaml" <<EOF
issuer: ${issuer}
storage:
  type: memory
web:
  http: 127.0.0.1:${dex_port}
oauth2:
  skipApprovalScreen: true
enablePasswordDB: true
staticClients:
- id: byrle-console
  secret: ${secret}
  name: byrle
  redirectURIs:
  - ${console}/oidc/callback
staticPasswords:
- email: alice@example.com
  hash: "\$2a\$10\$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W"
  username: alice
  userID: "08a8684b-db88-4b73-90a9-3cd1661f5466"
EOF
start_dex "$workdir/dex.yaml" "$dex_port" || fail "Dex did not start"

step "accounts: alice an admin, bob with no role, a token each"
"$binary" account create alice --role admin >/dev/null
"$binary" account create bob >/dev/null
printf '%s\n' "$password" | "$binary" account password alice >/dev/null
printf '%s\n' "$password" | "$binary" account password bob >/dev/null
alice_token="$("$binary" token create alice laptop 2>/dev/null)"
bob_token="$("$binary" token create bob laptop 2>/dev/null)"

printf 'version: 1\ncooldown_days: 0\n' >"$workdir/policy.yaml"
BYRLE_LISTEN="127.0.0.1:${port}" BYRLE_PROXY_URL="$registry" BYRLE_CONSOLE_URL="${console}/" \
BYRLE_POLICY="$workdir/policy.yaml" BYRLE_AUDIT_LOG="$workdir/audit.jsonl" \
BYRLE_SPOOL_DIR="$workdir/spool" BYRLE_OIDC_ISSUER="$issuer" \
BYRLE_OIDC_CLIENT_ID=byrle-console BYRLE_OIDC_CLIENT_SECRET="$secret" \
    "$binary" daemon >"$workdir/proxy.log" 2>&1 &
proxy_pid=$!
for _ in $(seq 1 60); do grep -q "byrle listening" "$workdir/proxy.log" && break; sleep 0.5; done

# A session cookie for $1, logged in by password through the API.
session() {
    local body
    body="$(printf '{"account":"%s","password":"%s"}' "$1" "$password")"
    curl -s -D - -o /dev/null -H 'content-type: application/json' -d "$body" \
        "${console}/api/v1/login" | tr -d '\r' | sed -n 's/^set-cookie: \(byrle_session=[^;]*\).*/\1/ip'
}
# GET $2 under the console's API with cookie $1: the body.
api() { curl -s -H "cookie: $1" "${console}/api/v1/$2"; }
# GET $2 with cookie $1: the status.
status_of() { curl -s -o /dev/null -w '%{http_code}' -H "cookie: $1" "${console}/api/v1/$2"; }

step "1/8  status is degraded while the intel store holds no snapshot"
admin="$(session alice)"
[[ -n "$admin" ]] || fail "alice did not log in by password"
readiness="$(api "$admin" status | json '[c["status"] for c in d["components"] if c["name"]=="readiness"][0]')"
[[ "$readiness" == "degraded" ]] || fail "readiness was $readiness with no snapshot"
echo "    ok (readiness degraded; alice logged in by password)"

step "2/8  a refresh loads the test streams, and status is up"
"$binary" refresh >"$workdir/refresh.out" 2>&1 || [[ $? -le 1 ]] || fail "byrle refresh failed"
sleep 6
states="$(api "$admin" status | json '",".join(sorted(set(c["status"] for c in d["components"])))')"
[[ "$states" == "up" ]] || fail "status after the refresh: $states"
echo "    ok (every component up)"

step "3/8  npm with alice's token, pip with bob's"
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
assert_unauthorized "${registry}is-number"
mkdir -p "$workdir/npm"
printf '//127.0.0.1:%s/registry/:_authToken=%s\n' "$port" "$alice_token" >"$workdir/npm/.npmrc"
(cd "$workdir/npm" && npm install --no-audit --no-fund --loglevel=error \
    --registry "$registry" --cache "$workdir/npm-cache" is-number@7.0.0 >"$workdir/npm.out" 2>&1) \
    || fail "npm install with alice's token failed: $(tail -15 "$workdir/npm.out")"
python3 -m venv "$workdir/venv"
"$workdir/venv/bin/pip" install --quiet --no-cache-dir \
    --index-url "http://bob:${bob_token}@127.0.0.1:${port}/registry/simple/" six==1.17.0 \
    || fail "pip install with bob's token failed"
sleep 2
echo "    ok (401 without a token; is-number installed by alice, six by bob)"

step "4/8  R3 to R9 name the account behind each request"
who="$(api "$admin" "dependencies?ecosystem=npm&name=is-number" | json 'd["versions"][0]["account"]')"
[[ "$who" == "alice" ]] || fail "is-number was served to $who"
who="$(api "$admin" "dependencies?ecosystem=pypi&name=six" | json 'd["versions"][0]["account"]')"
[[ "$who" == "bob" ]] || fail "six was served to $who"
lines="$(api "$admin" "requests?since=${since}&account=alice&name=is-number" | json 'len(d["lines"])')"
[[ "$lines" -ge 1 ]] || fail "no request line for alice's is-number"
unauthorized="$(api "$admin" "metrics/failures?answered=unauthorized" | json 'sum(r["count"] for r in d["failures"])')"
[[ "$unauthorized" -ge 1 ]] || fail "the request without a token is not counted"
created="$(api "$admin" "events?action=account-created" | json 'sorted(l["account"] for l in d["lines"])')"
[[ "$created" == "['alice', 'bob']" ]] || fail "account-created events: $created"
secret_shown="$(api "$admin" config | json '[s["value"] for s in d["environment"] if s["name"]=="BYRLE_OIDC_CLIENT_SECRET"][0]')"
[[ "$secret_shown" == "set" ]] || fail "the client secret was shown as $secret_shown"
api "$admin" "logs/$(date -u +%Y-%m-%d)" | grep -q '"name":"is-number"' || fail "the day's log holds no is-number line"
echo "    ok (dependencies, requests, failures, events, config, logs)"

step "5/8  a MAL record loaded after the install raises an alert, and refuses it now"
bundles yes
"$binary" refresh >"$workdir/refresh2.out" 2>&1 || [[ $? -le 1 ]] || fail "the second refresh failed"
alert="$(api "$admin" alerts | json '[(a["served"]["account"], a["advisory_id"]) for a in d["alerts"]]')"
[[ "$alert" == "[('alice', 'MAL-2099-2')]" ]] || fail "alerts: $alert"
refused="$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer ${alice_token}" \
    "${registry}is-number/-/is-number-7.0.0.tgz")"
[[ "$refused" == "403" ]] || fail "is-number after its MAL record answered $refused"
malware="$(api "$admin" "requests?since=${since}&answered=refused&check=known_malware" | json 'len(d["lines"])')"
[[ "$malware" -ge 1 ]] || fail "R5 shows no refusal for malware"
echo "    ok (alice's is-number alerted; refused as known_malware)"

step "6/8  bob, without the role, is 403 on every route that needs one"
user="$(session bob)"
for route in accounts dependencies alerts requests "metrics/failures" config events \
    "logs/$(date -u +%Y-%m-%d)" status; do
    code="$(status_of "$user" "$route")"
    [[ "$code" == "403" ]] || fail "bob on $route: $code"
done
[[ "$(status_of "" health)" == "200" ]] || fail "health without credentials was not 200"
echo "    ok (403 on each, health 200 without credentials)"

# Follow an OIDC login from the console through Dex as alice@example.com: the callback's
# headers and body, in $workdir/callback.headers and .body.
through_dex() {
    local jar="$workdir/dex.jar" begun location oidc_cookie url out action
    rm -f "$jar"
    begun="$(curl -s -D - -o /dev/null "${console}/oidc/login" | tr -d '\r')"
    location="$(printf '%s' "$begun" | sed -n 's/^location: //ip')"
    oidc_cookie="$(printf '%s' "$begun" | sed -n 's/^set-cookie: \(__Host-byrle_oidc=[^;]*\).*/\1/ip')"
    url="$location"
    for _ in 1 2 3 4; do
        out="$(curl -s -c "$jar" -b "$jar" -o "$workdir/dex.html" -w '%{redirect_url}' "$url")"
        [[ -z "$out" ]] && break
        url="$out"
    done
    action="$(grep -o '<form[^>]*action="[^"]*"' "$workdir/dex.html" | sed 's/.*action="//; s/"$//; s/&amp;/\&/g')"
    url="$(curl -s -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' \
        --data-urlencode login=alice@example.com --data-urlencode password=password \
        "http://127.0.0.1:${dex_port}${action}")"
    for _ in 1 2 3; do
        [[ "$url" == "${console}/oidc/callback"* ]] && break
        url="$(curl -s -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' "$url")"
    done
    curl -s -D "$workdir/callback.headers" -o "$workdir/callback.body" -H "cookie: $oidc_cookie" "$url"
}

step "7/8  through Dex: refused until linked, then logged in as alice"
through_dex
grep -q '^HTTP/1.1 403' "$workdir/callback.headers" || fail "an unlinked identity was not 403"
subject="$(grep -o '[^ >]* at [^ ]* is not linked' "$workdir/callback.body" | cut -d' ' -f1)"
[[ -n "$subject" ]] || fail "the 403 page named no subject"
"$binary" account link alice --issuer "$issuer" --subject "$subject" >/dev/null
through_dex
grep -q '^HTTP/1.1 200' "$workdir/callback.headers" || fail "the linked identity was not logged in"
oidc_session="$(tr -d '\r' <"$workdir/callback.headers" | sed -n 's/^set-cookie: \(byrle_session=[^;]*\).*/\1/ip')"
who="$(api "$oidc_session" session | json 'd["account"] + " " + d["by"]')"
[[ "$who" == "alice session" ]] || fail "the OIDC session is $who"
echo "    ok (403 until linked; then a session as alice)"

step "8/8  the account event log names each login"
grep -q '"action":"login","account":"alice"' "$BYRLE_ACCOUNT_EVENT_LOG" || fail "no login line"
grep -q '"action":"oidc-linked","account":"alice"' "$BYRLE_ACCOUNT_EVENT_LOG" || fail "no oidc-linked line"
echo "    ok"

echo
echo "PASS: the console meets the Stage 4.9 exit criterion."
