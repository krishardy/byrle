#!/usr/bin/env bash
# deployment/compose brought up as an operator would, with a local CA's certificate for
# localhost, then checked through nginx on TLS:
#   1. /-/byrle/health answers 200
#   2. the refresh service loads intel: it exits 0, or 1 with a stream's last load kept
#   3. /-/byrle/ready answers 200
#   4. an account and token made with `exec byrle byrle`, and pip installs with the token
#
# The compose directory is copied to a temporary one, with its .env and certificates, so
# nothing is written into the repository. Its containers and volumes are removed on exit.
#
#   BYRLE_IMAGE   the image to run (default: env.example's)
#   COMPOSE       the compose command (default: docker compose, then podman-compose)
#   BYRLE_PORT    the port nginx publishes (default 8774)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/make/lib/tls_front.sh
. "$repo_root/scripts/make/lib/tls_front.sh"
port="${BYRLE_PORT:-8774}"
front="https://localhost:$port"
failed=0

fail() { echo "FAIL: $*"; failed=1; }

if [[ -n "${COMPOSE:-}" ]]; then
    read -r -a compose <<<"$COMPOSE"
elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    compose=(docker compose)
elif command -v podman-compose >/dev/null 2>&1; then
    compose=(podman-compose)
else
    echo "FAIL: neither docker compose nor podman-compose is on PATH. Name one with COMPOSE=."
    exit 1
fi

workdir="$(mktemp -d)"
project="byrle-smoke-$$"
cleanup() {
    (cd "$workdir/compose" && "${compose[@]}" -p "$project" --profile refresh down -v \
        >/dev/null 2>&1) || true
    rm -rf "$workdir"
}
trap cleanup EXIT

cp -r "$repo_root/deployment/compose" "$workdir/compose"
mkdir "$workdir/tls"
make_certificates "$workdir/tls"

image="${BYRLE_IMAGE:-$(sed -n 's/^BYRLE_IMAGE=//p' "$workdir/compose/env.example")}"
cat >"$workdir/compose/.env" <<EOF
BYRLE_IMAGE=$image
BYRLE_PROXY_URL=$front
BYRLE_TLS_CERT=$workdir/tls/cert.pem
BYRLE_TLS_KEY=$workdir/tls/key.pem
BYRLE_HTTPS_PORT=$port
POSTGRES_PASSWORD=$(openssl rand -hex 32)
BYRLE_RP_KEY=$(openssl rand -hex 32)
BYRLE_MODE=observe
EOF

cd "$workdir/compose"
run() { "${compose[@]}" -p "$project" "$@"; }
curl=(curl -s --noproxy '*' --cacert "$workdir/tls/ca.pem")

echo "==> up: $image, $front"
run up -d

status=000
for _ in $(seq 1 60); do
    status="$("${curl[@]}" -o /dev/null -w '%{http_code}' "$front/-/byrle/health" || true)"
    [[ "$status" == 200 ]] && break
    sleep 1
done
[[ "$status" == 200 ]] || { fail "health answered $status"; run logs byrle nginx | tail -20; }

echo "==> refresh"
refreshed=0
run --profile refresh run --rm refresh >"$workdir/refresh.out" 2>&1 || refreshed=$?
[[ "$refreshed" -le 1 ]] || fail "refresh exited $refreshed: $(tail -3 "$workdir/refresh.out")"

status="$("${curl[@]}" -o /dev/null -w '%{http_code}' "$front/-/byrle/ready" || true)"
[[ "$status" == 200 ]] || fail "ready answered $status after refresh"

echo "==> account, token, pip"
run exec -T byrle byrle account create smoke >/dev/null
token="$(run exec -T byrle byrle token create smoke compose | tail -1)"
python3 -m venv "$workdir/venv"
"$workdir/venv/bin/pip" install --no-cache-dir --cert "$workdir/tls/ca.pem" \
    --index-url "https://smoke:$token@localhost:$port/pypi/simple/" six==1.17.0 \
    >"$workdir/pip.out" 2>&1 || fail "pip install failed: $(tail -3 "$workdir/pip.out")"

if [[ "$failed" -ne 0 ]]; then
    echo
    echo "FAIL: see above."
    exit 1
fi
echo
echo "PASS: deployment/compose serves pip through nginx on TLS, with intel loaded."
