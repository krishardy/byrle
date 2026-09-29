#!/usr/bin/env bash
# waharoa behind Caddy and behind nginx on TLS, with the configurations in
# docs/fronting-tls.md, checked with curl, npm and pip.
#
# A local CA signs a certificate for localhost. For each front on PATH, `caddy` and
# `nginx`, the proxy runs with WAHAROA_PUBLIC_URL set to the front's address. Asserts, per
# front:
#   1. /-/waharoa/health answers 200 through it
#   2. an artifact nothing has analysed is a 503 with Retry-After and x-waharoa-not-ready
#   3. npm installs through it, and the lockfile records the front's https address
#   4. pip installs through it
# A front that is not installed is reported and skipped.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
proxy_port="${WAHAROA_PORT:-8771}"
workdir="$(mktemp -d)"
pids=()
failed=0
checked=0

cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    rm -rf "$workdir"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; failed=1; }

cargo build --release --quiet --manifest-path "$repo_root/Cargo.toml"
binary="$repo_root/target/release/waharoa"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=waharoa test CA" \
    -keyout "$workdir/ca.key" -out "$workdir/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
    -keyout "$workdir/key.pem" -out "$workdir/cert.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' >"$workdir/san.ext"
openssl x509 -req -in "$workdir/cert.csr" -CA "$workdir/ca.pem" -CAkey "$workdir/ca.key" \
    -CAcreateserial -days 2 -extfile "$workdir/san.ext" -out "$workdir/cert.pem" 2>/dev/null

# docs/fronting-tls.md's Caddyfile, with this run's certificate and ports.
caddyfile() {
    printf '{\n\tadmin off\n\tauto_https disable_redirects\n}\n'
    printf 'localhost:%s {\n\ttls %s %s\n' "$1" "$workdir/cert.pem" "$workdir/key.pem"
    printf '\treverse_proxy 127.0.0.1:%s {\n\t\tflush_interval -1\n\t}\n}\n' "$proxy_port"
}

# docs/fronting-tls.md's nginx server block, with this run's certificate, ports and paths.
nginx_conf() {
    local dir="$2"
    printf 'pid %s/nginx.pid;\nerror_log %s/nginx-error.log;\nevents {}\nhttp {\n' "$dir" "$dir"
    printf '    access_log off;\n    client_body_temp_path %s/body;\n    proxy_temp_path %s/proxy;\n' "$dir" "$dir"
    printf '    server {\n        listen %s ssl;\n        server_name localhost;\n' "$1"
    printf '        ssl_certificate %s;\n        ssl_certificate_key %s;\n' "$workdir/cert.pem" "$workdir/key.pem"
    printf '        location / {\n            proxy_pass http://127.0.0.1:%s;\n' "$proxy_port"
    printf '            proxy_http_version 1.1;\n'
    # nginx's variable, written as it is.
    # shellcheck disable=SC2016
    printf '            proxy_set_header Host $http_host;\n'
    printf '            proxy_set_header X-Forwarded-Proto https;\n'
    printf '            proxy_buffering off;\n'
    printf '            proxy_request_buffering off;\n'
    printf '            proxy_read_timeout 300s;\n'
    printf '        }\n    }\n}\n'
}

# One front on `port`: the proxy, the front, then the four checks.
check() {
    local name="$1" port="$2" front="https://localhost:$2" dir="$workdir/$1"
    if ! command -v "$name" >/dev/null 2>&1; then
        echo "==> $name: NOT INSTALLED, skipped"
        return 0
    fi
    checked=$((checked + 1))
    mkdir -p "$dir/app"
    WAHAROA_PUBLIC_URL="$front" WAHAROA_LISTEN="127.0.0.1:$proxy_port" \
        WAHAROA_SPOOL_DIR="$dir/spool" "$binary" daemon >"$dir/proxy.log" 2>&1 &
    local proxy=$!
    pids+=("$proxy")
    for _ in $(seq 1 60); do grep -q "waharoa listening" "$dir/proxy.log" && break; sleep 0.5; done
    case "$name" in
        caddy)
            caddyfile "$port" >"$dir/Caddyfile"
            caddy run --config "$dir/Caddyfile" --adapter caddyfile >"$dir/front.log" 2>&1 &
            ;;
        nginx)
            nginx_conf "$port" "$dir" >"$dir/nginx.conf"
            nginx -p "$dir" -c "$dir/nginx.conf" -g 'daemon off;' >"$dir/front.log" 2>&1 &
            ;;
    esac
    local front_pid=$!
    pids+=("$front_pid")
    local curl=(curl -s --noproxy '*' --cacert "$workdir/ca.pem")
    for _ in $(seq 1 30); do
        "${curl[@]}" -o /dev/null "$front/-/waharoa/health" && break
        sleep 0.5
    done
    echo "==> $name, $front"

    local status
    status="$("${curl[@]}" -o /dev/null -w '%{http_code}' "$front/-/waharoa/health")"
    [[ "$status" == 200 ]] || fail "$name: health answered $status"

    local headers
    headers="$("${curl[@]}" -o /dev/null -D - "$front/ms/-/ms-2.1.3.tgz" | tr -d '\r')"
    grep -qE '^HTTP/[0-9.]+ 503' <<<"$headers" || fail "$name: an unanalysed artifact was not a 503"
    grep -qi '^retry-after: 1' <<<"$headers" || fail "$name: Retry-After did not pass through"
    grep -qi '^x-waharoa-not-ready: artifact-analysis' <<<"$headers" \
        || fail "$name: x-waharoa-not-ready did not pass through"

    printf '{"name":"a","version":"1.0.0","private":true}\n' >"$dir/app/package.json"
    (cd "$dir/app" && NODE_EXTRA_CA_CERTS="$workdir/ca.pem" npm install debug@4.4.1 \
        --registry="$front/" --cache "$dir/npm-cache" --no-audit --no-fund --loglevel=error) \
        >"$dir/npm.out" 2>&1 || fail "$name: npm install failed: $(tail -3 "$dir/npm.out")"
    grep -q "\"resolved\": \"$front/debug/-/debug-4.4.1.tgz\"" "$dir/app/package-lock.json" \
        || fail "$name: the lockfile does not record $front"

    python3 -m venv "$dir/venv"
    "$dir/venv/bin/pip" install --no-cache-dir --cert "$workdir/ca.pem" \
        --index-url "$front/simple/" six==1.17.0 >"$dir/pip.out" 2>&1 \
        || fail "$name: pip install failed: $(tail -3 "$dir/pip.out")"

    kill "$front_pid" "$proxy" 2>/dev/null || true
    wait "$front_pid" "$proxy" 2>/dev/null || true
    pids=()
    echo "    checked: health, the 503's headers, npm with the lockfile on $front, pip"
}

check caddy 8772
check nginx 8773

if [[ "$failed" -ne 0 ]]; then
    echo
    echo "FAIL: see above."
    exit 1
fi
if [[ "$checked" -eq 0 ]]; then
    echo
    echo "FAIL: neither caddy nor nginx is on PATH, so nothing was checked."
    exit 1
fi
echo
echo "PASS: every installed front passes the proxy through on TLS."
