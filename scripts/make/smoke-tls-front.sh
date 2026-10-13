#!/usr/bin/env bash
# byrle behind nginx on TLS, with the configuration in docs/fronting-tls.md, checked
# with curl, npm and pip.
#
# A local CA signs a certificate for localhost. The proxy runs with BYRLE_PROXY_URL set to
# nginx's address. Asserts:
#   1. /-/byrle/health answers 200 through it
#   2. an artifact nothing has analysed is a 503 with Retry-After and x-byrle-not-ready
#   3. npm installs through it, and the lockfile records the front's https address
#   4. pip installs through it
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
proxy_port="${BYRLE_PORT:-8771}"
workdir="$(mktemp -d)"
pids=()
failed=0

cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    rm -rf "$workdir"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; failed=1; }

if ! command -v nginx >/dev/null 2>&1; then
    echo "FAIL: nginx is not on PATH. Run 'make dev-setup'."
    exit 1
fi

cargo build --release --quiet --manifest-path "$repo_root/Cargo.toml"
binary="$repo_root/target/release/byrle"
rp_key="$(openssl rand -hex 32)"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=byrle test CA" \
    -keyout "$workdir/ca.key" -out "$workdir/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
    -keyout "$workdir/key.pem" -out "$workdir/cert.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' >"$workdir/san.ext"
openssl x509 -req -in "$workdir/cert.csr" -CA "$workdir/ca.pem" -CAkey "$workdir/ca.key" \
    -CAcreateserial -days 2 -extfile "$workdir/san.ext" -out "$workdir/cert.pem" 2>/dev/null

# docs/fronting-tls.md's nginx server block, with this run's certificate, ports and paths.
nginx_conf() {
    local dir="$2"
    printf 'pid %s/nginx.pid;\nerror_log %s/nginx-error.log;\nevents {}\nhttp {\n' "$dir" "$dir"
    # Every temp path, not just the two the proxy uses: nginx creates each at startup, and
    # the packaged defaults under /var/lib/nginx are not writable without root.
    printf '    access_log off;\n    client_body_temp_path %s/body;\n    proxy_temp_path %s/proxy;\n' "$dir" "$dir"
    printf '    fastcgi_temp_path %s/fastcgi;\n    uwsgi_temp_path %s/uwsgi;\n    scgi_temp_path %s/scgi;\n' "$dir" "$dir" "$dir"
    printf '    server {\n        listen %s ssl;\n        server_name localhost;\n' "$1"
    printf '        ssl_certificate %s;\n        ssl_certificate_key %s;\n' "$workdir/cert.pem" "$workdir/key.pem"
    printf '        location / {\n            proxy_pass http://127.0.0.1:%s;\n' "$proxy_port"
    printf '            proxy_http_version 1.1;\n'
    # nginx's variable, written as it is.
    # shellcheck disable=SC2016
    printf '            proxy_set_header Host $http_host;\n'
    printf '            proxy_set_header X-Forwarded-Proto https;\n'
    # shellcheck disable=SC2016
    printf '            proxy_set_header X-Forwarded-For $remote_addr;\n'
    printf '            proxy_set_header X-Byrle-RP-Key %s;\n' "$rp_key"
    printf '            proxy_buffering off;\n'
    printf '            proxy_request_buffering off;\n'
    printf '            proxy_read_timeout 300s;\n'
    printf '        }\n    }\n}\n'
}

# nginx on `port`: the proxy, nginx, then the four checks.
check() {
    local name=nginx port="$1" front="https://localhost:$1" dir="$workdir/nginx"
    mkdir -p "$dir/app"
    BYRLE_REQUIRE_TOKEN=0 BYRLE_RP_KEY="$rp_key" BYRLE_PROXY_URL="$front" BYRLE_LISTEN="127.0.0.1:$proxy_port" \
        BYRLE_SPOOL_DIR="$dir/spool" "$binary" daemon >"$dir/proxy.log" 2>&1 &
    local proxy=$!
    pids+=("$proxy")
    for _ in $(seq 1 60); do grep -q "byrle listening" "$dir/proxy.log" && break; sleep 0.5; done
    nginx_conf "$port" "$dir" >"$dir/nginx.conf"
    nginx -p "$dir" -c "$dir/nginx.conf" -g 'daemon off;' >"$dir/front.log" 2>&1 &
    local front_pid=$!
    pids+=("$front_pid")
    local curl=(curl -s --noproxy '*' --cacert "$workdir/ca.pem")
    for _ in $(seq 1 30); do
        "${curl[@]}" -o /dev/null "$front/-/byrle/health" && break
        sleep 0.5
    done
    echo "==> $name, $front"

    local status
    status="$("${curl[@]}" -o /dev/null -w '%{http_code}' "$front/-/byrle/health")"
    [[ "$status" == 200 ]] || fail "$name: health answered $status"

    local headers
    headers="$("${curl[@]}" -o /dev/null -D - "$front/ms/-/ms-2.1.3.tgz" | tr -d '\r')"
    grep -qE '^HTTP/[0-9.]+ 503' <<<"$headers" || fail "$name: an unanalysed artifact was not a 503"
    grep -qi '^retry-after: 1' <<<"$headers" || fail "$name: Retry-After did not pass through"
    grep -qi '^x-byrle-not-ready: artifact-analysis' <<<"$headers" \
        || fail "$name: x-byrle-not-ready did not pass through"

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

check 8773

if [[ "$failed" -ne 0 ]]; then
    echo
    echo "FAIL: see above."
    exit 1
fi
echo
echo "PASS: nginx passes the proxy through on TLS."
