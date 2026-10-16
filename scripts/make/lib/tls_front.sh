#!/usr/bin/env bash
# nginx on TLS in front of the proxy, with the configuration in docs/fronting-tls.md, for
# the smoke scripts. A local CA signs a certificate for localhost and 127.0.0.1.
#
# Sourced, not executed.

# Write ca.pem, cert.pem and key.pem into $1.
make_certificates() {
    local dir="$1"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=byrle test CA" \
        -keyout "$dir/ca.key" -out "$dir/ca.pem" 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
        -keyout "$dir/key.pem" -out "$dir/cert.csr" 2>/dev/null
    printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' >"$dir/san.ext"
    openssl x509 -req -in "$dir/cert.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca.key" \
        -CAcreateserial -days 2 -extfile "$dir/san.ext" -out "$dir/cert.pem" 2>/dev/null
}

# docs/fronting-tls.md's nginx server block: TLS on port $1 with the certificate in $3,
# passing to the proxy on port $4 with RP key $5. nginx's own files go in $2.
nginx_conf() {
    local port="$1" dir="$2" certs="$3" proxy_port="$4" rp_key="$5"
    printf 'pid %s/nginx.pid;\nerror_log %s/nginx-error.log;\nevents {}\nhttp {\n' "$dir" "$dir"
    # Every temp path, not just the two the proxy uses: nginx creates each at startup, and
    # the packaged defaults under /var/lib/nginx are not writable without root.
    printf '    access_log off;\n    client_body_temp_path %s/body;\n    proxy_temp_path %s/proxy;\n' "$dir" "$dir"
    printf '    fastcgi_temp_path %s/fastcgi;\n    uwsgi_temp_path %s/uwsgi;\n    scgi_temp_path %s/scgi;\n' "$dir" "$dir" "$dir"
    printf '    server {\n        listen %s ssl;\n        server_name localhost;\n' "$port"
    printf '        ssl_certificate %s;\n        ssl_certificate_key %s;\n' "$certs/cert.pem" "$certs/key.pem"
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
