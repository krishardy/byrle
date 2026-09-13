#!/usr/bin/env bash
# Run a disposable Postgres in a container, for the targets that need a real schema.
#
# Sourced, not executed. `start_postgres NAME PORT` runs the container, removes it when
# the caller exits, including on failure, and returns once it accepts connections.
#
# Readiness is checked over TCP, not the unix socket. The image's entrypoint runs initdb
# and its init scripts against a temporary server that listens only on the socket, then
# stops it and starts the real one. `pg_isready` on the socket succeeds during that window,
# and a connection through the published port then fails with `expected to read 5 bytes,
# got 0 bytes at EOF`, as `make test-integration` and `make sqlx-prepare` both did on
# 2026-09-13.

postgres_image="${WAHAROA_PG_IMAGE:-postgres:17-alpine}"
postgres_container=""

# The URL for the container published on port $1. `sslmode=disable`: it serves no TLS.
postgres_url() {
    printf 'postgres://waharoa:waharoa@127.0.0.1:%s/waharoa?sslmode=disable' "$1"
}

stop_postgres() {
    if [[ -n "$postgres_container" ]]; then
        docker rm -f "$postgres_container" >/dev/null 2>&1 || true
    fi
}

start_postgres() {
    postgres_container="$1"
    local port="$2"
    trap stop_postgres EXIT

    docker run -d --name "$postgres_container" \
        -e POSTGRES_PASSWORD=waharoa -e POSTGRES_USER=waharoa -e POSTGRES_DB=waharoa \
        -p "$port:5432" "$postgres_image" >/dev/null

    for _ in $(seq 1 60); do
        if docker exec "$postgres_container" pg_isready -h 127.0.0.1 -U waharoa >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "postgres did not accept TCP connections within 60s"
    docker logs "$postgres_container" 2>&1 | tail -20
    return 1
}
