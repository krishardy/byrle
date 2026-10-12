#!/usr/bin/env bash
# Run a disposable Postgres, for the targets that need a real schema.
#
# Sourced, not executed. `start_postgres NAME PORT` starts one, removes it when the caller
# exits, including on failure, and returns once it accepts TCP connections on PORT.
#
# It runs in a docker container when docker answers, and otherwise as a local cluster from
# `initdb` and `pg_ctl`. The local cluster is for a machine that cannot run a container
# daemon, such as a rootless podman container with no capabilities, where the binaries run
# as the invoking user. It lives in a temporary directory and listens on 127.0.0.1 only.
#
# Container readiness is checked over TCP, not the unix socket. The image's entrypoint runs
# initdb and its init scripts against a temporary server that listens only on the socket,
# then stops it and starts the real one. `pg_isready` on the socket succeeds during that
# window, and a connection through the published port then fails with `expected to read 5
# bytes, got 0 bytes at EOF`, as `make test-integration` and `make sqlx-prepare` both did
# on 2026-09-13.

postgres_image="${BYRLE_PG_IMAGE:-docker.io/library/postgres:18-alpine}"
postgres_container=""
postgres_local_dir=""
postgres_bin=""
postgres_kind=""
postgres_where=""

# The URL for the server on port $1, as role $2, password $3, database $4, each `byrle`
# when not given. `sslmode=disable`: it serves no TLS.
postgres_url() {
    printf 'postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable' \
        "${2:-byrle}" "${3:-byrle}" "$1" "${4:-byrle}"
}

# The directory holding `initdb`, `pg_ctl` and `createdb`: the PATH first, then Alpine's
# /usr/libexec/postgresqlNN, highest version first. Empty when neither has them.
find_postgres_bin() {
    local tool dir candidates=()
    if tool="$(command -v initdb)"; then
        candidates+=("$(dirname "$tool")")
    fi
    local versioned=(/usr/libexec/postgresql*/)
    local i
    for ((i = ${#versioned[@]} - 1; i >= 0; i--)); do
        candidates+=("${versioned[i]%/}")
    done
    for dir in "${candidates[@]}"; do
        if [[ -x "$dir/initdb" && -x "$dir/pg_ctl" && -x "$dir/createdb" ]]; then
            printf '%s' "$dir"
            return
        fi
    done
}

# Pick where the server runs: `container` when docker answers, else `local` when `initdb`
# and `pg_ctl` are found. Sets `postgres_kind` and `postgres_where` in the caller's shell,
# so it is called directly rather than in `$(...)`.
#
# `postgres_where` is read only by the scripts that source this file, which shellcheck
# does not see.
# shellcheck disable=SC2034
choose_postgres() {
    if docker info >/dev/null 2>&1; then
        postgres_kind=container
        postgres_where="container $postgres_image"
        return
    fi
    postgres_bin="$(find_postgres_bin)"
    if [[ -n "$postgres_bin" ]]; then
        postgres_kind=local
        postgres_where="local cluster from $postgres_bin"
        return
    fi
    echo "neither docker nor initdb and pg_ctl are available, and this needs a real Postgres."
    echo "Start docker, or install Postgres (on Alpine: apk add postgresql17)."
    return 1
}

stop_postgres() {
    if [[ -n "$postgres_container" ]]; then
        docker rm -f "$postgres_container" >/dev/null 2>&1 || true
    fi
    if [[ -n "$postgres_local_dir" ]]; then
        "$postgres_bin/pg_ctl" stop -D "$postgres_local_dir/data" -m immediate >/dev/null 2>&1 || true
        rm -rf "$postgres_local_dir"
    fi
}

start_postgres() {
    local name="$1"
    local port="$2"
    trap stop_postgres EXIT

    [[ -n "$postgres_kind" ]] || choose_postgres || return 1
    case "$postgres_kind" in
        container) start_postgres_container "$name" "$port" ;;
        local) start_postgres_local "$port" ;;
    esac
}

start_postgres_container() {
    postgres_container="$1"
    local port="$2"

    docker run -d --name "$postgres_container" \
        -e POSTGRES_PASSWORD=byrle -e POSTGRES_USER=byrle -e POSTGRES_DB=byrle \
        -p "$port:5432" "$postgres_image" >/dev/null

    for _ in $(seq 1 60); do
        if docker exec "$postgres_container" pg_isready -h 127.0.0.1 -U byrle >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "postgres did not accept TCP connections within 60s"
    docker logs "$postgres_container" 2>&1 | tail -20
    return 1
}

# `trust` authentication, so the password in `postgres_url` is sent and not checked. The
# server accepts connections from 127.0.0.1 only, and its socket is in the temporary
# directory rather than the system's.
start_postgres_local() {
    local port="$1"
    postgres_local_dir="$(mktemp -d)"
    local data="$postgres_local_dir/data"
    local log="$postgres_local_dir/server.log"

    if ! "$postgres_bin/initdb" -D "$data" -U byrle --auth=trust >"$log" 2>&1; then
        echo "initdb failed"
        tail -20 "$log"
        return 1
    fi
    # `-w` returns once the server reports itself ready, after its own startup. There is
    # no temporary server here, so it cannot answer early the way the image's does.
    if ! "$postgres_bin/pg_ctl" start -D "$data" -l "$log" -w -t 60 \
        -o "-p $port -k $postgres_local_dir -c listen_addresses=127.0.0.1" >/dev/null; then
        echo "postgres did not start within 60s"
        tail -20 "$log"
        return 1
    fi
    "$postgres_bin/createdb" -h 127.0.0.1 -p "$port" -U byrle byrle
}
