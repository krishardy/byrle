#!/usr/bin/env bash
# The development database from container/compose.yaml, for start-dev-db and
# start-dev-server.
#
# Sourced, not executed. `dev_db_args "$@"` checks USER PASSWORD DATABASE PORT and exports
# them as DEV_DB_USER, DEV_DB_PASSWORD, DEV_DB_NAME and DEV_DB_PORT for compose.yaml.
# `dev_compose ARGS...` runs podman-compose on that file. `dev_db_wait` returns once the db
# container reports healthy.
#
# podman-compose rather than `podman compose`, which runs docker-compose when it is
# installed, and then in whichever daemon DOCKER_HOST names; see
# docs/engineering_decisions/0101-dev-environment-compose.md.

dev_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
dev_compose_file="$dev_repo_root/container/compose.yaml"

dev_db_args() {
    if [[ $# -ne 4 || -z "$1" || -z "$2" || -z "$3" || ! "$4" =~ ^[0-9]+$ ]]; then
        echo "FAIL: usage: $(basename "$0") USER PASSWORD DATABASE PORT"
        return 1
    fi
    export DEV_DB_USER="$1" DEV_DB_PASSWORD="$2" DEV_DB_NAME="$3" DEV_DB_PORT="$4"
}

# The URL for the development database from the host. `sslmode=disable`: it serves no TLS.
dev_db_url() {
    printf 'postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable' \
        "$DEV_DB_USER" "$DEV_DB_PASSWORD" "$DEV_DB_PORT" "$DEV_DB_NAME"
}

dev_compose() {
    if ! command -v podman-compose >/dev/null 2>&1; then
        echo "FAIL: podman-compose is not on PATH."
        return 1
    fi
    podman-compose -f "$dev_compose_file" "$@"
}

# podman-compose 1.6.0 `up -d --wait db` did not return on 2026-11-25 after db reported
# healthy, so the health status is read from podman. The filter finds the container by its
# compose labels rather than the name podman-compose gives it.
dev_db_wait() {
    local id status=""
    id="$(podman ps -q --filter label=com.docker.compose.project=byrle-dev \
        --filter label=com.docker.compose.service=db)"
    if [[ -z "$id" ]]; then
        echo "FAIL: the db container is not running."
        return 1
    fi
    for _ in $(seq 1 60); do
        status="$(podman inspect --format '{{.State.Health.Status}}' "$id")"
        [[ "$status" == healthy ]] && return 0
        sleep 1
    done
    echo "FAIL: the db container was $status, not healthy, after 60s."
    podman logs "$id" 2>&1 | tail -20
    return 1
}
