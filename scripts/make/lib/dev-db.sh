#!/usr/bin/env bash
# The development database: a Postgres container in podman, kept between runs.
#
# Sourced, not executed. The container is `byrle-dev-db`, its data is in the podman volume
# of the same name, and it listens on 127.0.0.1:$BYRLE_DEV_DB_PORT, 5433 by default, so it
# does not take the port of a Postgres already on the machine. Its role, password and
# database are the first three arguments of start-dev-db.sh and run-dev.sh, set in the
# Makefile.

# shellcheck source=scripts/make/lib/postgres.sh
source "$(dirname "${BASH_SOURCE[0]}")/postgres.sh"

dev_db_name="byrle-dev-db"
dev_db_port="${BYRLE_DEV_DB_PORT:-5433}"

# Set dev_db_user, dev_db_password, dev_db_database and dev_db_url from USER PASSWORD
# DATABASE, or exit when one is missing or empty. The caller then shifts 3.
#
# They are read by the scripts that source this file.
# shellcheck disable=SC2034
read_dev_db_args() {
    if [[ $# -lt 3 || -z "$1" || -z "$2" || -z "$3" ]]; then
        echo "FAIL: usage: $(basename "$0") USER PASSWORD DATABASE"
        exit 1
    fi
    dev_db_user="$1"
    dev_db_password="$2"
    dev_db_database="$3"
    dev_db_url="$(postgres_url "$dev_db_port" "$1" "$2" "$3")"
}

# Exit unless podman is on PATH.
require_podman() {
    if ! command -v podman >/dev/null 2>&1; then
        echo "FAIL: podman is not on PATH."
        exit 1
    fi
}

# Whether the container exists, running or not.
dev_db_exists() {
    podman container exists "$dev_db_name"
}

# Whether the container is running.
dev_db_running() {
    [[ "$(podman inspect --format '{{.State.Running}}' "$dev_db_name" 2>/dev/null)" == true ]]
}
