#!/usr/bin/env bash
# The development database: a Postgres container in podman, kept between runs.
#
# Sourced, not executed. The container is `byrle-dev-db`, its data is in the podman volume
# of the same name, and it listens on 127.0.0.1:$BYRLE_DEV_DB_PORT, 5433 by default, so it
# does not take the port of a Postgres already on the machine.

# shellcheck source=scripts/make/lib/postgres.sh
source "$(dirname "${BASH_SOURCE[0]}")/postgres.sh"

dev_db_name="byrle-dev-db"
dev_db_port="${BYRLE_DEV_DB_PORT:-5433}"
# Read by the scripts that source this file.
# shellcheck disable=SC2034
dev_db_url="$(postgres_url "$dev_db_port")"

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
