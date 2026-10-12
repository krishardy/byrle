#!/usr/bin/env bash
# Run byrle in the foreground against the development database, from `make start-dev-db`.
# Arguments and the environment pass through to `make run`'s script; a
# BYRLE_DATABASE_URL already set is kept.
set -euo pipefail

script_dir="$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=scripts/make/lib/dev-db.sh
source "$script_dir/lib/dev-db.sh"
require_podman

if ! dev_db_running; then
    echo "FAIL: $dev_db_name is not running. Start it with: make start-dev-db"
    exit 1
fi
export BYRLE_DATABASE_URL="${BYRLE_DATABASE_URL:-$dev_db_url}"
exec "$script_dir/run.sh" "$@"
