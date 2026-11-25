#!/usr/bin/env bash
# Delete the development Postgres and its volume, then start an empty one with
# start-dev-db. Everything in it goes: accounts and tokens, decisions, the package store and
# the intel snapshot. The audit log is a file, and stays.
#
# Refuses while something listens on 127.0.0.1:8080, because a byrle daemon there would
# keep its connections to the deleted database.
#
# Usage: reset-dev-db.sh USER PASSWORD DATABASE PORT
set -euo pipefail

lib="$(dirname "${BASH_SOURCE[0]}")/lib"
# shellcheck source=scripts/make/lib/dev-db.sh
. "$lib/dev-db.sh"
# shellcheck source=scripts/make/lib/port.sh
. "$lib/port.sh"

dev_db_args "$@"
if ! require_free_ports 8080; then
    echo "FAIL: stop byrle first; it would keep using the deleted database."
    exit 1
fi

dev_compose down -v
exec "$(dirname "${BASH_SOURCE[0]}")/start-dev-db.sh" "$@"
