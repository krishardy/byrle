#!/usr/bin/env bash
# Stop the development database. Its container and data are kept.
set -euo pipefail

# shellcheck source=scripts/make/lib/dev-db.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/dev-db.sh"
require_podman

if dev_db_running; then
    podman stop "$dev_db_name" >/dev/null
    echo "$dev_db_name stopped."
else
    echo "$dev_db_name is not running."
fi
