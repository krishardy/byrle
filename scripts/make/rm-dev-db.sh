#!/usr/bin/env bash
# Delete the development database: its container and the volume holding its data.
set -euo pipefail

# shellcheck source=scripts/make/lib/dev-db.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/dev-db.sh"
require_podman

if dev_db_exists; then
    podman rm -f "$dev_db_name" >/dev/null
    echo "container $dev_db_name removed."
fi
if podman volume exists "$dev_db_name"; then
    podman volume rm "$dev_db_name" >/dev/null
    echo "volume $dev_db_name removed."
fi
echo "$dev_db_name is deleted."
