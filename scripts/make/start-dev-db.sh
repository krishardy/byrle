#!/usr/bin/env bash
# Start the development database in podman, creating its container and volume the first
# time. Returns once it accepts TCP connections, and prints its URL.
set -euo pipefail

# shellcheck source=scripts/make/lib/dev-db.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/dev-db.sh"
require_podman

if dev_db_running; then
    echo "$dev_db_name is already running."
elif dev_db_exists; then
    podman start "$dev_db_name" >/dev/null
    echo "$dev_db_name started."
else
    podman run -d --name "$dev_db_name" \
        -e POSTGRES_PASSWORD=byrle -e POSTGRES_USER=byrle -e POSTGRES_DB=byrle \
        -v "$dev_db_name:/var/lib/postgresql" \
        -p "127.0.0.1:$dev_db_port:5432" "$postgres_image" >/dev/null
    echo "$dev_db_name created and started."
fi

# Over TCP rather than the socket: see scripts/make/lib/postgres.sh.
for _ in $(seq 1 60); do
    if podman exec "$dev_db_name" pg_isready -h 127.0.0.1 -U byrle >/dev/null 2>&1; then
        echo "BYRLE_DATABASE_URL=$dev_db_url"
        exit 0
    fi
    sleep 1
done
echo "FAIL: $dev_db_name did not accept TCP connections within 60s."
podman logs "$dev_db_name" 2>&1 | tail -20
exit 1
