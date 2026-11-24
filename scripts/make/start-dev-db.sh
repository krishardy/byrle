#!/usr/bin/env bash
# Start the development Postgres alone, the db service in container/compose.yaml. Returns
# once its healthcheck, pg_isready over TCP, passes. Running it again while it is up
# changes nothing.
#
# Usage: start-dev-db.sh USER PASSWORD DATABASE PORT
set -euo pipefail

# shellcheck source=scripts/make/lib/dev-db.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/dev-db.sh"

dev_db_args "$@"
dev_compose up -d db
dev_db_wait

cat <<EOF

Postgres is listening on 127.0.0.1:$DEV_DB_PORT.

  url:     $(dev_db_url)
  psql:    psql '$(dev_db_url)'
  stop:    podman-compose -f container/compose.yaml stop db
  delete:  podman-compose -f container/compose.yaml down -v    (the database too)
EOF
