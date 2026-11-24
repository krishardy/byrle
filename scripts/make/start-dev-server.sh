#!/usr/bin/env bash
# Run byrle on the host in the foreground with `cargo run`, using the development Postgres
# that start-dev-db starts and the policy in dev/policy.yaml. The daemon applies
# migrations at startup.
#
# Usage: start-dev-server.sh USER PASSWORD DATABASE PORT
#
# Other settings come from the environment, for example:
#   BYRLE_UPSTREAM_NPM=https://registry.npmjs.org
#   BYRLE_REQUIRE_TOKEN=0
#   RUST_LOG=byrle=debug
set -euo pipefail

lib="$(dirname "${BASH_SOURCE[0]}")/lib"
# shellcheck source=scripts/make/lib/dev-db.sh
. "$lib/dev-db.sh"
# shellcheck source=scripts/make/lib/port.sh
. "$lib/port.sh"

dev_db_args "$@"
require_free_ports 8080

BYRLE_DATABASE_URL="$(dev_db_url)"
export BYRLE_DATABASE_URL
export BYRLE_LISTEN=127.0.0.1:8080
export BYRLE_POLICY="$dev_repo_root/dev/policy.yaml"

cat <<EOF
byrle will listen on http://$BYRLE_LISTEN, using Postgres on 127.0.0.1:$DEV_DB_PORT.

  intel:   BYRLE_DATABASE_URL='$BYRLE_DATABASE_URL' cargo run -- refresh
           (until it runs, artifacts answer 503)
  policy:  dev/policy.yaml; after editing it, kill -HUP <the byrle pid>
  stop:    Ctrl-C

EOF

exec cargo run --quiet --manifest-path "$dev_repo_root/Cargo.toml" -- daemon
