#!/usr/bin/env bash
# Tests that need a real Postgres, against one in a container.
#
# Postgres is the only backend, so it is the one the tests have to run against. The
# alternative was keeping SQLite for tests, which would have meant covering the backend
# nobody deploys; see docs/engineering_decisions/storage-sqlx-postgres.md.
#
# The container is torn down on exit, including on failure. The database it holds is
# disposable: every test creates its own schema and drops it first, so a test cannot see
# another's rows and a crashed run leaves nothing to clean up by hand.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
port="${WAHAROA_PG_PORT:-55433}"
# shellcheck source=scripts/make/lib/postgres.sh
. "$repo_root/scripts/make/lib/postgres.sh"

note() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

if ! docker info >/dev/null 2>&1; then
    echo "docker is not available, and these tests need a real Postgres."
    echo "Start docker, or point WAHAROA_TEST_DATABASE_URL at a database and run:"
    echo "  cargo test --test intel_postgres"
    exit 1
fi

note "postgres ($postgres_image) on port $port"
start_postgres "waharoa-test-pg-$$" "$port"

note "cargo test --test intel_postgres"
WAHAROA_TEST_DATABASE_URL="$(postgres_url "$port")" \
    cargo test --manifest-path "$repo_root/Cargo.toml" --test intel_postgres -- --test-threads=1
