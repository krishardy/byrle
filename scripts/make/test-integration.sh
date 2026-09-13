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
image="${WAHAROA_PG_IMAGE:-postgres:17-alpine}"
name="waharoa-test-pg-$$"
port="${WAHAROA_PG_PORT:-55433}"

note() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

if ! docker info >/dev/null 2>&1; then
    echo "docker is not available, and these tests need a real Postgres."
    echo "Start docker, or point WAHAROA_TEST_DATABASE_URL at a database and run:"
    echo "  cargo test --test intel_postgres"
    exit 1
fi

cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

note "postgres ($image) on port $port"
docker run -d --name "$name" \
    -e POSTGRES_PASSWORD=waharoa -e POSTGRES_USER=waharoa -e POSTGRES_DB=waharoa \
    -p "$port:5432" "$image" >/dev/null

for _ in $(seq 1 60); do
    if docker exec "$name" pg_isready -U waharoa >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
if [[ "${ready:-0}" != 1 ]]; then
    echo "postgres did not become ready within 60s"
    docker logs "$name" 2>&1 | tail -20
    exit 1
fi

note "cargo test --test intel_postgres"
# `sslmode=disable`: the container serves no TLS.
WAHAROA_TEST_DATABASE_URL="postgres://waharoa:waharoa@127.0.0.1:$port/waharoa?sslmode=disable" \
    cargo test --manifest-path "$repo_root/Cargo.toml" --test intel_postgres -- --test-threads=1
