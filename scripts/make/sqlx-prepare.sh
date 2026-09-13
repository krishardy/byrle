#!/usr/bin/env bash
# Regenerate the offline query cache in .sqlx/.
#
# `sqlx::query_as!` checks SQL against the real schema at compile time, which normally
# means a database has to be running to build. The cache in .sqlx/ is that check's answer,
# committed, so a contributor builds with nothing installed. It has to be regenerated
# whenever a query or a migration changes, and CI runs `--check` so a stale one is a build
# failure rather than a runtime surprise.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="${WAHAROA_PG_IMAGE:-postgres:17-alpine}"
name="waharoa-prepare-pg-$$"
port="${WAHAROA_PG_PORT:-55434}"
check=0
[[ "${1:-}" == "--check" ]] && check=1

note() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

if ! cargo sqlx --version >/dev/null 2>&1; then
    echo "sqlx-cli is not installed. Run 'make dev-setup'."
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "docker is not available, and preparing the cache needs a real schema to check against."
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
    exit 1
fi

# `sslmode=disable`: the container serves no TLS.
export DATABASE_URL="postgres://waharoa:waharoa@127.0.0.1:$port/waharoa?sslmode=disable"

note "migrations"
cargo sqlx migrate run --source "$repo_root/migrations"

if [[ "$check" == 1 ]]; then
    note "cargo sqlx prepare --check"
    cd "$repo_root" && cargo sqlx prepare --check -- --lib
else
    note "cargo sqlx prepare"
    cd "$repo_root" && cargo sqlx prepare -- --lib
fi
