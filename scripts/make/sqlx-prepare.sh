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
port="${WAHAROA_PG_PORT:-55434}"
check=0
[[ "${1:-}" == "--check" ]] && check=1
# shellcheck source=scripts/make/lib/postgres.sh
. "$repo_root/scripts/make/lib/postgres.sh"

note() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

if ! cargo sqlx --version >/dev/null 2>&1; then
    echo "sqlx-cli is not installed. Run 'make dev-setup'."
    exit 1
fi
choose_postgres || exit 1

note "postgres ($postgres_where) on port $port"
start_postgres "waharoa-prepare-pg-$$" "$port"

DATABASE_URL="$(postgres_url "$port")"
export DATABASE_URL

note "migrations"
cargo sqlx migrate run --source "$repo_root/migrations"

if [[ "$check" == 1 ]]; then
    note "cargo sqlx prepare --check"
    cd "$repo_root" && cargo sqlx prepare --check -- --lib
else
    note "cargo sqlx prepare"
    cd "$repo_root" && cargo sqlx prepare -- --lib
fi
