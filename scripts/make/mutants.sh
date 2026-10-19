#!/usr/bin/env bash
# Mutation testing, with cargo-mutants, over the Rust changed since a base commit.
#
# Coverage says a line ran. A mutant says whether any test fails when the line's behaviour
# changes. Only mutants inside the diff are tried, so a run covers one change rather than
# the whole tree. An edit can leave code outside the diff less tested, which this does not
# see, and a diff that touches only tests produces no mutants.
#
#   make mutants                 the working tree against HEAD, before committing
#   make mutants BASE=HEAD~3     everything since another commit
#
# BYRLE_MUTANTS_JOBS mutants (default 4) are built and tested at once, each in its own
# copy of the tree, with the `mutants` profile, which has no debug information. A cargo
# command running past BYRLE_MUTANTS_TIMEOUT seconds (default 300) is stopped and its
# mutant reported as timed out, so one hanging test cannot hold the run.
#
# An untracked `.rs` file is included whole: it is in no diff, and leaving it out reported
# "every mutant caught" for a module nothing had mutated.
#
# The tests in tests/postgres.rs skip without a database, so a mutant in the Postgres code
# would be missed. A Postgres is started for the run unless BYRLE_TEST_DATABASE_URL names
# one, and BYRLE_TEST_SCHEMA_PER_PROCESS=1 gives each job's tests their own schemas in it.
#
# Exit codes are cargo-mutants' own: 0 every mutant caught, 2 some missed, 3 some timed
# out, 4 the unmutated tree failed its tests. Results are in target/mutants.out.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
base="${1:-HEAD}"

if ! cargo mutants --version >/dev/null 2>&1; then
    echo "cargo-mutants is not installed. Run 'make dev-setup'."
    exit 1
fi

diff="$(mktemp)"
trap 'rm -f "$diff"' EXIT
git -C "$repo_root" diff "$base" -- '*.rs' >"$diff"
# A file git has never seen is in no diff, so a new module would be mutated not at all and
# the run would report every mutant caught. Each one is added to the diff as the whole file.
while IFS= read -r new; do
    git -C "$repo_root" diff --no-index /dev/null "$new" >>"$diff" || true
done < <(git -C "$repo_root" ls-files --others --exclude-standard -- '*.rs')
if [[ ! -s "$diff" ]]; then
    echo "no Rust changes since $base"
    exit 0
fi

if [[ -z "${BYRLE_TEST_DATABASE_URL:-}" ]]; then
    # shellcheck source=scripts/make/lib/postgres.sh
    . "$repo_root/scripts/make/lib/postgres.sh"
    choose_postgres || exit 1
    port="${BYRLE_PG_PORT:-55435}"
    echo "postgres ($postgres_where) on port $port, for tests/postgres.rs"
    start_postgres "byrle-mutants-pg-$$" "$port"
    # start_postgres sets its own EXIT trap; this one keeps removing the diff too.
    trap 'rm -f "$diff"; stop_postgres' EXIT
    export BYRLE_TEST_DATABASE_URL
    BYRLE_TEST_DATABASE_URL="$(postgres_url "$port")"
fi
export BYRLE_TEST_SCHEMA_PER_PROCESS=1

cd "$repo_root"
cargo mutants --in-diff "$diff" --output "$repo_root/target" --profile mutants \
    --jobs "${BYRLE_MUTANTS_JOBS:-4}" --timeout "${BYRLE_MUTANTS_TIMEOUT:-300}"
