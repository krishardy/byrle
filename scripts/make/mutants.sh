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
if [[ ! -s "$diff" ]]; then
    echo "no Rust changes since $base"
    exit 0
fi

cd "$repo_root"
cargo mutants --in-diff "$diff" --output "$repo_root/target"
