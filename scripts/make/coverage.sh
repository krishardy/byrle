#!/usr/bin/env bash
# Unit test coverage of the library, with the floor CLAUDE.md sets.
#
# The library only, which is what the rule covers. `src/main.rs` is startup wiring: the
# proxy itself lives in `src/proxy.rs`, tested against a fake registry, and `make
# smoke-npm` runs real clients through the binary end to end. Its figure is printed below
# so it is visible rather than excluded quietly.
#
# On the nightly in lib/coverage-toolchain.sh, so test code is not counted: see there.
#
# cargo-llvm-cov sets `--cfg coverage`, which compiles out the corpus and live tests, as
# CLAUDE.md excludes them. They do not run here, and counting the body of a test that
# cannot run reports a gap in the test suite that is not one.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

floor="${COVERAGE_FLOOR:-100}"

# shellcheck source=scripts/make/lib/coverage-toolchain.sh
. "$repo_root/scripts/make/lib/coverage-toolchain.sh"
nightly="+$byrle_coverage_toolchain"
# A target directory per toolchain. cargo-llvm-cov read objects a stable run had left in the
# shared one and reported 23% on 2026-09-29, against 92.5% with the directory removed.
export CARGO_LLVM_COV_TARGET_DIR="$repo_root/target/llvm-cov-$byrle_coverage_toolchain"

if ! cargo "$nightly" llvm-cov --version >/dev/null 2>&1; then
    echo "cargo-llvm-cov or $byrle_coverage_toolchain is not installed. Run 'make dev-setup'."
    exit 1
fi

# Three files need a real database and nothing else can reach them. Their tests are
# `tests/postgres.rs`, which `make test-integration` runs against a container and
# which return early without one, so this pass compiles them out and all three read 0%.
# CLAUDE.md excludes live tests from the floor, and a file only those tests reach is the
# same case. Decided 2026-09-16; their figures are printed below rather than excluded
# quietly.
#
# `src/intel/postgres.rs` is the advisory queries and `src/analysis/postgres.rs` is the
# artifact-analysis ones. `src/intel/refresh/run.rs` is the refresh that sends the first
# set: connect, fetch, write, replace. Everything a refresh decides without a database is
# elsewhere in `src/intel/`, inside the floor, and the analysis store's own logic is in
# `src/analysis/store.rs`.
live_only='src/(intel/(postgres|refresh/run)|analysis/postgres)\.rs'

printf '\n\033[1m==> library coverage (floor %s%%, lines and functions and regions)\033[0m\n' "$floor"
cargo "$nightly" llvm-cov --lib \
    --ignore-filename-regex "$live_only" \
    --fail-under-lines "$floor" \
    --fail-under-functions "$floor" \
    --fail-under-regions "$floor" \
    --summary-only "$@"

printf '\n\033[1m==> not part of the floor\033[0m\n'
cargo "$nightly" llvm-cov --summary-only 2>/dev/null | awk '/^Filename/ || /^main\.rs/'
cargo "$nightly" llvm-cov --lib --summary-only 2>/dev/null | awk '/^(intel|analysis)\/postgres\.rs/'
echo "    main.rs is startup wiring. 'make smoke-npm' and 'make smoke-clients' run real"
echo "    clients through the binary."
echo "    intel/postgres.rs, intel/refresh/run.rs and analysis/postgres.rs need a real
    database. 'make test-integration' runs their tests."
