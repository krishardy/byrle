#!/usr/bin/env bash
# Unit test coverage of the library, with the floor CLAUDE.md sets.
#
# The library only, which is what the rule covers. `src/main.rs` is startup wiring: the
# proxy itself lives in `src/proxy.rs`, tested against a fake registry, and `make
# smoke-npm` runs real clients through the binary end to end. Its figure is printed below
# so it is visible rather than excluded quietly.
#
# cargo-llvm-cov sets `--cfg coverage`, which compiles out the corpus and live tests, as
# CLAUDE.md excludes them. They do not run here, and counting the body of a test that
# cannot run reports a gap in the test suite that is not one.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

floor="${COVERAGE_FLOOR:-95}"

if ! cargo llvm-cov --version >/dev/null 2>&1; then
    echo "cargo-llvm-cov is not installed. Run 'make dev-setup'."
    exit 1
fi

# `src/intel/postgres.rs` speaks to a real database and nothing else. Its tests are
# `tests/intel_postgres.rs`, which `make test-integration` runs against a container and
# which return early without one, so this pass compiles them out and the file reads 0%.
# CLAUDE.md excludes live tests from the floor, and a file only those tests reach is the
# same case. Decided 2026-09-16; its figure is printed below rather than excluded quietly.
live_only='src/intel/postgres\.rs'

printf '\n\033[1m==> library coverage (floor %s%%, lines and functions and regions)\033[0m\n' "$floor"
cargo llvm-cov --lib \
    --ignore-filename-regex "$live_only" \
    --fail-under-lines "$floor" \
    --fail-under-functions "$floor" \
    --fail-under-regions "$floor" \
    --summary-only "$@"

printf '\n\033[1m==> not part of the floor\033[0m\n'
cargo llvm-cov --summary-only 2>/dev/null | awk '/^Filename/ || /^main\.rs/'
cargo llvm-cov --lib --summary-only 2>/dev/null | awk '/^intel\/postgres\.rs/'
echo "    main.rs is startup wiring. 'make smoke-npm' and 'make smoke-clients' run real"
echo "    clients through the binary."
echo "    intel/postgres.rs needs a real database. 'make test-integration' runs its tests."
