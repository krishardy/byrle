#!/usr/bin/env bash
# Unit test coverage, with the floor CLAUDE.md sets.
#
# Measured over the library only. `src/main.rs` is the proxy's async wiring, reached by
# `make smoke-npm` against a real npm client rather than by unit tests, and folding an
# end-to-end-tested binary into a unit-test number would describe neither honestly. Its
# figure is printed below so it is visible rather than excluded quietly.
#
# cargo-llvm-cov sets `--cfg coverage`, which compiles out the tests that need the
# network or a packument corpus on disk. They do not run here, and counting the body of
# a test that cannot run reports a gap in the test suite that is not one.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

floor="${COVERAGE_FLOOR:-90}"

if ! cargo llvm-cov --version >/dev/null 2>&1; then
    echo "cargo-llvm-cov is not installed. Run 'make dev-setup'."
    exit 1
fi

printf '\n\033[1m==> library coverage (floor %s%%)\033[0m\n' "$floor"
cargo llvm-cov --lib \
    --fail-under-lines "$floor" \
    --fail-under-functions "$floor" \
    --fail-under-regions "$floor" \
    --summary-only "$@"

printf '\n\033[1m==> src/main.rs, for reference (not part of the floor)\033[0m\n'
cargo llvm-cov --summary-only 2>/dev/null | awk '/^main\.rs/ || /^Filename/'
echo "    The proxy binary is covered by 'make smoke-npm', not by unit tests."
