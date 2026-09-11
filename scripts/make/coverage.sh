#!/usr/bin/env bash
# Unit test coverage, with the floor CLAUDE.md sets.
#
# Measured over the whole crate, `src/main.rs` included. That file is startup wiring
# only: the proxy itself lives in `src/proxy.rs` in the library, where it is tested
# against a fake registry, and `make smoke-npm` runs a real npm client through the
# binary end to end.
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

printf '\n\033[1m==> coverage (floor %s%%, lines and functions and regions)\033[0m\n' "$floor"
exec cargo llvm-cov \
    --fail-under-lines "$floor" \
    --fail-under-functions "$floor" \
    --fail-under-regions "$floor" \
    --summary-only "$@"
