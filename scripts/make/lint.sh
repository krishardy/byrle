#!/usr/bin/env bash
# Lint everything we actually maintain: Rust with clippy, shell with shellcheck.
#
# The shell half is not an afterthought. Per CLAUDE.md, every Makefile recipe is a
# thin wrapper around a script in this directory, so real logic lives in shell and
# clippy cannot see any of it.
#
# shellcheck is required rather than skipped when absent. A lint run that silently
# covers half the codebase and still reports success is the failure mode worth
# avoiding; an incomplete environment should say so.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
failed=0
note() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

note "rust (clippy)"
# --all-targets matters: tests and examples are where unchecked unwraps and dead
# helpers accumulate, and they are excluded by default.
if ! cargo clippy --manifest-path "$repo_root/Cargo.toml" --all-targets "$@" -- -D warnings; then
    failed=1
fi

note "shell (shellcheck)"
if ! command -v shellcheck >/dev/null 2>&1; then
    echo "shellcheck is not installed. Run 'make dev-setup'."
    exit 1
fi

# Every tracked shell script, not just scripts/make, so anything added later is
# covered without editing this file.
mapfile -t scripts < <(git -C "$repo_root" ls-files '*.sh')
if [[ ${#scripts[@]} -eq 0 ]]; then
    echo "no shell scripts tracked"
else
    printf '    checking %d script(s)\n' "${#scripts[@]}"
    if ! (cd "$repo_root" && shellcheck --color=auto "${scripts[@]}"); then
        failed=1
    fi
fi

note "result"
if [[ "$failed" -ne 0 ]]; then
    echo "FAIL: see above."
    exit 1
fi
echo "OK: rust and shell are clean."
