#!/usr/bin/env bash
# Lint everything we actually maintain: Rust with clippy, shell with shellcheck, and
# python far enough to know it parses.
#
# The shell half is not an afterthought. Per CLAUDE.md, every Makefile recipe is a
# thin wrapper around a script in this directory, so real logic lives in shell and
# clippy cannot see any of it.
#
# Note that shellcheck is required rather than skipped when absent. A lint run that
# silently covers half the codebase and still reports success is the failure mode worth
# avoiding; an incomplete environment should say so.
#
# Careful: a comment whose first word is the tool's own name is parsed as a directive
# and fails with SC1073. Start such lines with anything else.
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

note "rust (clippy, release profile)"
# The release profile turns off debug_assertions, so it compiles a different crate:
# `#[cfg(debug_assertions)]` code is removed. With only the debug profile checked, a
# release build stopped compiling when that attribute ended up on the wrong module in
# src/lib.rs (d648995), and nothing failed.
if ! cargo clippy --manifest-path "$repo_root/Cargo.toml" --release --lib --bins "$@" -- -D warnings; then
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
    # -x follows `source`, so the shared helper under scripts/make/lib is checked in the
    # context that uses it rather than reported as unreadable.
    if ! (cd "$repo_root" && shellcheck -x --color=auto "${scripts[@]}"); then
        failed=1
    fi
fi

# Only that the file parses. This is not a python linter and does not pretend to be one:
# it is the check that would have caught a helper whose quoting was mangled on the way
# into the repository, which is the failure these scripts actually have.
note "python (syntax)"
mapfile -t pyfiles < <(git -C "$repo_root" ls-files '*.py')
if [[ ${#pyfiles[@]} -eq 0 ]]; then
    echo "    no python files tracked"
else
    printf '    checking %d file(s)\n' "${#pyfiles[@]}"
    # The byte-code goes under target/ rather than beside the source, so linting does
    # not leave __pycache__ directories in the tree.
    if ! (cd "$repo_root" && PYTHONPYCACHEPREFIX="$repo_root/target/pycache" \
        python3 -m py_compile "${pyfiles[@]}"); then
        failed=1
    fi
fi

note "result"
if [[ "$failed" -ne 0 ]]; then
    echo "FAIL: see above."
    exit 1
fi
echo "OK: rust, shell and python are clean."
