#!/usr/bin/env bash
# Update dependencies to the newest versions the manifest already allows.
#
# Plain `cargo update`, which moves Cargo.lock within the semver constraints in
# Cargo.toml and updates transitive dependencies along with direct ones. It does not
# raise a constraint: a dependency held back by `^1` in Cargo.toml stays on 1.x, and
# moving it to 2.x is an edit to the manifest and a decision someone makes on purpose.
# `make check-deps` is what reports those, under "out of date".
#
# The config-format spike is deliberately left alone. Its Cargo.lock is the record of
# which four YAML parsers the spike actually ran against, and bumping it would replace
# that record with a claim about versions nobody tested. `make check-deps` still audits
# it for vulnerabilities, which is the half that has to stay current.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lock="$repo_root/Cargo.lock"

note() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

before="$(mktemp)"
trap 'rm -f "$before"' EXIT
cp "$lock" "$before"

# No summary of our own afterwards. `cargo update` names each crate and both versions as
# it goes, and a second pass over the lockfile produced version numbers with no crate
# attached to them, which is worse than saying nothing.
note "cargo update"
cargo update --manifest-path "$repo_root/Cargo.toml"

if diff -q "$before" "$lock" >/dev/null 2>&1; then
    note "nothing moved"
    exit 0
fi

note "next"
echo "  make test         nothing here proves the new versions work"
echo "  make check-deps   vulnerabilities, and what is still held back by a constraint"
