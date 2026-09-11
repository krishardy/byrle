#!/usr/bin/env bash
# Clippy across every target, warnings escalated to errors.
#
# --all-targets matters: tests and examples are where unchecked unwraps and dead
# helpers accumulate, and they are excluded by default.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec cargo clippy --manifest-path "$repo_root/Cargo.toml" --all-targets "$@" -- -D warnings
