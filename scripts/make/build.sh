#!/usr/bin/env bash
# Build the waharoa binary with the release profile, and print where it is.
#
# `--locked` so the build uses Cargo.lock as committed rather than resolving anew.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cargo build --release --locked --manifest-path "$repo_root/Cargo.toml" --bin waharoa
target_dir="$(cargo metadata --format-version 1 --no-deps --manifest-path "$repo_root/Cargo.toml" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
echo "$target_dir/release/waharoa"
