#!/usr/bin/env bash
# Run the byrle proxy in the foreground.
#
# Override the defaults with the environment:
#   BYRLE_LISTEN=127.0.0.1:8080
#   BYRLE_UPSTREAM_NPM=https://registry.npmjs.org
#   BYRLE_UPSTREAM_PYPI=https://pypi.org/simple
#   RUST_LOG=byrle=debug
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec cargo run --quiet --manifest-path "$repo_root/Cargo.toml" -- daemon "$@"
