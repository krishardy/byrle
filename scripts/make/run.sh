#!/usr/bin/env bash
# Run the waharoa proxy in the foreground.
#
# Override the defaults with the environment:
#   WAHAROA_LISTEN=127.0.0.1:8080
#   WAHAROA_UPSTREAM_NPM=https://registry.npmjs.org
#   WAHAROA_UPSTREAM_PYPI=https://pypi.org/simple
#   RUST_LOG=waharoa=debug
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec cargo run --quiet --manifest-path "$repo_root/Cargo.toml" -- daemon "$@"
