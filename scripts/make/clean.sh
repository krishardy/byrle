#!/usr/bin/env bash
# Remove what the build and the make targets write into the checkout: the cargo target
# directories of byrle and the config-format spike, dist/, and Python's __pycache__.
#
# The run-dev Postgres volume and .env are left alone: one holds data, the other a token.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
for manifest in "$repo_root/Cargo.toml" "$repo_root/spikes/config-format/Cargo.toml"; do
    cargo clean --manifest-path "$manifest"
done
rm -rf "$repo_root/dist"
find "$repo_root/scripts" -type d -name __pycache__ -prune -exec rm -rf {} +
