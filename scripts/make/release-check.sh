#!/usr/bin/env bash
# Whether tag $1 names this checkout's version: `v` and the version in Cargo.toml. A release
# built from a tag that says another version would publish one version under another's name.
#
#   make release-check TAG=v0.1.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tag="${1:-}"
[[ -n "$tag" ]] || { echo "usage: make release-check TAG=v<version>"; exit 2; }
version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$repo_root/Cargo.toml" | head -1)"
if [[ "$tag" != "v$version" ]]; then
    echo "tag $tag does not name Cargo.toml's version $version; tag v$version, or change the version"
    exit 1
fi
echo "tag $tag names version $version"
