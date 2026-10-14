#!/usr/bin/env bash
# A release binary for this machine's target, packaged for a GitHub release:
# dist/byrle-<version>-<target>.tar.gz, holding the binary, LICENSE and README.md, and its
# .sha256 beside it. Built with --locked and the offline query cache, as CI builds.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
target="$(rustc -vV | sed -n 's/^host: //p')"
name="byrle-$version-$target"

SQLX_OFFLINE=true cargo build --release --locked
rm -rf "dist/$name"
mkdir -p "dist/$name"
cp target/release/byrle LICENSE README.md "dist/$name/"
tar -C dist -czf "dist/$name.tar.gz" "$name"
rm -rf "dist/$name"
(cd dist && sha256sum "$name.tar.gz" >"$name.tar.gz.sha256")
echo "dist/$name.tar.gz"
