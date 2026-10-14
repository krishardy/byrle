#!/usr/bin/env bash
# The build context of Containerfile.release: each attested binary from dist/*.tar.gz,
# unpacked to dist/image/<arch>/byrle under the architecture name a container platform
# uses, so the image holds the binaries the release attested rather than a second build.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
rm -rf dist/image
shopt -s nullglob
tarballs=(dist/byrle-*.tar.gz)
[[ ${#tarballs[@]} -gt 0 ]] || { echo "no dist/byrle-*.tar.gz; run make release-binary"; exit 1; }
for tarball in "${tarballs[@]}"; do
    name="$(basename "$tarball" .tar.gz)"
    case "$name" in
        *-x86_64-unknown-linux-gnu) arch=amd64 ;;
        *-aarch64-unknown-linux-gnu) arch=arm64 ;;
        *) echo "no container platform for $name"; exit 1 ;;
    esac
    mkdir -p "dist/image/$arch"
    tar -xzf "$tarball" -C "dist/image/$arch" --strip-components=1 "$name/byrle"
    echo "dist/image/$arch/byrle from $tarball"
done
