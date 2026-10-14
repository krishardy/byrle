#!/usr/bin/env bash
# A static release binary for this machine's architecture, packaged for a GitHub release:
# dist/byrle-<version>-<arch>-unknown-linux-musl.tar.gz, holding the binary, LICENSE and
# README.md, and its .sha256 beside it. See docs/engineering_decisions/release-provenance.md.
#
# Built in the pinned rust:1-alpine image below, where the host target is musl and links
# statically, with --locked and the offline query cache. Run outside that image, this
# starts it with docker and runs itself inside.
set -euo pipefail

image="docker.io/library/rust:1-alpine@sha256:0cce0a5e0e8ba67b455257a3a02a1d99005f382748789d6464460028810f1627"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ -z "${BYRLE_IN_RELEASE_IMAGE:-}" ]]; then
    docker info >/dev/null 2>&1 || { echo "make release-binary needs docker, to build in $image"; exit 1; }
    exec docker run --rm -v "$repo_root:/src" -w /src \
        -e BYRLE_IN_RELEASE_IMAGE=1 -e BYRLE_OWNER="$(id -u):$(id -g)" "$image" \
        sh -c 'apk add --no-cache bash musl-dev gcc g++ make perl cmake linux-headers >/dev/null \
            && exec bash scripts/make/release-binary.sh'
fi

cd "$repo_root"
version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
target="$(rustc -vV | sed -n 's/^host: //p')"
name="byrle-$version-$target"
# Its own target directory: the checkout's belongs to the host, and holds glibc objects.
export CARGO_TARGET_DIR=/tmp/release-target

SQLX_OFFLINE=true cargo build --release --locked
binary="$CARGO_TARGET_DIR/release/byrle"
if readelf -d "$binary" | grep -q NEEDED; then
    echo "$binary links shared libraries:"
    readelf -d "$binary" | grep NEEDED
    exit 1
fi
rm -rf "dist/$name"
mkdir -p "dist/$name"
cp "$binary" LICENSE README.md "dist/$name/"
tar -C dist -czf "dist/$name.tar.gz" "$name"
rm -rf "dist/$name"
(cd dist && sha256sum "$name.tar.gz" >"$name.tar.gz.sha256")
chown -R "${BYRLE_OWNER:-$(id -u):$(id -g)}" dist
echo "dist/$name.tar.gz, static"
