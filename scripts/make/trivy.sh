#!/usr/bin/env bash
# Container scanning with trivy, for `make sast`.
#
# Two passes, both run even if the first fails:
#   config  misconfigurations in Containerfile. trivy has no checks for compose.yaml
#   image   known vulnerabilities in the packages of the image `make run-dev` runs
#
# The image is built here with podman, from the build cache, so the scan is of the current
# Containerfile. It is handed to trivy as a `podman save` archive, which needs no podman
# API socket. trivy finds the Debian packages of the distroless base in it. It does not
# find the Rust crates in the byrle binary, which carries no dependency list;
# `make check-deps` covers Cargo.lock.
#
# TRIVY_SEVERITY, default HIGH,CRITICAL, is the severities that fail the run.
#
# A vulnerability with no fixed package fails the run too: it is in the image either way.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

for tool in trivy podman; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "$tool is not installed. Run 'make dev-setup'."
        exit 1
    fi
done

image="localhost/byrle-trivy"
archive="$(mktemp -d)"
trap 'rm -rf "$archive"; podman rmi "$image" >/dev/null 2>&1 || true' EXIT

trivy_args=(--quiet --exit-code 1 --severity "${TRIVY_SEVERITY:-HIGH,CRITICAL}")
failed=0

echo "--- config: Containerfile"
# target/ is the host's build output, tens of gigabytes, and holds no configuration.
rc=0
trivy config "${trivy_args[@]}" --skip-dirs target --skip-dirs .git . || rc=$?
if [[ "$rc" -ne 0 ]]; then
    echo "    config scan exited $rc"
    failed=1
fi

echo "--- image: Containerfile, built as $image"
rc=0
{ podman build --quiet -t "$image" -f Containerfile . >/dev/null \
    && podman save --quiet -o "$archive/image.tar" "$image" \
    && trivy image "${trivy_args[@]}" --input "$archive/image.tar"; } || rc=$?
if [[ "$rc" -ne 0 ]]; then
    echo "    image build or scan exited $rc"
    failed=1
fi

if [[ "$failed" -ne 0 ]]; then
    echo "FAIL: see above."
    exit 1
fi
echo "OK: no ${TRIVY_SEVERITY:-HIGH,CRITICAL} findings."
