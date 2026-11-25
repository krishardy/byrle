#!/usr/bin/env bash
# Build the GuardDog image container/guarddog-byrle.sh runs, from container/Containerfile.guarddog.
#
# Usage: guarddog-image.sh [IMAGE]   (default localhost/byrle-guarddog:3.2.0)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="${1:-localhost/byrle-guarddog:3.2.0}"

podman build --tag "$image" --file "$repo_root/container/Containerfile.guarddog" \
    "$repo_root/container"
podman run --rm --pull=never "$image" --version
