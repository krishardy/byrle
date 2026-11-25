#!/usr/bin/env bash
# GuardDog for BYRLE_DETECTORS, run in the image `make guarddog-image` builds from
# container/Containerfile.guarddog. Takes GuardDog's arguments:
#
#   BYRLE_DETECTORS='guarddog=/path/to/guarddog-byrle {ecosystem} scan {name} --version={version} --output-format=json'
#
# The container mounts nothing of the host's but the named volume byrle-guarddog-cache, which
# holds GuardDog's lists of popular packages. It gets none of the host's variables but
# SOCKS and the forward proxies, which byrle passes a detector, and has no capabilities.
# Its network is podman's default, because GuardDog downloads the package itself.
# See docs/engineering_decisions/0146-guarddog-container.md.
set -euo pipefail

image="${BYRLE_GUARDDOG_IMAGE:-localhost/byrle-guarddog:3.2.0}"

forwarded=()
for name in SOCKS HTTPS_PROXY https_proxy HTTP_PROXY http_proxy NO_PROXY no_proxy; do
    if [[ -n "${!name:-}" ]]; then
        forwarded+=(--env "$name")
    fi
done

exec podman run --rm --pull=never --quiet \
    --read-only --tmpfs /tmp:rw,nosuid,nodev,size=1g \
    --volume byrle-guarddog-cache:/var/cache/guarddog \
    --cap-drop=all --security-opt=no-new-privileges \
    --pids-limit=256 --memory=2g \
    "${forwarded[@]}" \
    "$image" "$@"
