#!/usr/bin/env bash
# Build container/Containerfile.release for linux/amd64 and linux/arm64 from dist/image/ (make
# release-image-context) and push it to ghcr.io/<REPO>:<version>, the version being TAG
# without its `v`. Prints the image's index digest, and writes it as `digest` to
# $GITHUB_OUTPUT when that is set, for the step that attests it.
#
#   TAG=v0.2.0 REPO=krishardy/byrle GITHUB_ACTOR=<user> GITHUB_TOKEN=<token> release-image.sh
#
# The docker CLI's buildx does this rather than docker/setup-buildx-action, login-action and
# build-push-action, so no action from outside GitHub runs in a job holding `packages: write`
# and `id-token: write`. BuildKit runs in a container from the image pinned below; `make
# check-deps` reports when its tag moves.
set -euo pipefail

tag="${TAG:?set TAG, such as v0.2.0}"
repo="${REPO:?set REPO, such as krishardy/byrle}"
: "${GITHUB_ACTOR:?set GITHUB_ACTOR}" "${GITHUB_TOKEN:?set GITHUB_TOKEN}"
image="ghcr.io/$repo:${tag#v}"
buildkit="docker.io/moby/buildkit:v0.35.1@sha256:baf6138eb8c37644800c7c913fba051e840ebb9ba13eaf92d92ef9a1712d0b4c"
builder="byrle-release-$$"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
[[ -d dist/image ]] || { echo "no dist/image; run make release-image-context"; exit 1; }

metadata="$(mktemp)"
cleanup() {
    rm -f "$metadata"
    docker buildx rm "$builder" >/dev/null 2>&1 || true
    docker logout ghcr.io >/dev/null 2>&1 || true
}
trap cleanup EXIT

printf '%s' "$GITHUB_TOKEN" | docker login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
# The docker-container driver, because the default `docker` driver cannot push one image for
# two platforms. Containerfile.release only copies, so neither platform needs emulation.
docker buildx create --name "$builder" --driver docker-container --driver-opt "image=$buildkit"
docker buildx build --builder "$builder" --platform linux/amd64,linux/arm64 \
    --file container/Containerfile.release --tag "$image" \
    --metadata-file "$metadata" --push .

digest="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' \
    "$metadata")"
echo "$image@$digest"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "digest=$digest" >>"$GITHUB_OUTPUT"
fi
