#!/usr/bin/env bash
# Install the pinned shellcheck release for this Linux machine into $SHELLCHECK_DEST
# (default ~/.local/bin), its tarball checked against the release's sha256. CI's lint job
# runs it, so `make lint` there uses this version rather than the runner image's, and
# `make dev-setup` runs it where shellcheck is missing. `make check-deps` reports a newer
# release than the pin.
#
#   make install-shellcheck
set -euo pipefail

# shellcheck source=scripts/make/lib/shellcheck.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/shellcheck.sh"

dest="${SHELLCHECK_DEST:-$HOME/.local/bin}"
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) arch=x86_64 sha256="$shellcheck_sha256_x86_64" ;;
    Linux-aarch64 | Linux-arm64) arch=aarch64 sha256="$shellcheck_sha256_aarch64" ;;
    *) echo "no pinned shellcheck build for $(uname -s) $(uname -m)"; exit 1 ;;
esac

if [[ -x "$dest/shellcheck" ]] && "$dest/shellcheck" --version | grep -qx "version: ${shellcheck_version#v}"; then
    echo "shellcheck $shellcheck_version is in $dest"
    exit 0
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tarball="shellcheck-$shellcheck_version.linux.$arch.tar.gz"
curl -sSfL -o "$work/$tarball" \
    "https://github.com/koalaman/shellcheck/releases/download/$shellcheck_version/$tarball"
echo "$sha256  $work/$tarball" | sha256sum -c --quiet
tar -xzf "$work/$tarball" -C "$work"
mkdir -p "$dest"
install -m 0755 "$work/shellcheck-$shellcheck_version/shellcheck" "$dest/shellcheck"
echo "shellcheck $shellcheck_version installed in $dest"
