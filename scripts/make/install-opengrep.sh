#!/usr/bin/env bash
# Install the pinned opengrep release for this Linux machine into $OPENGREP_DEST (default
# ~/.local/bin), its binary checked against the release's sha256, for `make opengrep`.
# `make check-deps` reports a newer release than the pin.
#
#   make install-opengrep
set -euo pipefail

# shellcheck source=scripts/make/lib/opengrep.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/opengrep.sh"

dest="${OPENGREP_DEST:-$HOME/.local/bin}"
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) arch=x86 sha256="$opengrep_sha256_x86" ;;
    Linux-aarch64 | Linux-arm64) arch=aarch64 sha256="$opengrep_sha256_aarch64" ;;
    *) echo "no pinned opengrep build for $(uname -s) $(uname -m)"; exit 1 ;;
esac

if [[ -x "$dest/opengrep" && "$("$dest/opengrep" --version)" == "${opengrep_version#v}" ]]; then
    echo "opengrep $opengrep_version is in $dest"
    exit 0
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
binary="opengrep_manylinux_$arch"
curl -sSfL -o "$work/$binary" \
    "https://github.com/opengrep/opengrep/releases/download/$opengrep_version/$binary"
echo "$sha256  $work/$binary" | sha256sum -c --quiet
mkdir -p "$dest"
install -m 0755 "$work/$binary" "$dest/opengrep"
echo "opengrep $opengrep_version installed in $dest"
