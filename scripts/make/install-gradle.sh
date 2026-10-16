#!/usr/bin/env bash
# Install the pinned Gradle under $JAVA_DEST (default ~/.local/share/byrle), its zip
# checked against its pinned sha256, and link gradle into $BIN_DEST (default
# ~/.local/bin). Gradle runs on the JDK `make install-java` installs. `make dev-setup`
# runs it where gradle is missing. `make check-deps` reports a newer release than the pin.
#
#   make install-gradle
set -euo pipefail

# shellcheck source=scripts/make/lib/gradle.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/gradle.sh"

dest="${JAVA_DEST:-$HOME/.local/share/byrle}"
bin="${BIN_DEST:-$HOME/.local/bin}"
gradle="$dest/gradle-$gradle_version"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$dest" "$bin"

if [[ -x "$gradle/bin/gradle" ]]; then
    echo "Gradle $gradle_version is in $gradle"
else
    zip="gradle-$gradle_version-bin.zip"
    # services.gradle.org answers with a redirect to GitHub's release assets.
    curl -sSfL -o "$work/$zip" "https://services.gradle.org/distributions/$zip"
    echo "$gradle_sha256  $work/$zip" | sha256sum -c --quiet
    # Python's zipfile, as not every machine has unzip. It keeps no file modes, so the
    # launcher is made executable after.
    python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' \
        "$work/$zip" "$work/x"
    chmod +x "$work/x/gradle-$gradle_version/bin/gradle"
    mv "$work/x/gradle-$gradle_version" "$gradle"
    echo "Gradle $gradle_version installed in $gradle"
fi

ln -sf "$gradle/bin/gradle" "$bin/gradle"
echo "gradle linked in $bin"
