#!/usr/bin/env bash
# Install the pinned Temurin JDK and Maven for this Linux machine under $JAVA_DEST
# (default ~/.local/share/byrle), each tarball checked against its pinned checksum, and
# link java and mvn into $BIN_DEST (default ~/.local/bin). `make dev-setup` runs it where
# java or mvn is missing. `make check-deps` reports a newer release than either pin.
#
#   make install-java
set -euo pipefail

# shellcheck source=scripts/make/lib/java.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/java.sh"

dest="${JAVA_DEST:-$HOME/.local/share/byrle}"
bin="${BIN_DEST:-$HOME/.local/bin}"
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) arch=x64 sha256="$jdk_sha256_x64" ;;
    Linux-aarch64 | Linux-arm64) arch=aarch64 sha256="$jdk_sha256_aarch64" ;;
    *) echo "no pinned JDK build for $(uname -s) $(uname -m)"; exit 1 ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$dest" "$bin"

jdk="$dest/$jdk_release"
if [[ -x "$jdk/bin/java" ]]; then
    echo "JDK $jdk_release is in $jdk"
else
    tarball="OpenJDK21U-jdk_${arch}_linux_hotspot_${jdk_file_version}.tar.gz"
    curl -sSfL -o "$work/$tarball" \
        "https://github.com/adoptium/temurin21-binaries/releases/download/${jdk_release/+/%2B}/$tarball"
    echo "$sha256  $work/$tarball" | sha256sum -c --quiet
    mkdir -p "$jdk"
    tar -xzf "$work/$tarball" -C "$jdk" --strip-components=1
    echo "JDK $jdk_release installed in $jdk"
fi

maven="$dest/apache-maven-$maven_version"
if [[ -x "$maven/bin/mvn" ]]; then
    echo "Maven $maven_version is in $maven"
else
    tarball="apache-maven-$maven_version-bin.tar.gz"
    curl -sSfL -o "$work/$tarball" \
        "https://dlcdn.apache.org/maven/maven-3/$maven_version/binaries/$tarball"
    echo "$maven_sha512  $work/$tarball" | sha512sum -c --quiet
    mkdir -p "$maven"
    tar -xzf "$work/$tarball" -C "$maven" --strip-components=1
    echo "Maven $maven_version installed in $maven"
fi

for tool in "$jdk/bin/java" "$jdk/bin/javac" "$maven/bin/mvn"; do
    ln -sf "$tool" "$bin/$(basename "$tool")"
done
echo "java, javac and mvn linked in $bin"
