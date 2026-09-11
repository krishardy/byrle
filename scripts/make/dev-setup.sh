#!/usr/bin/env bash
# Install the development dependencies this project's targets expect.
#
# Deliberately additive and re-runnable: it installs what is missing and leaves
# anything already present alone.
set -euo pipefail

need() { command -v "$1" >/dev/null 2>&1; }

echo "==> rustup components"
rustup component add clippy rustfmt 2>&1 | sed 's/^/    /'

echo "==> cargo-audit (dependency advisories; used when re-running the config spike)"
if cargo audit --version >/dev/null 2>&1; then
    echo "    already installed"
else
    cargo install cargo-audit --locked
fi

echo "==> cargo-outdated (dependency freshness, used by 'make check-deps')"
if cargo outdated --version >/dev/null 2>&1; then
    echo "    already installed"
else
    cargo install cargo-outdated --locked
fi

echo "==> trufflehog (credential scanning, used by 'make sast')"
if need trufflehog; then
    echo "    found $(trufflehog --version 2>&1 | head -1)"
elif need brew; then
    brew install trufflehog
elif need go; then
    go install github.com/trufflesecurity/trufflehog/v3@latest
else
    # Upstream offers `curl ... install.sh | sh`. Not run automatically here: piping a
    # remote script into a shell is the pattern this project exists to distrust, and it
    # wants /usr/local/bin, so it is the operator's call rather than ours.
    echo "    NOT INSTALLED. Install with brew or go, or review and run:"
    echo "    https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh"
fi

echo "==> shellcheck (shell linting, used by 'make lint')"
if need shellcheck; then
    echo "    found $(shellcheck --version 2>/dev/null | awk '/^version:/ {print $2}')"
elif need pipx; then
    # shellcheck-py ships the real shellcheck binary in a platform wheel, so this
    # needs no root and works the same on Linux and macOS.
    pipx install shellcheck-py
elif need pip3; then
    pip3 install --user shellcheck-py
elif need pacman; then
    echo "    install with: sudo pacman -S shellcheck"
elif need apt-get; then
    echo "    install with: sudo apt-get install shellcheck"
elif need brew; then
    brew install shellcheck
else
    echo "    NOT INSTALLED and no installer found. 'make lint' cannot check shell."
fi

echo "==> semgrep (static analysis, used by 'make sast')"
if need semgrep; then
    echo "    found $(semgrep --version 2>/dev/null)"
elif need pipx; then
    pipx install semgrep
elif need pip3; then
    # --user keeps it out of the system site-packages; pipx is still preferable.
    pip3 install --user semgrep
else
    echo "    NOT INSTALLED and no pipx or pip3 found. 'make sast' cannot run."
    echo "    See https://semgrep.dev/docs/getting-started/"
fi

echo "==> kani (formal verification, used by 'make verify')"
if cargo kani --version >/dev/null 2>&1; then
    echo "    already installed"
else
    cargo install --locked kani-verifier
    # kani needs a second step to fetch its solver backend.
    cargo kani setup
fi

echo "==> npm (required by 'make smoke-npm')"
if need npm; then
    echo "    found $(npm --version)"
else
    echo "    NOT FOUND. Install Node.js; 'make smoke-npm' cannot run without it."
fi

echo
echo "dev setup complete."
