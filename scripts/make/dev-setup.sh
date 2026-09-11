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
