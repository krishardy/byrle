#!/usr/bin/env bash
# Formal verification with kani.
#
# There are no proof harnesses yet. Rather than pass vacuously, this reports that
# fact and exits nonzero, so "make verify is green" never means "nothing is proved".
# The §5.5 lattice (allow < warn < quarantine < block) and the monotonicity of
# parameterised rules are the obvious first proof obligations: they are total
# functions over small closed domains, which is exactly kani's sweet spot.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! cargo kani --version >/dev/null 2>&1; then
    echo "kani is not installed. Run 'make dev-setup', or see https://model-checking.github.io/kani/"
    exit 1
fi

if ! grep -rqs '#\[kani::proof\]' "$repo_root/src"; then
    echo "kani is installed, but no #[kani::proof] harnesses exist yet."
    echo "First obligations: the §5.5 action lattice and per-parameter monotonicity."
    exit 1
fi

exec cargo kani --manifest-path "$repo_root/Cargo.toml" "$@"
