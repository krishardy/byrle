#!/usr/bin/env bash
# Formal verification with kani.
#
# Exits nonzero when no harness exists, so "make verify is green" never means "nothing is
# proved".
#
# What is provable here is narrower than it looks. Kani reasons about allocation-free code
# over small domains; anything that allocates inside a symbolic loop is expensive and may
# not finish at all. `encoding_to_request` lowercases each token and did not complete on
# three arbitrary bytes in two minutes, while the allocation-free decision inside it
# verifies over five bytes in four seconds. `base_tag` hashes with SHA-256, which puts the
# `ETag` round-trip out of reach. Pick the piece that decides something and allocates
# nothing.
#
# Two of the harnesses do allocate, and cost what that predicts: `client_name` lowercases,
# and its two proofs are 53s and 34s of the run against milliseconds for the rest. They
# earn it. The whole per-client table rests on the client being the first token of the
# user-agent rather than a substring of it, and `pnpm/... npm/? ...` contains `npm/`.
#
# Every harness was checked against a mutation of the thing it claims, because a proof
# that passes vacuously is worse than none: it reads as coverage.
#
# Still owed, both Stage 2: the §5.5 lattice (allow < warn < quarantine < block) and the
# monotonicity of parameterised rules. Both are total functions over small closed
# domains, which is kani's sweet spot.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! cargo kani --version >/dev/null 2>&1; then
    echo "kani is not installed. Run 'make dev-setup', or see https://model-checking.github.io/kani/"
    exit 1
fi

if ! grep -rqs '#\[kani::proof\]' "$repo_root/src"; then
    echo "kani is installed, but no #[kani::proof] harnesses exist yet."
    echo "Owed: the §5.5 action lattice and per-parameter monotonicity."
    exit 1
fi

exec cargo kani --manifest-path "$repo_root/Cargo.toml" "$@"
