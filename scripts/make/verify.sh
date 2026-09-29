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
# The §5.5 lattice and the monotonicity of parameterised rules are done, in
# `src/policy/strictness.rs`, and they are what kani is for: total functions over small
# closed domains, verified in milliseconds each.
#
# `src/intel.rs` adds four over symbolic `f64`. They cost about a second each and they
# earn it: writing `Score::in_range` as `!(cvss < 0.0 || cvss > 10.0)` instead of a range
# `contains` admits NaN, and all four proofs fail on that mutation. The one-line unit test
# for the same property passes, because a test has to name NaN to find it and a proof does
# not.
#
# A harness must not call through `ecosystem::of`. Kani compiles every function in
# `ecosystem::TABLE` once one is reachable, down to `Url::parse`, and kani 0.67.0 panics on
# `idna`'s `ZeroSlice<u16>`. Build a `PackageKey` with `PackageKey::for_proof`.
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
