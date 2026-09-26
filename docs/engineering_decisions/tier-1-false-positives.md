# Tier 1 false-positive rates, measured

- **Status:** Measured 2026-09-26 with `examples/tier1_false_positives.py`. Part of the
  Stage 4 exit criterion: "all Tier 1 controls shipped with measured false-positive rates".
- **Related:** [provenance-check](provenance-check.md),
  [install-scripts-from-the-artifact](install-scripts-from-the-artifact.md),
  [quarantine-filter-metadata](quarantine-filter-metadata.md),
  [policy-diff-lockfiles](policy-diff-lockfiles.md)

## Method

Five dependency sets, resolved by npm and uv against the public registries into lockfiles.
For each set and each control, `waharoa policy diff` compares a policy that allows
everything with one that turns that control on. Every version that moves is a refusal of a
package in wide use and not reported as malicious, which is what a false positive means
here.

`policy diff` decides from metadata. It reads `install_scripts` from the registry's claim,
not from the tarball, and provenance as dropped or not, without verifying an attestation.
The provenance identity check was measured separately, by verifying every attested version
in `express eslint`: 17 verified and none changed identity ([provenance-check](provenance-check.md)).

## Results

| Set | Versions | `cooldown_days: 7` | `install_scripts: block` | `provenance: block` |
|---|---|---|---|---|
| npm: express eslint | 141 | 0 | 0 | 0 |
| npm: next react react-dom | 54 | 12 | 0 | 0 |
| npm: vite typescript vitest | 81 | 21, and 1 not read | 1 | 1, and 1 not read |
| pypi: requests flask django | 16 | 0 | 0 | 0 |
| pypi: numpy pandas scikit-learn matplotlib | 19 | 2 | 0 | 0 |
| **All** | **311** | **35 of 310 (11%)** | **1 of 311 (0.3%)** | **1 of 310 (0.3%)** |

### What each refused

| Control | Versions | Why |
|---|---|---|
| `cooldown_days: 7` | `next` 16.3.6 with `@next/env` and 8 `@next/swc-*` binaries, `baseline-browser-mapping` 2.11.26, `caniuse-lite` 1.0.30001812; `rolldown` 1.2.11 with 15 `@rolldown/binding-*`, `@oxc-project/types` 0.151.0, `vitest` 5.0.2 with `@vitest/mocker` and `@vitest/spy`, `magic-string` 1.4.2; `fonttools` 4.66.0, `pyparsing` 3.3.3 | published in the 7 days before 2026-09-26. 29 of the 35 are three releases, `next`, `rolldown` and `vitest`, with their platform and sibling packages. A date-dependent count: on another day it is a different list |
| `install_scripts: block` | `fsevents` 2.3.3 | declares `"install": "node-gyp rebuild"`. An optional dependency installed on macOS only |
| `provenance: block` | `why-is-node-running` 3.2.2 | published without an attestation on 2025-01-08, after 3.2.0 and 3.2.1 were published with one by the same maintainer |

## What a refusal costs

A cooldown refusal is a quarantine. On resolution the version is removed from the metadata
and the resolver takes an older one the range allows, so a fresh install succeeds on older
versions. A lockfile that pins the version fails on the pinned fetch until the quarantine
lifts, which the refusal names.

`fsevents` and `why-is-node-running` are `block` refusals. On resolution the resolver takes
another version when the range allows one. `why-is-node-running`'s 3.2.1 is attested and
satisfies `^3.2.0`. A lockfile pinning 3.2.2 fails until a `packages` exception releases it.

## Not read

`vite` 8.3.1's publish times could not be read: its full packument is 38,950,704 bytes, over
`WAHAROA_MAX_METADATA_BYTES`, then 32 MiB and sized at twice `typescript`'s 15.7 MB. The
proxy fetches the same document for the same checks, so for `vite` the cooldown and the
dropped-provenance check were unenforceable in the proxy too. The default was raised to 64
MiB the same day.
