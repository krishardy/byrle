# Each ecosystem's versions order by its own rules; PEP 440 is hand-written

- **Status:** Implemented 2026-09-18. `VersionOrder` and `Ordered` in `src/intel/range.rs`,
  `src/ecosystem/pypi/version.rs`, `Registry::versions` in `src/ecosystem.rs`,
  `examples/pep440_conformance.rs`.
- **Related:** [osv-ranges-and-scores](osv-ranges-and-scores.md),
  [pypi-simple-index](pypi-simple-index.md), [adapter-interface](adapter-interface.md)

## Decision

Each registry row names how its versions order: `VersionOrder::SemVer` for npm and
`VersionOrder::Pep440` for PyPI. A range is read at load, and compared at lookup, by the
order of the ecosystem it is for. A listed version is stored in the order's normalised form
and matches a version equal to it in that order, so a listed PyPI `1.0` matches `1.0.0`.

PEP 440 is parsed and ordered by `pypi::version::Version`, written here: 344 lines, and 112
of tests. It follows the `packaging` library, which is what pip resolves with.

## Normalisation and order

| Written | Normalised | Why |
|---|---|---|
| `V1.0` | `1.0` | case and a leading `v` are ignored |
| `1.0-1` | `1.0.post1` | a number after `-` is a post-release |
| `1.0alpha2`, `1.0-a.2` | `1.0a2` | alternative spellings and separators |
| `1.0c1`, `1.0pre1` | `1.0rc1` | |
| `1.0.dev` | `1.0.dev0` | a missing number is 0 |
| `1.0+Ubuntu-1` | `1.0+ubuntu.1` | local segments are joined with `.` |

Order, lowest first, for one release: `1.0.dev0`, `1.0a1.dev0`, `1.0a1`, `1.0rc1`, `1.0`,
`1.0+local`, `1.0.post1.dev0`, `1.0.post1`. `1.0` and `1.0.0` are equal.

## Before

Every range and every requested version was read as SemVer, with osv.dev's npm padding.
Over OSV's `PyPI/all.zip`, fetched 2026-09-18 (34,417,496 bytes):

| Measure | Count |
|---|---|
| PyPI `ECOSYSTEM` ranges | 24,659 |
| refused as not SemVer | 1,645 (6.7%) |
| most common refused shapes | `N.N.NrcN` 620, `N.N.N.N` 403, `N.N.NaN` 279, `N.NaN` 238 |
| range events with a `-`, stored and ordered as SemVer pre-releases | 94 |
| listed versions | 1,288,475 |
| listed versions that are strict SemVer, which is what a lookup read | 979,836 (76.0%) |

`GHSA-4vc9-4xpq-77vm` has `fixed: 2.6.11-1`, a post-release of 2.6.11. As SemVer it is a
pre-release below 2.6.11, so 2.6.11 was reported unaffected.

No PyPI stream is loaded yet, so none of this reached a decision.

## Conformance

`cargo run --example pep440_conformance` compares this parser with `packaging` 23.2 over every
distinct version written in a PyPI `versions` list or `ECOSYSTEM` range event in the bundle
above:

```text
versions checked:   42989
read differently:   0
ordered, adjacent:  40936
ordered differently: 0
```

2,052 of the 42,989 are not PEP 440 versions, such as `-class.-jw.util.version.Version-`.
Both refuse them.

One difference is deliberate: `packaging` reads a number of any size, and this reads up to
`u64::MAX`. No version in the bundle is larger.

## Rejected

| Alternative | Why not |
|---|---|
| `pep440_rs`, from uv | A dependency added to a supply-chain tool, for 344 lines of rules that are fixed by PEP 440 and checkable against `packaging` |
| Read PyPI versions as SemVer after padding | The measurements above |
| Store each ecosystem's versions in one sortable column form | Postgres would order them, but each ecosystem needs its own encoding, and ranges are already compared in Rust |
