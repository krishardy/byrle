# Install scripts are read from the artifact, not only from the metadata

- **Status:** Implemented 2026-09-21, the reader. `src/analysis.rs`. Read in the background
  since 2026-09-26: see [artifact-spool](artifact-spool.md).
- **Related:** [fetch-path-branching](fetch-path-branching.md),
  [artifact-analysis-store](artifact-analysis-store.md),
  [deferral-status-codes](deferral-status-codes.md),
  [policy-tier-resolution](policy-tier-resolution.md)

## Why the metadata is not enough

`install_scripts` decides on `PackageRecord::has_install_scripts`, which is the registry's
claim: npm's `hasInstallScript` on the abbreviated packument, its `scripts` keys on the full
one, and on PyPI whether the version offers only an sdist. The tarball is where the truth
is, and the two can disagree. A packument that omits `hasInstallScript` for a tarball whose
`package.json` runs `postinstall` is a package that installs code the metadata said nothing
about, and the version-level check passed it.

`analysis::Claim` names the three outcomes: `kept`, `undeclared` for an artifact that runs
what the metadata did not declare, and `overstated` for the reverse. The artifact adds to the
claim and never removes it: an `overstated` claim stands, because npm runs `node-gyp
rebuild` for a `binding.gyp` that `package.json` never names, and an sdist with no
`setup.py` still runs its PEP 517 backend. `overstated` is only
reported for a record from a full packument: the abbreviated one writes `hasInstallScript`
when it is true and omits it otherwise, so a record from one that claims nothing is not
claiming `false`.

## What is read

| Ecosystem | Read from | Counted as running on install |
|---|---|---|
| npm | `package.json` in the tarball | `preinstall`, `install`, `postinstall`, in the order npm runs them |
| PyPI | the sdist | a `setup.py` at the root of its directory, which pip runs to build it |

A `pyproject.toml` alone is not this. A PEP 517 build runs the backend the file names, which
is its own question and its own detector.

Verified against the published artifacts, `the_real_artifacts_declare_what_their_metadata_claims`,
which is ignored by default because it downloads them:

| Artifact | Metadata claims | The artifact declares |
|---|---|---|
| `bufferutil` 4.1.0, 163,631 bytes | `hasInstallScript: true` | `install: node-gyp-build` |
| `node-gyp-build` 4.8.4, 5,449 bytes | no `hasInstallScript` | a `test` script only |
| `six` 1.17.0 sdist, 34,031 bytes | an sdist, so pip builds it | `setup.py` |

## Cost tier

`Tier::Cheap`: one gzip stream and one JSON object. It runs in the background on the
spooled artifact, like every detector. A request waits for it with a 503 only when the
answer depends on it ([artifact-spool](artifact-spool.md)).

The reader is bounded. A member past `MAX_MEMBER_BYTES`, 4 MiB, is refused rather than read,
which is what a decompression bomb needs to be refused; a `package.json` is kilobytes. An
archive it cannot read is an error and never an answer of "runs nothing": not knowing is not
the same as knowing there is no script.

## The tar reader

`tar` 0.4.46, added for this: 234,226,833 downloads, 53,892,143 in 90 days, by the
maintainer of `flate2`, which the tree already has. It brings `filetime` and `libc`, both
for writing to disk, which this never does; `xattr` is optional and off. `make check-deps`
reports no vulnerable dependency after it.

Writing a tar reader by hand was the alternative. npm tarballs use GNU long-name and pax
headers for long paths, and a reader that missed one of those would report "runs nothing"
for a package that runs something, which is a false negative on a security check.
