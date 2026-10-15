# Install scripts are read from the artifact, not only from the metadata

- **Number:** 0062
- **Status:** Implemented 2026-09-21, the reader. `src/analysis.rs`. Read in the background
  since 2026-09-26: see [artifact-spool](0064-artifact-spool.md).
- **Related:** [fetch-path-branching](0003-fetch-path-branching.md),
  [artifact-analysis-store](0063-artifact-analysis-store.md),
  [deferral-status-codes](0021-deferral-status-codes.md),
  [policy-tier-resolution](0023-policy-tier-resolution.md)

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
| npm | `<top>/package.json`, the manifest directly under the tarball's top directory, as npm unpacks it | `preinstall`, `install`, `postinstall`, in the order npm runs them |
| PyPI | the sdist | a `setup.py` at the root of its directory, which pip runs to build it |
| cargo | `<top>/Cargo.toml` in the `.crate` | the build script `package.build` names, or `<top>/build.rs` when it names none, and `[lib] proc-macro = true`. `build = false` is none |

Until 2026-09-27 the npm reader took the first member whose path ended in `package.json`.
`package/node_modules/x/package.json`, a bundled dependency's manifest listed before the
package's own, then stood in for it, and so did `package/notpackage.json`: a tarball could
hide its own install script behind either. Found by the golden test that holds
`analysis::READER` to the readers' answers, and fixed as `install-scripts 2`.

A `pyproject.toml` alone is not this. A PEP 517 build runs the backend the file names, which
is its own question and its own detector.

Verified against the published artifacts, `the_real_artifacts_declare_what_their_metadata_claims`,
which is ignored by default because it downloads them:

| Artifact | Metadata claims | The artifact declares |
|---|---|---|
| `bufferutil` 4.1.0, 163,631 bytes | `hasInstallScript: true` | `install: node-gyp-build` |
| `node-gyp-build` 4.8.4, 5,449 bytes | no `hasInstallScript` | a `test` script only |
| `six` 1.17.0 sdist, 34,031 bytes | an sdist, so pip builds it | `setup.py` |

## cargo, added 2026-10-14

Asked for by the user ([cargo-plan](../cargo-plan.md) Q4): a build script and a proc-macro
are what `install_scripts` refuses, as a `postinstall` is. A crates.io index line says
neither, so a cargo record claims nothing, and every build script is `undeclared`. The
check is decided only from the `.crate`, read when it is downloaded. Without Postgres the
analyses are kept in memory, and the `.crate` is still read.

Read from the published `.crate` files, `real_crates_declare_their_build_scripts_and_proc_macros`:

| Crate | `Cargo.toml` | Read as |
|---|---|---|
| `serde` 1.0.229 | `build = "build.rs"` | `build.rs` |
| `serde_derive` 1.0.229 | `build = false`, `proc-macro = true` | `proc-macro` |
| `itoa` 1.0.18 | `build = false` | nothing |
| `libc` 0.2.0 | no `build`, no `build.rs` | nothing |

Until the `.crate` is read, `install_scripts` is `not analyzed`, asked for by the user
2026-10-14: `byrle explain pkg:cargo/serde@1.0.229` prints `install_scripts  not analyzed
crates.io's index does not say; the .crate is read when it is downloaded`, and the audit
line names it under `not_analyzed`. Before, it read `pass`. Like an unenforced check, it is
dropped from the verdict; a download is decided once its `.crate` is read, which records the
answer in `PackageRecord::install_scripts`. `Facts::install_scripts_analyzed` carries it to
`audit verify`; a line without it reads as analyzed.

`rustls` 0.23.45 has a build script too: under the default `block`, `make smoke-cargo`
saw it refused once read. The read took 79 ms, and the download was answered after one
1-second deferral. `analysis::READER` is `install-scripts 3`.

## Cost

One gzip stream and one JSON object: 0.4ms for `bufferutil` 4.1.0, 163,631 bytes. It runs
in the background on the spooled artifact, like every detector. A request waits for it with
a 503 only when the answer depends on it ([artifact-spool](0064-artifact-spool.md)).

`analysis::Tier`, which labelled this reader cheap, was deleted on 2026-09-26. It decided
whether a request waited for a detector, and since `c37f16c` none does.

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
