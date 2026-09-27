# An artifact's analysis is kept under the digest of its bytes

- **Status:** Implemented 2026-09-22, the store. `src/analysis/store.rs`,
  `src/analysis/postgres.rs`, `migrations/0009_artifact_analysis.sql`. Read by the fetch
  path since 2026-09-26, `proxy::analysed`.
- **Related:** [fetch-path-branching](fetch-path-branching.md),
  [verified-artifact-cache](verified-artifact-cache.md),
  [install-scripts-from-the-artifact](install-scripts-from-the-artifact.md),
  [intel-schema-keys-and-types](intel-schema-keys-and-types.md)

## Decision

An artifact is analysed on the first request that fetches it. What the detectors found is
written under the artifact's content digest, and every later request for those bytes reads
the stored answer instead of analysing again.

[fetch-path-branching](fetch-path-branching.md) already branches on that key: a novel
artifact with a cheap detector is buffered, analysed and forwarded, and one analysed before
streams through. The saving a hit buys is the analysis, so this is where the analysis is.

## The key is the bytes, not the package

The digest names what was read. A registry that repoints a version at different bytes
produces a different key, so those bytes are analysed rather than answered from the row the
previous bytes wrote.

The digest comes from the metadata, so the branch is decided before the fetch. The bytes
are hashed on the way past either way, which is [no-metadata-cache](no-metadata-cache.md)
and [verified-artifact-cache](verified-artifact-cache.md): a hit never skips the hash.

An analysis is permanently valid for its bytes and for the reader that wrote it, not for
its bytes alone. Each row records `analysis::READER`, `install-scripts 1`, and is read back
only by that reader, so a reader that finds something an older one missed reads every
artifact again rather than keep the older answer. Rows written before the column existed
read as the empty reader and are analysed again
(`migrations/0011_artifact_analysis_reader.sql`). Attestation results carry their verifier
the same way ([provenance-check](provenance-check.md)).

## Two stores, one key

| Store | Answers | Lives |
|---|---|---|
| `crate::verified` | have these bytes been past and verified | in the process, dies with it |
| `analysis::store` | what was found in them | Postgres, or in the process with no database |

They are not merged. `verified` is what makes a digest mismatch a finding, and it has to
record a digest only after bytes matched it. The analysis is a separate fact with a
different lifetime.

## Reading is not the same as finding nothing

`Scripts` holds `Declared` or `Unreadable`, and `names()` answers `None` for the second.
An archive the reader could not open is stored as that, with the message the error carried,
so a later request reads "not known" rather than "runs nothing". `src/analysis.rs` states
the rule and a `bool` would lose it on the way into storage.

The column decides, not the absence of script rows: an artifact that declares no script and
one nobody could read both have zero rows in `artifact_install_script`, and
`artifact_analysis.unreadable` is what separates them.

## Schema

Sizes follow [intel-schema-keys-and-types](intel-schema-keys-and-types.md): a `BIGINT`
identity per table, sized `VARCHAR` for strings with a bound, `TEXT` for the two without.

| Column | Type | Why |
|---|---|---|
| `artifact_analysis.digest` | `VARCHAR(128)` | `sha512-` and 88 base64 characters, 95 in all |
| `artifact_analysis.ecosystem`, `.name`, `.version` | `VARCHAR(64)`, `(512)`, `(255)` | the same sizes the advisory tables use |
| `artifact_analysis.unreadable` | `TEXT` | the message comes from serde_json or the tar reader, which bound nothing |
| `artifact_install_script.name` | `VARCHAR(64)` | `preinstall`, `install`, `postinstall`, `setup.py` |
| `artifact_install_script.body` | `TEXT` | an npm script body, which `package.json` does not limit |

`body` is `NULL` for a PyPI sdist, where the reader reports a `setup.py` at the root of the
archive and there is no command to report.

A write replaces the analysis row and its scripts in one transaction. Two clients can ask
for one artifact at once and each analysed the same bytes, so a second write is not an
error. The scripts are replaced rather than merged: a name the later answer does not carry
is a script no reader found.

## How large a buffer the analysis needs

A novel artifact is written to the spool, because the reader needs the archive. What that
costs is measured rather than picked. The analysis ran inside the request when this was
measured; it runs in the background since 2026-09-26 ([artifact-spool](artifact-spool.md)).

`examples/artifact_sizes.py` walks dependency edges from a seed of roots and measures every
package it reaches, which is the population a proxy serves: a real install is mostly small
transitive utilities and a few large ones. npm sizes come from a one-byte range request
against each tarball's host; PyPI reports a file's size in its JSON API.

| | npm, 1,178 artifacts | PyPI, 3,858 artifacts |
|---|---|---|
| p50 | 9,078 `@aws-sdk/credential-provider-web-identity@3.972.77` | 562,551 `ml_dtypes@0.6.0` |
| p90 | 315,640 `lodash@4.18.1` | 10,161,518 `pandas@3.0.6` |
| p99 | 9,624,925 `@typescript/typescript-openbsd-x64@7.0.2` | 124,096,356 `torch@2.14.0` |
| max | 41,746,205 `next@16.3.5` | 572,881,074 `tensorflow@2.21.0` |
| over 64 MiB | 0 | 43 (1.11%) |

A wheel runs nothing, so only an npm tarball and a PyPI sdist are read. Splitting PyPI by
kind takes the 572 MB artifact out of the population that needs a buffer:

| PyPI kind | n | p50 | p99 | max | over 64 MiB |
|---|---|---|---|---|---|
| `bdist_wheel` | 3,659 | 754,690 | 124,113,865 | 572,881,074 `tensorflow@2.21.0` | 42 (1.15%) |
| `sdist` | 199 | 238,888 | 47,025,035 | 81,802,749 `opencv-python@5.0.0.93` | 1 (0.50%) |

The artifacts that are read top out at 81,802,749 bytes in this sample, and the median is
9,078 on npm and 238,888 on PyPI. Nothing bounds the tail: PyPI's own per-file limit is
100 MB and is raised on request, which `tensorflow` at 572 MB is.

## What the reader has to see is a prefix, not the artifact

`analysis::member` walks the tar sequentially and returns at the first `package.json`, so
it needs a prefix rather than the whole archive. `examples/manifest_offset.py` asks each
tarball's host for a prefix and reports the smallest one a complete `package.json` member
is readable from, over 78 npm packages:

| Prefix | Readable from this | At or below it |
|---|---|---|
| 16 KiB | 15 | 15 |
| 64 KiB | 15 | 30 |
| 256 KiB | 22 | 52 |
| 1 MiB | 16 | 68 |
| 4 MiB | 5 | 73 |

Five are not readable from 4 MiB: `next`, `selenium-webdriver`, `three`, `echarts`,
`aws-sdk`. `package/package.json` is not always the first member, so the prefix is bounded
by the artifact rather than by a small constant.

That sample is the latest version of 78 widely installed packages, chosen by hand. It is
the adversarial half of the distribution rather than a representative one, which the
closure walk above shows: its median artifact is 9,078 bytes.

## Where it is kept

The Postgres store shares the pool the advisory mirror already holds, because the analyses
are written on the request path and the advisories are read on it, and a second pool would
double the connections a proxy holds for one database.
`migrations/0009_artifact_analysis.sql`, `0010_artifact_attestation.sql` and
`0011_artifact_analysis_reader.sql` are applied by the same `PgIntel::migrate`.

[`crate::env::DATABASE_URL`] is optional, and a proxy started without one is the
configuration the smoke tests run. That proxy uses `InProcess`, a bounded map that dies
with the process: each artifact is analysed once more after a restart, and a second proxy
shares nothing with the first. Postgres is what makes an analysis outlive either.

## Tests

`tests/postgres.rs`, run by `make test-integration` against a container, 44 tests. Six are
this store: an absent row, script order, replacement on re-analysis, unreadable against
declares-nothing, a name with no command, and two digests of one package. The file was
`tests/intel_postgres.rs` and covers both repository traits now, so it is `tests/postgres.rs`.
