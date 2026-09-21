# An artifact's analysis is kept under the digest of its bytes

- **Status:** Implemented 2026-09-22, the store. `src/analysis/store.rs`,
  `src/analysis/postgres.rs`, `migrations/0009_artifact_analysis.sql`. Not yet read by the
  fetch path.
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

## Where it is kept

The Postgres store shares the pool the advisory mirror already holds, because the analyses
are written on the request path and the advisories are read on it, and a second pool would
double the connections a proxy holds for one database.
`migrations/0009_artifact_analysis.sql` is applied by the same `PgIntel::migrate`.

[`crate::env::DATABASE_URL`] is optional, and a proxy started without one is the
configuration the smoke tests run. That proxy uses `InProcess`, a bounded map that dies
with the process: each artifact is analysed once more after a restart, and a second proxy
shares nothing with the first. Postgres is what makes an analysis outlive either.

## Tests

`tests/postgres.rs`, run by `make test-integration` against a container, 44 tests. Six are
this store: an absent row, script order, replacement on re-analysis, unreadable against
declares-nothing, a name with no command, and two digests of one package. The file was
`tests/intel_postgres.rs` and covers both repository traits now, so it is `tests/postgres.rs`.
