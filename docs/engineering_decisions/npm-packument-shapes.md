# What an npm packument holds, measured

- **Status:** Implemented. `src/ecosystem/npm/wire.rs`, `src/ecosystem/npm/normalize.rs`.
- **Related:** [adapter-interface](adapter-interface.md),
  [config-format-yaml-serde-saphyr](config-format-yaml-serde-saphyr.md),
  [artifact-digest-verification](artifact-digest-verification.md)

## Decision

The npm wire types ignore keys they do not model. npm adds fields to packuments without
notice, and a registry doing that must never break an install passing through the proxy.
The policy loader takes the opposite position and refuses unknown keys, because a typo in
an operator's policy must fail loudly rather than disable a rule.

A version that cannot be normalised is kept in `PackageMetadata::skipped` rather than
dropped. A version that vanishes between the registry and the policy engine is a version
nothing gates.

Each version is read on its own, from its raw JSON, so a field of the wrong type skips that
version and not the document. Until 2026-10-01 the whole map was read at once, and one bad
`scripts`, `maintainers` or `_npmUser` anywhere made the document unreadable, so the proxy
forwarded it unfiltered. A skipped version's tarball is refused as not listed, 403, so a
malformed `scripts` cannot pass `install_scripts: block` as "no install scripts". Decided
with the user. At package level, `time` and `dist-tags` keep only their string entries, and a
malformed `maintainers` reads as absent.

Reading each version on its own costs about a quarter more: `typescript`'s full packument,
15.7 MB and 3,839 versions, normalises in 27.9 ms against 22.5 ms, `next`'s 31.3 MB in 63.2
ms against 50.0 ms. The full packuments of the 613 npm packages in the
[source-diff](source-diff.md) lockfiles, 92,722 versions, normalise with none skipped.

## What was measured

24,852 versions across 47 packages, each fetched as both the abbreviated and the full
document, September 2026. The set mixes current packages with ones published in 2011 and
2012, where npm's metadata stops being uniform.

| Field | Found | So |
|---|---|---|
| `dist.tarball` | on every version | a version without one is a document defect and is skipped |
| `dist.shasum` | on every version | |
| `dist.integrity` | missing on 2, both from 2012: `event-stream@0.9.1`, `vue@0.8.6` | `Artifact::integrity` is an `Option` |
| `versions` key against the version's own `version` | never disagreed | the key is the authority, because npm resolves a range against it |
| `hasInstallScript` | `true` on 901 versions, absent on the rest, never `false` | absence reads as no install script |
| `repository` | an object 24,477 times, a string 5 times (`bower@1.8.11`–`1.8.14`, `rimraf@1.0.0`) | its deserializer takes both |
| install scripts, abbreviated against full | agreed on all 24,852 pairs | |
| `deprecated` | `false` in the full documents of `react` (1,079 versions), `react-dom` and `scheduler`, 2026-09-30 | read as absent. As a string field, it made each whole document unreadable |
| `repository` | `{}`, with no `url`, in `qs` | read as absent, as any `repository` or `gitHead` of another shape is. It made the document unreadable |

`real_packuments_normalise_without_skipping_anything` checks this against a corpus on disk.

| Field | Read as |
|---|---|
| `time` | full document only, keyed by version, plus `created` and `modified`, which are not versions |
| `maintainers`, `repository` at package level | a fallback: the per-version copy is what was true at publish time, so it is used when present |
| `deprecated` | the message `npm deprecate` set, in both documents. `npm deprecate pkg@range ""` clears it, and npm then omits the key |

What each document carries, as `record::PackageRecord` reads it:

| Field | Abbreviated | Full |
|---|---|---|
| name, version, `dist.*` | yes | yes |
| `hasInstallScript` | yes | no, read `scripts` |
| `dist.attestations`, `dist.signatures` | yes | yes |
| publish time (`time`) | no | yes |
| `maintainers`, `repository`, `_npmUser`, `gitHead` | no | yes |
| `scripts` bodies | no | yes |

`record::DocumentDetail` says which document a record came from, so a `None` reads as "not
fetched" from the abbreviated one and "the registry does not publish it" from the full one.
A missing publish time must not read as old enough. `repository.url` is kept verbatim,
`git+https://` included, and `directory` holds a monorepo package's subdirectory, such as
`packages/babel-traverse` for `@babel/traverse`.

Publish times are in the full document's `time` map and nowhere else. The registry serves no
projection of it: `?fields=time` returns the whole document and `/<package>/time` is a 404,
both checked against registry.npmjs.org. `npm::parse_publish_times` reads only the map,
without building 3,823 records for typescript to read one field each. `created` and
`modified` share the map and are not versions; npm's semver parsing refuses a version by
either name.

`npm deprecate pkg@range ""` clears a deprecation and npm then omits the key: of 566
deprecated versions across ten packages on 2026-09-20, none carried an empty message. An
empty one is read as not deprecated. The install scripts are `preinstall`, `install` and
`postinstall`; `prepare` and `prepublish` run when building from git or publishing, not when
installing a registry tarball. A maintainer entry with no name keeps an empty name rather
than being dropped, since the number of maintainers is itself a signal.

`real_packuments_normalise_without_skipping_anything` runs over a corpus on disk and is
ignored by default. Fill one directory per document kind and name them in
`BYRLE_NPM_CORPUS` (abbreviated) and `BYRLE_NPM_CORPUS_FULL`:

```text
curl -H "Accept: application/vnd.npm.install-v1+json" \
    https://registry.npmjs.org/typescript > abbrev/typescript.json
curl -H "Accept: application/json" \
    https://registry.npmjs.org/typescript > full/typescript.json
cargo test --lib -- --ignored --nocapture
```

It fails on any skipped version, checks every tarball URL classifies to the package the
document names and is on a reachable origin, and checks that rewriting every URL to the
origin it already names gives back the original bytes.

`repository`'s deserializer is written by hand rather than `#[serde(untagged)]`. `untagged`
buffers into an intermediate value and tries each variant, which discards
`deny_unknown_fields` on the variants and turns a field error into "no variant matched". It
would also allocate once per version.
