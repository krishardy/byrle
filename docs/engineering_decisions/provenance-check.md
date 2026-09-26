# The provenance check refuses a version its attestations contradict

- **Status:** Implemented 2026-09-26 for npm: `provenance` in `src/policy.rs`,
  `decide::Provenance`, `analysis::attestation`, `ecosystem::npm::attestation`, and
  `proxy::attested`. PyPI is reported unenforced.
- **Related:** [sigstore-verifier](sigstore-verifier.md),
  [pypi-provenance](pypi-provenance.md),
  [policy-schema-v1-frozen](policy-schema-v1-frozen.md),
  [artifact-spool](artifact-spool.md)

## Decision

`provenance: block`, the default, refuses a version when:

| Case | Example |
|---|---|
| An attestation it publishes fails verification | a forged or mismatched bundle |
| It publishes none, and the version published before it did | a release published from a laptop after a stolen token, instead of from CI |
| Its attestation names a different repository or workflow file than the version published before it | a fork, or a workflow added to the repository by an attacker |

A version with no attestation after one with none passes. Plan §5 does not require
provenance: 81% of 138 packages publish none.

All three are `block`, and each reason names the case. `set: { provenance: allow }` in a
`packages` entry releases all three, with a reason and an expiry like any exception. A
maintainer who publishes one release by hand, or renames the release workflow, is the
expected false positive for each.

## Per ecosystem, and not

Where the attestations are served and how they are laid out is the adapter's:
`ecosystem::npm::attestation` takes npm's document to the SLSA provenance bundle, and
leaves npm's publish attestation, which a registry key signs and no build does. PyPI's PEP
740 document is shaped differently, binds a sha256 rather than a sha512, and a version has
several files, so which file came before is its own decision. PyPI is reported unenforced
until that is built.

Verification, identity, the stored result and the fact are shared:
`analysis::attestation::verify` takes a Sigstore bundle and the digest the metadata
published, and `artifact_attestation` keeps the result by digest. A registry that cannot be
reached writes nothing, so a missing row means not yet verified.

## Definitions

- **The version published before it**: the version with the latest publish time earlier
  than this version's. On npm the times are in the full packument.
- **Identity**: the repository and workflow file an attestation names, without the ref.
  `github.com/python-attrs/attrs/.github/workflows/pypi-package.yml`, not
  `...@refs/tags/26.1.0`: every release is built from a new tag. Cut at the first
  `@refs/`, because a monorepo tags `@scope/pkg@1.2.3`.
- **Unknown**: nothing verified an attestation this version publishes, or the previous
  version is not known. The check is dropped by `enforce::unenforceable` and reported
  unenforced, as `cooldown_days` is without a publish date.

## Where it is decided

| Path | What it knows | Decides |
|---|---|---|
| Resolution, a packument filtered | the document only | dropped provenance, which needs nothing verified |
| Pinned fetch | the document, and verification results by digest | all three |
| `waharoa explain` | the document only | dropped provenance |

A pinned fetch whose attestations, or whose predecessor's, nothing has verified starts the
analysis job and, under `provenance: block`, answers 503 until the retry finds the result
([artifact-spool](artifact-spool.md)). The job verifies each against the digest the
packument published, so the previous version's tarball is never fetched. A registry that
answers 5xx or 429, or cannot be reached, stores nothing and the next request tries again.
A 404, a document that is not one, or a bundle that does not verify is stored as a failure.
A stored result is read back only by the verifier that wrote it, the `sigstore-verify`
version and a digest of its embedded root, so a failure a verifier upgrade fixes is not
kept.

An attestations document is fetched where the artifact would be: npm's registry through the
upstream, an origin the operator added directly, and any other origin not at all. One the
proxy will not fetch counts as an attestation that does not verify, naming the origin, so a
version cannot slip the check by pointing its attestations at a dead host.

The previous version's times come from the full packument. `provenance: block` fetches it
as a cooldown does (`Policy::needs_publish_times`), so a policy with `cooldown_days: 0` still
pays for the full document unless it sets `provenance: allow`.

A predecessor whose attestation does not verify leaves the check unknown for the version
after it, not refused: that version's own attestation may be sound.

## Measured

Every version in `npm install express eslint`, 141 on 2026-09-26, against the version
published before it. Identity was read from each SLSA statement's `workflow`, unverified:

| Outcome | Versions |
|---|---|
| no attestation, previous had none | 124 |
| attested, previous had none | 6 |
| attested, same identity as previous | 11 |
| no attestation, previous had one | 0 |
| attested, different identity | 0 |

`block` refuses none of them. The 17 attested versions were verified again the same day by
the code that decides, `ecosystem::npm::attestation::provenance_bundle` then
`analysis::attestation::verify` against each packument's integrity: all 17 verified, and
each of the 11 with an attested predecessor names the same identity as it.
