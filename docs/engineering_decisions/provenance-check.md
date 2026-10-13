# The provenance check refuses a version its attestations contradict

- **Status:** Implemented 2026-09-26 for npm and PyPI: `provenance` in `src/policy.rs`,
  `decide::Provenance`, `analysis::attestation`, `ecosystem::npm::attestation`,
  `ecosystem::pypi::attestation`, and `proxy::attested`.
- **Related:** [sigstore-verifier](sigstore-verifier.md),
  [pypi-provenance](pypi-provenance.md),
  [policy-schema-v1-frozen](policy-schema-v1-frozen.md),
  [artifact-spool](artifact-spool.md)

## Decision

`provenance: block`, the default, refuses a version when:

| Case | Example |
|---|---|
| An attestation it publishes fails verification | a forged or mismatched bundle |
| It publishes none, and a version before it did | a release published from a laptop after a stolen token, instead of from CI |
| Its attestation names a different repository or workflow file than a version before it | a fork, or a workflow added to the repository by an attacker |

The versions before it are the one published just before it, every version published in
`provenance_window_days`, 7 by default, before it, and the most recent attested version,
however old. Only the one just before was compared until 2026-09-26: a burst of malicious
releases then made each one after the first the predecessor of the next. Nx published 19 in
two hours, and the check caught 6; the window catches 17. eslint-config-prettier's burst
came 70.5 days after its last attested release, which no window of days reaches; the most
recent attested version catches all 6 ([incident-benchmark](incident-benchmark.md)).

Once a package has published provenance, every later version that publishes none is
refused, however long ago the last attested one was, until a `packages` exception releases
it. That is the answer after a stolen token, and the false positive when a maintainer stops
publishing from CI on purpose: `why-is-node-running` 3.2.2, the one version it refuses in
[tier-1-false-positives](tier-1-false-positives.md).

A version with no attestation after one with none passes. Plan §5 does not require
provenance: 81% of 138 packages publish none.

All three are `block`, and each reason names the case. `set: { provenance: allow }` in a
`packages` entry releases all three, with a reason and an expiry like any exception. A
maintainer who publishes one release by hand, or renames the release workflow, is the
expected false positive for each.

## Per ecosystem, and not

Where the attestations are served and how they are laid out is the adapter's:
`ecosystem::npm::attestation` takes npm's document to the SLSA provenance bundle, and
leaves npm's publish attestation, which a registry key signs and no build does.
`ecosystem::pypi::attestation` rebuilds PEP 740's provenance object as a Sigstore bundle:
its certificate and log entries become the verification material, and its statement and
signature a DSSE envelope. PyPI serves it at `/integrity/` on the index's host, and the
statement binds the file's sha256.

A PyPI version has several files, each with its own attestation. The requested file is
checked against its own. The version before it is read as a whole: it claims attestations
when any of its files does, and its identity is read from its attested sdist, or its first
attested file when it has no sdist. In 10 projects measured on 2026-09-26, attrs, requests,
sigstore, pydantic, cryptography, urllib3, idna, certifi, pip and setuptools, 1,634 versions
in all, no release attested only some of its files, and none dropped provenance after an
attested release.

A PEP 503 HTML index carries no upload time, so under one the version before is not known
and the check is reported unenforced.

Verification, identity, the stored result and the fact are shared:
`analysis::attestation::verify` takes a Sigstore bundle and the digest the metadata
published, and `artifact_attestation` keeps the result by digest. A registry that cannot be
reached writes nothing, so a missing row means not yet verified.

## Definitions

- **The versions before it**: the version with the latest publish time earlier than this
  version's, however old, every version published in the window before it, and the most
  recent attested version, however old. Only those claiming attestations are compared. On
  npm the times are in the full packument.
- **Identity**: the repository and workflow file an attestation names, without the ref.
  `github.com/python-attrs/attrs/.github/workflows/pypi-package.yml`, not
  `...@refs/tags/26.1.0`: every release is built from a new tag. Cut at the first
  `@refs/`, because a monorepo tags `@scope/pkg@1.2.3`.
- **Unknown**: nothing verified an attestation this version publishes, or the previous
  version is not known. The check is dropped by `enforce::unenforceable` and reported
  unenforced, as `cooldown_days` is without a publish date. A prior whose attestations do
  not verify is left out of the comparison, and when every prior's fails the answer is
  Unknown.

## Where it is decided

| Path | What it knows | Decides |
|---|---|---|
| Resolution, a packument filtered | the document only | dropped provenance, which needs nothing verified |
| Pinned fetch | the document, and verification results by digest | all three |
| `byrle explain`, `byrle policy diff` | the document only | dropped provenance |

A pinned fetch whose attestations, or whose predecessor's, nothing has verified starts the
analysis job and, under `provenance: block`, answers 503 until the retry finds the result
([artifact-spool](artifact-spool.md)). The job verifies each against the digest the
packument published, so the previous version's tarball is never fetched. A registry that
answers 5xx or 429, or cannot be reached, stores nothing and the next request tries again.
Under `provenance: block` the version answers 503 for as long as that lasts, with no bound
after which it is served unverified: fail closed, as a cold intel store does. Decided
2026-09-26, and pinned by `unverified_attestations_are_waited_for_only_when_they_can_refuse`.
A 404, a document that is not one, or a bundle that does not verify is stored as a failure.
A stored result is read back only by the verifier that wrote it, the `sigstore-verify`
version and a digest of its embedded root, so a failure a verifier upgrade fixes is not
kept.

An attestations document is fetched where the artifact would be: npm's registry through the
upstream, an origin the operator added directly, and any other origin not at all. One the
proxy will not fetch counts as an attestation that does not verify, naming the origin, so a
version cannot slip the check by pointing its attestations at a dead host.

The previous version's times come from the full packument, which every npm metadata request
asks for ([no-metadata-cache](no-metadata-cache.md)).

A version before it whose attestation does not verify is left out of the identity
comparison, and when every one of them fails the check is unknown for this version, not
refused: this version's own attestation may be sound.

## Identity changes across whole histories, measured 2026-10-13

`examples/provenance_identity_changes.py` reads every attested version of every package in
the five sets of [tier-1-false-positives](tier-1-false-positives.md), npm since 2023-04
and PyPI since 2024-10, identities unverified. It counts the versions each rule refuses:

- R0, this check: any version it is compared with names another identity
- R1: no version it is compared with names its identity
- R2: no attested version of the package published before it names its identity
- R3: no attested version published at least 7 days before it names its identity; with
  none that old, R0 over the attested versions of the 7 days before it

| Ecosystem | Packages attested | Attested versions compared | R0 | of R0, same owner | R1 | R2 | R3 | Packages R0 refuses in |
|---|---|---|---|---|---|---|---|---|
| npm | 98 | 30,261 | 2,339 | 2,327 | 291 | 71 | 382 | 35 |
| pypi | 24 | 263 | 2 | 2 | 2 | 2 | 2 | 2 |

R2 lets a burst through: once a new identity has published one version, every later one
from it passes. Two releases an hour apart from a new workflow, `x1` and `x2`, are refused
`x1` only. R3 refuses both until the identity is 7 days old. R0 refuses `x1` only too
when no version from the old identity falls in its window. R3's 382 are R2's 71 and the
versions after each within its first 7 days: 25 per rolldown binding, 12 each for react,
react-dom and scheduler, 5 per `@next` package.

R0's refusals are mostly release channels published from different workflows in one
repository: rolldown and its 11 bindings alternate a release workflow with a nightly canary
one, 205 refusals each. R2's 71 are the first version from each new identity:

| Change | Packages |
|---|---|
| a new workflow file in the same repository | rolldown and its bindings, next and `@next/*`, `@eslint/*` manual publish, baseline-browser-mapping, caniuse-lite |
| a new repository with the same owner | `@rolldown/pluginutils` 1.0.1, eslint-scope, eslint-visitor-keys, espree, matplotlib 3.10.8, scikit-learn 1.9.1 |
| a new owner | react, react-dom, scheduler: `facebook/react` to `react/react` |

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
