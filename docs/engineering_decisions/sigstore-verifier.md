# Attestations are verified with `sigstore-verify`, not `sigstore`

- **Status:** Decided 2026-09-26 at 0.13.0. Upgraded 2026-10-13 to `sigstore-verify =
  "=0.14.0"` with default features off: `src/analysis/attestation.rs` verifies,
  `src/ecosystem/npm/attestation.rs` reads npm's document. 0.14.0 returns the identity as
  a `SubjectAltName`, read with `as_str()`. `VerificationPolicy::any_identity()` still
  checks the certificate chain, its SCT and the transparency log. The verifier id changes
  with the version, so stored attestation results are verified again.
- **Related:** [pypi-provenance](pypi-provenance.md),
  [sqlx-0-8-and-rsa-advisory](sqlx-0-8-and-rsa-advisory.md),
  [artifact-spool](artifact-spool.md)

## What was asked

`TODO.md` Stage 4: validate `sigstore-rs` before verifying provenance, with a cosign
shell-out as the fallback. Plan §5 keeps provenance recorded rather than required, so the
work is verifying the attestations a package does publish. That needs a verifier that
accepts what npm and PyPI serve.

## Two crates, both from the Sigstore project

| | `sigstore` 0.14.0 | `sigstore-verify` 0.13.0 |
|---|---|---|
| Repository | `sigstore/sigstore-rs` | `sigstore/sigstore-rust` |
| Created | 2021-10-04 | 2025-11-20 |
| Releases | 8 since 0.8.0; 0.14.0 on 2026-05-22 | 19; 0.12.0 and 0.13.0 both on 2026-09-23 |
| Open issues, stars | 75, 242 | 14, 27 |
| Contributors | 40 | 10; `wolfv` wrote 205 of 272 commits |
| MSRV | none declared | 1.86 |
| Builds on kani's `nightly-2025-11-21` (rustc 1.93) | yes | yes |
| Crates added to this tree | 97 (227 to 324) | 30 (227 to 257) |
| Compiles `rsa` | yes, through `openidconnect`, which `verify` requires via `fulcio` and `oauth`. `make check-deps` would fail on RUSTSEC-2023-0071 | no |
| Merkle inclusion proof and SET | not checked: `bundle/verify/verifier.rs` has both as `TODO(tnytown) ... sigstore-rs#285` | checked, with the checkpoint signature (`verify_impl/tlog.rs`) |
| Trusted root | `ManualTrustRoot`, or TUF behind `sigstore-trust-root` | embedded `SIGSTORE_PRODUCTION_TRUSTED_ROOT`; TUF behind `tuf` |

## Against real attestations

Verified offline on 2026-09-26, each against the tarball or sdist it names.
The example programs lived in the scratch tree and are not kept.

| Attestation | `sigstore` 0.14.0 | `sigstore-verify` 0.13.0 |
|---|---|---|
| npm publish, `sigstore@5.0.0`, signed with npm's registry key | `Bundle(VerificationMaterialContentUnsupported)` | verified with the key from `registry.npmjs.org/-/npm/v1/keys`, tlog verified |
| npm SLSA provenance v1, `sigstore@5.0.0`, sha512 subject | `Bundle(DssePayloadDecode)`: it reads only a sha256 subject | verified, identity `https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main`, tlog verified |
| PEP 740, `attrs-26.1.0.tar.gz`, sha256 subject | `Signature(Transparency)` on the `dsse` tlog entry; not isolated from the bundle conversion below | verified, identity `https://github.com/python-attrs/attrs/.github/workflows/pypi-package.yml@refs/tags/26.1.0`, tlog verified |
| The SLSA bundle against the tarball with one byte flipped | not reached | `artifact hash does not match any subject in attestation` |

PyPI serves a PEP 740 attestation rather than a Sigstore bundle. Both runs converted it the
same way: `verification_material.certificate` and `transparency_entries` into
`verificationMaterial`, and `envelope.statement` and `envelope.signature` into a
`dsseEnvelope` with payload type `application/vnd.in-toto+json`.

## Decision

Use `sigstore-verify`, default features off and `rustls` on, pinned to an exact version.
Do not use `sigstore`: it verifies none of the three attestations, skips the log's
inclusion proof and SET, and compiles `rsa`.

A cosign shell-out is not needed. It would put a Go binary and a process per artifact on
the analysis path to do what a 30-crate dependency does in-process.

## Risks carried

- `sigstore-verify` is ten months old, and one author wrote 205 of its 272 commits.
  Two minor versions shipped on one day, so the API moves. The pin is exact and an upgrade
  is a reviewed change.
- The embedded trusted root changes only with a crate upgrade. Sigstore rotating a key
  before a release carries it would fail every verification until the upgrade. A stored
  result names the verifier that wrote it, and another verifier does not read it, so the
  failures end with the upgrade rather than being kept. TUF
  (`tuf` feature) would follow rotations at runtime, and this sandbox's egress proxy
  refuses `tuf-repo-cdn.sigstore.dev`, so it was not tested.
- npm's publish attestation is signed with a registry key served at
  `/-/npm/v1/keys`, not by the Sigstore root. That key list is a second trust input.
