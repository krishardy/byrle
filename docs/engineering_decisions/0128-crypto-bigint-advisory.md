# RUSTSEC-2026-0387 accepted while `crypto-bigint` 0.5.5 is built only for `pgp`

- **Number:** 0128
- **Status:** Decided by the user 2026-11-03. Implemented 2026-11-03: `accept_under_pgp`
  and `built_under` in `scripts/make/check-deps.sh`.
- **Related:** [sqlx-0-8-and-rsa-advisory](0028-sqlx-0-8-and-rsa-advisory.md),
  [maven-signatures](0113-maven-signatures.md)

## Decision

`make check-deps` passes `--ignore RUSTSEC-2026-0387` to cargo-audit while every crate
byrle depends on directly that `crypto-bigint` 0.5.5 is built under is `pgp`. Any other
route fails the check.

The same rule now applies to RUSTSEC-2023-0071 and `rsa`.

## Why

RUSTSEC-2026-0387 reports timing differences in `crypto-bigint` operations meant to run in
constant time. The fix is in 0.7.6. `pgp` 0.21.0, the newest release, reaches 0.5.5
through `elliptic-curve` 0.13.8 and `cx448` 0.1.1:

| Route | To `crypto-bigint` 0.5.5 |
|---|---|
| `pgp` → `cx448` | direct |
| `pgp` → `elliptic-curve` | direct |
| `pgp` → `k256`, `p256`, `p384`, `p521` → `ecdsa` → `elliptic-curve` | through `elliptic-curve` |

A timing difference leaks a secret operand. byrle calls `pgp` only to verify a Maven
signature with a public key, the public signature and the public file. It holds no
private key and decrypts nothing.

## Evidence, 2026-11-03

| Command | Result |
|---|---|
| `make check-deps` | `ok: crypto-bigint@0.5.5 is built for pgp, which only verifies`, then `OK: no vulnerable dependencies.` |
| the same, with the crate changed to `tokio` | `tokio is built for axum,reqwest,sqlx,tokio, not pgp alone.`, exit 2 |

## Rejected

| Option | Why not |
|---|---|
| leave `make check-deps` failing | no release of `pgp` takes `crypto-bigint` 0.7 |
| ignore the advisory with no premise | a new dependent that signs or decrypts would be covered quietly |
| check only `crypto-bigint`'s direct dependents, as the `rsa` check did | they are `cx448` and `elliptic-curve`, not `pgp`, so the check cannot name the caller |

## Cost

When `pgp` moves to `crypto-bigint` 0.7.6 or later, the ignore covers nothing and can go.
