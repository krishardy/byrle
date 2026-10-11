# Console login crates: argon2, and jsonwebtoken on aws-lc-rs

- **Status:** Decided 2026-10-11, by the user. Not yet implemented. TODO Stage 4.9.
- **Related:** [admin-plan](../admin-plan.md) §8 Q4,
  [sqlx-0-8-and-rsa-advisory](sqlx-0-8-and-rsa-advisory.md)

## Decision

| Use | Crate |
|---|---|
| Password hashing | `argon2` 0.6.0, Argon2id, default features |
| OIDC ID token verification | `jsonwebtoken` 11.1.0, `default-features = false`, `features = ["aws_lc_rs"]` |

The rest of the OIDC flow is written here, over the `reqwest`, `sha2` and `base64` already
in the build:

- the provider's discovery document;
- the authorization request with `state`, `nonce` and PKCE;
- the code exchange;
- the provider's keys, fetched again when a token names a key not held;
- `iss`, `aud`, `exp` and `nonce` checked;
- the algorithms accepted are the ones configured, never the one a token's header names.

## Measured 2026-10-11

Each candidate added to a copy of this crate's `Cargo.lock`. "Builds `rsa`" is
`cargo tree -e normal --target all -i rsa`. MSRV is the highest `rust-version` among the
added crates; kani 0.67.0 compiles with rustc 1.93.

| Candidate | Crates added | Builds `rsa` | Highest MSRV | `cargo audit` |
|---|---|---|---|---|
| `argon2` 0.6.0 | 6 | no | 1.87 | clean |
| `password-auth` 1.1.0-rc.1 | 7 | no | 1.87 | clean |
| `bcrypt` 0.19.3 | 4 | no | 1.85 | clean |
| `openidconnect` 4.0.1, default features off | 55 | yes | 1.88 | clean |
| `openidconnect` 4.0.1, default features | 56, with `reqwest` 0.12.28 | yes | 1.88 | clean |
| `jsonwebtoken` 11.1.0, `rust_crypto` | 17 | yes | 1.88 | clean |
| `jsonwebtoken` 11.1.0, `aws_lc_rs` | 1 | no | 1.88 | clean |

`jsonwebtoken` on `aws_lc_rs` adds one crate because `aws-lc-rs` 1.18.1 is already built
through `rustls`. `argon2` and `jsonwebtoken` together passed `cargo check` against this
crate, with a probe that hashes and verifies a password and decodes a JWT against a JWK.

## Rejected

| Option | Why not |
|---|---|
| `bcrypt` | Truncates passwords at 72 bytes |
| `password-auth` | A release candidate; a wrapper over `argon2` |
| `openidconnect` | 55 crates, and builds `rsa`, which ends the RUSTSEC-2023-0071 exception in `make check-deps`. RSA verification with a public key is not what that advisory attacks, but the exception would then rest on review rather than on `cargo tree` |
| `jsonwebtoken` on `rust_crypto` | Builds `rsa`; 17 crates |

## What it costs

The OIDC flow is code this project owns, held at 100% coverage. A mistake in it is a
security defect. [admin-plan](../admin-plan.md) §5 lists the checks for the threat model.
