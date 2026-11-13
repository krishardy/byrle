# sqlx held at 0.8 until kani 0.68.0, and RUSTSEC-2023-0071 accepted while `rsa` is not built

- **Number:** 0028
- **Status:** Implemented. Amended 2026-10-17: `rsa` is built for `pgp`. Amended 2026-11-13:
  sqlx is on 0.9, with kani 0.68.0
- **Where:** `Cargo.toml` (sqlx `0.9`), `scripts/make/lib/sqlx-cli.sh` (sqlx-cli `0.9`),
  `scripts/make/dev-setup.sh` (kani `0.68.0`),
  `scripts/make/check-deps.sh` (the ignore and its premise check)
- **Related:** [storage-sqlx-postgres](0025-storage-sqlx-postgres.md)

## Decision

sqlx is held at 0.8. `Cargo.lock` has 0.8.6. `dev-setup.sh` installs sqlx-cli 0.8 and replaces
an installed CLI of another minor, so `make sqlx-prepare` runs the version the build uses.

`make check-deps` passes `--ignore RUSTSEC-2023-0071` to cargo-audit only while `cargo tree
-e normal --target all` finds no `rsa` crate. If it finds one, `make check-deps` fails.

## sqlx 0.8 rather than 0.9

0.9.0 is the current release. It was tried on 2026-09-13 and reverted. What changed in 0.9:

| Change in 0.9 | Effect here | State |
|---|---|---|
| `rust-version = 1.94.0` on sqlx, sqlx-core, sqlx-macros, sqlx-macros-core, sqlx-postgres | `make verify` fails. kani 0.67.0 compiles with its bundled `rustc 1.93.0-nightly (53732d5e0 2025-11-20)` and cargo refuses the build | Blocks the upgrade |
| `query` and `raw_sql` take `SqlSafeStr`: a `&'static str` or `AssertSqlSafe(..)` | `tests/postgres.rs` did not compile | Prepared in part. `insert` takes `&'static str`. `fresh` asserts schema names are `[a-z0-9_]`. Its four `format!` calls still need `AssertSqlSafe` |
| Connecting to a server that serves no TLS | Fails unless the URL carries `sslmode=disable` | Both container scripts pass it |
| `.sqlx/` query files | Each column gains an `origin` | Regenerate |
| `rsa` | No longer in `Cargo.lock` | The RUSTSEC-2023-0071 block can go |

With 0.9 and the fixes above, 9 of 9 integration tests passed and `make sqlx-prepare
ARGS=--check` still failed on a changed query.

`make check-deps` lists sqlx 0.8.6 against 0.9.0 as outdated. It fails on that only with
`CHECK_DEPS_STRICT=1`.

### Ways around kani, rejected

| Option | Why not |
|---|---|
| Upgrade Rust | `kani-compiler` links `librustc_driver` from its bundled nightly. The project's stable toolchain (1.98.1) is not what `make verify` compiles with. 0.67.0 is the newest kani on crates.io |
| Build kani from its `main` branch | `main` pins `nightly-2026-08-21`, which is new enough. Rejected: it tracks an unreleased kani |
| sqlx optional behind a default feature, `make verify` with `--no-default-features` | Worked: 30 harnesses verified. Rejected: sqlx is not optional |

### kani 0.68.0

kani 0.68.0 bundles `nightly-2026-08-21`, which is new enough for sqlx 0.9. It does not
compile this crate: on 2026-09-25 `make verify` failed at `HEAD` `cb53416` with an internal
compiler error, `kani-compiler/src/intrinsics.rs:243:17: assertion failed:
matches!(output.kind(), TyKind :: RigidTy(RigidTy::Int(IntTy::I32)))`. `dev-setup.sh`
installs 0.67.0 until a release compiles it.

### Lifting the hold

When a kani release bundles rustc 1.94 or later:

1. Set `kani_version` in `dev-setup.sh` and reinstall kani through `make dev-setup`.
2. Set sqlx to `0.9` in `Cargo.toml` and `sqlx_minor="0.9"` in `dev-setup.sh`, then run
   `make dev-setup`.
3. Wrap the four `format!` calls in `fresh` in `AssertSqlSafe`.
4. If `rsa` has left `Cargo.lock`, remove the RUSTSEC-2023-0071 block from `check-deps.sh`.
5. `make sqlx-prepare`, then `make verify`, `make test-integration`, `make sqlx-prepare
   ARGS=--check`, `make check-deps`.

### Amended 2026-11-13: hold lifted with kani 0.68.0

kani 0.68.0 is still the newest release. On 2026-11-13 it compiled this crate:
`Complete - 30 successfully verified harnesses, 0 failures, 30 total.` The panic at
`intrinsics.rs:243` did not recur. Rust stable is 1.100.0 and the repository pins no toolchain;
`make verify` compiles with kani's bundled `nightly-2026-08-21`.

| Step | State |
|---|---|
| 1. `kani_version="0.68.0"` | Done |
| 2. sqlx `0.9`, `byrle_sqlx_minor="0.9"` | Done. sqlx-cli 0.9.0 installed |
| 3. `AssertSqlSafe` in `tests/postgres.rs` | Done: the four in `fresh` and `connect`, the `raw_sql` in the range check, and the `UPDATE artifact_source` |
| 3a. `AssertSqlSafe` in `src/intel/postgres.rs` | Done: the two statements in `write_advisories`, which format in `load::ADVISORY_COLUMNS` |
| 4. Remove the RUSTSEC-2023-0071 block | Not done. `rsa` is built for `pgp` (amended 2026-10-17) |
| 5. `make sqlx-prepare`, `make test-integration` | Done. `make sqlx-prepare` added an `origin` to each column in 33 of 63 `.sqlx/` files. `make test-integration`: 61 passed, 0 failed. `make sqlx-prepare ARGS=--check` passes |

`make lint`, `make verify` and `make test` pass. `libsqlite3-sys` 0.30.1 stays in `Cargo.lock`
under `sqlx-sqlite` 0.9.0, which is not built, and RUSTSEC-2026-0459 still fails `make check-deps`.

## RUSTSEC-2023-0071

The advisory is against `rsa`: a timing side channel (the Marvin Attack) that can recover an
RSA private key. `rsa` reaches `Cargo.lock` through `sqlx-mysql`. byrle enables only the
`postgres` feature, so neither `sqlx-mysql` nor `rsa` is compiled. cargo-audit reads
`Cargo.lock`, not the build, so it reports `rsa` anyway.

Evidence, 2026-09-13:

| Command | Result |
|---|---|
| `cargo tree -e normal --target all \| grep 'rsa v'` | no output |
| `cargo tree -i rsa` | `warning: nothing to print.` |
| `Cargo.lock` entries listing `rsa` as a dependency | `sqlx-mysql` only |

The premise check was mutation-tested. With its pattern changed from `rsa v` to `sqlx v`, a
crate that is built, `make check-deps` printed `rsa IS in the build. The RUSTSEC-2023-0071
exception no longer holds.` and exited 2.

### Amended 2026-10-17: `rsa` is built, for `pgp` alone

`pgp` 0.21.0, which verifies Maven's PGP signatures
([maven-signatures](0113-maven-signatures.md)), depends on `rsa` 0.9.10, and RSA cannot be
left out of it: most signatures on Central are RSA. Decided by the user 2026-10-17: the
advisory is accepted while `rsa` is built only for `pgp`. The advisory's leak is in RSA's
private-key operations, decryption and signing; byrle holds no private key and calls `pgp`
only to verify a signature with a public key.

`make check-deps` passes the ignore while `cargo tree -e normal --target all -i rsa
--depth 1` names `pgp` as `rsa`'s only dependent, and fails when anything else depends on
it. With the check changed to expect a dependent named `pgpx`, `make check-deps` printed
`rsa is built for pgp, not pgp alone.` and exited 2.

Amended 2026-11-03 by [crypto-bigint-advisory](0128-crypto-bigint-advisory.md): the check
reads every route from byrle to `rsa` and passes while `pgp` is the only crate byrle depends
on directly among them.

`pgp` adds 87 crates to the build. With `pgp`, their 88 licences are 63 MIT and Apache-2.0,
either, 17 MIT, 4 BSD-3-Clause, 3 MIT or Apache-2.0 or a BSD, and 1 Zlib.

## Alternatives considered

**Ignore the advisory unconditionally**, in `audit.toml` or as a bare `--ignore`. Rejected:
enabling a MySQL feature would put `rsa` in the binary and the ignore would still hide it.

**Fail `make check-deps` until the advisory clears.** Rejected: it reports a crate that is
not in the binary. A gate that is red for that reason gets ignored for every reason.
