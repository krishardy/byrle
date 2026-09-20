# What CI gates, and what it does not

- **Status:** Implemented. `.github/workflows/ci.yml`.
- **Related:** [storage-sqlx-postgres](storage-sqlx-postgres.md),
  [sqlx-0-8-and-rsa-advisory](sqlx-0-8-and-rsa-advisory.md)

## Decision

Three jobs, each one `make` target, on push to `main` and on every pull request:

| Job | Target | Gates |
|---|---|---|
| `lint` | `make lint` | rustfmt, clippy with warnings as errors, shellcheck, python syntax |
| `test` | `make test` | the unit tests |
| `sqlx` | `make sqlx-prepare ARGS=--check` | `.sqlx/` against the migrations |

A job runs a `make` target and nothing else, so what CI checks is what a contributor runs.
The logic stays in `scripts/make/`, per CLAUDE.md.

`make sqlx-prepare` starts its own Postgres container through `scripts/make/lib/postgres.sh`,
so the workflow has no `services:` block. The runner has Docker, and the script a contributor
runs is the one that runs here.

`sqlx-cli` is installed by `waharoa_install_sqlx_cli` in `scripts/make/lib/sqlx-cli.sh`, which
`scripts/make/dev-setup.sh` also calls. The pin was in `dev-setup.sh` alone; CI needed it too,
and a second copy could drift from the first. It has to track the `sqlx` version in
`Cargo.toml`: `make sqlx-prepare` writes the offline cache the build reads, and a CLI of
another minor writes a cache the build does not accept.

The toolchain is `stable`. There is no `rust-toolchain.toml` and no `rust-version` in
`Cargo.toml`, so a contributor runs whatever stable rustup gives them; CI checking an older
toolchain would pass on lints they cannot see. It is written out rather than left to the
runner's default so the choice is visible.

## What is not gated

| Target | Why not |
|---|---|
| `make coverage` | needs `cargo-llvm-cov`, and the 95% floor is enforced by review today |
| `make verify` | needs a kani install, which bundles its own rustc, and roughly 10 GB of memory: `kani-compiler` reached 9,526 MiB RSS on 2026-09-20 and `earlyoom` sent it SIGTERM at 9.9% memory free. A kill reads as `(signal: 15, SIGTERM)` with `Found 0 compilation errors`, which is a machine that ran out of room, not a proof that failed |
| `make test-integration` | a second Postgres container for 9 tests the `sqlx` job's schema already proves loadable |
| `make mutants` | minutes per changed file, and it measures a diff rather than a state |
| `make sast` | needs semgrep and trufflehog |

These are the expensive installs, not the unimportant checks. `make verify` in particular
holds 30 kani harnesses and exits nonzero when none exist, so leaving it out means a push can
land with a proof broken. Running the three cheap gates first is the smaller thing that works;
adding the rest is a separate decision about CI minutes.

## Flakes this was expected to hit

`TODO.md` predicted two CI flakes before any CI existed, and both were fixed before this
workflow was written:

| Flake | Fix |
|---|---|
| `pg_isready` answering during initdb's temporary server, so a connection then failed with `expected to read 5 bytes, got 0 bytes at EOF` | `scripts/make/lib/postgres.sh` checks readiness over TCP, not the unix socket |
| a test freeing a port and another process taking it | `util::test_support::closing_server` keeps the port bound and closes each connection unanswered |

## Not verified here

A workflow file is exercised by pushing. `make lint` covers rust, shell and python, not YAML,
and `act` is not installed. What was checked locally: the YAML parses and declares the three
jobs above, `waharoa_install_sqlx_cli` reports the pinned CLI already installed, and
`make lint`, `make test` and `make sqlx-prepare ARGS=--check` each pass. Whether the jobs run
on the runner is unproven until the first push.
