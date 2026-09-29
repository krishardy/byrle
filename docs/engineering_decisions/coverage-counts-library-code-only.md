# The coverage floor counts library code, not tests

- **Status:** Implemented 2026-09-29. `scripts/make/coverage.sh`,
  `scripts/make/lib/coverage-toolchain.sh`, every `#[cfg(test)]` item in `src/`.
- **Related:** [main-is-a-thin-wrapper](main-is-a-thin-wrapper.md)

## Decision

`make coverage` runs cargo-llvm-cov on a pinned nightly, `nightly-2026-09-28`. On nightly,
cargo-llvm-cov sets `--cfg coverage_nightly`, and every `#[cfg(test)]` item carries
`#[cfg_attr(coverage_nightly, coverage(off))]`. Test code is compiled and run but not
counted. Builds, tests, lint, kani and release stay on stable.

The floor is 100% of lines, functions and regions, as CLAUDE.md sets it.

## Why

CLAUDE.md sets the floor for library code. On stable, llvm-cov counts the code of the
tests in the same file, and a passing test leaves branches that never run:

| In a test | What is never run |
|---|---|
| `assert!(matches!(x, P))` | `matches!`'s `_ => false` arm |
| `let P = x else { panic!() }` | the `panic!` |
| `assert!(c, "{}", f())` | `f()`, evaluated only on failure |
| a spawned server `async move { serve().await; }` | the end of the block |

On 2026-09-29, 265 of 776 missed lines and regions were in test code. `coverage(off)` is
not stable on rustc 1.98.1 (rust-lang/rust#84605).

## Alternatives

| Option | Why not |
|---|---|
| Rewrite each test so every branch runs | about 265 edits to tests, and each new `matches!` or `let … else` in a test adds one |
| Move tests to separate files and ignore them by name | every inline test module moved |
| Keep 95% | the floor then hides library code with no test |

## Log calls

`sqlx-core` turns on `tracing`'s `log` feature. Each event then has a branch that hands it to
`log` when no tracing subscriber takes it, and that branch holds the event's fields. No test
reached it: 381 of 803 missed regions on 2026-09-29 were in log calls.

Test builds add `tracing`'s `log-always` feature, and tests install no tracing subscriber,
so every event is off where it is logged and takes that branch. A `log` logger, installed
before `main` with `ctor`, receives each record, and `test_support::capture` keeps the
records of the capturing thread at its level. A log call is covered once any test reaches
it. Release builds do not have `log-always` or the logger.

An earlier arrangement captured through a tracing subscriber with a per-thread filter. A
filter on the fmt layer left every event on once installed, and a global filter left each
captured event on, so a log call reached only by a capturing test stayed uncovered.

## Generic functions

`llvm-cov report` counts each generic function by its best-covered instantiation. A test
that calls one with its own type, such as `fetched::<u8>`, makes an instantiation that
reaches some branches and not others. On 2026-09-29, 26 missed regions were such cases.

A generic function with branches takes its arguments in a small generic shell and calls a
non-generic core: `ReachableOrigins::new` calls `ReachableOrigins::of` with slices, and
`Spool::write` calls `write_chunks` with a `dyn Stream`. A test that has to call a generic
function uses the type production does.

## Consequences

- `make dev-setup` installs the nightly and its `llvm-tools-preview`.
- A new `#[cfg(test)]` item needs the attribute too, or its code counts toward the floor.
- A nightly that stops building the crate is replaced by editing the pin.
