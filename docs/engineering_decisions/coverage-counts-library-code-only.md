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

## Consequences

- `make dev-setup` installs the nightly and its `llvm-tools-preview`.
- A new `#[cfg(test)]` item needs the attribute too, or its code counts toward the floor.
- A nightly that stops building the crate is replaced by editing the pin.
