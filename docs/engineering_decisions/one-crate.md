# One library crate and one binary, not a workspace

- **Status:** Decided 2026-09-20. Deferred from Stage 1, decided here because the adapter
  interface is what the answer waited on.
- **Related:** [adapter-interface](adapter-interface.md),
  [main-is-a-thin-wrapper](main-is-a-thin-wrapper.md)

## Decision

`waharoa` stays one library crate with a thin binary. No workspace, no crate per ecosystem,
no crate per layer.

## Why the answer waited on the adapter interface

The case for a workspace is that a crate boundary enforces a layering a module boundary
only suggests. [adapter-interface](adapter-interface.md) is what an npm crate and a PyPI
crate would have to be built on, and it turned out to be three shared modules (`route`,
`origin`, `record::PackageMetadata`) and four exhaustive `match`es over `Ecosystem`, not a
trait.

A `match` over an enum is the opposite of a plugin seam: adding an ecosystem means editing
the core, which is the property the stage structure wants, since a new adapter should fail
to compile until every decision has an answer for it. Splitting the arms into crates would
put each arm behind a dependency edge pointing the wrong way: the core would depend on every
adapter to write the match, and every adapter on the core for the record type.

## The costs a workspace would buy off, measured 2026-09-20

| | Value |
|---|---|
| Rust in `src/` | 41,985 lines in 75 files |
| Largest module | `proxy.rs`, 5,317 lines, 2,809 of them tests |
| Rebuild after touching `proxy.rs` | 2.8s |
| Touch `policy/decide.rs`, build and run 859 lib tests | 4.8s |
| Crates in `Cargo.lock` | 337 |

Compile time is the usual reason to split, and it buys nothing here.

## Rejected

| Option | Why not |
|---|---|
| A crate per ecosystem | The dependency edges point both ways: see above |
| A crate per layer (transport, policy, intel) | The layering is already visible as modules, and `cargo` does not check what a reviewer can read in one file |
| A workspace for build times | 2.8s incremental |

## When to revisit

- A third party writes an adapter, which needs a trait and a published interface. That is
  Stage 6's "declare the adapter interface stable".
- An incremental rebuild passes roughly half a minute.
