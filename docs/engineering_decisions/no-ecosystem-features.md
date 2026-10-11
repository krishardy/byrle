# Every build carries every ecosystem

- **Status:** Decided 2026-10-11, by the user.
- **Related:** [one-crate](one-crate.md), [adapter-interface](adapter-interface.md)

## Decision

No Cargo feature per ecosystem. Every build of the binary serves npm and PyPI, and each
ecosystem added later.

## Why

Splitting the ecosystems into features gains little, and adds to the testable surface:
each combination of features is a build that has to compile and pass the tests.

## Rejected

| Option | Why not |
|---|---|
| A Cargo feature per ecosystem, so a build carries only the ecosystems it serves | Little gain; more builds to test |

## When to revisit

When a reason to split comes up. Raised 2026-09-26 as Ad-hoc #21 in `TODO.md`, and closed
in Stage 4.5.
