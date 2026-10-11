# The console's web interface: Rust, HTML from maud

- **Status:** Decided 2026-10-11, by the user, "for now". Not yet implemented. TODO Stage 4.9.
- **Related:** [admin-plan](../admin-plan.md) §8 Q3, [console-listener](console-listener.md)

## Decision

The console's pages are HTML rendered in Rust with `maud`. Filters are forms and links.
Charts are SVG rendered on the server.

## Measured 2026-10-11

Rust: each crate added to a copy of this crate's `Cargo.lock`, 360 packages. npm:
`npm install --package-lock-only --ignore-scripts`, npm 11.21.0, which resolves the tree
without downloading or running any package.

| Option | Packages added | Shipped to the browser |
|---|---|---|
| Rust, `maud` | 3 crates: `maud`, `maud_macros`, `proc-macro2-diagnostics` | none |
| Rust, `askama` | 6 crates | none |
| TypeScript, React, Vite, Vitest | 214 npm packages | `react`, `react-dom`, `scheduler` |
| TypeScript, Preact, Vite, Vitest | 232 npm packages | `preact` |
| TypeScript, no framework, `tsc` | 1 npm package | none |

## Why

- One language, and the console is inside the 100% coverage floor `make coverage` checks.
- 3 crates, against 214 npm packages that run on every build machine.
- The views are tables, filters and counts.

## Rejected

| Option | Why not |
|---|---|
| `askama` | 6 crates against 3, and templates in separate files |
| TypeScript with React or Preact | 214 or 232 packages, a second coverage floor, node in the release build |

## When to revisit

A view that has to update without a page load. TypeScript compiled by `tsc` alone, on
pages Rust renders, is the first option then.
