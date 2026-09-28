# License: Apache-2.0

- **Status:** Implemented 2026-09-28. `LICENSE`, `CONTRIBUTING.md`, `license` in
  `Cargo.toml`.
- **Plan reference:** decision #5

## Decision

Apache-2.0. DCO sign-off rather than a CLA. Trademark held separately.

## Rationale

Permissive licensing is the norm among comparable projects: pkggate and Aikido Safe
Chain are both MIT. The Apache-2.0 patent grant matters for security tooling. DCO keeps
friction low for adapter and detector contributions, which plan §2 identifies as the
scarce resource.

## Consequences

`LICENSE` is the Apache License 2.0 text unchanged, its appendix included. `CONTRIBUTING.md`
asks for `Signed-off-by` on every commit and carries the Developer's Certificate of Origin
1.1. No check enforces the sign-off yet. The trademark note is not written.
