# TLS: reverse proxy first

- **Status:** Decided
- **Plan reference:** decision #3

## Decision

Reverse proxy first. A CA-terminating forward proxy comes later.

## Rationale

Every target package manager supports pointing at an alternate registry. That needs no
CA distribution and no trust-store surgery on developer machines. Terminating mode is
an enterprise anti-bypass feature rather than a starting point.

## Consequences

- The inbound leg is plain HTTP on loopback. The upstream leg uses rustls with
  `rustls-platform-verifier`, which reqwest 0.13 pulls in by default.
- Reverse proxy mode is advisory: a developer who resets their registry URL defeats it.
  Plan §7 records this as a known bypass vector.
- Custom CA bundle support for the upstream connection is not implemented as of
  Sept 2026. Private registries and TLS-inspecting corporate middleboxes need it.
  Tracked in TODO.md.
