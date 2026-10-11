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
- Custom CA bundle support for the upstream connection is implemented (`src/tls.rs`).
  `BYRLE_CA_BUNDLE` merges a PEM bundle with the platform roots, for a private registry
  with an internal CA or a TLS-inspecting corporate middlebox.
  `BYRLE_CA_BUNDLE_EXCLUSIVE=1` trusts only the bundle and drops every public root,
  which pins the upstream so a compromise of any public CA cannot impersonate the
  registry. Verified against registry.npmjs.org with a self-signed CA: merged it connects,
  exclusive it fails at the handshake.

## See also

- [terminating-tls-certificates](terminating-tls-certificates.md) for how the terminating
  mode holds certificates: pre-issued leaves for the known registry domains, no CA key on
  the proxy.
- [enforcement-tiers](enforcement-tiers.md) for what terminating mode buys over the
  tiers that need no CA, and for what to build before it. A hosts-file or DNS override
  needs TLS termination for the same reason a forward proxy does, so it is the same
  decision wearing different clothes.
