# A CA bundle for the upstream connection, merged or exclusive

- **Status:** Implemented. `src/tls.rs`, `startup::upstream_client`.
- **Related:** [tls-reverse-proxy-first](tls-reverse-proxy-first.md),
  [environment-variables](environment-variables.md)

## Decision

reqwest 0.13's default `rustls` feature pulls `rustls-platform-verifier`, so the upstream
connection validates against the OS trust store with no configuration. That misses a
private registry with an internal CA, and a corporate TLS-inspecting middlebox whose
certificate the OS store may not carry. `WAHAROA_CA_BUNDLE` names a PEM bundle, trusted in
one of two modes:

| Mode | Trusted | Chosen by |
|---|---|---|
| Merge | the bundle and the platform's roots | the default |
| Exclusive | only the bundle | `WAHAROA_CA_BUNDLE_EXCLUSIVE=1` |

Exclusive pins the upstream to a known CA, so a compromise of any public CA cannot be used to
impersonate the registry. Verified with a self-signed CA against `registry.npmjs.org`:
merged, the request succeeds; exclusive, it fails at the TLS handshake.

## Errors

A bundle with no certificates is refused at startup. Both modes would hide it otherwise:
merging nothing changes nothing, and trusting nothing exclusively fails every handshake,
which reads as a network fault rather than a bad path.

A `CERTIFICATE` block whose base64 decodes to something that is not a certificate passes
`Certificate::from_pem_bundle`, and the TLS backend refuses it when the client is built.
That error names the file; without it the failure read "failed to build HTTP client".
`tests/fixtures/tls/refused.pem` is such a file.
