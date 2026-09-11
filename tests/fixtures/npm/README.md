# npm packument fixtures

Real registry responses, trimmed to one version each, captured Sept 2026. They are the
input for normaliser tests: the bytes on the wire are what a proxy actually handles, so
tests target those rather than a hand-built stub.

Each package is here for a property, and both documents are kept because they differ in
ways that matter (see `src/record.rs`):

| Fixture | Property under test |
|---|---|
| `lodash-4.17.21` | unscoped name, no install script, no attestations |
| `@babel_traverse-8.0.5` | scoped name, which becomes a percent-encoded purl namespace |
| `esbuild-0.28.2` | `hasInstallScript: true` in abbreviated, `postinstall` in full |
| `sigstore-5.0.0` | `dist.attestations` and an OIDC `trustedPublisher` |

`.abbrev.json` is `Accept: application/vnd.npm.install-v1+json`, which is what npm
requests during an install and therefore what the proxy normally sees. `.full.json` is
the default document. Trimming removed `readme`, `_rev`, `users`, all other versions,
and all `time` entries except `created`, `modified` and the kept version.

To refresh one, request the same two documents and apply the same trimming. Do not
hand-edit them: a fixture that no registry would ever emit tests nothing.
