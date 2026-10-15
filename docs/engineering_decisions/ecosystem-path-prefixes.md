# Each ecosystem is served under a prefix of its own

- **Status:** Decided by the user 2026-10-15, as option B below. Implemented in
  `ecosystem::Registry::prefix`, `ecosystem::serving`, `ecosystem::within`, and
  `proxy::unrouted`.
- **Related:** [adapter-interface](adapter-interface.md), [go-plan](../go-plan.md),
  [request-flow](../request-flow.md)

## What it replaced

npm answered every path no other row claimed. PyPI claimed `/simple/` and `/packages/`, and
cargo `/cargo/`. npm has packages named `cargo`, `simple` and `packages`: npm's `cargo`
0.8.0 tarball, `/cargo/-/cargo-0.8.0.tgz`, was routed to cargo and fetched from
static.crates.io, which answered 404. `b21be4b` sent such a path back to npm; Go's `/go/`
would have met npm's `go` package the same way.

## Decision

| Ecosystem | Prefix | Client points at |
|---|---|---|
| npm | `/npm/` | `https://byrle.example.com/npm/` |
| PyPI | `/pypi/` | `https://byrle.example.com/pypi/simple/`; files at `/pypi/packages/` |
| cargo | `/cargo/` | `sparse+https://byrle.example.com/cargo/` |

A row's prefix is its ecosystem's name, and a test holds it so. A path under no prefix,
past the proxy's own `/-/byrle/` endpoints, answers 404 naming each prefix, and nothing is
asked upstream. Rewritten artifact URLs carry the prefix: `https://byrle.example.com/npm/
lodash/-/lodash-4.17.21.tgz`. An ETag the proxy marks is marked with the same base, so a
tag issued at the root is not turned back.

`byrle doctor` checks the whole URL a client is pointed at, not only its origin: npm
pointed at `https://byrle.example.com/` is a problem, with `npm config set registry
https://byrle.example.com/npm/` as its fix.

| Option | Configurations and lockfiles written for v0.1.0 |
|---|---|
| A. A prefix for each, the root kept as npm's, logged as deprecated | keep working |
| **B. A prefix for each, nothing at the root** | an npm or pip pointed at the root, and a lockfile recording tarball URLs at the root, get 404 until pointed at the prefix and the lockfile regenerated |
| C. A host name for each ecosystem | keep working, at a DNS name and a certificate per ecosystem |

`byrle warm` asks for a lockfile's artifacts under the prefix, whichever host its URLs
name: `/npm/<name>/-/<file>` from an npm lockfile, and
`/pypi/packages/...` from `uv.lock`.
