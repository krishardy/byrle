# Terminating TLS: pre-issued certificates, not a CA on the proxy

- **Status:** Decided Sept 2026, not implemented
- **Plan reference:** decision #3, [enforcement-tiers](enforcement-tiers.md) tiers 4 and 5
- **Supersedes:** the CA-on-the-proxy question raised in
  [enforcement-tiers](enforcement-tiers.md)

## Decision

For the terminating modes, the proxy holds **leaf certificates and keys for the registry
domains**, issued out of band by whatever CA the organisation already has trusted. No CA
key on the proxy.

Configuration is per ecosystem, naming the certificate and key files. The domains a
certificate covers are read from its own SANs rather than configured separately.

Minting certificates on the fly from a CA key held by the proxy stays available as an
onramp, and is documented as the less secure option.

## Why this is better than a CA on the proxy

**Nothing on the proxy can sign anything new.** A CA key signs certificates for as long as
it is valid, for whatever names it is asked for. A leaf key signs nothing. Compromise of
the proxy yields the ability to impersonate exactly the domains those certificates already
name, and nothing else.

**Every client already does ordinary chain validation.** Pre-issued leaves need nothing
beyond it, so there is no property of the verifier that has to hold for this to work, and
nothing to test per platform before shipping.

Constraining a CA to the registry names is not used here and is not being evaluated. The
minting onramp therefore holds an unconstrained CA key, which is the plain description of
what it is and why it is the less secure option.

## The domains are known, and they are sets

| Ecosystem | Hosts | Serving |
|---|---|---|
| npm | `registry.npmjs.org` | metadata and artifacts |
| PyPI | `pypi.org` | metadata |
| | `files.pythonhosted.org` | artifacts |
| crates.io | `crates.io`, `index.crates.io`, `static.crates.io` | API, index, artifacts |

Verified Sept 2026: `pypi.org/simple/requests/` links artifacts on
`files.pythonhosted.org`, and a PyPI JSON response gives the same host.

So the unit of configuration is not one domain per ecosystem. It is a set of
certificates, each covering one or more names, grouped by ecosystem so that incomplete
coverage can be reported.

**Incomplete coverage reproduces a failure already measured.** A PyPI deployment holding a
certificate for `pypi.org` and not `files.pythonhosted.org` sees metadata and never an
artifact. That is the same shape as pnpm fetching `dist.tarball` directly: the proxy
observes the package and never the bytes. The proxy should say so at startup rather than
half working, which means listing the domains it can answer for and the ecosystems whose
set is incomplete.

## Read the domains from the certificate

A separately configured domain list can disagree with what the certificate actually
covers, and the failure is a handshake error at install time rather than a configuration
error at startup. Reading the SANs makes them one thing, and lets startup print exactly
which names the proxy can answer for.

## What it unlocks

- **No client registry configuration at all.** The client talks to `registry.npmjs.org`
  and reaches the proxy, so the advisory bypass in §7 stops applying to anything routed
  through the network.
- **No artifact URL rewriting.** `dist.tarball` already names a host the proxy answers
  for, so lockfiles keep the origin registry's URLs and stay portable. The failure
  measured earlier, where `npm ci` fetches the proxy address recorded in a lockfile and
  fails once that address stops answering, does not arise. `BYRLE_REWRITE_ARTIFACTS=0`
  becomes correct in this mode, and the two modes compose rather than competing.
- **Clients that ignore the registry configuration are covered**, provided DNS or egress
  routes them, which is the gap tiers 1 to 3 cannot reach at all.

## Costs, stated plainly

**Issuance.** Someone has to issue certificates for domains the organisation does not own.
An internal CA can, being bound by neither CAA nor Certificate Transparency, but a PKI
team may refuse, and leaves expire, so rotation becomes an operational task. Avoiding that
is exactly what the minting onramp buys, and what it costs is a CA key on the proxy.

**Blast radius is inherent to interception.** A leaf key for `registry.npmjs.org` signed by
a CA the organisation's machines trust lets a compromised proxy impersonate that domain to
anything on those machines, browsers included, not only to package managers. Name
constraints do not help, since they would permit exactly that name. This is a property of
terminating TLS, not of this design.

**Trust store work does not go away.** The issuing CA still has to be trusted by the OS
store, by Node through `NODE_EXTRA_CA_CERTS`, and by npm through `cafile` and
`strict-ssl`, with the Python and Rust equivalents for those ecosystems.

**Key material on the proxy.** Leaf keys are worth what the blast radius above says they
are. File permissions should be checked at startup, keys never logged, and loading from a
secrets manager should be possible rather than requiring files on disk.

## The refusal policy carries over unchanged

Tier 3 already removes versions whose artifacts the proxy cannot see. What changes between
modes is not the policy but the set it reads: in reverse-proxy mode the served origins are
the upstream, the default registry and anything configured, because artifact URLs are
rewritten to point here; in terminating mode they are the domains the proxy holds
certificates for, because those are the connections it actually sees.

So a terminating deployment gets the same three states, decided from the certificate SANs:

- **Served**, the proxy sees the connection and examines the artifact.
- **Allowed direct**, the proxy does not see it and the operator has said that is
  acceptable (`BYRLE_ALLOW_DIRECT_ORIGINS`).
- **Refused**, neither, so the version is removed from the packument.

**Only `dist.tarball` needs this, for npm.** pacote resolves `dist.attestations.url`
against the configured registry rather than using it as written: `lib/registry.js` takes
`new URL(dist.attestations.url).pathname` and joins it to `this.registry`, with the
comment "Always fetch attestations from the current registry host". The host in that URI
is discarded unconditionally, so it cannot route a client anywhere. The other URIs a
packument carries, `homepage`, `repository.url` and `bugs.url`, are not fetched during an
install. Worth rechecking per client and per ecosystem rather than assuming it holds for
pnpm, yarn or PyPI.

## Not implemented

Decision #3 stands: reverse proxy first. This records the shape so the terminating mode is
built deliberately rather than arrived at. Tracked in TODO.md.
