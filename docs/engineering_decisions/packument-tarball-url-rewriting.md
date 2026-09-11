# Rewriting `dist.tarball` to point at the proxy

- **Status:** Decided Sept 2026, implemented Stage 1
- **Supersedes:** plan §4, "npm needs no packument rewriting"
- **Code:** `npm::rewrite_artifact_origins`, `proxy::rewrite_packument`
- **Reproduce:** `make smoke-clients`

## Decision

The proxy rewrites every artifact URL in a packument to point at itself, for every
client. Only the origin changes; the path is kept.

An artifact whose origin is not one the proxy already fronts, meaning neither the
configured upstream nor the default registry, is left alone.

## Why it was reopened

Plan §4 recorded that npm resolves tarballs against the configured registry regardless of
what `dist.tarball` says, so rewriting would buy nothing. That was measured on npm alone,
and it is not true of the other clients.

Each client was pointed at a controlled registry serving one package whose `dist.tarball`
named a host where that package does not exist. A client that rewrites the URL installs;
one that uses it verbatim gets a 404.

| Client | Result | Behaviour |
|---|---|---|
| npm 9.9.4 | installed | rewrites to the configured registry |
| pnpm 10.33.0 | `ERR_PNPM_FETCH_404` | uses the URL verbatim |
| yarn 1.22.22 | `404 Not Found` | uses the URL verbatim |

Against the real registry this showed up as silence. Installing `express` through the
proxy, npm sent 67 packuments and 69 tarballs; pnpm sent 66 packuments and **zero**
tarballs, and installed successfully. Every artifact went straight to registry.npmjs.org,
so digest verification never ran and Stage 3 would have had nothing to analyse.

## Why rewrite for npm too

npm does not need it. Rewriting for it anyway means one behaviour for the whole
ecosystem instead of a per-client table keyed on user-agent, which would make the response
vary by client and would need maintaining as clients change.

## Why it is now affordable

The plan's objection was that rewriting means buffering and re-serialising every
packument. Buffering is no longer a new cost: packuments are already buffered and parsed
to be normalised. Only re-serialisation is new.

Measured in a release build on the largest packument seen, typescript at 8.7 MB
abbreviated:

| Step | Cost |
|---|---|
| parse to a JSON value | 36 ms |
| rewrite URLs | 1.6 ms |
| serialise | 10 ms |
| gzip, `Compression::fast()` | 18 ms |

`fast` rather than `default`: 18 ms against 117 ms, for 2.06 MB against 1.69 MB. A 22%
larger body on a hop that is usually loopback or a LAN, for a sixth of the CPU.
`serde_json`'s `preserve_order` feature is on, so key order survives and the forwarded
document differs from the original only in the URLs.

## Lockfiles, which was the real objection

Clients record the resolved artifact URL, so rewriting puts the proxy's address in
lockfiles. Measured, and it is not uniform:

| Client | Before rewriting | After rewriting |
|---|---|---|
| npm | `resolved: https://registry.npmjs.org/...` | `resolved: <proxy>/...` |
| yarn 1 | `resolved "https://registry.npmjs.org/..."` | `resolved "<proxy>/..."` |
| pnpm | `resolution: {integrity, tarball: https://registry.npmjs.org/...}` | `resolution: {integrity}` |

pnpm omits the tarball URL when it matches the configured registry and derives it at
install time, so for pnpm the lockfile becomes registry-independent: more portable than
before, not less.

For npm and yarn the address is recorded, so it has to be a stable name that everyone
consuming the lockfile can reach. `WAHAROA_PUBLIC_URL` pins it; otherwise the request's
own `Host` is used. Two consequences, and they are the same fact seen from two sides: a
lockfile committed from behind the proxy cannot be installed without the proxy, which
means CI cannot silently skip enforcement, and the proxy becomes something CI depends on
being reachable.

## Why not rewrite artifacts on other origins

Rewriting those would mean the proxy fetching from an arbitrary host on a client's behalf,
which is a capability worth not having. They stay as they are, and
`npm::bypassing_origin` reports them so they are visible rather than silent.

## Consequences

- Registry signatures are unaffected. pacote signs `${mani._id}:${mani._integrity}`
  (`lib/registry.js`), which is name, version and integrity. The URL is not covered.
  `dist.integrity` is never touched.
- The forwarded body is no longer the upstream's bytes, so `Content-Length`,
  `Content-Encoding` and `ETag` are all set to describe what the proxy sends. The `ETag`
  is marked with a tag derived from the proxy's own address, and an `If-None-Match` from
  a proxy at a different address is dropped rather than revalidated, which would otherwise
  let a 304 leave a client serving artifact URLs pointing at an address nobody listens on.
- **Forwarding a packument unrewritten now means more than it used to.** It used to mean
  the metadata went unobserved; it now means every artifact for that package is fetched
  wherever the document says, which for pnpm and yarn is not through the proxy. Every such
  path logs `UNINSPECTED` so one grep finds all of them. Stage 1 forwards in all of them
  rather than failing an install, and Stage 2 has to decide whether that stays acceptable.
- A registry serving artifacts at non-canonical paths still routes correctly, because the
  path is preserved, but `classify_path` returns `Other` for those requests, so they lose
  digest verification.
