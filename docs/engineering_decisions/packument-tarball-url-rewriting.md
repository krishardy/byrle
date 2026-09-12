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
| yarn 4.9.1 | `YN0035: Package not found` | uses the URL verbatim, and records it in the lockfile as `__archiveUrl` |
| bun 1.3.14 | `error: GET ... 404` | uses the URL verbatim |

npm is the only one of the five that rewrites, which is the argument for doing it for all
of them rather than per client.

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

**How it is done matters more than it looks.** The obvious approach, parsing into a
`serde_json::Value` and re-serialising, cost 36 ms to parse and 10 ms to serialise
typescript, and the value tree dominated memory: 24 simultaneous large packuments peaked
at 1,436 MB while the encoded bodies totalled 27.6 MB.

Instead the rewrite takes the artifact URLs already found during normalisation and
replaces each wherever it appears as a complete quoted string, walking the text once. Peak
RSS on the same load fell to 472 MB and the median from 223 MB to 97 MB.

That is only safe because of what the documents actually look like. Measured across the
corpus, both kinds: of 49,704 artifact URLs, 49,702 appear exactly once as a complete
quoted string and 2 appear twice, both as `_resolved`. Escaped forward slashes occur in 2
of 94 documents and only inside README prose, never in a URL. If any URL is not found the
whole rewrite fails, rather than half of it landing and sending some artifacts to the
proxy while others still point at the registry.

Two things fall out of it. The forwarded document is byte-identical to the upstream's
apart from the URLs, which re-serialising cannot promise. And `_resolved`, an npm internal
field repeating `dist.tarball`, is rewritten too; a `dist.tarball`-only rewrite left it
pointing at the origin registry.

Re-compression uses `Compression::fast()` rather than `default`: 18 ms against 117 ms, for
2.06 MB against 1.69 MB. A 22% larger body on a hop that is usually loopback or a LAN, for
a sixth of the CPU.

## Lockfiles, which was the real objection

Clients record the resolved artifact URL, so rewriting puts the proxy's address in
lockfiles. Measured, and it is not uniform:

| Client | After rewriting, what the lockfile records |
|---|---|
| npm | `resolved: <proxy>/...` |
| yarn 1 | `resolved "<proxy>/..."` |
| bun | the proxy URL in `bun.lock` |
| pnpm | nothing: `resolution: {integrity}` alone |
| yarn 4 | nothing: `resolution: "lodash@npm:4.18.1"` alone |

pnpm and yarn 4 omit the tarball URL when it matches the configured registry and derive
it at install time, so for those two the lockfile becomes registry-independent: more
portable than before, not less. They record the URL only when it is off-registry, which
is the case the refusal removes anyway.

For npm, yarn 1 and bun the address is recorded, so it has to be a stable name that
everyone consuming the lockfile can reach. `WAHAROA_PUBLIC_URL` pins it; otherwise the request's
own `Host` is used, which on a developer machine is whatever they typed.

That address becomes load-bearing. Measured: a lockfile written through a proxy on one
port, then `npm ci` against a proxy on another, fails outright. npm goes to the address in
`resolved` and does not fall back to the registry given on the command line. So the proxy
warns at startup when `WAHAROA_PUBLIC_URL` is unset.

Two consequences, the same fact seen from two sides: a lockfile committed from behind the
proxy cannot be installed without the proxy, which means CI cannot silently skip
enforcement, and the proxy becomes something CI depends on being reachable.

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
  is marked with a tag derived from the proxy's own address.
- **Only a tag this proxy issued at this address may revalidate.** A 304 authorises the
  client to serve what it cached, which is safe only for a body the proxy produced here.
  Two cases are dropped so upstream sends a body to rewrite afresh:
  - A tag from this proxy at another address. A 304 would leave the client serving
    artifact URLs pointing at an address nobody listens on.
  - A tag the proxy never issued. Measured: with rewriting enabled at an address that
    previously ran without it, npm sent the upstream's own tag, the registry answered 304,
    and the client kept its unrewritten copy. npm re-derives artifact URLs from the
    configured registry so it still came through the proxy, but pnpm and yarn use the URL
    as written, so for them that cached copy sends every artifact to the origin registry.

  This costs a packument re-fetch the first time a client with a warm cache meets a
  rewriting proxy. Tarball requests are unaffected, since tarballs are not rewritten and a
  304 on one is harmless.
- **The 304 response carries the marked tag, not the upstream's.** A 304 relays the
  upstream's `ETag`, and a client stores whatever comes back. Left alone that replaces the
  marked tag with the upstream's; the next revalidation sends a tag the rule above drops,
  and the client gets a full body. Four requests for lodash before the tag was marked on
  the 304 path: 200 (68,970 bytes), 304, 200, 304. After: 200, then 304 every time. The
  marked tag is byte-identical on both paths, because `mark_etag` is a function of the
  upstream tag and the base, and a 304 by definition names the same upstream tag.
- **While rewriting, `If-None-Match` is the only conditional forwarded.** `If-Match`,
  `If-Modified-Since`, `If-Unmodified-Since` and `If-Range` are dropped whole, because a
  304 earned by a date says nothing about which proxy rewrote the body the client holds.
  yarn 4 sends `If-Modified-Since` alongside `If-None-Match` on every revalidation;
  RFC 9110 §13.1.3 has the server ignore the date when a tag is present, so dropping it
  changes nothing for yarn 4 and removes the case where a date arrives alone.

  Measured over two installs of lodash through the proxy with a warm client cache: yarn 4
  is the only one of the five clients that revalidates. Its second run sent the marked tag
  and got a 304, saving 247,067 bytes. npm, pnpm, yarn 1 and bun sent no conditional at
  all; each served the second install entirely from its own cache.
- **Forwarding a packument unrewritten now means more than it used to.** It used to mean
  the metadata went unobserved; it now means every artifact for that package is fetched
  wherever the document says, which for pnpm and yarn is not through the proxy. Every such
  path logs `UNINSPECTED` so one grep finds all of them. Stage 1 forwards in all of them
  rather than failing an install, and Stage 2 has to decide whether that stays acceptable.
- A registry serving artifacts at non-canonical paths still routes correctly, because the
  path is preserved, but `classify_path` returns `Other` for those requests, so they lose
  digest verification.
