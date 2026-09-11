# Rewriting `dist.tarball`: reopened

- **Status:** Open question, reopened Sept 2026 by measurement
- **Plan reference:** §4, "npm needs no packument rewriting"
- **Reproduce:** `make smoke-clients`

## The decision as it stands

The proxy forwards packuments byte for byte and does not rewrite `dist.tarball`. Plan §4
recorded this as settled, on the grounds that npm resolves tarballs against the
configured registry regardless of what the packument says, so rewriting would buy
nothing and cost a great deal.

## What the measurement showed

That is true of npm and false of pnpm and yarn.

Each client was pointed at a controlled registry serving one package whose `dist.tarball`
named `https://registry.npmjs.org`, a host where that package does not exist. A client
that rewrites the URL to the configured registry installs successfully; one that uses the
URL verbatim gets a 404.

| Client | Result | What it proves |
|---|---|---|
| npm 9.9.4 | installed | rewrites to the configured registry |
| pnpm 10.33.0 | `ERR_PNPM_FETCH_404 GET https://registry.npmjs.org/...` | uses the URL verbatim |
| yarn 1.22.22 | `404 Not Found` on the same URL | uses the URL verbatim |

Against the real registry the same divergence shows up as silence. Installing `express`
through the proxy: npm sent 67 packuments and 69 tarballs; pnpm sent 66 packuments and
**zero** tarballs, and installed successfully. Every artifact went straight to
registry.npmjs.org.

## What it costs today

For pnpm and yarn the proxy sees metadata and never the bytes:

- No digest verification. The check exists and never runs.
- Nothing for artifact analysis to analyse, which is all of Stage 3.
- Metadata policy still applies, because both clients do fetch packuments through the
  proxy. A metadata-only verdict is most of Stage 2's detection surface, so these clients
  are degraded rather than unprotected.

## What closing it would cost

Rewriting `dist.tarball` to point at the proxy makes lockfiles environment-specific.
Measured on lockfiles written through the proxy today, both record the origin registry
and are portable:

- `package-lock.json`: every `resolved` is `https://registry.npmjs.org/...`
- `pnpm-lock.yaml`: every `resolution.tarball` is `https://registry.npmjs.org/...`

After rewriting, both would record the proxy's own address. A lockfile committed from a
machine behind the proxy would name a host nobody else can reach.

The plan's other objection, that rewriting means buffering and re-serialising every
packument, no longer holds: packuments are already buffered and parsed to be normalised
(see [packument-body-inspection.md](packument-body-inspection.md)). Re-serialising is the
remaining new cost, along with the risk of a rewritten document differing from the
original in some way a client notices.

## Open

Whether to rewrite, and if so whether to do it only for clients that need it. The
user-agent is already parsed, so serving a rewritten packument to pnpm and yarn and the
original to npm is possible. That makes the response vary by client, which is a property
worth being deliberate about rather than arriving at.

Not decided here. What is settled is that the §4 finding is npm-specific, and the plan has
been corrected to say so.
