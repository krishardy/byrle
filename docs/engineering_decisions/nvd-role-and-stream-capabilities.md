# NVD role, and per-ecosystem stream capabilities

- **Status:** Decided
- **Plan reference:** decision #7

## Decision

NVD is `enrich`-only for npm and PyPI, joined on exact CVE ID. `match` is permitted for
Maven, where CPE coverage is stronger, and is revisited when that adapter is scoped.

Generalised: stream capability is a matrix of `(stream, ecosystem) -> set of roles`,
with roles `match`, `enrich` and `malware`.

## Rationale

CPE-to-PURL is a category mismatch rather than a mapping problem. CPE identifies
products, not packages. The mapping is lossy in both directions, has no authoritative
table, and is assigned by NVD analysts rather than package maintainers. GHSA, reaching
us via OSV, already covers npm and PyPI with proper package ranges.

Coverage is uneven per stream *and* per ecosystem, so a per-stream capability flag
cannot express the truth; the capability has to be a matrix.

`malware` is separate from `match` because the §5.5 non-overridable floor is scoped to
`known_malware: block`. Any stream holding `malware` for an ecosystem can trigger the
one rule nobody can override, which is a higher trust bar than reporting a vulnerability.

## Consequences

- Enrichment runs as a background job, never on the hot path, and NVD failures never
  block a verdict.
- An `enrich`-capable stream returning a higher CVSS *can* change a verdict through
  `max_cvss`. Accepted: enrichment would be decorative otherwise. It can only escalate
  within an existing finding, never originate one.
- Coverage gaps become computable: an enabled ecosystem with no `match`-capable stream
  is a firewall that cannot block anything. Startup warning plus a `waharoa doctor`
  check.
- Plugins declare their own capabilities; operators may demote a stream they distrust.
  Promotion, especially into `malware`, is deliberately harder than demotion.

The capability matrix and its YAML shape remain in plan §3 ("Stream capabilities by
ecosystem").
