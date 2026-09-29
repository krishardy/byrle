# NVD role, and per-ecosystem stream capabilities

- **Status:** Decided. The gap check is implemented: `intel::capabilities_of`,
  `LoadedSnapshot::gaps`.
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
- The capability is enforced by types. `intel::Finding` and `intel::Enrichment` are
  different types with no conversion, and `EnrichStream` is asked about an advisory, with
  no package argument, and cannot return a `Finding`. The `compile_fail` doctest in
  `src/intel.rs` checks that an `Enrichment` does not become a `Finding`. An enrichment
  applies when its id is the advisory's id or any alias. It can raise a score and mark an
  advisory exploited, never the reverse, so the result does not depend on the order
  enrichments arrive in. An originated finding is never exploited: that is what `enrich`
  streams know. A score outside 0.0 to 10.0 is dropped and the finding kept.
- A stream a snapshot records that this build does not know is granted nothing. The policy
  has no `streams` block, so an operator cannot change the grants yet.
- Plugins declare their own capabilities; operators may demote a stream they distrust.
  Promotion, especially into `malware`, is deliberately harder than demotion.

The capability matrix and its YAML shape remain in plan §3 ("Stream capabilities by
ecosystem").

## Streams this build declares, 2026-09-15

The frozen v1 policy schema has no `streams` block, so this build declares each stream's
capabilities itself, keyed by the name a snapshot records the stream under
(`intel::capabilities_of`). A stream it does not know is granted nothing.

| Stream | Ecosystem | Capabilities |
|---|---|---|
| `osv/npm` | npm | match, malware |
| `datadog/npm` | npm | match, malware |
| `cisa/kev` | every served ecosystem | enrich |

`LoadedSnapshot::gaps` gives each served ecosystem (each row of `ecosystem::TABLE`: npm and
PyPI) that no stream in
the snapshot provides `match` for, then each that no stream provides `malware` for. The proxy
warns once per gap at startup, for the snapshot loaded then, and `waharoa doctor` reports a gap
in the snapshot `/ready` returns as a warning.

### Asked of the user, 2026-09-15

| Question | Chosen |
|---|---|
| Is an ecosystem with `match` and no `malware` stream also a startup warning? | yes |

`known_malware` is the one check with no exception, and it never fires without a `malware`
stream. `osv/npm` provides both for npm, so neither gap is reported today.

No refresh writes a snapshot with a gap today: `waharoa refresh` loads nothing when OSV does
not load. The check is for an ecosystem added without a stream, such as PyPI in Stage 3.
