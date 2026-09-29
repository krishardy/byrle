# GitHub Advisory is a signal stream beside OSV, not a replacement for it

- **Status:** Decided 2026-09-16. Overlap measured; the stream is being built.
- **Related:** [datadog-stream](datadog-stream.md),
  [policy-tier-resolution](policy-tier-resolution.md),
  [advisory-stream-licences](advisory-stream-licences.md),
  [stream-descriptor-table](stream-descriptor-table.md),
  [intel-schema-keys-and-types](intel-schema-keys-and-types.md)

## Decision

OSV and GitHub Advisory are both signal streams. Each is checked independently, each records
what it holds about a package, and the full set is judged once at the end, at
`Evaluate_Decision_Vector` in [policy-tier-resolution](policy-tier-resolution.md): "Every
check runs. No check can stop the ones after it."

Two streams reporting the same vulnerability is corroboration, not waste. This is what
[datadog-stream](datadog-stream.md) already settled for Datadog: "Rows are not merged with
OSV's: a package both flag has a `datadog` record and an `osv` record." GitHub is the same
shape of source and gets the same treatment, as `github/npm`.

Overlap with OSV is therefore a measurement, not a reason to build or not build. It is
recorded below because it says how much of the npm advisory set has two independent streams
behind it and how much has one.

## Fetching

`waharoa refresh` POSTs the GraphQL query with `Authorization: bearer` and the token from
`WAHAROA_GITHUB_TOKEN`, paging by cursor until GitHub reports no next page. The pages are
joined into one JSON array, which the stream's parse reads as one buffer and its ceiling
bounds. Without a token the stream does not load, and the other streams still do.

The ceiling is 64 MiB: 9,980 rows came to 5.6 MB on 2026-09-16. `securityVulnerabilities`
returns one node per advisory and range, so `github::parse` groups the nodes by advisory.
A range is written as one bound or a comma-separated pair: `>= 0.0.1, < 2.1.27`,
`< 2.1.30`, `= 1.2.3`. An exact version is stored as a listed version, and a version is
padded as OSV's are, so `1.5` matches the published `1.5.0`. An advisory with no range is
every version, as OSV's `introduced: "0"` is. GitHub writes a score of 0.0 for an advisory
it has not scored, and that is read as no score, so the band gives one.

## The schema change this needs

Datadog did not hit this: it mints `DATADOG-npm-<name>`, an id space disjoint from anything
OSV publishes. GitHub publishes the same `GHSA-` ids OSV imports, and
`migrations/0001_intel.sql` declares:

```sql
publisher_id VARCHAR(128) NOT NULL UNIQUE
```

A global unique on `publisher_id` means the second stream to load `GHSA-2h44-8472-frjj` fails
the load. The constraint becomes `UNIQUE (source, publisher_id)`: an advisory id is unique
within the stream that published it, which is what the column's own comment assumes when it
says "Different streams use different id spaces for the same vulnerability."

What this does not change, checked before deciding:

| Code | Why it is unaffected |
|---|---|
| `PgIntel::replace` key read-back | already `SELECT publisher_id, id FROM advisory WHERE source = $1`, so the map is per source |
| `load::children` | takes that per-source map |
| `advisory_alias` | `UNIQUE (advisory_id, alias)`, keyed on the advisory row, so each row keeps its own aliases |
| `exploited_cve` join | `k.cve_id = a.publisher_id` marks both rows exploited, which is the intended reading: the vulnerability is exploited whichever stream reported it |

`PgIntel::package` selects one row per advisory and carries `a.source`, so two streams holding
one id come back as two `Record`s, each naming its stream. That is the per-stream flag the
decision vector reviews.

## Overlap, measured 2026-09-16

Every npm advisory reachable through GitHub's GraphQL
`securityVulnerabilities(ecosystem: NPM)`, against the `GHSA-` records in OSV's
`npm/all.zip`. Distinct `ghsaId`, withdrawn excluded on both sides. The bundle was fetched in
the same run, `last-modified: Tue, 15 Sep 2026 21:36:00 GMT`.

| | GitHub | OSV bundle |
|---|---|---|
| rows returned | 9,980 | n/a |
| distinct advisories | 7,406 | 7,405 |
| not withdrawn | 7,056 | 7,055 |
| carrying a CVSS score | 5,198 | n/a |

| Set | Count |
|---|---|
| in both, so two streams corroborate | 7,053 |
| GitHub only | 3 |
| OSV only | 2 |

100 pages of 100, one GraphQL point each, 100 of 5,000 per hour.

## The five that differ

| Advisory | Package | Published | Why it differs |
|---|---|---|---|
| `GHSA-2gvc-4f3c-2855` | `openclaw` | 2026-04-17 | absent from the bundle |
| `GHSA-8w7w-67mw-r5p7` | `generator-jhipster` | 2022-10-06 | absent from the bundle |
| `GHSA-m2hm-hrr2-6p2q` | `bootstrap-3-typeahead` | 2022-05-24 | absent from the bundle; also a Composer advisory |
| `GHSA-4j66-8f4r-3pjx` | `bun` | 2025-07-23 | **withdrawn on GitHub 2025-08-11, live in the bundle** |
| `GHSA-9ppg-jx86-fqw7` | `cline` | 2026-02-19 | live on GitHub, not returned by `securityVulnerabilities` |

None of the three GitHub-only advisories was published after the bundle was built, so none is
explained by the bundle being a snapshot.

`GHSA-4j66-8f4r-3pjx` is withdrawn on GitHub and not withdrawn in OSV's bundle. `osv::parse`
skips withdrawn records, so with only the OSV stream the proxy holds an advisory GitHub
retracted 13 months earlier. Two streams disagreeing is the case the flag set exists to show.

## Method caveat

`securityVulnerabilities(ecosystem: NPM)` returns advisory-and-range rows, so an advisory with
no npm version range in that connection does not appear. `GHSA-9ppg-jx86-fqw7` is live on
GitHub and absent from the 7,406, which is how it lands in the OSV-only column. The GitHub
count is a floor.

## Live, 2026-09-16

`waharoa refresh` into an empty Postgres 17, all four streams:

```text
waharoa refresh: 100 pages from https://api.github.com/graphql
advisories written                 283702
aliases written                     43741
affected rows written              285265
ranges written                      19520
exploited CVE ids written            1710
snapshot sha256:e6d672371ed7757f2e7f719fc89f8a7d10bde9f79f6954afef1187a2e9920073
took 159.3s
```

| Source | Advisory rows |
|---|---|
| `osv` | 228,330 |
| `datadog` | 48,316 |
| `github` | 7,056 |

7,056 is the whole measured set. Two streams holding one id, which the old global unique on
`publisher_id` refused:

```text
github GHSA-2h44-8472-frjj 9.6
osv    GHSA-2h44-8472-frjj 9.6
```

Both score it 9.6, because `github::score` reads the band through `osv::band_ceiling` when
GitHub gives no vector score. `GHSA-4j66-8f4r-3pjx`, withdrawn on GitHub and live in the
bundle, is stored under `osv` and not under `github`: the flag set shows one stream retracting
what the other still reports.

## Exclusive lower bounds

The three advisories GitHub holds and OSV's bundle lacks all write `>`:

```text
GHSA-2gvc-4f3c-2855 openclaw              2026.3.28 t 2026.4.15
GHSA-8w7w-67mw-r5p7 generator-jhipster    6.8.0     t 6.9.0
GHSA-m2hm-hrr2-6p2q bootstrap-3-typeahead 4.0.2     t
```

`> 4.0.2` says 4.0.2 is the last version not affected. `Interval` carried
`introduced: Option<V>`, an inclusive bound, so storing it would have reported 4.0.2 itself as
vulnerable. The first load of this stream dropped those advisories instead and wrote 7,045
rows, which is how the gap was found: the stream's whole unique contribution was missing.

`Interval` now carries `start: Start<V>`, `First` / `Introduced(v)` / `After(v)`, mirroring
`End`. An excluded bound with no version is unrepresentable rather than refused at runtime.
Migration 0007 adds `advisory_range.introduced_excluded`, a CHECK that an excluded bound names
a version, and puts the column in the uniqueness index, since `>= 1.0.0, < 2.0.0` and
`> 1.0.0, < 2.0.0` are different intervals.

12 stored range rows carry an excluded bound, all from `github`. OSV writes only inclusive
lower bounds, so every `osv` and `datadog` row is `f`.

`an_excluded_lower_bound_does_not_cover_its_own_version` holds the property: `> 4.0.2` excludes
4.0.2, includes 4.0.3, and includes `4.0.3-alpha`, which sorts above 4.0.2.

## Attribution

GHSA text is CC-BY-4.0 and owes attribution wherever it is shown. `summary` is stored in
`advisory` and selected by nothing, so no GHSA text is displayed today, from either stream.
The obligation attaches the first time a verdict renders one.
