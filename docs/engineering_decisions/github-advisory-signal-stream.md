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
waharoa refresh: fetching https://api.github.com/graphql
waharoa refresh: 100 pages from https://api.github.com/graphql
advisories written                 283691
aliases written                     43731
affected rows written              285265
ranges written                      19508
exploited CVE ids written            1710
snapshot sha256:5d57fbc3afd850ce229596afac97a6497435a177cbf48a9f9cce88265ce45521
took 211.9s
```

| Source | Advisory rows |
|---|---|
| `osv` | 228,330 |
| `datadog` | 48,316 |
| `github` | 7,045 |

Two streams holding one id, which the old constraint refused:

```text
github GHSA-2h44-8472-frjj 9.6
osv    GHSA-2h44-8472-frjj 9.6
```

Both score it 9.6, because `github::score` reads the band through `osv::band_ceiling` when
GitHub gives no vector score. `GHSA-4j66-8f4r-3pjx`, withdrawn on GitHub and live in the
bundle, is stored under `osv` and not under `github`: the flag set shows one stream retracting
what the other still reports.

## What is not stored yet: exclusive lower bounds

7,045 rows against the 7,056 advisories measured. The 11 missing ones write
`vulnerableVersionRange` with `>`, an exclusive lower bound, and `Interval::introduced` is
inclusive: `contains` asks `v >= from`. Storing `> 4.0.2` as `introduced: 4.0.2` would report
4.0.2 itself as vulnerable when it is the last safe version, so `github::bounds` returns
`Bounds::Unexpressed` and an advisory with no other range is dropped.

All three advisories GitHub has and OSV lacks are in those 11:

| Advisory | Range |
|---|---|
| `GHSA-2gvc-4f3c-2855` | `> 2026.3.28, < 2026.4.15` |
| `GHSA-8w7w-67mw-r5p7` | `> 6.8.0, < 6.9.0` |
| `GHSA-m2hm-hrr2-6p2q` | `> 4.0.2` |

So the stream delivers corroboration on 7,045 advisories today and none of the three it alone
would add. `Interval` needs an exclusive lower bound before it does, which is a change to a
type OSV also uses, a column on `advisory_range`, and the `contains` comparison. Tracked in
`TODO.md` under this item.

## Attribution

GHSA text is CC-BY-4.0 and owes attribution wherever it is shown. `summary` is stored in
`advisory` and selected by nothing, so no GHSA text is displayed today, from either stream.
The obligation attaches the first time a verdict renders one.
