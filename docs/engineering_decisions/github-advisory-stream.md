# A GitHub Advisory stream adds 3 advisories to what OSV already ships

- **Status:** Measured 2026-09-16. Not built.
- **Related:** [advisory-stream-licences](advisory-stream-licences.md),
  [nvd-role-and-stream-capabilities](nvd-role-and-stream-capabilities.md),
  [stream-descriptor-table](stream-descriptor-table.md),
  [osv-ranges-and-scores](osv-ranges-and-scores.md)

## What was measured

Every npm advisory reachable through GitHub's GraphQL
`securityVulnerabilities(ecosystem: NPM)`, against the `GHSA-` records in OSV's
`npm/all.zip`. Both sides counted by distinct `ghsaId`, withdrawn records excluded on both.
The bundle was fetched in the same run, `last-modified: Tue, 15 Sep 2026 21:36:00 GMT`.

| | GitHub | OSV bundle |
|---|---|---|
| rows returned | 9,980 | n/a |
| distinct advisories | 7,406 | 7,405 |
| not withdrawn | 7,056 | 7,055 |
| carrying a CVSS score | 5,198 | n/a |

| Set | Count |
|---|---|
| in both | 7,053 |
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
explained by the bundle being a snapshot. Publication lag is not what separates the two sets.

## Decision

Do not build a GitHub Advisory stream as a second `match` source for npm. It would restate
7,053 of 7,056 advisories the OSV stream already loads, for 3 the bundle lacks, at the cost of
a paginated authenticated fetch, a credential, and a `fetch` variant that the descriptor in
[stream-descriptor-table](stream-descriptor-table.md) does not have: `fetch` is one
unauthenticated GET of one body, and `parse` takes one body.

This is what [advisory-stream-licences](advisory-stream-licences.md) already said in prose:
"GHSA, reaching us via OSV, already covers npm and PyPI with proper package ranges." The
numbers put a size on it.

## The finding worth keeping

`GHSA-4j66-8f4r-3pjx` is withdrawn on GitHub and not withdrawn in OSV's bundle. `osv::parse`
skips withdrawn records, so the proxy holds an advisory GitHub retracted 13 months earlier.
One record is not a reason to take a GraphQL dependency. It is a reason to know that
withdrawal does not always propagate, and it is the one thing GitHub tells us that OSV does
not.

If a GitHub stream is built later, the case for it is withdrawals and freshness, and its
capability is `enrich`, not `match`: it would retract and rescore advisories the OSV stream
originated, which is what `EnrichStream` exists for.

## Method caveat

`securityVulnerabilities(ecosystem: NPM)` returns advisory-and-range rows, so an advisory with
no npm version range in that connection does not appear. `GHSA-9ppg-jx86-fqw7` is live on
GitHub and absent from the 7,406, which is how it lands in the OSV-only column. The GitHub
count is therefore a floor, understating by an unmeasured amount of the same order as the
differences above.

## Attribution

Not reached. GHSA text is CC-BY-4.0 and owes attribution wherever it is shown. `summary` is
stored in `advisory` and selected by nothing, so no GHSA text is displayed today. The
obligation attaches the first time a verdict renders one.
