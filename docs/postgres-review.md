# Postgres review

A performance review of the schema in `migrations/` (0001 to 0029) and the queries against
it, for TODO.md ad-hoc #48. Measured 2026-10-19 at `e32c6a2` on Postgres 18, a local
cluster from `scripts/make/lib/postgres.sh`. Intel came from `byrle refresh` of every stream
but GitHub's, each served from a local copy so the network adds no time. The analysis tables
came from `make bench`'s `npm ci` and `uv pip install` through the proxy. Nothing here is
changed yet: each finding ends with what would change.

## Sizes

After one refresh:

| Table | Rows | Heap | Indexes |
|---|---|---|---|
| `advisory_affected` | 2,322,689 | 174 MB | 219 MB |
| `advisory` | 325,074 | 42 MB | 27 MB |
| `advisory_alias` | 105,381 | 6.8 MB | 11 MB |
| `advisory_range` | 63,667 | 5.6 MB | 7.2 MB |
| every other table | under 1,600 each | under 1 MB each | |

`advisory_affected` by ecosystem: pypi 1,381,531, maven 651,678, npm 286,859, golang 2,459,
cargo 162. A package has 9.5 rows on average. The most is
`org.jenkins-ci.main/jenkins-core`, 125,518 rows over 259 advisories: OSV lists each affected
version.

## 1. A disposition by version reads every decision

`analysis/postgres.rs` `read_dispositions` asks `artifact_disposition` for an
`Artifact::Version`. The view is `SELECT DISTINCT ON (digest) * ... ORDER BY digest, id DESC`
over all of `artifact_decision`, and the version filter is applied after it. `byrle artifact
show <purl>` and `GET /api/v1/artifact` run it.

With 1,000,000 generated decision rows, 1,477 MB, as a year at the default
`BYRLE_DECISION_RETENTION_DAYS` of 365 holds for about 2,700 decisions a day. Each row is a
copy of one real decision's JSON, over 200,000 digests and 20,000 names:

| Query | Time |
|---|---|
| the view, `WHERE ecosystem = $1 AND name = $2 AND version = $3` | 86,581 ms |
| `DISTINCT ON (digest)` over `artifact_decision` with the version filter inside | 0.55 ms |
| the view, `WHERE digest = $1` | 0.04 ms |

The filter inside answers the same rows while each digest names one version. In the 577
real decisions `make bench` wrote, none of the 149 digests names two. Change: filter before `DISTINCT ON`, in the query or in a function the view is
replaced by.

## 2. A package's intel is one row per affected version

`PgIntel::package` is asked once for each metadata document and each artifact the proxy
decides (`intel_for`), and nothing keeps its answer. It returns one row per
`advisory_affected` and `advisory_range` row, each carrying its advisory's columns and alias
array, 481 bytes wide in the plan. The rewrite returns one row per advisory, with its
versions and ranges each `array_agg`ed, and the same snapshot, `exploitation_loaded`, KEV
joins and order. Both read to the end in psql, three runs each, after `VACUUM FULL`:

| Package | Advisories | Rows now | One row per version | One row per advisory |
|---|---|---|---|---|
| maven `org.jenkins-ci.main/jenkins-core` | 259 | 126,027 | 286 to 289 ms | 37 to 38 ms |
| pypi `praisonai` | 207 | 122,620 | 243 to 333 ms | 34 ms |
| pypi `tensorflow` | 860 | 56,693 | 146 to 155 ms | 23 to 26 ms |
| npm `next` | 73 | 177 | 0.9 to 1.4 ms | 0.5 to 0.6 ms |
| npm `lodash` | 10 | 10 | 0.3 to 0.4 ms | 0.1 ms |

For jenkins-core, tensorflow and next, the two answers hold the same count of versions,
ranges and advisories. The proxy also decodes each row it is sent. Change: the rewrite, read
into `PackageIntel` as it is built today.

## 3. A refresh rewrites every row, changed or not

`write_source` deletes every advisory of a source, copies its rows back, then runs
`UPDATE advisory ... SET cached = p.cached` over every advisory to keep its first-seen time.
No source is skipped when its digest is the one `intel_source` holds. Four refreshes of the
same feeds into a new database, autovacuum on:

| After refresh | `advisory` total | its dead rows | `advisory_affected` total | its dead rows | Refresh time |
|---|---|---|---|---|---|
| 1 | 69 MB | 0 | 393 MB | 0 | 21.5 s |
| 2 | 180 MB | 650,148 | 772 MB | 2,322,689 | 32.0 s |
| 3 | 282 MB | 1,299,994 | 1,149 MB | 4,645,378 | 38.1 s |
| 4 | 373 MB | 649,926 | 1,353 MB | 4,647,866 | 38.6 s |

Change: skip a source whose digest matches the one stored, and write `cached` in the copy,
from `prior_cached`, rather than updating each row after it.

## 4. Indexes

| Index | Size | Scans | Finding |
|---|---|---|---|
| `advisory_affected_unique` `(advisory_id, ecosystem, name, COALESCE(version, ''))` | 137 MB | 0 | enforces uniqueness on copy. Its `advisory_id` prefix is what `ON DELETE CASCADE` from `advisory` finds rows by: with no index led by `advisory_id`, `DELETE FROM advisory WHERE source = $1` ran over 10 minutes and was cancelled |
| `advisory_affected_pkey` `(id)` | 50 MB | 0 | no query or foreign key reads `id` |
| `advisory_affected_lookup` `(ecosystem, name)` | 32 MB | 616 | the lookup `package` uses |
| `advisory_alias_by_alias` `(alias)` | 4.6 MB | 0 | no query filters on `alias` |
| `advisory_range_pkey` `(id)` | 1.4 MB | 0 | as `advisory_affected_pkey` |

With the unique indexes led by `(ecosystem, name)`, plain indexes on `advisory_id`, and the
two primary keys and `advisory_alias_by_alias` dropped, after one refresh and `VACUUM FULL`,
`advisory_affected`'s indexes were 162 MB rather than 219 MB, and its total 337 MB rather
than 393 MB. Refresh times over the next three refreshes, 29.0 to 69.2 s, were too noisy to
compare. Change: those indexes, and drop the `id` columns of `advisory_affected` and
`advisory_range`.

## 5. `VARCHAR(n)` and `TEXT`

Postgres stores `VARCHAR(n)`, `VARCHAR` and `TEXT` the same way, and `n` adds only a length
check on write ([the manual](https://www.postgresql.org/docs/18/datatype-character.html)).
Changing one to the other changes neither size nor speed. The schema's widths are a refusal
of an oversized value, such as a 513-character package name. No change.

Smaller types that would save space:

| Column | Today | Smaller | Saving |
|---|---|---|---|
| `ecosystem` in `advisory_affected`, `advisory_range` | `VARCHAR(64)`, 5 bytes average plus 1 | `SMALLINT` or an enum, 2 or 4 | an estimated 7 MB at 2.4 million rows |
| `digest` in the `artifact_*` tables, `<algorithm>:<hex>` | `VARCHAR(128)`, 72 bytes for sha256 | `BYTEA` with an algorithm byte, 33 for sha256, 65 for sha512 | about half of each digest index; the tables hold 1,600 rows today |

Neither is worth a migration at today's sizes.
