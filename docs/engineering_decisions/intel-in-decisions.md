# Intel in decisions: one lookup per package, fail closed

- **Status:** Implemented. `intel_for` in `src/proxy.rs`, `PackageIntel` and `Intel::package`
  in `src/intel/store.rs`, `Facts::with_intel` in `src/policy/facts.rs`,
  `intel::postgres::from_env` and `src/startup.rs`.
- **Related:** [osv-malware-load](osv-malware-load.md),
  [deferral-status-codes](deferral-status-codes.md),
  [storage-sqlx-postgres](storage-sqlx-postgres.md)

## Decision

With a policy and `BYRLE_DATABASE_URL` both set, every decision the proxy makes consults
the intel store:

| Store | Proxy answers | `known_malware`, `kev`, `max_cvss` |
|---|---|---|
| not configured | as before | dropped as unenforceable, and reported so |
| answers | decides with what the store knows | `known_malware` and `max_cvss` enforced. `kev` enforced once the snapshot includes `cisa/kev`, and dropped as unenforceable before: see [kev-stream](kev-stream.md) |
| holds no snapshot | 503 | not reached |
| holds a snapshot with no stream for the package's ecosystem | 503 | not reached: see [uncovered-ecosystem-fails-closed](uncovered-ecosystem-fails-closed.md) |
| errors | 503 | not reached |

With no policy nothing is enforced and the store is not asked.

`byrle explain` exits 1 and `byrle policy diff` exits 4 when a configured store cannot
answer, rather than print a verdict reached without it. The proxy refuses to start when
`BYRLE_DATABASE_URL` is set and the connection or migration fails.

## Fail closed, with 503

Plan §5 makes a failed intel source fail closed by default. `known_malware` has no
exception, so serving while the store cannot be asked would pass malware through with
nothing to say so. The setting that would make it fail open is not built.

503 rather than 403: plan §5 reserves 5xx for the proxy not being ready, and a 403 reads as
policy refusing a package that may be fine. The body names no cause. The cause is logged,
because a database error can carry the database's address.

## One query per package

`policy_refused_versions` decides every version in a packument, 3,823 for typescript.
`Intel::package` returns every row for a package with the version each names, and
`PackageIntel::for_version` picks the rows for one version. It is one SQL statement, so the
snapshot id and the rows are read from the same committed state, and a refresh cannot land
between them.

## What reaches the engine

`Facts::with_intel` sets `known_malware` from the malware rows and `intel` to `Consulted`,
even when nothing is known against the version, because the store was asked. `advisories`
holds one entry per advisory id, each with its aliases so a `vuln_advisory_ids` exception
can name it by CVE. Two streams reporting one advisory are one entry listing both sources:
the highest score stands, the direction `max_cvss` reads, and either stream's exploitation
marks it. A record with no score is kept with `cvss` `None`, and `max_cvss` refuses it. A
malware record with no score is left out: `known_malware` refuses it already. See
[osv-ranges-and-scores](osv-ranges-and-scores.md).

`enforce::artifact` and `enforce::unenforceable` take the intel state from the caller. Before
this they rebuilt facts from the record alone, which always read `NotConsulted`.

The `Intel` trait returns boxed futures, so `Proxy` holds `Arc<dyn Intel>` and proxy tests
use `FixedIntel`, a store with one fixed reply, with no container. The trait is kept with one
backend so the decision engine is unit-tested with no database. A store that cannot answer
returns an error, not an empty answer: empty means a stream was asked and knew nothing.

`for_version` gives each advisory once per stream. An advisory stored against every version,
a listed version and a range covering it is one answer. Two streams reporting one advisory
are two signals, so the key is the stream and the id.

| `IntelError` | Means |
|---|---|
| `Range` | a stored range does not parse. The loader writes none; matching it against nothing would drop the advisory |
| `Unkeyed` | a row refers to an advisory the load did not key: a loader defect |
| `Unread` | a kept snapshot was not read for this package, so "nothing known" would be wrong |

## Evidence

Live, 2026-09-13. Store loaded by `byrle refresh`, proxy with `version: 1` and
`cooldown_days: 0`, upstream `registry.npmjs.org`:

| Request | Result |
|---|---|
| packument `--hiljson`, every version malware in OSV | 200, 0 of 1 versions left |
| tarball `--hiljson/-/--hiljson-0.0.1-security.tgz` | 403, `known_malware: reported as malware` |
| packument `lodash` | 200, 117 versions |
| tarball `lodash/-/lodash-4.17.21.tgz` | 200 |
| packument `lodash`, database container stopped | 503 |

The audit log line for the pinned refusal:

```
{"path":"pinned","ecosystem":"npm","name":"--hiljson","version":"0.0.1-security","action":"block","checks":["known_malware"],"intel_snapshot":"sha256:cf3822e6036d97297ed303a25fd3330eab20d13671495aea49b5c435f0c3392f"}
```

`byrle explain pkg:npm/--hiljson@0.0.1-security`:

```
  known_malware    FAIL block        reported as malware; this has no exception
  verdict: block
```

Each mutation below was caught by the proxy tests, which run against a fixed-reply store:

| Mutation | Caught by |
|---|---|
| A store with no snapshot serves | `a_store_that_cannot_answer_is_a_503_on_both_paths_and_nothing_is_fetched` |
| A store that errors serves | `a_store_that_cannot_answer_is_a_503_on_both_paths_and_nothing_is_fetched` |
| The pinned path passes no intel to `enforce::artifact` | `known_malware_in_the_store_is_refused_on_a_pinned_fetch` |
| The packument path passes no intel to the filter | `known_malware_in_the_store_is_filtered_from_the_packument` |
| The store is asked when no policy is configured | `without_a_policy_a_store_that_is_down_changes_nothing` |
