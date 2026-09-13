# OSV version ranges and CVSS scores

- **Status:** Implemented. `src/intel/range.rs` (intervals), `src/intel/osv.rs` (GHSA records,
  scores), `migrations/0002_ranges.sql`, `PackageIntel::for_version` in `src/intel/store.rs`,
  `Advisory::is_named` in `src/policy/decide.rs`.
- **Related:** [osv-malware-load](osv-malware-load.md),
  [intel-in-decisions](intel-in-decisions.md),
  [advisory-stream-licences](advisory-stream-licences.md)

## Decision

`waharoa refresh` loads OSV's npm `GHSA-` records beside its `MAL-` records. Version ranges are
stored as intervals and evaluated when a package is looked up. Each record is scored from its
CVSS vector into `advisory.cvss`. With a store configured, `max_cvss` is enforced and `kev` is
reported unenforced.

## Ranges

| npm entry shape | Stored as |
|---|---|
| a range that is every version, such as `introduced: "0"` alone | `advisory_affected`, `version` NULL, and nothing else from the entry |
| a `versions` list | `advisory_affected`, one row per version |
| any other range, with or without a list | `advisory_range`, one row per interval |

A range's events are sorted by version. `introduced` opens an interval, the next `fixed` or
`last_affected` closes it, and one left open has no upper bound. That is the OSV schema's
evaluation, run once at load. The loader has no list of a package's versions to expand an
interval against, and Postgres does not order SemVer, so intervals are compared in Rust over
the rows `Intel::package` returns. `Intel::lookup`, which only tests call, is now
`for_version` over `package` too.

`package` is what the proxy already asks once per package. Against the store loaded
2026-09-13, `EXPLAIN ANALYZE` uses `advisory_affected_lookup` and `advisory_range_lookup` for
both packages below:

| Package | Rows returned | Execution time |
|---|---|---|
| `lodash` | 10 | 0.44 ms |
| `openclaw`, the most rows of any npm package | 591 | 6.3 ms |

| Choice | Value | Why |
|---|---|---|
| Comparator | `semver` 1.0, strict SemVer 2.0 | OSV `SEMVER` ranges are SemVer 2.0. The 31 npm `ECOSYSTEM` ranges all hold versions such as `13.0` and `2026.04.1` |
| A range holding a version that is not SemVer | not stored, counted in `unexpressed` | reading it needs a second comparator |
| Build metadata | removed before comparing | SemVer 2.0 gives it no precedence and `semver` compares it |
| A packument version that is not SemVer, such as `3.0.0rc1` | in no range. Still matches a listed version and every version | |
| A stored range that does not parse | `IntelError::Range`, a 503 | the loader writes none. Matching it against nothing would drop the advisory |
| `limit` events, `GIT` ranges | not stored | no npm record carried either |
| An event object with more than one key | not stored | the schema allows one |

A list and a range beside it are both stored. `MAL-2025-3661` lists `99.9.0` and `99.9.1`
beside `introduced: "99.9.1"`, and a version published into that range after the list was
written is only in the range.

## Scores

| Choice | Value | Why |
|---|---|---|
| What is read | `CVSS_V3` and `CVSS_V4` entries in `severity`, parsed by `cvss` 2.2.0 | no npm record carried another type |
| A record with both (809) | the v4 score | v3 and v4 are different scoring systems. Taking the higher would compare them as one |
| A record with 3.0 and 3.1 | the 3.1 score | the newer version |
| Metrics scored | base metrics only | 313 records also carry others: 309 v4 vectors with `E`, 4 v3 vectors with `E`, `RL` or `RC`. `cvss` counts `E` in a v4 score, where `E:U` lowers it, and refuses a v3 vector carrying any |
| A v3 vector missing a base metric | unread, no score | `cvss` parses `CVSS:3.1/AV:N` and scores it 0.0, which passes every `max_cvss` |
| A base metric given twice | unread, no score | |
| No CVSS vector, only a `database_specific` severity band (688) | no score | a band is not a number |

An unscored record still counts toward `known_malware` and is left out of `advisories`, so
`max_cvss` cannot fire for it.

## `vuln_advisory_ids` exceptions and aliases

A `vuln_advisory_ids` exception names advisories by id, and operators usually know the CVE id.
OSV stores a GitHub advisory under its `GHSA-` id, with the CVE as an alias: 5,972 of 7,052
non-withdrawn `GHSA-` records carry one. `Intel::package` returns each advisory's aliases,
`Advisory` carries them, and `Advisory::is_named` matches the id or any alias.

## `kev`

No stream the store loads marks an advisory exploited. OSV carries no exploitation data and
the CISA KEV stream is not built. `enforce::unenforceable` reports `kev` whenever the store
answers, `explain --policy` prints `unenforced, no exploitation stream`, and startup warns
`NOT ENFORCED: kev` under `kev: block`.

## Licence

GHSA text is CC-BY-4.0. `summary` is stored and nothing displays it: `explain` prints advisory
ids and scores. No GHSA record is committed as a fixture. Tests use synthetic `GHSA-0000-...`
ids.

## What is stored, measured

`cargo run --example osv_tally` over `npm/all.zip` fetched 2026-09-13 (214,977,916 bytes):

```
stored: malware                    221217
stored: vulnerability, scored        6340
stored: vulnerability, unscored       688
skipped: withdrawn                    680
skipped: other publisher                2
skipped: no npm package                 0
skipped: nothing storable              24
records                            228951
stored with something left out          4
CVSS vectors unread                     0
affected rows                      233239
ranges                              10326
```

Against [osv-malware-load](osv-malware-load.md), the 533 `MAL-` records that needed range
evaluation are stored. The 2 other-publisher records are `EEF-CVE-2026-56812` and
`GSD-2022-1000008`. The 24 records storing nothing hold only ranges with versions that are not
SemVer.

## Evidence

Each mutation below was caught.

| Mutation | Caught by |
|---|---|
| `fixed` includes itself | `fixed_excludes_itself_and_last_affected_includes_itself` |
| `last_affected` excludes itself | `fixed_excludes_itself_and_last_affected_includes_itself` |
| Build metadata kept | `build_metadata_does_not_order` |
| Events not sorted | `events_are_sorted_before_they_pair` |
| A second `introduced` moves the open interval's start | `a_second_introduced_inside_an_open_interval_changes_nothing` |
| Every range type read | `ecosystem_ranges_are_read_and_git_ones_are_not` |
| Every version does not subsume the rest of the entry | `every_version_subsumes_a_list_beside_it` |
| Intervals not stored | `a_bounded_range_alone_is_stored_as_that_range` |
| v3 taken over v4 | `a_v4_score_is_taken_over_a_v3_one_in_either_order` |
| Incomplete v3 vector scored | `a_vector_that_does_not_parse_is_counted_and_scores_nothing` |
| Non-base metrics kept | `threat_and_temporal_metrics_do_not_change_the_base_score` |
| A repeated base metric accepted | `a_base_metric_given_twice_is_unread` |
| `GHSA` without the dash read | `the_id_prefix_decides_malware_and_whether_the_record_is_read` |
| `vuln_advisory_ids` ignores aliases | `an_advisory_may_be_ignored_by_an_alias` |
| Ranges ignored by `for_version` | `a_version_sees_the_ranges_holding_it_once_each` |
| An advisory matched twice returned twice | `a_version_sees_the_ranges_holding_it_once_each` |
| Score not written to CSV | `a_score_is_written_as_the_number_it_is` |
| `fixed` and `last_affected` columns swapped | `each_interval_is_one_row_with_its_end_in_the_column_that_names_it` |
| `kev` reported enforced when the store answers | `a_consulted_store_leaves_every_intel_check_but_kev_enforced` |
| `explain --policy` reports `kev` enforced | `the_policy_view_lists_settings_and_entries` |
| Tally counts malware as scored | `stored_records_are_tallied_by_kind_and_what_they_left_out` |
| Tally does not count partly stored records | `stored_records_are_tallied_by_kind_and_what_they_left_out` |
| Range rows read as every version (Postgres) | `a_loaded_range_is_found_for_the_versions_inside_it` |
| A stored range that does not parse read as every version (Postgres) | `a_stored_range_that_does_not_parse_is_an_error_not_an_empty_answer` |
| Range rows not copied (Postgres) | `a_version_published_into_a_range_after_the_list_was_written_is_found` |
| Aliases not read back (Postgres) | `a_vulnerability_record_loads_with_its_score_and_aliases` |

Live, 2026-09-13, debug build. `waharoa refresh` into Postgres 17 wrote 228,245 advisories,
37,951 aliases, 233,239 affected rows and 10,326 ranges in 46.9s. Policy `version: 1`,
`cooldown_days: 0`, `max_cvss: 7.0`, upstream `registry.npmjs.org`:

| Request | Result |
|---|---|
| packument `lodash` | 200, 2 versions left: `4.18.0`, `4.18.1` |
| tarball `lodash/-/lodash-4.17.21.tgz` | 403, `max_cvss: block` |
| tarball `--hiljson/-/--hiljson-0.0.1-security.tgz` | 403, `known_malware: reported as malware` |

`waharoa explain pkg:npm/lodash@4.17.21`:

```
  kev              unenforced        no exploitation stream is loaded, so no advisory is marked exploited
  max_cvss         FAIL block        GHSA-f23m-r3pf-42rh 6.5, GHSA-r5fr-rjxr-66jc 8.1, GHSA-xxjr-mmjv-4gpg 7.9
  verdict: block
```

`GHSA-r5fr-rjxr-66jc` is `introduced: 4.0.0, fixed: 4.18.0`, a range with no `versions` list.
`GHSA-xxjr-mmjv-4gpg` carries a v3 vector scoring 6.5 and a v4 vector with `E:P`, and 7.9 is
the v4 base score. With `vuln_advisory_ids: [CVE-2021-23337]`, an alias of `GHSA-r5fr-rjxr-66jc`, the
verdict stays `block` on `GHSA-xxjr-mmjv-4gpg` 7.9.

The audit line for the lodash refusal:

```
{"path":"pinned","ecosystem":"npm","name":"lodash","version":"4.17.21","action":"block","checks":["max_cvss"],"unenforceable":["kev"],"intel_snapshot":"sha256:cf3822e6036d97297ed303a25fd3330eab20d13671495aea49b5c435f0c3392f"}
```

The snapshot id is the one the malware-only load recorded from the same bundle. It hashes the
bundle bytes, not what a build's loader stored from them.
