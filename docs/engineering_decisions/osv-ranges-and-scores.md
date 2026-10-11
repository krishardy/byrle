# OSV version ranges and CVSS scores

- **Status:** Implemented. `src/intel/range.rs` (intervals), `src/intel/providers/osv/mod.rs` (GHSA
  records, scores), `src/intel/rows.rs` (the row types), `migrations/0002_ranges.sql`, `PackageIntel::for_version` in `src/intel/store.rs`,
  `Advisory::is_named` in `src/policy/decide.rs`.
- **Related:** [pep440-version-order](pep440-version-order.md), which orders PyPI's versions
  by PEP 440; this file is npm's SemVer order.
  [osv-malware-load](osv-malware-load.md),
  [intel-in-decisions](intel-in-decisions.md),
  [advisory-stream-licences](advisory-stream-licences.md)

## Decision

`byrle refresh` loads OSV's npm `GHSA-` records beside its `MAL-` records. Version ranges are
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
evaluation, run once at load. The sort is stable, so events at one version keep the
record's order. An `introduced` inside an open interval changes nothing, and an end with
no interval open is ignored. `0` means "before the first version" only as `introduced`. The loader has no list of a package's versions to expand an
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
| Comparator | `semver` 1.0, strict SemVer 2.0 | OSV `SEMVER` ranges are SemVer 2.0 |
| A range or listed version such as `13.0` or `2026.04.1` | padded by `range::padded` and stored padded: `13.0.0`, `2026.4.1` | see [Short and zero-padded versions](#short-and-zero-padded-versions) |
| A range containing a version that is not SemVer once padded, such as `1.0.0rc1` | not stored, counted in `unexpressed` | none is in the data. osv.dev refuses it too |
| A listed version that is not SemVer once padded | stored as written | |
| Build metadata | removed before comparing | SemVer 2.0 gives it no precedence and `semver` compares it |
| A packument version that is not SemVer | in no range. Still matches a listed version and every version | none seen: 0 in 103 packages. `express` lists `3.0.0-rc1`, and only its tarball name spells `3.0.0rc1` |
| A stored range that does not parse | `IntelError::Range`, a 503 | the loader writes none. Matching it against nothing would drop the advisory |
| `limit` events, `GIT` ranges | not stored | no npm record carried either |
| An event object with more than one key | not stored | the schema allows one |

### Short and zero-padded versions

On 2026-09-13 the 31 npm `ECOSYSTEM` ranges in 28 `GHSA-` records held 17 versions that are not
SemVer, and `total4` listed `12.0` in 2 records. Every one is short or zero-padded, and none is
published. The registry, asked on 2026-09-15:

| Written | Published |
|---|---|
| `next` `13.0` | `13.0.0` |
| `@solana/web3.js` `1.77`, `1.78`, `1.89`, `1.90` | `1.77.0`, `1.78.0`, `1.89.0`, `1.90.0` |
| `directus` `9.11`, `9.22` | `9.11.0`, `9.22.0` |
| `ckeditor4-dev` `4.16` | `4.16.0` |
| `qwc2` `2025.08.14` | `2025.8.14` |
| `openclaw` `2026.03.28` | `2026.3.28` |
| `@tmlmobilidade/utils` `20260509.0340.15` | `20260509.340.15` |
| `nocodb` `2026.04.1`, `2026.05.1`; `nodebb` `0.70`; `primefaces` `8.0`; `qooxdoo` `1.3`; `servify-express` `1.2`; `total4` `12.0` | no version with those first two numbers |

| Reader | `13.0` | `2026.04.1` | `1.0.0rc1` |
|---|---|---|---|
| osv.dev `semver_index.coerce` | `13.0.0` | `2026.4.1` | refused, sorted above every version |
| osv-scalibr `ParseSemverVersion` | equal to `13.0.0` | equal to `2026.4.1` | `rc1` read as a pre-release |
| node-semver, loose | invalid | `2026.4.1` | `3.0.0-rc1` |
| `range::padded` | `13.0.0` | `2026.4.1` | refused |

`padded` follows osv.dev. The two OSV readers agree on every version in the data. They differ only
on a pre-release with no hyphen, which no npm range contains.

A list and a range beside it are both stored. `MAL-2025-3661` lists `99.9.0` and `99.9.1`
beside `introduced: "99.9.1"`, and a version published into that range after the list was
written is only in the range.

## Scores

| Choice | Value | Why |
|---|---|---|
| What is read | `CVSS_V3` and `CVSS_V4` entries in `severity`, parsed by `cvss` 3.0.0 | no npm record carried another type |
| A record with both (809) | the v4 score | v3 and v4 are different scoring systems. Taking the higher would compare them as one |
| A record with 3.0 and 3.1 | the 3.1 score | the newer version |
| Metrics scored | base metrics only | 313 records also carry others: 309 v4 vectors with `E`, 4 v3 vectors with `E`, `RL` or `RC`. `cvss` counts `E` in a v4 score, where `E:U` lowers it. 2.2.0 refused a v3 vector carrying any; 3.0.0 reads it and scores the base |
| A v3 vector missing a base metric | unread, no score | `cvss` parses `CVSS:3.1/AV:N` and scores it 0.0, which passes every `max_cvss` |
| A base metric given twice | unread, no score | |
| No CVSS vector, only a `database_specific` severity band (689) | the top of the band | decided 2026-09-15, below |
| A vector that does not parse, and a band | unread, no score | the band does not hide a vector that failed |

`cvss` 3.0.0 replaced 2.2.0 on 2026-09-29. Over the 2,201 distinct `CVSS_V3` and `CVSS_V4`
vectors in OSV's npm and PyPI bundles fetched that day, 1,262 of them v4, both versions gave
the same score for 2,187 and refused the same 2. The other 12 are v3.1 vectors with temporal
metrics, which 2.2.0 refused and 3.0.0 scores; `base_vector` removes those metrics before
either parses, so no stored score changes.

A malware record with no score counts toward `known_malware` and is left out of
`advisories`. Any other record with no score is refused by `max_cvss`, below.

### Severity bands, 2026-09-15

GitHub gives every `GHSA-` record a band in `database_specific.severity`. 689 of the 7,052
non-withdrawn npm `GHSA-` records in `npm/all.zip` of 2026-09-15 carry no CVSS vector, only a
band, and until this change `max_cvss` never fired for them. Each is scored at the top of its
band's CVSS v3.1 range:

| Band | Records | CVSS v3.1 range | Score stored |
|---|---|---|---|
| `LOW` | 80 | 0.1 to 3.9 | 3.9 |
| `MODERATE` | 152 | 4.0 to 6.9 | 6.9 |
| `HIGH` | 338 | 7.0 to 8.9 | 8.9 |
| `CRITICAL` | 119 | 9.0 to 10.0 | 10.0 |

| Asked of the user | Chosen |
|---|---|
| A band's score for `max_cvss` | the upper bound, so a threshold inside a band refuses what the band could be |

`max_cvss` refuses a score over the threshold. Under the default 6.9, `MODERATE` passes and
`HIGH` fails, the same as either end of the bands would give. Under 7.5, `HIGH` fails at 8.9
and would pass at 7.0.

Only `LOW`, `MODERATE`, `HIGH` and `CRITICAL` are read. Other text, a number or a
`database_specific` that is not an object scores nothing. None of the 689 is in the KEV
catalogue.

The band is stored in `advisory.severity_band` (migration 0005) and carried to `explain`,
which prints `GHSA-... 8.9 from band HIGH`. The rows encoding carries it as a seventh
`advisory` column, so the format line is `byrle intel rows 2`, and a kept rows file written
as `rows 1` is refused. Nothing had been deployed. `byrle refresh` counts band-scored records
on a line of its own, `scored from a severity band`, already inside `scored`.

Live, 2026-09-15, into an empty Postgres 17 with `examples/policy.yaml` (`max_cvss: 6.9`). Stored,
by band: `LOW` 80 at 3.9, `MODERATE` 152 at 6.9, `HIGH` 338 at 8.9, `CRITICAL` 119 at 10. Then:

```text
$ byrle explain pkg:npm/faker@6.6.6
  max_cvss         FAIL block        over max_cvss 6.9: GHSA-5w9c-rv96-fr7g 8.9 from band HIGH

$ byrle explain pkg:npm/ws@1.1.0
  max_cvss         FAIL block        over max_cvss 6.9: GHSA-5v72-xg48-5rpm 7.5, GHSA-6663-c963-2gqg 8.9 from band HIGH, GHSA-96hv-2xvq-fx4p 7.5

$ byrle explain pkg:npm/ws@1.1.1
  max_cvss         FAIL block        over max_cvss 6.9: GHSA-5v72-xg48-5rpm 7.5, GHSA-96hv-2xvq-fx4p 7.5
```

`faker@6.6.6` passed `max_cvss` before this change: its one advisory had no score.
`GHSA-6663-c963-2gqg` is fixed in 1.1.1, so it leaves `ws` there.

`make mutants` over the change: 57 mutants, 44 caught, 12 unviable, 1 missed: `!` deleted from
`!rows.malware` in `Tally::count`, which the test's one banded malware record and one banded
vulnerability counted the same either way. A second banded vulnerability was added to
`stored_records_are_tallied_by_kind_and_what_they_left_out`, and `cargo mutants --file
src/intel/refresh.rs --re Tally::count` then caught it.

### Advisories with no score, 2026-09-15

A non-malware record with no CVSS vector and no band is stored with `cvss` NULL.
`Facts::with_intel` keeps it in `advisories` with `Advisory::cvss` `None`, and `max_cvss`
refuses it. 0 npm records in `npm/all.zip` of 2026-09-15 are unscored. A malware record with no
score is left out of `advisories`, as `known_malware` refuses it.

| Asked of the user | Chosen |
|---|---|
| An advisory with no score, before an operator scores it | refused by `max_cvss` |
| Where a score is given | the policy file, `advisory_scores` |
| Which advisories | every non-malware one with no vector and no band |
| `version: 1` or `version: 2` | added to `version: 1`, as nothing was deployed |

```yaml
advisory_scores:
  - advisory_id: GHSA-xxxx-xxxx-xxxx
    cvss: 5.3
    reason: vendor advisory scores it 5.3
    expires: "2026-11-30"
```

| Rule | Held by |
|---|---|
| `advisory_id` is matched against the advisory's id and its aliases | `decide::score` |
| An entry is used only while the advisory has no stored score | `decide::score` |
| Two entries naming one advisory, by id and by alias: the higher score | `decide::score` |
| A lapsed entry is not used, and the advisory is unscored again | `AdvisoryScore::in_force` |
| `cvss` is 0.0 to 10.0 | `PolicyError::ScoreOutOfRange` |
| `expires` or `permanent: true`, not both | `PolicyError::UndatedScore`, `PolicyError::BothDatedAndPermanent` |
| One entry per `advisory_id` | `PolicyError::DuplicateScore` |
| `expires` is within the expiry ceiling | `PackageError::TooFarAhead` |

A `vuln_advisory_ids` exception excuses an unscored advisory as it excuses a scored one. `kev`
reads an unscored advisory. Before this change an unscored advisory was left out of
`advisories`, so `kev` never read it. `byrle policy check` lists permanent entries under
`permanent`, and `explain --policy` lists every entry.

An entry has no selector and sets no `Rule`, so `packages::findings` does not compare it and
`PackageError::Tightens` does not apply to it.

Live, 2026-09-15: a refresh into an empty Postgres 17, then the stored score of
`GHSA-5w9c-rv96-fr7g` cleared, so the one advisory against `faker@6.6.6` is unscored. The
policy is `max_cvss: 6.9` and `cooldown_days: 0`.

| `advisory_scores` | `max_cvss` line of `byrle explain pkg:npm/faker@6.6.6` | verdict |
|---|---|---|
| none | `FAIL block over max_cvss 6.9 or unscored: GHSA-5w9c-rv96-fr7g unscored` | block |
| cvss 5.0, expires 2026-10-01 | `pass` | allow |
| cvss 5.0, expires 2026-09-14 | `FAIL block over max_cvss 6.9 or unscored: GHSA-5w9c-rv96-fr7g unscored` | block |
| cvss 8.0, permanent | `FAIL block over max_cvss 6.9: GHSA-5w9c-rv96-fr7g 8.0 from advisory_scores[0]` | block |

With the stored score in place, the same four policies each printed
`GHSA-5w9c-rv96-fr7g 8.9 from band HIGH`, block.

`make mutants` over the change: 53 mutants, 44 caught, 7 unviable, 2 missed.
`!excused.is_empty()` in `explain::found` replaced with `true` survived, as no case had a
`packages` entry that matched and excused nothing. The golden case `over max_cvss, an entry
that excuses none of it` was added, and `cargo mutants --file src/explain.rs --re found` then
caught it. `run_explain` in `main.rs` returning a default exit code survived, as in
[kev-stream](kev-stream.md): no test runs the binary's `explain`.

## `vuln_advisory_ids` exceptions and aliases

A `vuln_advisory_ids` exception names advisories by id, and operators usually know the CVE id.
OSV stores a GitHub advisory under its `GHSA-` id, with the CVE as an alias: 5,972 of 7,052
non-withdrawn `GHSA-` records carry one. `Intel::package` returns each advisory's aliases,
`Advisory` carries them, and `Advisory::is_named` matches the id or any alias.

## `kev`

OSV carries no exploitation data. Until the KEV stream was built, `enforce::unenforceable`
reported `kev` whenever the store answered, and startup warned `NOT ENFORCED: kev` under
`kev: block`. It is now enforced once a snapshot includes `cisa/kev`: see
[kev-stream](kev-stream.md).

## Licence

GHSA text is CC-BY-4.0. `summary` is stored and nothing displays it: `explain` prints advisory
ids and scores. No GHSA record is committed as a fixture. Tests use synthetic `GHSA-0000-...`
ids.

## What is stored, measured

`cargo run --example osv_tally` over `npm/all.zip` fetched 2026-09-13 (214,977,916 bytes):

```
stored: malware                    221217
stored: vulnerability, scored        6363
stored: vulnerability, unscored       689
skipped: withdrawn                    680
skipped: other publisher                2
skipped: no npm package                 0
skipped: nothing storable               0
records                            228951
stored with something left out          0
CVSS vectors unread                     0
affected rows                      233239
ranges                              10357
```

With severity bands read, over `npm/all.zip` fetched 2026-09-15:

```
stored: malware                    221237
stored: vulnerability, scored        7052
scored from a severity band           689
stored: vulnerability, unscored         0
skipped: withdrawn                    681
skipped: other publisher                2
records                            228972
CVSS vectors unread                     0
affected rows                      233274
ranges                              10357
```

Before versions were padded, the 2026-09-13 bundle gave `scored 6340`, `unscored 688`,
`nothing storable 24`, `stored with something left out 4` and `ranges 10326`. `affected rows`
is unchanged: `total4`'s `12.0` became `12.0.0`, one row for one.

Against [osv-malware-load](osv-malware-load.md), the 533 `MAL-` records that needed range
evaluation are stored. The 2 other-publisher records are `EEF-CVE-2026-56812` and
`GSD-2022-1000008`.

## Evidence

Each mutation below was caught.

| Mutation | Caught by |
|---|---|
| A short version not padded | `a_short_or_zero_padded_version_is_padded_as_osv_dev_reads_it`, `a_range_is_stored_and_ordered_by_its_padded_versions`, `a_short_version_in_a_range_or_a_list_is_stored_padded` |
| A fourth number accepted | `a_short_or_zero_padded_version_is_padded_as_osv_dev_reads_it` |
| The padded result not checked as SemVer | the same |
| The pre-release and build dropped | the same |
| Build metadata read as numbers | `build_metadata_does_not_order` |
| A range sorted by its written versions | `a_range_is_stored_and_ordered_by_its_padded_versions`, `a_short_version_in_a_range_or_a_list_is_stored_padded` |
| A range stored as written | the same two |
| A listed version not padded | `a_short_version_in_a_range_or_a_list_is_stored_padded` |
| A listed version that does not pad dropped | the same |
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

Live, 2026-09-13, debug build. `byrle refresh` into Postgres 17 wrote 228,245 advisories,
37,951 aliases, 233,239 affected rows and 10,326 ranges in 46.9s. Policy `version: 1`,
`cooldown_days: 0`, `max_cvss: 7.0`, upstream `registry.npmjs.org`:

| Request | Result |
|---|---|
| packument `lodash` | 200, 2 versions left: `4.18.0`, `4.18.1` |
| tarball `lodash/-/lodash-4.17.21.tgz` | 403, `max_cvss: block` |
| tarball `--hiljson/-/--hiljson-0.0.1-security.tgz` | 403, `known_malware: reported as malware` |

`byrle explain pkg:npm/lodash@4.17.21`:

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

The snapshot id is the one the malware-only load recorded from the same bundle. It hashed the
bundle bytes, not what a build's loader stored from them.
[snapshot-identity](snapshot-identity.md) replaced it with a hash over the stored rows.
