# Datadog's npm manifest is a malware source of its own

- **Status:** Implemented. `src/intel/providers/datadog.rs`, `range::stored`, `intel::capabilities_of`,
  `waharoa refresh`.
- **Related:** [advisory-stream-licences](advisory-stream-licences.md),
  [kev-stream](kev-stream.md),
  [nvd-role-and-stream-capabilities](nvd-role-and-stream-capabilities.md),
  [osv-malware-load](osv-malware-load.md)

## Decision

`waharoa refresh` fetches Datadog's npm manifest after the KEV catalogue and stores every
entry as source `datadog`. Each package is one `advisory` row, `publisher_id`
`DATADOG-npm-<name>`, `malware` true, with no score, summary or aliases:

| Manifest entry | `advisory_affected` rows |
|---|---|
| `null`, every version | one, `version` NULL |
| a list of versions | one per version, padded as OSV's listed versions are (`range::stored`) |

The snapshot records the manifest as stream `datadog/npm`, granted `match` and `malware` for
npm. Rows are not merged with OSV's: a package both flag has a `datadog` record and an `osv`
record.

The dataset is Apache-2.0. What it adds to OSV was measured before loading it, in
[advisory-stream-licences](advisory-stream-licences.md).

## Asked of the user, 2026-09-15

| Question | Chosen |
|---|---|
| Datadog flags every version, OSV lists specific versions | both stored, and `waharoa refresh` prints each such package |
| Both flag the same versions | both stored |
| Record id | `DATADOG-npm-<name>`, one record per package |

## Refresh

| Fails | OSV | KEV | Datadog | Exit |
|---|---|---|---|---|
| OSV fetch or read | last load stays | last load stays | last load stays | 1 |
| KEV fetch or read | loaded | last load stays | loaded | 1 |
| Datadog fetch or read | loaded | loaded | last load stays | 1 |
| none | loaded | loaded | loaded | 0 |

What is read loads in one transaction, `PgIntel::replace`, and records one snapshot.

A manifest is refused whole when it is not a JSON object mapping each package to `null` or a list of
strings, when a name is empty, when `DATADOG-npm-<name>` is longer than
`advisory.publisher_id`'s 128 bytes, when a list is empty, when a version is longer than
`advisory_affected.version`'s 255 bytes, or when the object is empty. Postgres refusing a long
value would fail the OSV load in the same transaction, so the parser refuses it first. An
empty manifest would delete every stored record. At commit `8fff54014596` the longest name was
88 bytes and the longest version 22.

The ceiling is 16 MiB, 9.9 times the 1,698,934-byte manifest of 2026-09-14.

## PyPI, 2026-09-19

`datadog/pypi` reads `samples/pypi/manifest.json` the same way, as records
`DATADOG-pypi-<name>` with names PEP 503 normalised. It was 49,739 bytes and listed 1,834
packages, 1,817 at every version. The first refresh to load it reported 840 packages it flags
at every version and `osv/pypi` flags only at some.

## Disagreements

`datadog::disagreements` gives each package Datadog flags at every version that has OSV
malware records, none of them at every version. A listed version and a range both count as
some. A record that is not malware, such as a `GHSA-` vulnerability, is not compared: it says
nothing about which versions are malicious. After the load, `waharoa refresh` prints one line
per package, then the count. Nothing is printed when the manifest was not read.

## Evidence

`waharoa refresh` into an empty Postgres 17, 2026-09-15, manifest sha256
`6e7101a3…bb5d` (commit `8fff54014596`):

```text
advisories written                 276602
aliases written                     37985
affected rows written              284769
ranges written                      10357
exploited CVE ids written            1710
datadog every version, osv some      3079
took 54.4s
```

The same refresh without Datadog wrote 228,289 advisories and 233,274 affected rows in 30.9s
([kev-stream](kev-stream.md)).

| Source | Advisories | Affected rows | Every version | Kept rows file, gzipped |
|---|---|---|---|---|
| `osv` | 228,289 | 233,274 | 206,812 | 5,579,809 bytes |
| `datadog` | 48,313 | 51,495 | 46,242 | 745,547 bytes |

`DATADOG-npm-vant` has 8 rows, 2.13.3 to 4.9.14. The first disagreement lines, and the two
packages measured before loading:

```text
0vulns-dependency-confusion-poc: datadog/npm every version, osv/npm some: MAL-2025-5016
1password-sdk-examples: datadog/npm every version, osv/npm some: MAL-2025-1540
24712-pl5004: datadog/npm every version, osv/npm some: MAL-2026-3361
@lottiefiles/lottie-player: datadog/npm every version, osv/npm some: MAL-2024-10301
@toptal/picasso: datadog/npm every version, osv/npm some: MAL-2025-6038
```

With `examples/policy.yaml`:

```text
$ waharoa explain pkg:npm/vant@2.13.3
  known_malware    FAIL block        reported as malware; this has no exception
  install_scripts  FAIL block        declares an install script
  verdict: block

$ waharoa explain pkg:npm/vant@2.13.2
  verdict: allow

$ waharoa explain pkg:npm/%40lottiefiles/lottie-player@2.0.4
  known_malware    FAIL block        reported as malware; this has no exception
  verdict: block
```

OSV has no record for vant 2.13.3, and lists lottie-player 2.0.5 to 2.0.7, not 2.0.4.
`waharoa refresh` peaked at 612 MB resident, sampled from `/proc/<pid>/status` `VmHWM`.

A second refresh with `HTTPS_PROXY` at a closed port and OSV's and CISA's hosts in
`NO_PROXY`, so only the manifest fetch fails:

```text
waharoa refresh: datadog/npm is not loaded, and its last load stays: fetching https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/manifest.json: error sending request for url (...)
advisories written                 228289
exploited CVE ids written            1710
snapshot sha256:7796cc91f979b1af1704f75e3889320de0c2bd2642cd0f1a24faf2398ba53cb4
refresh exit 1
```

`advisory` still had 48,313 `datadog` rows, `intel_source` still listed `datadog` with the same
digest, the snapshot id matched the first refresh, and `explain pkg:npm/vant@2.13.3` still
printed `known_malware FAIL block`. No disagreement line was printed.

| Test | Covers |
|---|---|
| `each_package_is_one_malware_record_at_every_version_or_its_listed_ones` | ids, `null` as every version, listed versions padded |
| `an_entry_that_would_not_load_refuses_the_manifest` | empty name, id and version at and past their column widths, empty list |
| `a_document_that_is_not_a_manifest_or_lists_nothing_is_refused` | not an object, a value not `null` or a list of strings, an empty object |
| `a_package_datadog_flags_at_every_version_and_osv_only_at_some_is_a_disagreement` | listed and ranged OSV malware records, agreement, a `GHSA-` record ignored, the printed line |
| `each_stream_this_build_loads_is_granted_what_it_may_say_and_no_other_stream_is` | `datadog/npm` granted `match` and `malware` for npm |
| `a_kept_snapshot_answers_as_postgres_does` | a `datadog` source loaded beside `osv` and `cisa/kev`, the same records from kept files |

`make mutants` over the change: 29 mutants, 20 caught, 5 unviable, 4 missed. 3 are in `main.rs`,
which has no unit tests: `run_refresh` returning a default exit code, `optional` returning
`None`, and the exit-0 arm deleted. The two refreshes above exit 0 and 1. The last, `16 << 20`
as `16 >> 20` in `MAX_MANIFEST_BYTES`, is caught by `the_ceiling_is_sixteen_mebibytes`, added
after the run. `cargo mutants --file src/intel/datadog.rs` then gave 20 mutants, 17 caught and
3 unviable.
