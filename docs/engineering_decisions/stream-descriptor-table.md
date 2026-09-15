# Every advisory stream is declared in one table

- **Status:** Implemented. `src/intel/stream.rs`, `intel::capabilities_of`, `waharoa refresh`.
- **Related:** [nvd-role-and-stream-capabilities](nvd-role-and-stream-capabilities.md),
  [kev-stream](kev-stream.md),
  [datadog-stream](datadog-stream.md),
  [osv-malware-load](osv-malware-load.md),
  [ingestion-history](ingestion-history.md)

## Decision

One `Stream` per advisory stream, in `intel::stream::ALL`. A descriptor holds what a refresh
needs to know before it fetches, and how to read the bundle once it has one:

| Field | Holds |
|---|---|
| `source` | the name a row is stored under |
| `stream` | the name a snapshot records the bundle under |
| `url` | where the bundle is fetched from |
| `ceiling` | bytes past which the fetch is refused |
| `requirement` | `Required` or `Optional` |
| `grants` | what the stream may say, per ecosystem |
| `parse` | the bundle's bytes as `Parsed { payload, tally }` |

`waharoa refresh` loops over `ALL` in order. `intel::capabilities_of` reads `grants`. Neither
holds a branch naming a stream.

`Requirement` is what the refresh does when a stream does not load:

| Requirement | A stream that does not fetch or parse |
|---|---|
| `Required` | nothing loads, the streams after it are not fetched, exit 1 |
| `Optional` | that stream's last load stays, the others load, exit 1 |

OSV is the one `Required` stream and is first in `ALL`, held by
`exactly_one_stream_is_required_and_it_is_the_first`. It carries every vulnerability and
malware record the proxy matches on, so a refresh without it would replace the store with the
catalogues alone.

`Payload` is the two shapes a load encodes:

| Payload | Encoded by | Child tables |
|---|---|---|
| `Advisories(Vec<Rows>)` | `load::encode` | `advisory_alias`, `advisory_affected`, `advisory_range` |
| `Exploited(BTreeSet<String>)` | `load::encode_exploited` | none |

`Payload::rows` is empty for `Exploited`, which is what `PgIntel::replace` already expected of
a catalogue.

## Fetching stays in `waharoa refresh`

A fetch is network I/O. Everything a descriptor holds is decidable from the bytes, so the
library is unit-testable with no network and `src/intel/stream.rs` is at 100% lines. The
binary keeps the parts that need a socket, a database and a clock: the HTTP client, the
byte-ceiling enforcement, the transaction and the printing.

`waharoa refresh` also keeps the reporting that no single stream can produce.
`datadog::disagreements` compares OSV's rows to Datadog's, so it belongs to neither
descriptor. `Parsed::tally` is `Some` only for OSV, which counts records as it reads them;
`None` for a catalogue and a manifest, which count nothing. A stream that counts nothing
prints nothing rather than a row of zeros.

## Mirroring is not here

The item this closed read "fetch / mirror / refresh / normalize". Serving a stream from a
local copy is tracked separately, under "Local mirrors for all streams" in `TODO.md`, and no
descriptor field names a mirror.

## Consequences

Adding a stream is a descriptor and a `parse` shim. `capabilities_of` picks up its grants with
no edit, because it reads the same table the refresh loops over. Before this, a stream name
appeared in a `match` arm in `intel::capabilities_of` and again in a hand-written branch in
`run_refresh`, and the two could disagree.

A stream this build does not declare is granted nothing: `by_stream` returns `None` and
`capabilities_of` adds no grant. That is what a snapshot recording `osv/pypi` gets from an npm
build, held by
`each_stream_this_build_loads_is_granted_what_it_may_say_and_no_other_stream_is`.

`source` and `stream` are separate fields because they differ for OSV (`osv` and `osv/npm`) and
for Datadog (`datadog` and `datadog/npm`). They are the same string for KEV, `cisa/kev`, which
snapshots and the ingestion history already record.

## Tests

| Test | Covers |
|---|---|
| `exactly_one_stream_is_required_and_it_is_the_first` | the invariant the refresh loop relies on |
| `a_stream_this_build_does_not_declare_is_not_found` | `ALL` in order, an undeclared stream |
| `kev_stores_and_records_under_the_same_name` | `source` and `stream` both `cisa/kev` |
| `each_stream_declares_the_url_and_ceiling_its_module_gives` | no URL or ceiling restated in the table |
| `the_osv_bundle_parses_to_advisories_and_a_tally` | the OSV shim, 7 records, 1 withdrawn, 6 rows |
| `advisories_encode_as_advisories_and_carry_the_rows_the_child_tables_are_built_from` | the Datadog shim, `Kind::Advisories` |
| `exploited_ids_encode_as_exploited_and_have_no_rows` | the KEV shim, `Kind::Exploited`, no rows |
| `a_bundle_that_does_not_read_gives_the_error_as_a_string` | each shim's error as `NotLoaded::error` |

## Evidence

Three refreshes against one Postgres 17, 2026-09-16, OSV's npm bundle 215,055,714 bytes.

All three streams load:

```text
waharoa refresh: fetching https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
waharoa refresh: fetching https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
waharoa refresh: fetching https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/manifest.json
advisories written                 276639
aliases written                     37988
affected rows written              284811
ranges written                      10359
exploited CVE ids written            1710
datadog every version, osv some      3080
snapshot sha256:1f05d26920e43ef2124e0ad4d5cf990a8d5b603747cd25bb1e36bfbdaebd99a9
took 62.6s
refresh exit 0
```

The three fetch lines are in `ALL`'s order. `advisory` held 228,323 `osv` rows and 48,316
`datadog` rows, and `exploited_cve` held 1,710.

`HTTPS_PROXY` at a closed port, so the OSV fetch fails:

```text
waharoa refresh: fetching https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
waharoa refresh: nothing loaded: fetching https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip: error sending request for url (...)
refresh exit 1
```

One fetch line. The KEV catalogue and the Datadog manifest were not fetched, which is what
`Requirement::Required` is for: the refresh stops rather than downloading bundles it will not
load. `advisory` still held 228,323 `osv` and 48,316 `datadog` rows, and `exploited_cve` 1,710.

The same proxy with OSV's and CISA's hosts in `NO_PROXY`, so only the manifest fetch fails:

```text
waharoa refresh: datadog/npm is not loaded, and its last load stays: fetching https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/manifest.json: error sending request for url (...)
advisories written                 228323
aliases written                     37988
affected rows written              233313
ranges written                      10359
exploited CVE ids written            1710
snapshot sha256:1f05d26920e43ef2124e0ad4d5cf990a8d5b603747cd25bb1e36bfbdaebd99a9
took 60.1s
refresh exit 1
```

OSV and KEV loaded, 228,323 advisories rather than 276,639. `advisory` still held 48,316
`datadog` rows, so Datadog's last load stayed, and the snapshot id matched the first refresh:
the manifest that was not fetched was the one already stored. No disagreement line was
printed, because `datadog::disagreements` needs both streams' rows.

| Refresh | OSV | KEV | Datadog | Fetches | Exit |
|---|---|---|---|---|---|
| none fails | loaded | loaded | loaded | 3 | 0 |
| OSV fetch fails | last load stays | last load stays | last load stays | 1 | 1 |
| Datadog fetch fails | loaded | loaded | last load stays | 3 | 1 |

The first two rows restate [datadog-stream](datadog-stream.md)'s refresh table, measured
again after the loop replaced the hand-written branches.

## Mutants

`make mutants` over the change: 9 mutants, 4 caught, 3 unviable, 2 missed. Both missed are in
`src/main.rs`, which has no unit tests; `scripts/make/coverage.sh` says why.

| Missed | What it changes | What showed it |
|---|---|---|
| `main.rs:710` `run_refresh` returns `Default::default()` | every refresh exits 0 | the two refreshes above exit 1 |
| `main.rs:877` `l.source == source` becomes `!=` | `rows_of` returns another stream's rows | `datadog every version, osv some` printed 3080, and is 0 when the rows are swapped |

The three unviable mutants are `Payload::encode`, `Payload::rows` and `by_stream` replaced with
`Default::default()`, which does not compile: `Encoded`, `Rows` and `Stream` have no `Default`.
