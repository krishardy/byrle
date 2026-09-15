# The CISA KEV catalogue is a source of its own, joined at lookup

- **Status:** Implemented. `src/intel/kev.rs`, `migrations/0003_exploited.sql`,
  `load::encode_exploited`, `PgIntel::replace`, `SnapshotIntel::read`,
  `enforce::unenforceable`, `waharoa refresh`.
- **Related:** [alias-matching](alias-matching.md), [snapshot-identity](snapshot-identity.md),
  [advisory-stream-licences](advisory-stream-licences.md),
  [intel-in-decisions](intel-in-decisions.md)

## Decision

`waharoa refresh` fetches CISA's Known Exploited Vulnerabilities catalogue after OSV's npm
bundle and stores its CVE ids as source `cisa/kev` in `exploited_cve`. A lookup marks an
advisory exploited when its `publisher_id` or one of its aliases is listed, the match
`intel::is_named` makes. `kev` is enforced once a snapshot includes `cisa/kev`.

The catalogue is CC0 1.0. An entry gives a `cveID` and no package, and only `cveID` is read.

## Asked of the user, 2026-09-15

| Question | Options | Chosen |
|---|---|---|
| Where the ids are stored | a table of their own, joined at lookup; `advisory.exploited` set at load | a table of their own |
| The catalogue cannot be fetched or read | load OSV, keep the last KEV load, exit 1; fail the refresh | load OSV, keep the last KEV load, exit 1 |
| Kept snapshot files carry the KEV rows | yes; no | yes |

`advisory.exploited` set at load would be cleared by the next OSV load, which deletes
`advisory` rows by source. `exploited_cve` is deleted by source too, so loading either source
leaves the other's rows alone. `advisory.exploited` stays in the schema, `FALSE` on every row,
and the lookup reads it `OR` the join. `migrations/0001_intel.sql` still says only an `enrich`
stream sets it. sqlx checks each applied migration's checksum, so the comment is left as it is.

## Refresh

| Fails | OSV | KEV | Exit |
|---|---|---|---|
| OSV fetch or read | last load stays | last load stays | 1 |
| KEV fetch or read | loaded | last load stays | 1 |
| neither | loaded | loaded | 0 |

When both are read they load in one transaction, `PgIntel::replace`, and record one snapshot.

A catalogue is refused whole when it is not JSON with a `vulnerabilities` list of objects
with `cveID`, when a `cveID` is not `CVE-`, four digits, `-` and at least four digits, when
one is longer than `exploited_cve.cve_id`'s 128 bytes, or when the list is empty. Postgres
refusing a long id would fail the OSV load in the same transaction, so the parser refuses it
first. An empty list would delete every stored id.

The ceiling is 16 MiB, 9.7 times the 1,722,859-byte catalogue of 2026-09-14.

## Encoding

A kept `cisa/kev` rows file is its own format, so the advisory format was left unchanged by it:

```text
waharoa intel exploited 1
source cisa/kev
exploited_cve 47189
(47,189 bytes of CSV)
```

A row is the source and the id, in id order. The manifest lists `cisa/kev` and its digest
beside `osv`, so the snapshot id covers both.

## Where `kev` is reported unenforced

| Store | `enforce::unenforceable` | `explain --policy` |
|---|---|---|
| none | `known_malware`, `kev`, `max_cvss` | `unenforced, no advisory stream` |
| answers, no `cisa/kev` source | `kev` | `unenforced, no exploitation stream` |
| answers, `cisa/kev` loaded | nothing | `enforced` |

`PackageIntel::exploitation_loaded` carries it, and `decide::Intel::Consulted` takes it from
there:

| Reader | Answers from |
|---|---|
| `PgIntel::package` | an `intel_source` row for `cisa/kev`, in the same statement as the rows |
| `SnapshotIntel` | the manifest listing `cisa/kev` |
| `explain --policy` | the newest snapshot's sources including `cisa/kev`, `LoadedSnapshot::exploitation_loaded` |

`explain --policy` read the newest snapshot's streams until 2026-09-15. It matched because KEV's
stream and source are both named `cisa/kev`; OSV's and Datadog's are not (`osv/npm` and `osv`,
`datadog/npm` and `datadog`). A snapshot loaded with no stream recorded for the catalogue gave
`PgIntel::package` true and `explain --policy` false. `SnapshotIntel` and `explain --policy` now
both call `LoadedSnapshot::exploitation_loaded`, which reads `sources`, and `PgIntel::package`
asks `intel_source` in its statement. A kept snapshot records no streams, so streams could not
be the one record.

Live, 2026-09-15, `examples/policy.yaml`: `explain --policy` printed `kev unenforced, no advisory
stream` on an empty store and `kev enforced` after a refresh, and `GET /-/waharoa/ready` answered
200 with `"sources":["cisa/kev","datadog","osv"]`. `make mutants` over the change: 14 mutants, 4
caught, 9 unviable, 1 missed, `run_explain` in `main.rs` returning a default exit code, which
has no unit tests.

Before this, `explain --policy` printed `unenforced, no exploitation stream` for `kev` with no
store at all. It now prints `unenforced, no advisory stream`, the reason `unenforceable` gives.

## What `kev` does not reach

`Facts::with_intel` leaves an advisory with no score out of `advisories`, because
`Advisory::cvss` is a number. An exploited advisory with no score does not fail `kev`. That is
the open unscored-advisories item in TODO.md.

## Evidence

`waharoa refresh` into an empty Postgres 17, 2026-09-15:

```text
advisories written                 228289
aliases written                     37985
affected rows written              233274
ranges written                      10357
exploited CVE ids written            1710
took 30.9s
```

The kept `cisa/kev` rows file is 5,478 bytes gzipped. The listed ids mark 13 stored records
exploited, each by its CVE alias, and each has a score, so none is left out of `advisories`:

| Record | CVSS | Packages |
|---|---|---|
| `GHSA-2m8v-572m-ff2v` | 7.8 | systeminformation |
| `GHSA-399j-vxmf-hjvr` | 9.8 | @react-native-community/cli, @react-native-community/cli-server-api |
| `GHSA-4r4m-qw57-chr8` | 5.3 | vite |
| `GHSA-995f-9x5r-2rcj` | 9.6 | electron |
| `GHSA-c2gp-86p4-5935` | 6.5 | puppeteer |
| `GHSA-f29h-pxvx-f335` | 7.5 | eslint-config-prettier and 5 others |
| `GHSA-fv66-9v8q-g76r` | 10 | react-server-dom-parcel, -turbopack, -webpack |
| `GHSA-g7cv-rxg3-hmpx` | 9.6 | 42 `@tanstack/` packages |
| `GHSA-h47j-hc6x-h3qq` | 9.9 | mongo-express |
| `GHSA-j7hp-h8jx-5ppr` | 8.8 | electron |
| `GHSA-jpcq-cgw6-v4j6` | 6.9 | jquery |
| `GHSA-qqvq-6xgj-jw8g` | 8.8 | electron |
| `GHSA-v98v-ff95-f3cp` | 9.9 | n8n |

With `examples/policy.yaml`, `waharoa explain --policy` prints `kev               enforced`, and:

```text
$ waharoa explain pkg:npm/jquery@3.4.1
  kev              FAIL block        GHSA-jpcq-cgw6-v4j6
  max_cvss         pass
  verdict: block
```

`max_cvss` passes: 6.9 is not over `max_cvss: 6.9`. `EXPLAIN ANALYZE` of `PgIntel::package` for
jquery: 1.5 ms. `exploited_cve` is read by a sequential scan, 0.12 ms per advisory row, because
the `OR` with the alias subquery does not use `exploited_cve_by_cve_id`.

A second refresh with `HTTPS_PROXY` at a closed port and OSV's host in `NO_PROXY`, so only
the catalogue fetch fails:

```text
waharoa refresh: cisa/kev is not loaded, and its last load stays: fetching https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json: error sending request for url (...)
advisories written                 228289
exploited CVE ids written               0
snapshot sha256:351dfb792d8cf70a002968c5dd68496c7a65d75b273ac0636d7827887f10e8e5
refresh exit 1
```

`exploited_cve` still held 1,710 ids, `intel_source` still listed `cisa/kev` with the same
digest, the snapshot id matched the first refresh, and `explain pkg:npm/jquery@3.4.1` still
printed `kev FAIL block`.

| Test | Covers |
|---|---|
| `a_catalogue_marks_the_advisories_it_lists_and_is_replaced_apart_from_osv` | one snapshot for both sources, id and alias matches, OSV reloaded alone, catalogue replaced alone |
| `a_kept_snapshot_answers_as_postgres_does` | kept files and Postgres give the same records and `exploitation_loaded` |
| `a_kept_catalogue_marks_each_advisory_it_lists_by_id_or_alias` | listed versions and ranges marked, a package with no advisory |
| `every_check_refuses_on_a_pinned_fetch_and_filters_the_packument` | `kev` refuses in the proxy on both paths |
| `an_exploited_advisory_refuses_only_once_the_catalogue_is_loaded` | `artifact` with and without the catalogue |
| `one_id_that_is_not_a_cve_id_refuses_the_catalogue` | the id check, at and past 128 bytes |

`make mutants` over the change: 100 mutants, 53 caught, 22 unviable, 25 missed. 14 are in
`main.rs`, which has no unit tests; the refresh and `explain` paths were run live above. 10 are
`+=` counts in `PgIntel::replace`, which `make mutants` tests without a database. With
`WAHAROA_TEST_DATABASE_URL` set, `cargo mutants --file src/intel/postgres.rs --re
PgIntel::replace` caught all 10. The last, `16 << 20` as `16 >> 20` in `MAX_CATALOGUE_BYTES`,
is caught by `the_ceiling_is_sixteen_mebibytes`.
