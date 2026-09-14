# Advisory aliases are matched, not merged

- **Status:** Implemented. `intel::is_named` and `Finding::enriched_by` in `src/intel.rs`,
  `Record::finding` in `src/intel/store.rs`, `Advisory::is_named` in `src/policy/decide.rs`.
- **Related:** [osv-ranges-and-scores](osv-ranges-and-scores.md),
  [advisory-stream-licences](advisory-stream-licences.md)

## Decision

An advisory is named by its id or any alias. `intel::is_named` is that match, and both uses
call it:

| Use | Names | Reaches |
|---|---|---|
| `Finding::enriched_by` | an `Enrichment`'s id, such as a KEV entry's `cveID` | the `GHSA-` record carrying that CVE as an alias |
| `Advisory::is_named` | a `vuln_advisory_ids` exception | the same |

Records that share an id by aliases stay separate advisories. `explain` and a refusal
list each.

## Asked of the user, 2026-09-15

| Option | Chosen |
|---|---|
| Match on aliases only | yes |
| Merge records joined by an id or alias: aliases unioned, highest score, malware and exploited if any says so | no |
| Merge only a `GHSA-` record with a `MAL-` record that lists it | no |

## Why not merge

Over `npm/all.zip` fetched 2026-09-13, 228,269 records are stored. 31 groups of them are
joined by ids in their aliases, and in all 31 one record lists another's id.

| Kind | Groups | Affected versions |
|---|---|---|
| `GHSA-` and `GHSA-` | 14 | 9 differ, 5 match |
| `GHSA-` and `MAL-` | 11 | 10 differ; `MAL-` lists versions where `GHSA-` gives ranges |
| `MAL-` and `MAL-` | 6 | 5 share no package, such as a scoped and an unscoped name |

GitHub gives a fix bypass the CVE ids of the advisory it bypasses, and lists each as the
other's alias. They are separate bugs with separate fixed versions:

| Pair | Aliases in common | Each |
|---|---|---|
| lodash `GHSA-xxjr-mmjv-4gpg`, `GHSA-f23m-r3pf-42rh` | CVE-2025-13465, CVE-2026-2950 | `_.unset` pollution, fixed 4.17.23; array path bypass, fixed 4.18.0 |
| fastify `GHSA-mg2h-6x62-wpwc`, `GHSA-247c-9743-5963` | CVE-2025-32442, CVE-2026-33806 | content-type parsing, fixed 5.3.2; leading-space bypass, fixed 5.8.5 |

Merging them would give two bugs one score and one id.

The other reason the TODO gave, "so one vuln never fires three rules", does not occur.
`decide` gives each check one result, whatever number of advisories it reads.

## What matching costs

An enrichment naming a CVE shared by an advisory and its bypass applies to both. For a KEV
entry that marks both exploited, which is the stricter reading.

`migrations/0001_intel.sql` still says an `enrich` stream matches nothing until the
deduplication item lands. sqlx checks each applied migration's checksum, so the comment is
left as it is.

## Evidence

`a_kev_entry_reaches_an_osv_finding_through_its_alias_and_only_through_it` replaces
`an_osv_finding_and_a_kev_entry_do_not_join_on_the_ids_they_carry`, which held the opposite.
`a_row_gives_its_aliases_to_the_finding_so_an_enrichment_keyed_on_one_applies` covers
`Record::finding`.
