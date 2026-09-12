# Advisory stream data licences, and what each stream is worth

- **Status:** Verified Sept 2026, before implementing any stream
- **Plan reference:** §3 intel sources, §10.6
- **Related:** [intel-distribution-fetch-from-origin](intel-distribution-fetch-from-origin.md),
  [nvd-role-and-stream-capabilities](nvd-role-and-stream-capabilities.md)

The plan requires each stream's **data** licence to be checked before it is implemented,
separately from the tooling licence in the same repository, because the two frequently
differ. Checking them turned up a second thing worth recording: the measured volume each
stream actually contributes, which does not match the order the plan lists them in.

## Licences

| stream | tooling | data | attribution |
|---|---|---|---|
| OSV.dev | Apache-2.0 | **not stated; inherited per source** | depends on the source |
| GitHub Advisory (GHSA) | n/a | **CC-BY-4.0** | **required** |
| OSSF Malicious Packages | Apache-2.0 | not separately stated | unclear |
| CISA KEV | n/a | US Government work, 17 USC 105 | none |
| NVD | n/a | **not verified** | not verified |
| Aikido Intel | n/a | **not verified** | not verified |

### OSV carries no licence metadata

An OSV record has `id`, `summary`, `details`, `affected`, `references`, `severity`,
`database_specific` and `aliases`. There is no licence field, checked against a live
record. OSV aggregates, so the terms on any given record are the terms of whichever
source produced it, and the **id prefix is the only hint**: a `GHSA-` record is
CC-BY-4.0 and needs attribution, a `MAL-` record's terms are unstated.

That is a real consequence for any tool that repeats what a record says. Ours is
bounded by [intel-distribution-fetch-from-origin](intel-distribution-fetch-from-origin.md):
we host and redistribute nothing, every stream is fetched from its own origin, so the
obligation that attaches is attribution in what we **display**, not in what we ship.
A verdict that quotes a GHSA summary is quoting CC-BY-4.0 text and has to say so.

### Not verified, and why that is recorded rather than guessed

NVD's terms page did not return its terms to an automated fetch, and Aikido's public API
endpoint returned an empty body to an unauthenticated request. Neither is implemented, and
neither should be until someone reads the terms directly. Recording "not verified" is the
point of the check: a blank in this table is a stream that cannot be built yet.

## What each stream is worth, measured

Against OSV's full npm bundle (`npm/all.zip`, 206 MB) and CISA's KEV catalogue, both
fetched Sept 2026:

| | count |
|---|---|
| npm advisories in OSV | 228,951 |
| of those, malware records (`MAL-`) | **221,548 (96.8%)** |
| of those, real vulnerabilities (`GHSA-`) | 7,401 (3.2%) |
| npm advisories carrying a CVE id | 6,041 |
| distinct npm CVE ids | 6,032 |
| KEV entries, all ecosystems and products | 1,709 |
| **npm CVE ids that appear in KEV** | **13** |

### The npm advisory database is a malware database

96.8% of what OSV holds for npm is `MAL-` records, not CVEs. The `known_malware` check
therefore has 221,548 records to match against while `max_cvss` has 6,041, two orders of
magnitude apart. The plan lists OSV first for "best ecosystem coverage"; the stronger
reason is that it is the malware feed, and the malware feed is almost all of it.

### KEV is an enrichment, and for npm it is nearly a no-op

A KEV entry has `cveID`, `vendorProject`, `product`, `dateAdded`, `dueDate` and prose.
**It has no package identifier of any kind**, checked across all 1,709 entries. Its
contents are operating systems and network appliances: Microsoft 388, Cisco 97, Apple 94,
Adobe 81, Google 74.

Two consequences:

- **KEV can never originate a finding.** It cannot be asked "what is wrong with this
  package", only "is this CVE known to be exploited". That is the `enrich` capability in
  the plan's matrix, the same as NVD, and it should be type-enforced the same way.
- **For npm it reaches 13 CVEs**, out of 1,709 entries and 6,032 npm CVEs. The `kev`
  check is still worth having, because it is an escalation on advisories another stream
  already found and so costs a set lookup, but it should not be built before the two
  checks that have four and five orders of magnitude more to match against.

## Order to implement

1. **OSV malware records.** 221,548 npm records, and the only source for the check that
   cannot be excepted.
2. **OSV and GHSA vulnerability records**, for `max_cvss`. Attribution obligation attaches
   here, so the display path needs it before this ships.
3. **CISA KEV**, last. A set lookup over CVE ids the step above already produced, reaching
   13 npm CVEs today.

NVD and Aikido stay unimplemented until their terms are read by a person.
