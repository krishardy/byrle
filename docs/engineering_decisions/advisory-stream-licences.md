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
| OSV.dev | Apache-2.0 | **per source, all permissive** | depends on the source |
| GitHub Advisory (GHSA) | n/a | **CC-BY-4.0** | **required** |
| OSSF Malicious Packages | Apache-2.0 | **Apache-2.0** | notice retention |
| CISA KEV | n/a | **CC0 1.0** | none |
| NVD | n/a | **public domain** | none |
| Aikido Intel | n/a | **commercial account required** | n/a, deferred |

### OSV's sources, and which two reach npm

OSV publishes the per-source licences at <https://google.github.io/osv.dev/data/>. Read
2026-09-13; every one is permissive.

| source | licence | attribution |
|---|---|---|
| GitHub Advisory Database | CC-BY-4.0 | yes |
| PyPI Advisory Database | CC-BY-4.0 | yes |
| Go Vulnerability Database | CC-BY-4.0 | yes |
| Python Software Foundation Database | CC-BY-4.0 | yes |
| Erlang Ecosystem Foundation CNA | CC-BY-4.0 | yes |
| OSS-Fuzz | CC-BY-4.0 | yes |
| Ubuntu | CC-BY-SA-4.0 | yes |
| OpenSSF Malicious Packages | Apache-2.0 | no |
| RConsortium Advisory Database | Apache-2.0 | no |
| Bitnami Vulnerability Database | Apache-2.0 | no |
| Rust Advisory Database | CC0-1.0 | no |
| Global Security Database | CC0-1.0 | no |
| Haskell Security Advisories | CC0-1.0 | no |
| opam | CC0-1.0 | no |
| Drupal Advisory Database | MIT | no |
| AlmaLinux | MIT | no |
| Rocky Linux | BSD | no |

Converted sources (Debian Security Advisories, Alpine SecDB, NVD CVEs) do not state
licences on that page. None is an npm source.

**Four of these reach npm, and two are stored.** The 228,951 npm advisories measured below
are 221,548 `MAL-` (OpenSSF Malicious Packages, Apache-2.0), 7,401 `GHSA-` (GitHub Advisory
Database, CC-BY-4.0), and one record each from two other sources, identified 2026-09-15:

| id | source | licence | npm entry | the same package in a loaded record |
|---|---|---|---|---|
| `EEF-CVE-2026-56812` | Erlang Ecosystem Foundation CNA | CC-BY-4.0 | `phoenix`, 4 ranges | `GHSA-63mc-hw7g-86rr`, the same 4 ranges; each lists the other as an alias |
| `GSD-2022-1000008` | Global Security Database | CC0 1.0 | `faker.js`, no version and no range | `GHSA-5w9c-rv96-fr7g` lists `faker` 6.6.6 |

`osv::parse` skips both as `Skipped::OtherPublisher`, so neither is stored or displayed.

So for npm: **attribution is owed on GHSA text and nothing else that is stored.** Ubuntu's CC-BY-SA-4.0
is the only share-alike term in the list and it is an operating-system source, so it
cannot reach an npm verdict. If a Linux-distribution ecosystem is ever added, share-alike
has to be looked at again before any OSV text is displayed.

### OSV carries no licence metadata

An OSV record has `id`, `summary`, `details`, `affected`, `references`, `severity`,
`database_specific` and `aliases`. There is no licence field, checked against a live
record. OSV aggregates, so the terms on any given record are the terms of whichever
source produced it, and the **id prefix is the only hint**: a `GHSA-` record is CC-BY-4.0
and needs attribution, a `MAL-` record is Apache-2.0 and does not.

That mapping is sound for npm because its four sources have four disjoint prefixes. No code
decides an obligation from a prefix: `osv::parse` reads `MAL-` and `GHSA-` records and skips
the rest. It does not generalise: a `CVE-` record could come from several of the sources
above under different terms. Any code that decides an obligation from a prefix has to be
scoped to npm, or read `database_specific` instead.

That is a real consequence for any tool that repeats what a record says. Ours is
bounded by [intel-distribution-fetch-from-origin](intel-distribution-fetch-from-origin.md):
we host and redistribute nothing, every stream is fetched from its own origin, so the
obligation that attaches is attribution in what we **display**, not in what we ship.
A verdict that quotes a GHSA summary is quoting CC-BY-4.0 text and has to say so.

### Verified by reading, not by fetching

OSSF Malicious Packages and CISA KEV were read by a person (2026-09-13). Both moved off
"unclear":

- **OSSF is Apache-2.0 on the data, not only the tooling.** That settles the terms on the
  `MAL-` records, which are 96.8% of the npm advisories measured below, and clears the
  first stream in the order below to be built.
- **CISA KEV is CC0 1.0**, an explicit public-domain dedication rather than the 17 USC 105
  inference recorded here before. It removes the question of what covers the compiled
  catalogue as opposed to the US-authored works in it. No attribution is owed.
- **NVD is public domain.** It compiles from other sources and asserts no licence of its
  own, so nothing is owed. What we would take from it is CVSS scores, which are NIST's own
  analysis rather than text carried over from a source, so the compiled-from-elsewhere
  point does not reach our use of it.

### Aikido Intel is not a free public feed

Its public API endpoint returned an empty body to an unauthenticated request because there
is no unauthenticated access to have: Aikido Intel requires a commercial account. The plan
had it listed as "free, public, no account", which was wrong.

It is deferred to post-v1, to be revisited after launch when there is a running project to
approach them about sponsorship with. The plan's thesis was partly resting on it and no
longer does: what supports the claim that competitive coverage can be assembled from free
feeds is OSSF's 221,548 npm malware records, measured below.

Every stream that remains in the plan is licence-cleared. Licensing has stopped being what
gates the intel layer.

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

96.8% of what OSV holds for npm is `MAL-` records, not vulnerability advisories. The `known_malware` check
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
  the plan's matrix, the same as NVD. `src/intel.rs` enforces this: `EnrichStream`
  returns `Enrichment`, which is a different type from `Finding` with no conversion to it,
  and is asked about advisory ids rather than about a package.
- **For npm it reaches 13 CVEs**, out of 1,709 entries and 6,032 npm CVEs. The `kev`
  check is still worth having, because it is an escalation on advisories another stream
  already found and so costs a set lookup, but it should not be built before the two
  checks that have four and five orders of magnitude more to match against.

## Order to implement

1. **OSV malware records.** 221,548 npm records, and the only source for the check that
   cannot be excepted. Licence-cleared: Apache-2.0 via OSSF.
2. **OSV and GHSA vulnerability records**, for `max_cvss`. Attribution obligation attaches
   here, so the display path needs it before this ships.
3. **CISA KEV**, last. A set lookup over CVE ids the step above already produced, reaching
   13 npm CVEs today. Licence-cleared: CC0 1.0, nothing owed.

NVD is cleared and unimplemented. Aikido is deferred to post-v1: it requires a commercial
account, so it cannot be a dependency of the launch.

## What the capability types are worth today

Nothing yet. Of the three capabilities, `match` and `malware` are what OSV provides, and
`enrich`, the one the type separation exists to constrain, has no implemented producer.
NVD and KEV are both cleared to be built and both are `enrich`, so that changes: the
constraint stops being hypothetical as soon as either lands. The separation is built now
because retrofitting it after three streams share a record type is more work than starting
with two types.

## Scores are refused rather than clamped

`Score::new` accepts 0.0 to 10.0 and returns `None` for anything else, NaN and both
infinities included. The finding survives without a score; only the number is dropped.

The reason is order independence, not tidiness. Every comparison against NaN is false, so
an unvalidated NaN passed through `>` stays wherever it lands first: `[NaN, 9.0]` settles
on NaN, `[9.0, NaN]` on 9.0. Four kani proofs in `src/intel.rs` cover this: that nothing
out of range is accepted, that any two accepted scores stand in exactly one relation, that
two enrichments in either order reach the same score, and that enrichment never lowers one.

Clamping was rejected. A NaN has no defensible direction to clamp in, and clamping 99.9
down to 10.0 would invent the one value that blocks everything.
