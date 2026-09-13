# waharoa — Open Source Dependency Firewall

> **Working name: `waharoa`** — te reo Māori for the carved gateway of a pā, literally
> the *long entrance*. The metaphor is exact: the gate you pass through before you are
> inside the walls.
>
> ✅ **Registry availability VERIFIED (Sept 2026).** Checked by direct exact-name lookup,
> which is definitive in a way search never is. All four return 404: `crates.io`, the npm
> registry, PyPI, and the `waharoa` GitHub org. Known-existing names were checked in the
> same run and return 200, so the 404s are real absences rather than a broken probe; the
> same probe confirms the npm `yett` collision noted below. Only known collision is the
> Waikato town, which will not compete in technical search results.
>
> ⚠ **Cultural check outstanding.** A waharoa is often the most significant carving on a
> marae, so this is not neutral vocabulary. Worth running past someone with standing to
> advise — not as box-ticking, but because the difference between a name that lands well
> and one that reads as appropriation is context a dictionary will not give you.
>
> **Ruled out, with reasons — do not relitigate:**
> - **portcullis** — crowded, and crowded in this exact neighbourhood. Docker ships a
>   `portcullis` secrets-redaction library; `imjasonh/portcullis` is a CLI that verifies
>   trust via Sigstore/Rekor before execution (conceptually adjacent enough to confuse);
>   Portcullis Labs is Cisco's EMEA security R&D arm. The GitHub org handle is taken.
> - **waha** (the root word, *mouth/entrance*) — `devlikeapro/waha`, a WhatsApp HTTP API,
>   is an established self-hosted server tool distributed via Docker with its own domain
>   and docs site. Different ecosystem, but the same distribution channel and better SEO.
> - **anything containing "-gate"** — the scandal suffix has gone international.
> - **pkggate** — already an existing OSS competitor (see §2).
>
> **Fallback shortlist**, if waharoa fails a check: `yett` (Scots, the iron lattice gate
> of a tower house — but an npm package of that name exists, a third-party script
> execution controller, uncomfortably adjacent), `ravelin`, `barmkin`, `merlon`,
> `cordon`.

A self-hosted proxy that evaluates packages against a security policy **before** they
are downloaded, extracted, or executed. Blocks known malware and policy violations
across multiple package ecosystems from a single YAML configuration.

---

## 1. Problem

Package managers execute untrusted code at install time. By the time an npm
`postinstall` script runs, it already has access to source code, SSH keys, cloud
credentials, environment variables, and CI tokens. Scanning after installation is too
late for the developer workstation.

The window between a malicious version being published and being detected by threat
intelligence is where most successful supply-chain attacks land. Any defense wired
purely to known-malware feeds is structurally reactive and blind during exactly that
window.

## 2. Positioning

"Dependency firewall" is an established category (OpenSSF published a definition in
July 2026). Existing implementations:

| Product | Model | Gap we address |
|---|---|---|
| Socket Firewall | Free tier + Enterprise | Detection intelligence is proprietary and closed |
| Sonatype Repository Firewall | Commercial, self-hostable | Enterprise licensing, closed policy engine |
| Bytesafe | Commercial | Closed |
| Cloudsmith | Commercial, OPA/Rego | Tied to their hosted registry |
| Harness Artifact Registry | Commercial, OPA | Tied to their platform |
| pkggate | **MIT**, OSV-based, Python | Self-described early prototype, 0 stars, solo maintainer, npm + PyPI only |
| Datadog supply-chain-firewall | **Open source** | ✅ Evaluated — see below. CLI wrapper, not a proxy. Different architecture. |
| Aikido Safe Chain | **MIT** tool, Intel feed needs a commercial account | Client-side shim rather than a policy proxy |
| depthfirst | Commercial | Closed agentic detection |

**Datadog supply-chain-firewall — evaluation (Sept 2026).** Not a competitor to this
design so much as a different answer to the same question. It is a **CLI wrapper**:
`scfw run npm install react` introspects the command, resolves the full set of packages
that would actually be installed including transitives, checks them, then either runs
the real command or blocks. It never sits in the network path.

- **Sources:** Datadog's own public malicious-packages dataset (daily), OSV advisories,
  and optionally **GuardDog**, their OSS heuristic scanner. npm and pip only. GitHub
  Action wrapper for CI.
- **Their advantage:** sidesteps registry configuration and TLS entirely — the messy
  part of our early stages.
- **Their limitation:** only protects commands a developer remembers to prefix. A
  reverse proxy catches everything pointed at the registry, including installs from
  IDEs and tooling that never touch a wrapped shell command.
- **Reusable idea:** GuardDog is a real OSS heuristic detector and should slot into our
  Tier 3 detector interface. Tracked in Stage 4.

**Our thesis (revised, Sept 2026).** The original framing was that malware
intelligence is an unassailable moat, so an OSS project must compete elsewhere. That is
now only half true. OSV's npm bundle carries 228,951 advisories, of which 221,548 are
OSSF Malicious Packages malware records under Apache-2.0, measured directly rather than
taken from a vendor's claims. Competitive detection coverage can be assembled from free
feeds without owning a detection pipeline.

Aikido Intel was originally counted in this list on the understanding that it was free and
public. It requires a commercial account, so it is out of the launch and deferred to
post-v1. The thesis does not rest on it: the 221,548 figure is OSSF alone.

That makes the **pluggable advisory stream interface the strategic centerpiece**, not a
nice-to-have. No commercial vendor will aggregate every free feed, because each is
selling their own. We can.

Combined with the second pillar: **high-value controls that require no intel at all** —
cooldown periods, lifecycle script policy, registry-vs-source diffing, provenance
enforcement — plus a fully inspectable policy engine and auditable verdicts.

**Licensed Apache-2.0.** Permissive is the ecosystem norm here (pkggate and Aikido Safe
Chain are both MIT), the patent grant matters for security tooling, and adapter/detector
contributions are the scarce resource. DCO rather than a CLA. Trademark held separately.

### Non-goals

- Competing on proprietary malware detection or behavioral ML
- Being a package registry or artifact store (we sit in front of one)
- SBOM generation, license compliance reporting, runtime protection
- Replacing SCA tooling for already-installed dependencies

## 3. Detection strategy

**Tier 1 — intel-independent controls (the differentiator).** These need no threat
feed and cover the publish-to-detection gap:

- **Cooldown / quarantine.** Hold newly published versions for N days.
- **Lifecycle script policy.** npm `postinstall`/`preinstall`, Python `setup.py`
  execution in sdists, cargo `build.rs`.
- **Provenance enforcement.** Require sigstore / npm provenance attestations where
  the package claims to publish them.
- **Registry-vs-source diffing.** Compare the published tarball against the tagged
  git source. Strong signal, underused by existing tools.
- **Metadata heuristics.** Package age, maintainer age, missing repository link,
  sudden maintainer change, typosquat edit distance to high-download packages.

**Tier 2 — public advisory streams.** Pluggable from day one. Each stream implements a
common interface (fetch, mirror, refresh, normalize to advisory record) so operators
can enable, disable, or add sources without forking.

| Stream | Keying | Notes |
|---|---|---|
| OSV.dev | PURL | Primary. Best ecosystem coverage, includes malicious-package records. Already aggregates GHSA. |
| GitHub Advisory | GHSA ID + package range | Curated, fast-moving. GraphQL API, needs a token. |
| NVD | **CPE** | ⚠ Not package-keyed. See below. |
| OSSF Malicious Packages | PURL | Free community malware feed, aggregates several contributors. **Publishes natively in OSV format**, so it reuses the OSV normalization path — no reshaping. Low cost to add. |
| Datadog malicious-packages | package name/version | Free, public, no account, daily updates. ⚠ **Likely already ingested via OSSF** — Datadog contributes upstream to it. Verify overlap before implementing; skip if it is a strict subset. |
| Aikido Intel | package name/version | ⚠ **Requires a commercial account.** Not a free public feed. Deferred to post-v1, pending a sponsorship conversation after launch. |

All streams mirrored locally so lookups never leak the user's dependency graph upstream.

**Stream design constraints:**

- **Verify each stream's data license before implementing it.** The license on the
  reports is not necessarily the license on the tooling in the same repository — an
  Apache-2.0 project may publish its data under Creative Commons or a custom term.
  Check the data explicitly, per stream, and record the finding. This is a hard
  prerequisite for any stream we mirror and redistribute lookups against.

- **Identity reconciliation is mandatory, not optional.** The same vulnerability
  appears across all three feeds under different IDs. Normalize via CVE/GHSA/OSV
  aliases and deduplicate before the policy engine sees anything, or a single vuln
  fires three rules and every verdict triple-counts.
- **NVD's CPE keying is a real impedance mismatch.** CPE identifies products, not
  packages; the mapping is lossy in both directions, has no authoritative table, and is
  assigned by NVD analysts rather than package maintainers. **Resolved: NVD is
  `enrich`-only for npm and PyPI**, joined on exact CVE ID, since GHSA (via OSV) already
  covers those ecosystems with proper package ranges. NVD may hold `match` for Maven,
  where CPE coverage is stronger — revisit when that adapter is scoped. Enrichment runs
  as a background job, never on the hot path, and NVD failures never block a verdict.
- **Severity conflicts.** The same vulnerability routinely carries different CVSS scores across
  NVD and GHSA. Precedence must be configurable, since any `max_cvss` rule is
  meaningless without it.
- **Withdrawn advisories must propagate.** A withdrawn GHSA that stays cached locally
  blocks a package forever.
- **Per-stream rate limits and auth.** NVD throttles hard without an API key; GitHub
  requires a token. Refresh scheduling is per-stream, not global.

### Stream capabilities by ecosystem

Coverage is uneven per stream *and* per ecosystem, so capability is a matrix —
`(stream, ecosystem) -> set of roles` — not a per-stream property.

| Role | Meaning |
|---|---|
| `match` | Can independently produce a finding against a package |
| `enrich` | Can attach severity, CWE, references to a finding produced elsewhere; **can never create one** |
| `malware` | Can produce a malicious-package verdict specifically |

```yaml
streams:
  nvd:
    capabilities:
      npm:   [enrich]
      pypi:  [enrich]
      maven: [match, enrich]
```

**`malware` is deliberately separate from `match`.** Known malware always blocks and has
no exception (§5), so any stream holding `malware` for an ecosystem can trigger the one
check an operator cannot write their way past. That is a far higher trust bar than
reporting a vulnerability, and granting it must be explicit.

**Declared by the plugin, overridable by the operator.** The plugin ships an honest
self-assessment; operators can demote a stream they distrust for a given ecosystem.
Promotion is harder than demotion, especially into `malware`.

**Coverage gaps become computable.** For each enabled ecosystem, check that at least one
enabled stream provides `match`. An ecosystem adapter running with no `match`-capable
stream is a firewall that structurally cannot block anything — startup warning plus a
`waharoa doctor` check. This composes with the §4 adapter maturity tiers: adapter maturity
and intel coverage are separate axes and both belong in `waharoa status`.

**Accepted consequence:** an `enrich`-capable stream returning a higher CVSS than the
matching stream *can* change a verdict via `max_cvss`. Enrichment would be decorative
otherwise. It can only escalate within an existing finding, never originate one, and the
behavior must be explicit in severity precedence config rather than emergent.

### Intel storage and refresh

**Storage is sqlx over Postgres, with no ORM.** SeaORM was planned for one reason, "one
codebase for both backends", and there is one backend. Queries are SQL checked at compile
time by `sqlx::query_as!` against the real schema; migrations are plain `.sql` under
`sqlx::migrate!`. This removes a dependency rather than swapping one, since SeaORM is built
on sqlx and the refresh path was already going to use it directly. See
[storage-sqlx-postgres](engineering_decisions/storage-sqlx-postgres.md).

The cost is that the macros need a database at compile time. `cargo sqlx prepare` writes an
offline cache to `.sqlx/`, checked in, so a contributor builds without one; CI runs
`cargo sqlx prepare --check` so it cannot drift from the migrations.

**Postgres is the only backend.** SQLite was targeted alongside it and has been dropped:
supporting two backends bought portability nobody asked for and constrained the refresh
path, which is the one place the storage layer has to be fast. There is no embedded
fallback and no development-only backend.

**Development and tests run against Postgres in a container.** `make test-integration`
starts one, runs the tests that need a database, and tears it down. Tests that do not need
a database must not require the container: the policy engine, the decision vector and
everything above the repository trait are pure and stay that way.

**The repository trait stays, for a different reason.** It was there for backend
portability, which is now moot. It remains because §Standards requires 95% unit coverage
excluding corpus and live tests, so everything above the storage seam has to be testable
with no database at all. Reading "one backend, no ORM" and deleting the trait would put the
policy engine behind a container.

**Everything in the multi-instance section below is a production requirement**, not an
optional extra for large deployments. Every deployment is Postgres, so refresh
coordination and reading `intel_snapshot_id` from the database are load-bearing
everywhere.

**Distribution: none.** Every stream fetches from its own origin — OSV publishes
per-ecosystem bundles to a public GCS bucket, GitHub Advisory is queried under the
user's token, OSSF Malicious Packages is a git repo. We never host or redistribute
intel. The artifact stays a single binary.

**Refresh must be atomic.** A failed refresh must never leave a half-populated advisory
set that silently under-blocks. A load deletes one stream's rows and copies the new ones in
one transaction. See [osv-malware-load](engineering_decisions/osv-malware-load.md).

**Multi-instance**, which is a bigger change than the storage layer:

- **Refresh coordination.** N replicas rebuilding simultaneously is wasteful and racy.
  Needs advisory-lock leader election, or a separate `waharoa refresh` command run as a
  cron/Job with the proxies read-only.
- **`intel_snapshot_id` must be read from the database, not computed locally**, or
  replicas silently disagree and the reproducibility guarantee breaks.

**Snapshot identity** is a hash over every source's stored rows, so two stores with the same
id contain the same rows, whichever bundles they were read from. Refresh writes it to
`intel_snapshot` and every proxy reads it from there. Postgres keeps the latest load only.
`waharoa refresh` also keeps each snapshot as files of the rows the id hashes, which
`policy diff --snapshot` reads and air-gapped export will read. See [snapshot-identity](engineering_decisions/snapshot-identity.md).

**Cold start fails closed, with 503 — never 403.** A 403 during warming looks like a
policy violation for a package that is fine, which costs trust immediately. A readiness
endpoint answers 503 until a snapshot is loaded, so an orchestrator sends the proxy no
traffic until then.
It reports each stream's loaded digest rather than a percentage: a refresh is one
transaction, so there is no partial load to measure. See
[readiness-endpoint](engineering_decisions/readiness-endpoint.md).

**Query-on-clean live fallback (adopted from pkggate's design).** The mirror answers
malicious verdicts at zero latency; the live API is queried *only* for versions the
mirror considers clean, catching advisories published since the last refresh. Three
constraints:

- Use OSV `/v1/querybatch`, not sequential calls — a large lockfile is hundreds of lookups.
- Cache clean results for a short window.
- **Its own fail-open/closed setting**, separate from mirror availability, defaulting to
  **fail-open with a warning**. The mirror remains authoritative; an optional enrichment
  layer must not halt every install when an upstream API is unreachable.
- Opt-in, and documented as a privacy tradeoff: it leaks the clean subset of the
  dependency graph.

**Tier 3 — pluggable detectors.** Distinct from advisory streams: streams supply
*known facts about packages*, detectors perform *analysis*. Separate interfaces, so
organizations can attach commercial feeds or in-house analysis without forking.

## 4. Architecture

Four layers. Only the first two are ever rewritten per ecosystem.

```
package manager
      |
      v
[ transport adapter ]   speaks one registry protocol (npm, PEP 503, sparse index...)
      |
      v
[ normalizer ]          registry metadata -> common package record
      |
      v
[ policy engine ]       ecosystem-agnostic; operates only on the common record
      |
      v
[ analysis cache ]      keyed by tarball digest, permanently valid, offline-capable
      |
      v
upstream registry (allow) | HTTP 403 + audit log (block)
```

**Package identity is PURL** throughout the core. OSV already keys on PURL, so Tier 2
lookups stay uniform across ecosystems at no cost.

#### PURL rules

Four npm identity rules, measured against OSV's full npm corpus: two types rather than
one, no lowercasing, keying on parsed components, and identity read from the packument.
See
[docs/engineering_decisions/purl-identity-rules.md](engineering_decisions/purl-identity-rules.md).
### Interception points per ecosystem

| Ecosystem | Mechanism | Notes |
|---|---|---|
| npm | registry URL | Simple. Per-package metadata, resolve-as-you-go. ✅ Verified Stage 1: pass-through only, no packument rewriting needed. See below. |
| PyPI | `--index-url`, PEP 503 | Backtracking resolver fetches metadata for versions it will never install. Different traffic shape. |
| cargo | source replacement, sparse index | Simplest protocol of the three. |
| Go | `GOPROXY` | Immutable modules + checksum DB already solve tamper-evidence. Low marginal value. |
| Maven | mirror in `settings.xml` | Largely client-side resolution. Slower publish cadence. |

**npm needs no packument rewriting (measured Stage 1, Sept 2026, npm 9.9.4).** This was
the open question that decided whether we are a pass-through or a rewriting proxy, and it
is not obvious from the data: `dist.tarball` in a packument is an absolute
`https://registry.npmjs.org/...` URL, so the naive reading is that npm would fetch
tarballs direct from upstream and we would never see them. It does not, for tarball URLs
on the default registry host: npm rewrites those to the *configured* registry, so every
tarball request arrives at the proxy unmodified.

Measured on `npm install express`: 66 packages installed, and every one of them was
fetched through the proxy at both the metadata and the tarball leg, with nothing going
direct. Rewriting bodies would mean buffering and re-serializing every packument, which
collides with the streaming fetch path below, and would make lockfiles
environment-specific. This is npm's behavior, not registry protocol; yarn and pnpm are
untested.

⚠ **Superseded: this finding was npm-specific, and the proxy now rewrites `dist.tarball`
for every client (Sept 2026).** pnpm 10 and yarn 1 use the URL verbatim, so against the
real registry every artifact went straight to registry.npmjs.org and the proxy saw only
metadata. Installing `express`: npm sent 67 packuments and 69 tarballs; pnpm sent 66
packuments and zero tarballs and installed successfully. The proxy therefore points
artifact URLs at itself, uniformly rather than per client. Full reasoning, costs and
lockfile effects in
[docs/engineering_decisions/packument-tarball-url-rewriting.md](engineering_decisions/packument-tarball-url-rewriting.md);
reproduce with `make smoke-clients`.

**The rewrite is conditional on the host, and that is a bypass vector (corrected Sept
2026).** An earlier version of this finding said npm ignores the host in `dist.tarball`
outright. It does not. Tested with a controlled registry serving the same package two
ways: with `dist.tarball` on `https://registry.npmjs.org`, npm fetched it from the
configured proxy; with `dist.tarball` on another origin, npm fetched it from that origin
and the proxy saw no tarball request at all.

So a compromised or hostile registry can serve a packument whose artifact lives on a host
the proxy does not sit in front of, and the install proceeds unexamined. The proxy does
see the packument, so this is detectable: refuse, or flag, a `dist.tarball` whose origin
is neither the configured upstream nor the default registry. Not implemented; see TODO.

### Rollout order and rationale

npm and PyPI carry effectively all the malware volume, so they ship first and ship
**enforcing**. cargo is third because the sparse index is easy and it proves the
adapter interface against a third protocol. Go and Maven are deferred — breadth buys
far less security than the ecosystem count implies, and the cost is an issue tracker
that is 80% protocol plumbing instead of detection work.

**The failure mode to avoid:** five half-working proxies, none trusted enough to run
in blocking mode. Every ecosystem carries a published maturity tier
(`enforcing` / `observe-only` / `experimental`) in the README and in `waharoa status`.

## 5. Policy configuration

Single YAML file. Global settings, and per-package exceptions to them. The decision flow
chart, the reasoning and the measurements behind it are in
[engineering_decisions/policy-tier-resolution.md](engineering_decisions/policy-tier-resolution.md).

```yaml
version: 1

# Thresholds. One value each for the deployment.
cooldown_days: 7
max_cvss: 6.9

# Whether these checks run. `block` or `allow`.
install_scripts: block
kev: block

# Explicitly forbidden. Exact versions, permanent, absolute.
denials:
  - purl: "pkg:npm/chalk@5.6.1"
    reason: "compromised release, Sept 2025"

# Exceptions. Per package. May only loosen.
packages:
  - match: { ecosystem: npm, name: "@mycompany/*" }
    set: { cooldown_days: 0 }
    reason: "internal, published by our CI"
    permanent: true
    added_by: alice

  - match: { ecosystem: npm, purl: "pkg:npm/legacy-thing@2.1.0" }
    set: { kev: allow, vuln_advisory_ids: ["CVE-2024-1234"] }
    reason: "mitigated by network policy"
    expires: "2026-11-30"
    added_by: bob
```

**Every setting is global. Every exception is per package. Nothing is per ecosystem.**

### The checks

| check | scope | may be excepted |
|---|---|---|
| explicitly forbidden (`denials`) | per package | no |
| known malware | not configurable | no |
| `cooldown_days`, the age threshold | global | yes |
| `kev` | global | yes |
| `max_cvss` | global | yes, per advisory id |
| `install_scripts` | global | yes |

Three things are not configurable at all:

- **Known malware always blocks.** No setting and no exception. It is behaviour rather
  than policy.
- **Which ecosystems run which check.** `install_scripts` is asked of every ecosystem, and
  Go has no install step to ask about. That is a property of Go, not something an operator
  sets. Such a check reports **not-applicable**, never a violation.
- **Whether a check may be excepted.** An organisation that does not want KEV exceptions
  writes none.

### Evaluation

Every check runs. Each appends one result to a decision vector, and the disposition is
taken from the whole vector rather than at the first failure.

```
  denials          passed
  known_malware    passed
  cooldown_days    failed    -> quarantine    (published 2 days ago, needs 7)
  kev              excepted  -> allow         (packages[3], expires 2026-11-30)
  max_cvss         passed
  install_scripts  failed    -> block         (no exception)

  decision: block
```

The decision is the strongest action in the vector. The outcome is identical to stopping
at the first failure, because every check must pass for a package to be delivered. What
changes is what is known when the answer is given: every reason rather than the first,
`explain` with nothing to reconstruct, `policy diff` that names which check moved, and
observe-only as "record it and deliver anyway" rather than a second path through the
engine.

Four results, and three of them contribute `allow`:

| result | meaning | contributes |
|---|---|---|
| `passed` | the check had nothing against this package | `allow` |
| `failed` | it did | its action |
| `excepted` | it did, and a `packages` entry excused it | `allow` |
| `not_applicable` | the check has no meaning for this ecosystem | `allow` |

They are distinguished anyway, because what an operator needs to know is not the same as
what the decision needs. `excepted` is the one carrying operational risk and is what an
expiry review has to find; an exception that never reaches `excepted` is doing no work.

The short circuit survives in one place: in front of expensive analysis. None of the
checks above costs anything worth deferring for, but Stage 4's capability analysis and
source diff do, and they run only if the cheap vector has not already settled the answer.

### Actions

`allow < quarantine < block`. Each has a producer:

| | meaning | produced by |
|---|---|---|
| `allow` | delivered | everything that passes |
| `quarantine` | refused now, allowed later | a package younger than `cooldown_days` |
| `block` | refused | denials, known malware, KEV, an advisory over `max_cvss`, install scripts |

`quarantine` lapses without anyone doing anything, which is what separates it from
`block`. It is a **packument filter**, not an artifact refusal: the version is removed
from the document the client resolves against, so the client picks an older one by itself
rather than failing.

There is no `warn`. Nothing delivers-with-a-concern.

### Provenance is recorded, not required

`dist.attestations` and the rest are kept on the package record and shown in `explain`.
Nothing is refused for lacking them.

Measured on the 138 packages of a real `npm install express eslint`: 112 (81%) publish no
provenance, against 0 that carry an install script. Every other check fires on a minority,
which is why per-package exceptions work for them. Requiring provenance would forbid the
majority and the exception list would become the dependency list.

It is also the one check that cannot be asked of every ecosystem: npm has
`dist.attestations`, PyPI has PEP 740 at low coverage, cargo has nothing, Maven has GPG
signatures, which are identity rather than build provenance, and Go has a checksum
database, which is tamper-evidence. A global requirement would forbid 100% of three
ecosystems.

### `denials` — permanent, absolute

Structurally separate from `packages`, not a flag on a shared record. Always exact
version, always tightening, never expires, never overridable. The type has **no `expires`
field**, so a denial with an expiry date is unrepresentable rather than merely
discouraged.

### `packages` — the exception tier

One syntax, one code path. It may only **loosen**: an entry that would tighten is a
load-time error, because tightening a single package is not something this tier is for and
allowing it would reopen questions about what outranks what.

- **`ecosystem` is a required field on every selector.** Package names do not collide
  meaningfully across registries, npm `requests` and PyPI `requests` being unrelated
  projects, so a cross-ecosystem match is almost always a mistake. Requiring it removes an
  axis from containment logic and makes `{name: "*", cooldown_days: 0}` impossible to
  write by accident. `purl` selectors satisfy this inherently.

**Loosening requires justification, and emits no warning.** A warning per entry would
become noise that hides everything else. A required field cannot be ignored the way a
warning can.

- `reason` — always required
- `expires` — required, **maximum 90 days from today**, configurable
- `permanent: true` — explicit alternative to `expires`, requires `reason`, and is
  reported separately by `policy check` so genuine invariants stay individually visible
  instead of hiding among dated entries

Rationale for expiry: a justification is true when written and silently stops being true
later. Reviewed versions get superseded, internal packages change owners, the blocker gets
fixed and nobody deletes the entry. Expiry inverts the default so an unexamined entry dies
rather than persisting, which makes deletion the outcome of inattention.

An entry that changes nothing is **valid**. It warns at load and `doctor` flags it,
because it is almost always a selector that no longer matches what it was written for, but
it does not stop a policy from loading.

#### Match resolution: most-specific-wins by subset containment

Specificity is a **strict subset relation**, not a heuristic score. A is more specific
than B if the set of packages A matches is a strict subset of B's:

- `@mycompany/foo` ⊂ `@mycompany/*` ⊂ `*`
- exact version ⊂ any version
- selector + predicate (`has_install_scripts: true`) ⊂ same selector without it

Decidable because the predicate vocabulary is closed, a direct payoff of the hand-rolled
engine over Rego, where an open expression language would make containment undecidable.
Keeping it closed is enforced at load: a name is `*`, `prefix*` or a literal, and a version
is exact or absent. Admitting a range and reporting "incomparable" would be worse than
refusing it, because the overlap check below could no longer fire either.

- **Incomparable overlaps are a load-time error.** `{name: "a*", has_install_scripts:
  true}` vs `{name: "ab*"}` overlap with neither containing the other. No principled
  winner exists, so refuse to start and require an explicit disambiguating entry. This is
  what makes most-specific-wins safe: it never silently guesses.
- **Exact duplicates are a separate load-time error.** They are comparable and still
  wrong: whichever wins, the other is dead, and which one depends on file order.
- `explain` shows the winning selector **and** the ones it beat.
- `policy check` flags selectors that can never win because a strictly more specific entry
  always shadows them.

#### Defining "looser"

`allow < quarantine < block`. Any move down the order is loosening. Parameterized settings
need a **declared monotonicity direction per parameter**, which cannot be inferred:

| Parameter | Stricter direction |
|---|---|
| `cooldown_days` | higher |
| `max_cvss` | lower |

Getting one backwards would refuse entries that tighten and accept entries that loosen,
which is worse than having no check. Where a change is **incomparable**, refuse: an entry
whose direction cannot be proven is not one to admit.

#### Version ranges

Resolved by the **normalizer** into a concrete match set before the policy engine sees
them, keeping semver / PEP 440 / cargo range syntax in the adapter layer. Validate against
the PyPI adapter before freezing the interface.

### Policy impact analysis

`waharoa policy diff` evaluates a policy change against real packages rather than the
config in isolation.

```
waharoa policy diff --from policy.yaml --to policy-new.yaml \
                  --against ./lockfiles/ --snapshot <intel_id>
```

- **Intel snapshot is pinned.** Without it, a new block cannot be attributed to the edit
  rather than to an advisory published overnight. This is what `intel_snapshot_id` is
  for.
- **Package set from lockfiles or the audit log.** Lockfiles give the full resolved graph
  including transitives; the audit log gives actual observed traffic, including packages
  resolved but never locked. Support both.
- **Transitions reported in both directions**, grouped with counts. `allow -> block` is
  what operators ask for; `block -> allow` is the more dangerous one to ship unnoticed.
- **`--as-of <date>`.** Cooldown and exception expiry are both time-dependent. Running
  `--as-of +30d` against an *unchanged* policy shows exactly which packages break when
  entries lapse. With the 90-day ceiling this is the renewal workflow: a scheduled job
  surfacing upcoming expiries with concrete impact instead of a list of dates nobody can
  prioritize.
- **Nonzero exit on any loosening transition**, so a policy repo can gate weakening
  changes on review.

### HTTP stack

axum server-side, reqwest upstream, with no fetch trait in Stage 1. See
[docs/engineering_decisions/http-stack-axum-reqwest.md](engineering_decisions/http-stack-axum-reqwest.md).
### Configuration format

YAML, loaded by `serde-saphyr`. Decided by spike against the real policy; see
[docs/engineering_decisions/config-format-yaml-serde-saphyr.md](engineering_decisions/config-format-yaml-serde-saphyr.md).
The spike harness is kept runnable as `make spike-config`.
### Fetch path: streaming, buffering, and deferral

Not a global stream-vs-buffer mode. The packument publishes an artifact digest
(`dist.integrity` on npm), so on a tarball request we already know whether that exact
artifact has been analyzed — **before fetching a byte.**

| Case | Behavior |
|---|---|
| Analyzed before (cache hit) | **Stream through.** Flat memory, no added latency. |
| Novel + cheap analysis | **Buffer, analyze, forward.** Tar listing is tens of ms; invisible. |
| Novel + expensive analysis | **Defer with `429` + `Retry-After`.** Git clone is tens of seconds. |

The registry-supplied hash is a **cache key, not a trust anchor.** We verify the digest
of what actually arrives; a mismatch against the packument's claim is itself a finding.

**Analysis cost is part of the detector contract**, declared per detector, not guessed
at runtime. Only expensive-tier detectors can produce a deferral, so the common path
never retries.

#### Status codes

| Code | Meaning | Scope |
|---|---|---|
| **502** | Upstream registry unreachable or malformed | Not our fault; nothing to retry against us |
| **503** | *We* are not ready — intel mirror warming | All requests, indiscriminately |
| **429** | We are ready; **this artifact** is under analysis | One artifact; everything else serves normally |

503 at cold start is correct not because it is the proxy convention — that is 502 — but
because we are the service that is not ready. The registry is healthy; our mirror has
not loaded. Describing ourselves is exactly accurate, and `Retry-After` is native to it.

429 for deferral, because 503 would imply a whole-service outage for a single-artifact
condition and send an operator debugging in the wrong direction. Client retry behavior
is the secondary argument, not the primary one.

**No 4xx that reads as a block** for any not-ready state — the same rule that put 503
rather than 403 at cold start. A 403 from a registry proxy means "policy denied you,"
and anything else wearing that code is a trust problem.

#### Client compatibility

Package managers bucket status codes rather than reading them semantically: 4xx is
generally terminal, 5xx and 429 retryable. So the choice is constrained by observed
client behavior, not by protocol elegance.

- **Per-client selection inferred from user-agent**, which the transport already parses
  to pick a metadata dialect. Shipped table of known clients; operator-forceable global
  override so a client's behavior change between versions does not wait on our release.
- **Unknown user-agent → 503.** An unknown client is likely a library or CI tool with
  unknown retry behavior; fail toward the more widely retried code.
- **Machine-readable reason and artifact digest in a response header and body**, since
  neither code distinguishes cold start from per-artifact analysis on its own.
- **Log every deferral and whether the client returned inside the window.** Turns the
  compatibility table from guesswork into evidence — and into the case we bring to
  package-manager maintainers.
- **Upstream work, filed early:** ask npm / pip / uv / cargo to honor `429` +
  `Retry-After` where they do not. This argues on its own merits — a registry proxy
  legitimately rate-limiting is a real scenario independent of this tool — so it is a
  small, uncontroversial patch with a long lead time.

⚠ **Known risk:** npm may apply its own backoff and fail the install rather than waiting
politely. Needs testing against real clients in Stage 1. Mitigations: `Retry-After`
short enough to land inside npm's own retry window, plus a bounded internal wait as a
fallback for clients that give up.

**Cooldown hides most of this in practice.** A seven-day quarantine means an artifact
has almost always been analyzed long before anyone is permitted to install it. The
genuinely exposed case is a pinned install of a brand-new version under a waiver —
rare, and arguably correct, since a waiver is an explicit acceptance of risk.

### Fail closed

- Unknown keys are a **hard error**, never ignored. A typo'd `install_script` that
  silently does nothing is worse than having no tool, because the user believes they
  are protected.
- Unrecognized `version` -> refuse to start, never fall back to permissive.
- Detector or intel-source failure -> configurable, defaults to fail closed.

## 6. UX principles

**Warn mode is the default.** One blocked legitimate build and the tool is disabled
permanently. Adopters ratchet from observe to enforce on their own schedule.

**Exceptions are cheap to add and expire by default.** `reason` and `expires` are
mandatory fields. This is what stops the allowlist from quietly becoming a permanent
bypass.

**`waharoa explain` is a first-class command.** Shows the effective merged policy for an
ecosystem, and the resolved verdict for a given package with the rule that fired.
Policy engines nobody can inspect stay stuck in warn mode forever. It doubles as the
regression test surface.

**`waharoa policy check --strict`** exits nonzero on any unacknowledged loosening, so an
org can gate its policy repo in CI and require sign-off on weakening changes.

**Audit log** is JSON Lines: package, version, ecosystem, verdict, rule that fired,
requester, timestamp. Developers and security read the same log.

## 7. Trust and threat model

A tool that intercepts every dependency install is itself a supply-chain risk and a
single point of failure.

- Fully self-hostable, no mandatory outbound calls to us
- Local OSV mirror so the dependency graph never leaks
- Reproducible verdicts: same policy + same intel snapshot = same result, pinnable and
  air-gappable
- Own releases published with provenance attestations; we hold ourselves to the policy
  we ship
- Fail-closed default on proxy unavailability, with a documented break-glass path

**How requests are made to reach the proxy at all** is a stack of mechanisms, not one
choice. The tiers, what each costs, and what each fails to cover are in
[docs/engineering_decisions/enforcement-tiers.md](engineering_decisions/enforcement-tiers.md).
The short version: refusing artifacts whose origin is not in the proxy configuration needs
no CA, no root and no network changes, and should be built before any network-level
interception.

**Known bypass vectors, stated honestly in the README:**

- **Reverse proxy mode is advisory, not mandatory.** A developer who resets their
  registry URL defeats it entirely. The mitigation is `waharoa doctor`, which verifies
  effective client config.
  - ⚠ **Lockfile verification now works for npm and yarn, and does not for pnpm.
    Corrected Sept 2026.** This previously read that npm normalizes `resolved` back to
    `https://registry.npmjs.org/...` regardless of the configured registry, so a lockfile
    could not evidence that the proxy was used. That was measured before the proxy
    rewrote artifact URLs, and rewriting changed it. Measured after:
    | Client | Lockfile field | Records |
    |---|---|---|
    | npm 9.9.4 | `resolved` | the proxy address |
    | yarn 1.22.22 | `resolved` | the proxy address |
    | pnpm 10.33.0 | `resolution.tarball` | omitted entirely |
    So for npm and yarn a lockfile does evidence proxy use, and CI can check it. pnpm
    omits the URL when it matches the configured registry and derives it at install time,
    which makes its lockfiles portable and leaves them with nothing to check. Re-check per
    client on upgrade: this is client behavior, not protocol.
- **Non-terminal install paths.** IDE extensions, browser extensions, and MCP servers
  install packages without going through a configured package manager. Aikido raises
  this specifically in the context of AI agents. A registry proxy cannot see any of it.
  Endpoint-level coverage is out of scope for us.
- **npm cache bypass.** npm serves from its local cache without consulting the registry,
  so a pre-existing cache silently skips enforcement. pkggate documents
  `npm cache clean --force` as a required onboarding step; `waharoa doctor` should detect
  and warn about this.

**Explicitly out of scope:** we do not stop a determined attacker who already controls
the developer's machine, and we do not claim to detect novel malware ahead of the
research community.

## 8. Underserved angle: AI coding agents

OpenSSF notes agents should operate under the same dependency policies as humans, and
that a package is not safe merely because a capable model suggested it. Everyone
acknowledges this; nobody has built for it.

Agents install packages autonomously, at machine speed, with no human reviewing the
choice — a different threat shape from a developer typing `npm i`. Post-v1
opportunities: agent-specific stricter policy profiles, rate limiting on novel package
introduction, and an approval-request flow instead of a hard block.

## 9. Milestones

| Milestone | Contents | Exit criteria |
|---|---|---|
| **M1** Pass-through proxy | Reverse proxy, npm adapter, normalizer, PURL identity. No policy. | `npm install` completes through the proxy with the full transitive graph correctly normalized |
| **M2** Decision layer | Policy engine, merge semantics, package tier, OSV + intel store, audit log, `explain` | npm enforcing; a real package blocked for a real reason; policy spec frozen |
| **M3** Second ecosystem | PyPI adapter | Adapter interface survives a second protocol unchanged |
| **M4** Differentiators | Cooldown, lifecycle scripts, provenance, source diffing | Tier 1 controls shipped; this is the launch story |
| **M5** Hardening | Analysis cache, offline mode, `--strict`, perf | Real team runs it in blocking mode |
| **M6** Third ecosystem | cargo | Three protocols; adapter interface documented as stable |
| **M7** Public launch | Docs, maturity tiers, security policy | External adopters |

The former M0 spike is dissolved. Its interception proof lives inside M1, whose exit
criterion subsumes it; the reverse proxy is standard architecture plus certificate
management, not something that needed proving. **M1 is deliberately falsifiable without
any policy logic:** a wrong PURL surfaces as a wrong PURL, not as a mysterious verdict.

## 10. Decisions and open questions

Each decision has its own file under
[docs/engineering_decisions/](engineering_decisions/). This table is the index; the
reasoning, alternatives and consequences live in the files, not here.

### Decided

| # | Decision | Summary |
|---|---|---|
| 1 | [Language](engineering_decisions/language-rust.md) | Rust |
| 2 | [Policy engine](engineering_decisions/policy-engine-hand-rolled.md) | Hand-rolled, Rego as a later optional escape hatch |
| 3 | [TLS](engineering_decisions/tls-reverse-proxy-first.md) | Reverse proxy first, CA-terminating forward proxy later |
| 4 | [Quarantine](engineering_decisions/quarantine-filter-metadata.md) | Filter metadata on resolution, hard fail on pinned fetch |
| 4b | [Cooldown vs. urgent fixes](engineering_decisions/cooldown-waivers-manual-only.md) | Manually reviewed version waivers only |
| 5 | [License](engineering_decisions/license-apache-2.md) | Apache-2.0, DCO, trademark separate |
| 6 | [Intel distribution](engineering_decisions/intel-distribution-fetch-from-origin.md) | None; fetch from origin. Postgres only; ORM choice moved to #14 |
| 7 | [NVD role](engineering_decisions/nvd-role-and-stream-capabilities.md) | `enrich`-only for npm/PyPI; per-ecosystem capability matrix |
| 8 | [Package override tier](engineering_decisions/package-override-tier.md) | Superseded by [policy-tier-resolution](engineering_decisions/policy-tier-resolution.md): no floor, `packages` loosens only |
| 13 | [Policy tiers and evaluation](engineering_decisions/policy-tier-resolution.md) | Global settings, per-package exceptions, decision vector; supersedes the old §5 and §5.5 |
| 11 | [Config format](engineering_decisions/config-format-yaml-serde-saphyr.md) | YAML via `serde-saphyr`; schema forbids `#[serde(untagged)]` |
| 12 | [HTTP stack](engineering_decisions/http-stack-axum-reqwest.md) | axum + reqwest; no fetch trait in Stage 1 |
| 14 | [Storage](engineering_decisions/storage-sqlx-postgres.md) | sqlx over Postgres, no ORM; compile-time checked SQL with a checked-in `.sqlx/` cache |
| n/a | [sqlx version and `rsa` advisory](engineering_decisions/sqlx-0-8-and-rsa-advisory.md) | sqlx held at 0.8 until kani bundles rustc 1.94; RUSTSEC-2023-0071 ignored only while `rsa` is not compiled |
| n/a | [OSV malware load](engineering_decisions/osv-malware-load.md) | npm `MAL-` records via `waharoa refresh`; `all.zip` read in memory; delete by source and `COPY` in one transaction |
| n/a | [Intel in decisions](engineering_decisions/intel-in-decisions.md) | One store query per package; a store that cannot answer is a 503 |
| n/a | [OSV ranges and scores](engineering_decisions/osv-ranges-and-scores.md) | `GHSA-` records loaded; ranges stored as intervals and compared as SemVer 2.0 at lookup; v4 base score over v3; `vuln_advisory_ids` matches aliases |
| n/a | [Environment variables](engineering_decisions/environment-variables.md) | Every name, default, help line and parser in `src/env.rs`; a value that does not parse refuses to start |
| n/a | [Command line parser](engineering_decisions/cli-parser-clap.md) | clap 4 with default features off, 4 crates; parsing in `src/cli.rs`, help pinned by golden files |
| n/a | [Intel schema keys and types](engineering_decisions/intel-schema-keys-and-types.md) | Every table keyed by a `BIGINT` identity; publisher ids and digests are sized unique columns; `TIMESTAMPTZ`; `TEXT` only for `summary`. An over-long value fails the refresh |
| n/a | [Policy schema v1 frozen](engineering_decisions/policy-schema-v1-frozen.md) | `version: 1` is closed: no key added, removed, renamed or retyped, and no default changed. Anything new is `version: 2` |
| n/a | [Readiness endpoint](engineering_decisions/readiness-endpoint.md) | `GET /-/waharoa/ready`: 503 when a policy and an intel store are set and the store holds no snapshot or cannot answer; reports each stream's loaded digest, no percentage |
| n/a | [Snapshot identity](engineering_decisions/snapshot-identity.md) | The snapshot id is a hash over every source's stored rows, not the bundles. Postgres keeps the latest load; `waharoa refresh` also keeps each snapshot as files of the same encoding |
| n/a | [`policy check`](engineering_decisions/policy-check.md) | Loads as the proxy does; lists entries that change nothing, never win, or are `permanent: true`; `--strict` exits 1 on the first two |
| n/a | [PURL identity rules](engineering_decisions/purl-identity-rules.md) | Do not lowercase npm names; key on parsed components |

### Staging

| # | Decision | Remaining gate |
|---|---|---|
| 9 | [Stage structure](engineering_decisions/stage-structure.md) | M1 transport, M2 policy. Spike dissolved |
| 10 | [Fetch path](engineering_decisions/fetch-path-branching.md) | Branch decided before fetching; npm retry behaviour untested |
| 13 | [Name](engineering_decisions/project-name-waharoa.md) | Registry checks passed; cultural consultation outstanding |

### Open questions


