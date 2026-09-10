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
| Aikido Safe Chain | **MIT**, free public Intel feed | Client-side shim rather than a policy proxy |
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
now only half true. Between OSV, GitHub Advisory, OSSF Malicious Packages, and Aikido
Intel — which is free, public, and reports analyzing up to 100,000 malicious packages a
day, confirming ~19,500 malicious out of ~7.5M versions in Q2 2026 — competitive
detection coverage can be assembled without owning a detection pipeline.

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
| Aikido Intel | package name/version | Free, public, no account. High volume, commercial-grade. Highest-value non-OSV addition. |

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
- **Severity conflicts.** The same CVE routinely carries different CVSS scores across
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

**`malware` is deliberately separate from `match`.** The §5.5 non-overridable floor is
scoped to `known_malware: block`, so any stream holding `malware` for an ecosystem can
trigger the one rule nobody can override. That is a far higher trust bar than reporting
a CVE, and granting it must be explicit.

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

**ORM: SeaORM, targeting SQLite and Postgres.** Async-native, one codebase for both
backends. A repository trait sits in front of it; the **bulk refresh path uses raw sqlx
underneath**, since ORM inserts are far too slow for hundreds of thousands of advisory
rows. The ORM serves the lookup path only.

**Distribution: none.** Every stream fetches from its own origin — OSV publishes
per-ecosystem bundles to a public GCS bucket, GitHub Advisory is queried under the
user's token, OSSF Malicious Packages is a git repo. We never host or redistribute
intel. The artifact stays a single binary.

**Refresh must be atomic.** Build into a temp table and swap, so a failed refresh never
leaves a half-populated advisory set that silently under-blocks. Postgres gives
transactional DDL; SQLite needs the temp-table-and-rename dance.

**Postgres implies multi-instance**, which is a bigger change than the storage layer:

- **Refresh coordination.** N replicas rebuilding simultaneously is wasteful and racy.
  Needs advisory-lock leader election, or a separate `waharoa refresh` command run as a
  cron/Job with the proxies read-only.
- **`intel_snapshot_id` must be read from the database, not computed locally**, or
  replicas silently disagree and the reproducibility guarantee breaks.

**Snapshot identity** is the hash of concatenated per-stream bundle digests: one
reproducibility token across all streams, pinnable and exportable for air-gapped use.

**Cold start fails closed, with 503 — never 403.** A 403 during warming looks like a
policy violation for a package that is fine, which costs trust immediately. The 503 body
states that intel is loading and the percentage complete. A readiness endpoint reports
per-stream progress so orchestrators hold traffic until warm.

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

### Interception points per ecosystem

| Ecosystem | Mechanism | Notes |
|---|---|---|
| npm | registry URL | Simple. Per-package metadata, resolve-as-you-go. |
| PyPI | `--index-url`, PEP 503 | Backtracking resolver fetches metadata for versions it will never install. Different traffic shape. |
| cargo | source replacement, sparse index | Simplest protocol of the three. |
| Go | `GOPROXY` | Immutable modules + checksum DB already solve tamper-evidence. Low marginal value. |
| Maven | mirror in `settings.xml` | Largely client-side resolution. Slower publish cadence. |

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

Single YAML file. Global defaults, per-ecosystem overrides, a cross-cutting exception
list.

```yaml
version: 1

defaults:
  known_malware: block
  cooldown:
    action: quarantine
    days: 7
  install_scripts: warn
  provenance_required: false

ecosystems:
  npm:
    provenance_required: true
    install_scripts:
      action: allow
      loosens_global: true
      reason: "node-gyp builds until we vendor prebuilts"
      expires: 2026-11-30
  cargo:
    cooldown: { action: block, days: 14 }

exceptions:                 # ⚠ SUPERSEDED PENDING REVIEW — see §5.5
  - match: { ecosystem: npm, name: "@mycompany/*" }
    set: { cooldown: allow, provenance_required: false }
    reason: "internal, published by our CI"
    expires: 2026-12-31
    added_by: alice
```

### Merge semantics

- Ecosystem rules **override** global rules.
- Overrides that **loosen** the effective policy emit a warning.
- List-valued rules **replace** rather than union (predictable, safer).
- Exceptions are a separate selector list, not nested in `ecosystems`, because
  internal-scope packages cut across ecosystems and every adopter needs them on day one.

### Defining "looser"

Action values form a lattice: `allow < warn < quarantine < block`. Any move down the
order is loosening.

Parameterized rules need a **declared monotonicity direction per parameter** — it
cannot be inferred:

| Parameter | Stricter direction |
|---|---|
| `cooldown.days` | higher |
| `min_package_age` | higher |
| `max_cvss` | lower |

Getting one backwards fires warnings in exactly the wrong direction, which is worse
than having none. Where an override is **incomparable** (e.g. `block/3d` -> `warn/30d`),
warn: fail loud when tightening cannot be proven.

**Not-applicable is not loosening.** `install_scripts` has no meaning for Go modules.
Report N/A in `explain`; do not warn, or the channel becomes noise.

### Acknowledgment

Warnings emit **at config load and in `explain`**, never per-request — per-package
warnings become wallpaper within a day.

If loosening warnings cannot be acknowledged, users silence them by deleting the
global rule, which removes the baseline for every other ecosystem. So:

- Unacknowledged loosening -> warns
- `loosens_global: true` + `reason` + `expires` -> logs to audit trail, passes `--strict`
- Expired acknowledgment -> warns again

Same discipline as the exception list, so there is one mental model for both.

### 5.5 Package-level overrides and denials — RESOLVED

Evaluation order, most authoritative first. First match short-circuits.

```
denials  ->  floor  ->  packages  ->  ecosystems  ->  defaults
```

#### `denials` — permanent, absolute

Structurally separate from `packages`, not a flag on a shared record. Always exact
version, always tightening, never expires, never overridable by any tier. The type has
no `expires` field and no code path that consults precedence, so a denial with an
expiry date is unrepresentable rather than merely discouraged. Evaluated first and
short-circuits, so denials outrank even the floor.

#### `floor` — non-overridable minimum, per ecosystem

Structurally separate from `defaults`. The merge function that handles `defaults` never
receives floor rules, so no code path exists by which a lower tier could override one.
In Rust this is a distinct type with no override constructor — compiler-enforced rather
than a runtime check.

- **Operator-extensible.** Any rule may be promoted into the floor, so a security team
  can make `provenance_required: true` unbypassable for their org.
- **`known_malware: block` is pinned and cannot be removed.** Otherwise "editable floor"
  collapses into "no floor."
- **Per-ecosystem, and mandatory for every enabled ecosystem.** A missing floor for an
  enabled ecosystem is a **startup failure**, not a default. You cannot silently begin
  proxying a new ecosystem with no floor.
  - ⚠ **Breaking-change policy:** adding an adapter breaks existing configs until a
    floor is declared. Shipped templates must include floors for every supported
    ecosystem so the default path is not a startup failure.
- Floor rules that do not apply to an ecosystem report **not-applicable**, never a
  violation.
- **Threat model scope:** the floor guards against careless overrides at lower tiers. It
  does not defend against someone with write access to the policy file, who can edit the
  floor directly. State this explicitly; do not imply a stronger guarantee.
- Because a floor rule can wedge every build with no escape hatch below it, `explain`
  renders the floor as its own section rather than folding it into effective policy, and
  `policy check` reports floor blast radius against a recent lockfile before deploy.

#### `packages` — unified override tier

Replaces the earlier separate `exceptions` block. One syntax, one code path. The tier
handles both loosening (the common case) and tightening (e.g. raising cooldown on a
package you distrust), so `packages` is the honest name.

- **`ecosystem` is a required field on every selector.** Package names do not collide
  meaningfully across registries — npm `requests` and PyPI `requests` are unrelated
  projects — so a cross-ecosystem match is almost always a mistake. Requiring it makes
  tiers strictly linear, removes an axis from containment logic, and makes
  `{name: "*", cooldown: 0}` impossible to write by accident. `purl` selectors satisfy
  this inherently. Additive path if a real case appears: allow `ecosystem: [npm, pypi]`
  as an explicit list.
- **Tiers are strictly linear.** Tiers encode how many packages a rule affects, not how
  narrowly its conditions are scoped.

**Loosening requires justification, and emits no warning.** Warnings are correct at the
ecosystem tier where loosening is unexpected; here it is the tier's purpose, and
per-entry warnings would become noise that hides the ecosystem-tier warnings that
matter. A required field cannot be ignored the way a warning can. Tightening entries
need no justification.

- `reason` — always required on loosening entries
- `expires` — required, **maximum 90 days from today**
- `permanent: true` — explicit alternative to `expires`, requires `reason`, and is
  reported separately by `policy check` so genuine invariants (internal namespaces)
  stay individually visible instead of hiding among dated entries

Rationale for expiry: a justification is true when written and silently stops being
true later. Reviewed versions get superseded, internal packages change owners, the
blocker gets fixed and nobody deletes the entry. Expiry inverts the default so an
unexamined entry dies rather than persisting — deletion becomes the outcome of
inattention, which is the safe direction.

**Loosening is measured against the effective policy above the rule**, not the global
default. Otherwise a rule that loosens relative to its ecosystem but happens to match
global slips through unjustified.

#### Match resolution: most-specific-wins by subset containment

Specificity is a **strict subset relation**, not a heuristic score. A is more specific
than B if the set of packages A matches is a strict subset of B's:

- `@mycompany/foo` ⊂ `@mycompany/*` ⊂ `*`
- exact version ⊂ version range ⊂ any version
- selector + predicate (`has_install_scripts: true`) ⊂ same selector without it

Decidable because the predicate vocabulary is closed — a direct payoff of the
hand-rolled engine over Rego, where an open expression language would make containment
undecidable.

- **Incomparable overlaps are a load-time error.** `{name: "@mycompany/*"}` vs.
  `{name: "*", has_install_scripts: true}` overlap with neither containing the other.
  No principled winner exists, so refuse to start and require an explicit disambiguating
  entry. This is what makes most-specific-wins safe: it never silently guesses.
- Exact-duplicate selectors are also a load-time error.
- `explain` shows the winning selector **and** the ones it beat.
- `policy check` flags selectors that can never win because a strictly more specific
  entry always shadows them.

#### Version ranges

Resolved by the **normalizer** into a concrete match set before the policy engine sees
them, keeping semver / PEP 440 / cargo range syntax in the adapter layer. Validate
against the PyPI adapter before freezing the interface.

#### Example

```yaml
version: 1

denials:
  - purl: pkg:npm/chalk@5.6.1
    reason: "compromised release, Sept 2025"

floor:
  npm:
    known_malware: block        # pinned, cannot be removed
    provenance_required: true
  pypi:
    known_malware: block

defaults:
  cooldown: { action: quarantine, days: 7 }
  install_scripts: warn

ecosystems:
  npm:
    install_scripts:
      action: allow
      loosens_global: true
      reason: "node-gyp builds until we vendor prebuilts"
      expires: 2026-11-30

packages:
  - match: { ecosystem: npm, name: "@mycompany/*" }
    set: { cooldown: { days: 0 } }
    reason: "internal, published by our CI"
    permanent: true
    added_by: alice
  - match: { ecosystem: npm, purl: "pkg:npm/chalk@5.6.2" }
    set: { cooldown: { days: 0 } }
    reason: "reviewed by security, fixes GHSA-xxxx"
    expires: 2026-10-15
    added_by: alice
```

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
  exceptions lapse. With the 90-day ceiling this is the renewal workflow: a scheduled job
  surfacing upcoming expiries with concrete impact instead of a list of dates nobody can
  prioritize.
- **Nonzero exit on any loosening transition**, so a policy repo can gate weakening
  changes on review.

### HTTP stack

**axum server-side, reqwest upstream.** Both are hyper underneath with the missing
pieces filled in, and since a proxy runs both halves in the same process, sharing a
hyper version and body types means an upstream stream flows into the response without
conversion.

The asymmetry that decides it: hyper's server side is reasonably complete (framing,
keep-alive, HTTP/2 — you supply routing and middleware, which is what axum adds), but
hyper's client side hands you a *connection*, not a client. DNS, TLS setup, connection
pooling and redirect handling would all be ours to own. That is not work a security
tool wants to take on to gain control it may not need.

**Not a lock-in.** The two sides are independent — replacing the upstream client never
touches axum, which does not know what fetches for it. And reqwest's response body
converts into a hyper-compatible stream, so the hashing wrapper is the same code either
way; a swap adds pooling via `hyper-util` plus redirects, contained in one module.

**Put the upstream fetch behind a narrow trait from day one** — roughly *packument by
name* and *body stream by URL*, two or three methods. Then the client is an
implementation detail behind a boundary we control.

> This deliberately contradicts the Stage 3 reasoning for deferring the *adapter*
> abstraction, so the distinction matters: there, one implementation existed and the
> shape of the second was unknown. Here both shapes are known and the surface is three
> methods, not a whole protocol.

Streaming works cleanly in axum — its response body is just an `http-body`
implementation, so it forwards chunks as they arrive without buffering, and the hashing
wrapper sits in that chain naturally.

### Configuration format — OPEN, spike required

`serde_yaml` is archived, and every successor has a real defect:

| Option | Status |
|---|---|
| `serde_yml` | ❌ **RUSTSEC-2025-0068** — unsound and unmaintained, repo archived. Disqualifying on its own; unshippable for a tool that consumes the advisory DB flagging it. |
| `serde_norway` | Hard fork via `unsafe-libyaml-norway`; named by RustSec as a maintained alternative. Fixes the Norway problem (bare `no` parsing as boolean false — relevant given keys like `provenance_required`). Still C FFI. |
| `serde-yaml-ng` | Direct continuation of dtolnay's original — battle-tested, familiar API. But uses unmaintained `unsafe-libyaml`: C FFI with an unmaintained upstream, awkward to defend in our own audit output. |
| `serde-saphyr` | ✅ **Chosen.** Pure Rust, no C FFI. Zero `unsafe` in its own code and in its parser, both carrying `forbid(unsafe_code)`. Panic-free on malformed input, no tag-driven object construction (the classic YAML RCE vector), configurable nesting/size budgets, parses straight to Rust types with no intermediate document model. **Corrected Sept 2026: now 1.2.0, not 0.0.10** (1.0.0 released July 2026 after two RCs, steady cadence since). It also no longer depends on `saphyr` at all, having vendored its own `granit-parser`, so the "upstream calls serde support soon-to-be" objection is void. Residual risk: single maintainer, and a 26-crate tree that pulls `encoding_rs` (SIMD, plenty of `unsafe`). |
| `toml` | Pure Rust, well maintained by the toml-rs team, Rust's own format, no Norway problem, and by far the smallest tree (6 crates). `toml_parser` gates its own `unsafe` behind an opt-in feature, off by default, though `winnow` beneath it carries 44 `unsafe` blocks that are not feature-gated. Rejected on the two format criteria, not on dependencies. See the findings below. |

#### Spike result (Sept 2026): **YAML, loaded by `serde-saphyr`**

The spike was run as specified: the real §5.5 policy (2 denials, per-ecosystem floor,
3 package entries with selectors, `set` blocks, `reason`, `expires`, `permanent`) written
in both formats, plus 16 malformed or probing variants, loaded by all four candidates
through one identical `deny_unknown_fields` schema.

**The premise that framed this decision was wrong, and that is what changed the answer.**
The tiebreak assumed TOML was the only pure-Rust option. `serde-saphyr` is now 1.2.0
rather than 0.0.10, has dropped `saphyr` for its own `granit-parser`, and carries zero
`unsafe` in both crates. So the "pure Rust versus readable" trade no longer exists, and
YAML wins on both format criteria without paying a dependency penalty.

**1. Readability.** YAML 50 lines, TOML 70. Verbosity is not the real cost. Inside
`[[packages]]`, TOML requires the scalar keys (`reason`, `expires`, `permanent`,
`added_by`) to precede the `[packages.match]` and `[packages.set.*]` sub-tables, so the
justification must be written before the thing it justifies. Writing an entry in its
natural reading order is a parse error, and a misleading one: the trailing keys get
absorbed into the still-open cooldown table, producing ``unknown field `added_by`,
expected `action` or `days` ``. Every package entry an operator writes is exposed to this.

**2. Unknown-key rejection.** Survives in all four loaders at all four depths tested
(root, inside a `match` selector, inside a `set` block, inside the polymorphic rule
struct). A tie, with one important exception recorded as a schema constraint below.

**3. Error quality.** `serde-saphyr` is clearly best: source excerpt, caret, and plain
language (`tabs disallowed within this context (block indentation)` where libyaml-based
crates say `found character that cannot start any token`). `toml` has good spans but two
misleading-error classes, both from table syntax rather than from serde: the ordering
case above, and a typo'd `[[package]]` for `[[packages]]`, which reports `duplicate key`
against a correct line six lines further down instead of naming the unknown table.
`serde_norway` and `serde-yaml-ng` are byte-identical in output, adequate for serde
errors and poor for syntax errors.

**Dependency and security posture.** All four are clean under `cargo audit` (method
validated by confirming it still flags RUSTSEC-2025-0068 against the excluded
`serde_yml`). `serde-saphyr` plus `granit-parser` carry zero `unsafe` and both set
`forbid(unsafe_code)`; the cost is a 26-crate tree that pulls `encoding_rs`. `toml` is
6 crates. The libyaml pair carry C FFI.

**Two assumptions the spike falsified, recorded so they are not re-derived:**

- **Alias bombs are not a discriminator.** All three YAML crates refuse a 9^8 expansion.
  libyaml has its own repetition limit and refuses in ~9ms; `serde-saphyr` refuses via
  its node budget but takes ~100ms and emits a genuinely bad message (`budget breached:
  Nodes { nodes: 250001 }` followed by five repeated position clauses). A known wart.
  Note the first version of this test was invalid: the lazy struct-directed path skipped
  fields the target type never demanded, so everything appeared to parse. The valid test
  deserializes into a recursive value type that forces full materialization.
- **The Norway problem is dissolved by a type-directed parser, not by `serde_norway`.**
  `serde-saphyr` resolves the bare token `no` against the target type: `false` for a
  `bool` field, `"no"` for a `String` field. Both are what the author meant.
  `serde_norway` and `serde-yaml-ng` always yield the string, so the entirely natural
  `provenance_required: no` is a hard type error.

**Schema constraint, load-bearing: never `#[serde(untagged)]`.** Rule fields are
polymorphic (`install_scripts: warn` or a table carrying the §5 acknowledgment). Modelled
with `untagged`, a typo inside the table form degrades to `data did not match any variant
of untagged enum ScriptRule` in *every* loader, in both formats, silently defeating the
fail-closed guarantee that unknown keys are a hard error. A hand-written `Deserialize`
that calls `deserialize_any` and dispatches `visit_str` to the bare form and `visit_map`
to the table form restores the exact message (``unknown field `expiress`, expected one of
action, loosens_global, reason, expires``) with correct spans in both YAML and TOML. This
applies to every polymorphic rule field added later, not just `install_scripts`.

**Feature posture.** `default-features = false`, `features = ["deserialize"]`: we only
ever read config, never write it. `include` and `include_fs` stay **off** permanently.
File inclusion in the policy file of a security tool is attack surface, not convenience.

**Residual risk and the exit.** `serde-saphyr` is a single-maintainer crate about six
weeks past 1.0. That risk is bounded because the schema uses plain `serde` derives with
zero crate-specific attributes: all four candidates deserialized the identical `Policy`
type in the spike, so switching loaders is a one-line change. **`serde_norway` is the
named fallback**, being the alternative RustSec itself points to.

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

**Known bypass vectors — must be stated honestly in the README:**

- **Reverse proxy mode is advisory, not mandatory.** A developer who resets their
  registry URL defeats it entirely. Mitigations are `waharoa doctor` (verifies effective
  client config) and CI lockfile verification that all resolved URLs point at the proxy.
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

### Decided

| # | Question | Decision | Rationale |
|---|---|---|---|
| 1 | Language | **Rust** | Maintainer fluency; type system encodes the §5 lattice, monotonicity, and non-overridable floor. Costs: immature `sigstore-rs`, no OSV client, `serde_yaml` archived, rustls strictness. |
| 2 | Policy engine | **Hand-rolled**, Rego as later optional escape hatch | Rule set is small and closed; Rego cannot express loosening detection or the floor natively; `explain` is far harder over Rego. |
| 3 | TLS | **Reverse proxy first**, CA-terminating forward proxy later | All target package managers support alternate registries. No CA distribution, no trust-store surgery. Terminating mode is an enterprise anti-bypass feature. |
| 4 | Quarantine | **Filter metadata on resolution, hard fail on pinned fetch** | Substitution breaks lockfile integrity hashes. Filtering lets the resolver pick a clean version naturally. |
| 4b | Cooldown vs. urgent fixes | **Manually reviewed version waivers only**, no automatic advisory-based bypass | Auto-waiver is attacker-exploitable via fake advisories. Reduces to the §5.5 package tier. One path only — no emergency fast path; deploy latency accepted as the cost of a single auditable route. |
| 5 | License | **Apache-2.0**, DCO, trademark separate | Ecosystem norm; patent grant; zero friction for adapter contributors. |
| 11 | Config format | **YAML, loaded by `serde-saphyr`** (`deserialize` only; `include` off). Fallback `serde_norway`. Schema forbids `#[serde(untagged)]` | Spike run Sept 2026 against the real §5.5 policy in both formats. The framing premise was stale: `serde-saphyr` is 1.2.0 with zero `unsafe`, so pure-Rust no longer implies TOML. YAML then wins on both format criteria. TOML's `[[packages]]` ordering rule makes the natural writing order a parse error with a misleading message. See §5. |
| 8 | §5.5 package tier | **All seven issues resolved.** Separate `denials` / `floor` / `packages` blocks; evaluation order denials → floor → packages → ecosystems → defaults; floor operator-extensible, per-ecosystem, mandatory, `known_malware` pinned; `ecosystem` required on selectors; loosening needs `reason` + `expires` (90d max) or `permanent: true`, no warning; most-specific-wins by subset containment with incomparable overlaps a load-time error; ranges resolved in the normalizer | Schema freeze unblocked. See §5.5. |
| 7 | NVD role | **`enrich`-only for npm/PyPI**, `match` permitted for Maven; generalized to a per-ecosystem stream capability matrix (`match` / `enrich` / `malware`) | CPE-to-PURL is a category mismatch, not a mapping problem. Coverage is uneven per stream *and* ecosystem, so capability must be a matrix. |
| 6 | Intel distribution | **None — fetch from origin.** SeaORM over SQLite + Postgres; fail-closed cold start with 503; adopt query-on-clean live fallback | OSV/GHSA/OSSF all self-host their feeds. Postgres for multi-instance. See §3. |

### Staging

| # | Decision | Rationale |
|---|---|---|
| 13 | Name | **`waharoa`**: ✅ registry checks passed (Sept 2026), ⚠ cultural consultation still outstanding | Free on all four registries: crates.io, npm, PyPI and the GitHub org all return 404 on the exact name, with known-existing controls returning 200 to prove the check meaningful. Clean namespace vs. `waha`/`portcullis`. Consultation is the remaining gate. See header. |
| 12 | HTTP stack | **axum server-side, reqwest upstream**, behind a narrow fetch trait we own | Both sit on hyper and share body types, so a stream from upstream flows into the response without conversion. Hyper's client is a *connection*, not a client — pooling, redirects, DNS and TLS would all be ours. See §5. |
| 10 | Fetch path | **Cache hit streams; novel + cheap buffers; novel + expensive defers with 429.** Packument digest decides the branch before fetching | Content-based verdicts are almost never needed at fetch time — policy evaluates on metadata, which is already resolved. See §5. |
| 9 | Stage structure | **Spike dissolved; split transport from policy.** M1 = pass-through proxy, M2 = decision layer | The reverse proxy is well-understood architecture, not a research risk. Splitting on the transport/policy boundary makes identity bugs falsifiable before evaluation logic exists. |

### Open questions


