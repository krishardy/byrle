# waharoa — Staged TODO

Stages are sequential. Each has an exit criterion; do not start the next stage until it
is met. Within a stage, `[!]` marks items that block the exit criterion.

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocks stage exit

---

## Ad-hoc

Items that I've added that are not stage-bound.

1. Look at the witchcraft binary collection (from edrazine) and look into integrating wsolver into a fuzzing and formal analysis process of the compiled binary.

## Stage 1 — Pass-through proxy (transport)

**Goal:** installs work through us, and every package is correctly identified. **No
policy at all.** This stage is falsifiable on its own: if the normalizer produces a
wrong PURL you find out here, rather than debugging a wrong verdict later and not
knowing whether the bug is in identity or in evaluation.

**npm only, concretely.** No adapter trait, no plugin surface, no generalization for
hypothetical ecosystems. The abstraction is extracted in Stage 3 against two real
implementations.

- [x] Language: **Rust** (decided)
- [x] Review Datadog supply-chain-firewall — **done, see plan §2.** CLI wrapper, not a
      proxy; different architecture, not a positioning threat. GuardDog integration is
      the reusable idea (Stage 4 detector interface).
- [x] Reverse-proxy registry endpoint between npm and registry.npmjs.org. axum catch-all,
      reqwest upstream, bodies streamed through verbatim with `Content-Encoding` intact
      (reqwest's `gzip` feature is deliberately off, so nothing is decompressed behind our
      back). Upstream failure maps to 502, per §5. Run it with `make run`.
- [~] rustls + platform verifier for the **upstream** connection. Verifier half **done**:
      reqwest 0.13's default `rustls` feature pulls `rustls-platform-verifier` 0.7, so the
      upstream leg validates against the OS trust store. Inbound stays plain HTTP on
      loopback, per decision #3.
      - [ ] **Custom CA bundle is NOT implemented.** Needed for private registries and for
            corporate TLS-inspecting middleboxes, which would otherwise fail to verify.
            `Client::add_root_certificate`, plus config to point at a bundle.
- [x] Serve `npm install lodash` successfully through the proxy. Covered by `make smoke-npm`.
- [x] Block one hardcoded package name with HTTP 403, proving interception. Throwaway, and
      kept deliberately awkward: it is env-only (`WAHAROA_BLOCK`), with no config file
      behind it, so it cannot quietly become a feature. Stage 2 replaces it.
- [x] Confirm transitive deps are also intercepted, not just top-level. `npm install
      express` pulls 66 packages and every one was fetched through the proxy at both the
      metadata and tarball leg. The block test goes further: `ms` is blocked while
      installing `debug`, so it fires on a package the user never named, on the packument
      request, with no tarball fetched.
- [x] **Finding: npm needs no packument rewriting.** The open question behind this stage.
      `dist.tarball` is an absolute `registry.npmjs.org` URL, but npm resolves tarballs
      against the *configured* registry and ignores it, so we are a pass-through. Recorded
      in plan §4. Re-check per client; yarn and pnpm are untested.
- [x] **Finding: the lockfile-verification mitigation in §7 does not work for npm.**
      npm normalizes `resolved` back to the canonical registry URL with both `--registry`
      and `.npmrc`, so a lockfile cannot evidence that the proxy was used. Plan §7
      corrected. The anti-bypass control has to come from somewhere else.
- [ ] `[!]` PURL as internal identity type
- [ ] `[!]` Common package record schema (name, version, ecosystem, publish time,
      maintainers, repo URL, has-install-scripts, provenance, hashes)
- [ ] `[!]` npm transport + normalizer, written **concretely** — no adapter abstraction
      yet. Extraction deferred to Stage 3, where PyPI gives a second shape to design
      against. An interface designed against one caller gets it wrong.
- [ ] Conditional requests (ETag / If-None-Match) so pass-through stays cheap

### Spikes and decisions (do these first)
- [x] **SPIKE: config format, done. See plan §5.** Decision: **YAML via `serde-saphyr`**
      (`default-features = false`, `features = ["deserialize"]`; `include`/`include_fs`
      stay off). Fallback `serde_norway`. Ran the real §5.5 policy in both formats plus
      16 malformed variants through one shared `deny_unknown_fields` schema.
      Key finding: the plan's premise was stale. `serde-saphyr` is 1.2.0, not 0.0.10,
      dropped `saphyr` for its own `granit-parser`, and has zero `unsafe` in both crates,
      so pure-Rust no longer implies TOML. YAML then wins on readability and error
      quality. All four candidates clean under `cargo audit`.
      Two assumptions falsified: alias bombs are refused by all three YAML crates (not a
      discriminator), and the Norway problem dissolves under a type-directed parser
      rather than under `serde_norway`.
- [ ] **Schema constraint from the spike: never `#[serde(untagged)]`** on polymorphic
      rule fields. Carried into the Stage 2 loader; not a Stage 1 exit blocker. It silently defeats unknown-key rejection in every loader and both
      formats. Hand-write `Deserialize` with `deserialize_any` + `visit_str`/`visit_map`.
      Applies to every polymorphic rule field, not just `install_scripts`.
- [x] **HTTP stack: axum server-side, reqwest upstream.** Hyper's client is a
      connection, not a client — pooling/redirects/DNS/TLS would all be ours.
- [x] **Narrow upstream-fetch trait: DEFERRED, confirmed Sept 2026.** The plan had
      recorded it as day-one work from a conversation summary nobody had agreed to.
      Decided against: Stage 1 holds to its own rule and calls reqwest concretely, with
      the boundary extracted in Stage 2/3 against real callers, exactly as the adapter
      trait is. The "both shapes are already known" argument did not survive review, and
      it is weakest for the method that matters most: a single body-stream signature has
      to serve all three §5 fetch branches (stream, buffer, defer), none of which exist
      yet, so it would be designed against zero callers.
- [ ] Testing strategy is unrecorded anywhere, and deferring the trait makes it load
      bearing: with no seam to inject a fake, Stage 1 needs HTTP-level fixtures. For a
      proxy that is arguably the better target anyway, since the bytes on the wire are
      the product. Pick the approach before writing the first transport test.
- [~] **Name: `waharoa`.** Registry half **done**: all four exact-name lookups return
      404 (crates.io, npm, PyPI, the GitHub org), with known-existing controls returning
      200 in the same run to prove the probe works. The name is free.
      - [ ] `[!]` **Cultural consultation still outstanding.** This is the remaining gate
            on the name, and it is a human conversation, not a lookup. See plan header.
- [ ] Shipped policy template must declare a floor for **every** supported ecosystem, or
      the default path is a startup failure (§5.5). `examples/policy.yaml` is the spike
      artifact and is deliberately incomplete: it declares `ecosystems.cargo` with no
      `floor.cargo`. Complete it when the floor check lands.
- [ ] Defer: single binary vs. workspace crates. Splitting later is cheap; not enough
      information yet.

### Fetch path and status codes
- [ ] `[!]` Read `dist.integrity` from the packument — artifact digest known **before**
      the tarball is fetched, so cache-hit vs. cache-miss is decided up front
- [ ] `[!]` Cache hit → stream through. Flat memory, no added latency.
- [ ] `[!]` Stream the body through a hashing wrapper (`http-body` frame poll — feed
      each chunk to the hasher before forwarding). Verify at the end; abort the response
      cleanly on mismatch. Note there is **no mid-stream branch into buffering** — the
      packument digest decides stream-vs-buffer *before* the fetch, so buffering is its
      own path chosen up front.
- [ ] `[!]` Verify the digest of what actually arrives against the packument's claim;
      a mismatch is a finding, not a cache error. The registry hash is a **key**, not a
      trust anchor.
- [ ] `[!]` Status-code split: **502** upstream unreachable/malformed · **503** we are
      not ready (mirror warming, all requests) · **429** we are ready but this one
      artifact is under analysis
- [ ] `[!]` Never 4xx-that-reads-as-a-block for a not-ready state (same rule as cold start)
- [ ] Per-client code selection inferred from user-agent (already parsed for dialect);
      shipped table of known clients, operator-forceable global override
- [ ] Unknown user-agent falls back to **503** — fail toward the more widely retried code
- [ ] Machine-readable reason + artifact digest in response header and body (neither
      code distinguishes cold-start from per-artifact analysis on its own)
- [ ] Log every deferral and whether the client returned inside the window — turns the
      compatibility table into evidence
- [ ] `[!]` Test real client retry behavior early: npm may apply its own backoff and fail
      the install rather than waiting. Tune `Retry-After` to land inside npm's retry
      window; bounded internal wait as fallback for clients that give up.
- [ ] File upstream issues asking npm / pip / uv / cargo to honor `429` + `Retry-After`.
      Argues on its own merits (a proxy legitimately rate-limiting is a real scenario),
      so it is a small uncontroversial patch. Long lead time — file early.
- [ ] Test with npm, yarn, and pnpm — note where behavior diverges
- [ ] Confirm npm cache bypass behavior; `npm cache clean --force` needed on onboarding
- [ ] `waharoa doctor` — verify effective client config, detect npm cache bypass

**Exit:** a real `npm install` completes through the proxy with the full transitive
graph correctly normalized to PURLs, and the hardcoded block fires before the tarball
is fetched. Leave it running for a week and trust it.

---

## Stage 2 — Decision layer (policy + intel)

**Goal:** the policy engine and its semantics, on top of a transport you already trust.
The spec gets frozen here.

- [ ] `[!]` Pick `serde_yaml` replacement before writing the loader (it is archived)

### Policy engine
- [ ] `[!]` YAML loader with **hard error on unknown keys**
- [ ] `[!]` `version` field; refuse to start on unrecognized version
- [ ] `[!]` Action lattice: `allow < warn < quarantine < block`
- [ ] `[!]` Global -> ecosystem merge; ecosystem overrides win
- [ ] `[!]` Per-parameter monotonicity declarations (cooldown.days ↑, max_cvss ↓, ...)
- [ ] `[!]` Loosening detection, including the incomparable case (warn on unprovable)
- [ ] `[!]` N/A handling — not-applicable rules never count as loosening
- [ ] `[!]` Loosening warnings emit at config load only, never per-request
- [ ] `[!]` `loosens_global` acknowledgment with required `reason` + `expires`
- [ ] Expired acknowledgment re-warns
- [ ] List-valued rules replace rather than union
- [ ] Golden-file tests for every merge case in the plan's tables

### Package tier

- [ ] `[!]` Evaluation order: denials → floor → packages → ecosystems → defaults,
      first match short-circuits
- [ ] `[!]` `Denial` type with **no** `expires` field and no precedence code path
- [ ] `[!]` `Floor` type with no override constructor (compiler-enforced)
- [ ] `[!]` Floor is per-ecosystem; **startup failure** if an enabled ecosystem has none
- [ ] `[!]` `known_malware: block` pinned into every floor, not removable
- [ ] `[!]` Floor rules report not-applicable for ecosystems where they have no meaning
- [ ] `[!]` Unified `packages` tier; `exceptions` block removed
- [ ] `[!]` `ecosystem` required on every package selector (load-time error if absent)
- [ ] `[!]` Loosening requires `reason` + `expires`; **no warning emitted**
- [ ] `[!]` `expires` ceiling of 90 days from today, configurable
- [ ] `[!]` `permanent: true` as explicit alternative, requires `reason`
- [ ] `[!]` Loosening measured against effective policy **above the rule**
- [ ] `[!]` Specificity as strict subset containment, not a score
- [ ] `[!]` Incomparable overlaps and exact duplicates are load-time errors
- [ ] Range resolution in the normalizer, never in the engine
- [ ] `explain` shows winning selector and the ones it beat, per tier
- [ ] `policy check` flags permanently-shadowed selectors
- [ ] `policy check` reports floor blast radius against a recent lockfile
- [ ] `policy check` lists `permanent: true` entries separately
- [ ] Tests: denial cannot be undone by any tier, including floor
- [ ] Tests: floor survives a hostile config file
- [ ] Shipped config templates include floors for every supported ecosystem
- [ ] Document the adapter-addition breaking-change policy

### `waharoa policy diff`

- [ ] `[!]` Evaluate two policies against a real package set
- [ ] `[!]` Pin `--snapshot` so policy changes are not conflated with intel changes
- [ ] `[!]` Package set from lockfiles **and** from the audit log
- [ ] `[!]` Report transitions both directions, grouped with counts
- [ ] `[!]` Nonzero exit on any loosening transition (CI gate)
- [ ] `--as-of <date>` for time-dependent verdicts (cooldown, expiry)
- [ ] Scheduled-job recipe: `--as-of +30d` to surface upcoming expiries with impact

### Intel — advisory streams
- [ ] `[!]` **Verify each stream's data license before implementing it** — separate from
      the tooling license in the same repo; the two frequently differ (Apache-2.0 code,
      CC-licensed reports). Record the finding per stream.
- [ ] `[!]` Advisory stream interface (fetch / mirror / refresh / normalize)
- [ ] `[!]` Per-ecosystem capability matrix: `match` / `enrich` / `malware`
- [ ] `[!]` Type-enforce that `enrich` records cannot originate a finding
- [ ] `[!]` `malware` capability gated separately — it can trigger the non-overridable floor
- [ ] Plugin-declared capabilities, operator-overridable; promotion harder than demotion
- [ ] Startup warning + `doctor` check: ecosystem enabled with no `match`-capable stream
- [ ] `waharoa status` shows adapter maturity and intel coverage as separate axes
- [ ] Explicit severity precedence config (enrich may escalate `max_cvss`, never originate)
- [ ] `[!]` Common advisory record schema with alias set (CVE, GHSA, OSV, MAL IDs)
- [ ] `[!]` OSV.dev stream, lookup by PURL
- [ ] `[!]` Deduplication across streams via alias reconciliation — before the policy
      engine, so one vuln never fires three rules
- [ ] `[!]` GitHub Advisory stream (GraphQL, token auth)
- [ ] `[!]` Aikido Intel stream — free, public, no account; highest-value non-OSV feed
- [ ] OSSF Malicious Packages stream — publishes natively in OSV format, so it reuses
      the OSV normalization path rather than needing its own
- [ ] Datadog malicious-packages — **check OSSF overlap first**; Datadog contributes
      upstream to OSSF, so this is likely already ingested. Only implement if it adds
      real coverage. Verify data license and per-version lookup shape.
- [ ] NVD stream — `enrich`-only for npm/PyPI, joined on exact CVE ID
- [ ] NVD enrichment runs as a background job, never on the hot path
- [ ] Revisit NVD `match` capability if/when the Maven adapter is scoped
- [ ] Configurable severity precedence when streams disagree on CVSS
- [ ] Withdrawal propagation — withdrawn advisories must clear from the local mirror
- [ ] Per-stream refresh scheduling, rate limits, and API key config
- [ ] Local mirrors for all streams (no dependency-graph leakage)
- [ ] Per-stream enable/disable in policy config
- [ ] Configurable fail-open/fail-closed on stream unavailability, default closed
- [ ] Stream authoring guide for third-party sources

### Intel storage
- [ ] `[!]` SeaORM over SQLite; repository trait in front
- [ ] `[!]` Bulk refresh on raw sqlx (ORM too slow at 100k+ rows)
- [ ] `[!]` Atomic refresh via temp-table swap
- [ ] `[!]` Cold start fails closed with **503, never 403** + readiness endpoint with %
- [ ] Query-on-clean live OSV fallback, opt-in, default fail-open, privacy tradeoff documented

### Observability
- [ ] `[!]` JSON Lines audit log: package, version, ecosystem, verdict, rule, timestamp
- [ ] `[!]` `waharoa explain --policy` — effective merged policy per ecosystem
- [ ] `[!]` `waharoa explain <purl>` — verdict plus the rule that fired
- [ ] `waharoa status` — ecosystem maturity tiers
- [ ] CI lockfile verification: all resolved URLs point at the proxy

**Exit:** a real package blocked for a real reason, with `explain` naming the rule that
fired; npm enforcing against OSV with a real policy file; `explain` correct across every
merge and loosening case in all tiers; policy schema declared frozen.

---

## Stage 3 — Second ecosystem (PyPI)

**Goal:** **extract** the adapter interface, using npm and PyPI as the two shapes to
design against. The interface is an output of this stage, not an input. If PyPI forces
changes to the core, that is the finding — make it now, not after five adapters exist.

- [ ] `[!]` PEP 503 simple-index transport, written concretely first
- [ ] `[!]` Extract the adapter interface (transport + normalizer) from the two working
      implementations — refactor, not upfront design
- [ ] `[!]` Reimplement npm and PyPI on the extracted interface, behavior unchanged
- [ ] `[!]` Handle the backtracking resolver's traffic shape (metadata fetched for
      versions never installed — do not treat as install intent)
- [ ] `[!]` PyPI normalizer to the common record
- [ ] `[!]` sdist vs. wheel distinction for install-script semantics
- [ ] pip and uv both verified
- [ ] Ecosystem-namespaced predicates degrade loudly (report N/A, never silent pass)
- [ ] Document every core change this stage forced

**Exit:** PyPI enforcing; adapter interface extracted from two working implementations
and documented; npm still passes every Stage 1 and Stage 2 test after the refactor.

---

## Stage 4 — Differentiators

**Goal:** the intel-independent controls. This is the launch story, not stages 1–3.

- [ ] `[!]` **Cooldown / quarantine** — hold versions published within N days
- [ ] `[!]` Resolution path: filter quarantined versions from metadata (packument /
      simple index / sparse index) so the resolver picks a clean version naturally
- [ ] `[!]` Pinned path: hard fail with the rule that fired and the quarantine lift date
- [ ] `[!]` Surface filtering in response header, audit log, and `explain` — silent
      modification is its own trust problem
- [ ] `policy check` flags cooldown waivers whose underlying cooldown already elapsed
- [ ] `[!]` **Lifecycle script policy** — npm pre/postinstall, Python sdist `setup.py`
      — cheap tier, buffers inline
- [ ] `[!]` **Provenance enforcement** — sigstore / npm provenance verification
  - [ ] `[!]` Validate `sigstore-rs` maturity first; cosign shell-out as fallback
- [ ] `[!]` **Declare an analysis cost tier for every content detector** — cheap
      detectors buffer inline (tar listing, ~tens of ms); expensive detectors defer with
      429. Only expensive ones may produce a retry. The tier is part of the detector
      contract, not a runtime guess.
- [ ] **Registry tarball vs. git source diffing** — expensive tier (git clone, ~tens of s)
  - [ ] Resolve repo URL and matching tag from package metadata
  - [ ] Normalize for expected build artifacts and packaging noise
  - [ ] Tune until the false-positive rate is publishable
- [ ] Metadata heuristics: package age, maintainer age, missing repo link, maintainer
      change, typosquat distance
- [ ] Pluggable detector interface for third-party/commercial feeds
  - [ ] Evaluate **GuardDog** (Datadog, OSS heuristic scanner) as a first-party detector
- [ ] Benchmark each control against known 2025–26 incidents (shai-hulud, tinycolor,
      chalk, nx, eslint-config-prettier) and publish the results

**Exit:** all Tier 1 controls shipped with measured false-positive rates.

---

## Stage 5 — Hardening

**Goal:** make it something a real team will run in blocking mode.

- [ ] `[!]` Analysis cache keyed by **tarball content digest** (install-script presence,
      source diff, capability analysis — permanently valid). Metadata always passes
      through to upstream; no binary caching.
- [ ] `[!]` Reproducible verdicts: same policy + same intel snapshot = same result
- [ ] `[!]` Offline / air-gapped mode with pinnable intel snapshots
- [ ] `[!]` `waharoa policy check --strict` — nonzero exit on unacknowledged loosening
- [ ] `[!]` Warn mode as the shipped default
- [ ] Latency budget and benchmarks on a large lockfile (cold and warm cache)
- [ ] ACME / Let's Encrypt support; document fronting with Caddy/nginx
- [ ] Honor `HTTPS_PROXY` for upstream traffic
- [ ] Proxy-unavailable behavior + documented break-glass path
- [ ] Our own releases published with provenance attestations
- [ ] `SECURITY.md`, disclosure policy, threat model doc
- [ ] Get one external team running it in blocking mode; fix what they hit

**Exit:** an external team runs it enforcing for two weeks without disabling it.

---

## Stage 6 — Third ecosystem (cargo)

- [ ] Sparse index transport adapter
- [ ] Source replacement configuration + onboarding docs
- [ ] `build.rs` mapped to install-script semantics
- [ ] Declare the adapter interface stable and document it for contributors

**Exit:** three protocols on one unchanged interface.

---

## Stage 7 — Launch

- [ ] `[!]` README with per-ecosystem maturity tiers stated prominently
- [ ] `[!]` Quickstart per ecosystem (npm, PyPI, cargo)
- [ ] `[!]` Policy reference doc with every rule and its monotonicity direction
- [x] License: **Apache-2.0** (decided)
- [ ] `[!]` Add LICENSE, DCO sign-off in CONTRIBUTING, trademark note
- [ ] `[!]` README: document known bypass vectors honestly (plan §7)
- [ ] `[!]` Name availability check across npm, PyPI, crates.io, GitHub
- [ ] Migration guide from Socket Firewall Free / pkggate
- [ ] CONTRIBUTING.md, adapter authoring guide, detector authoring guide
- [ ] OSV mirror distribution plan (plan §10.6)
- [ ] Announce: OpenSSF slack, HN, relevant ecosystem security channels

---

## Deferred / post-v1

- [ ] Go adapter (`GOPROXY`) — low marginal value, checksum DB already covers tamper-evidence
- [ ] Maven adapter (`settings.xml` mirror)
- [ ] **AI agent profiles** — stricter policy for agent-initiated installs
- [ ] Rate limiting on novel package introduction
- [ ] Approval-request flow as an alternative to hard block
- [ ] Rego escape hatch for complex org policies
- [ ] Install-time sandboxing
- [ ] Hosted intel service (only if there is clear demand and it stays optional)
