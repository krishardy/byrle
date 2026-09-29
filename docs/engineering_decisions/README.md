# Engineering decisions

One file per decision. Each records what was decided, why, what was rejected, and what
it costs. The index in [../project_plan.md](../project_plan.md) §10 links here; the
reasoning lives here rather than in the plan.

Status is **Decided**, **Staging**, **Implemented**, or **Open question**. Staging means the decision is
made but a gate remains, and the file names the gate. Implemented means it is in the
code, and the file names where.

| Decision | Status |
|---|---|
| [Language: Rust](language-rust.md) | Decided |
| [Policy engine: hand-rolled](policy-engine-hand-rolled.md) | Decided |
| [TLS: reverse proxy first](tls-reverse-proxy-first.md) | Decided |
| [Quarantine: filter metadata](quarantine-filter-metadata.md) | Decided |
| [Cooldown waivers: manual only](cooldown-waivers-manual-only.md) | Decided |
| [License: Apache-2.0](license-apache-2.md) | Decided |
| [Intel distribution: fetch from origin](intel-distribution-fetch-from-origin.md) | Decided |
| [NVD role and stream capabilities](nvd-role-and-stream-capabilities.md) | Decided |
| [Package override tier](package-override-tier.md) | Superseded by [policy-tier-resolution](policy-tier-resolution.md) |
| [Config format: YAML via serde-saphyr](config-format-yaml-serde-saphyr.md) | Decided |
| [HTTP stack: axum and reqwest](http-stack-axum-reqwest.md) | Decided |
| [Command line: clap, default features off](cli-parser-clap.md) | Implemented |
| [Environment variables: one module](environment-variables.md) | Implemented |
| [PURL identity rules for npm](purl-identity-rules.md) | Decided |
| [Storage: sqlx over Postgres, no ORM](storage-sqlx-postgres.md) | Implemented, lookup path only |
| [sqlx held at 0.8, RUSTSEC-2023-0071 accepted while `rsa` is not built](sqlx-0-8-and-rsa-advisory.md) | Implemented |
| [What CI gates, and what it does not](ci-gates.md) | Implemented, unverified until first push |
| [Loading OSV malware records](osv-malware-load.md) | Implemented, `waharoa refresh` |
| [Intel in decisions: one lookup per package, fail closed](intel-in-decisions.md) | Implemented |
| [An ecosystem no stream covers fails closed](uncovered-ecosystem-fails-closed.md) | Implemented |
| [A PyPI index is filtered by policy, with or without intel](pypi-index-filtering.md) | Implemented |
| [Each ecosystem's versions order by its own rules; PEP 440 is hand-written](pep440-version-order.md) | Implemented |
| [Policy version ranges are VERS strings, in every ecosystem](policy-version-ranges.md) | Implemented |
| [`doctor` checks pip and uv, and reads uv's TOML configuration](doctor-python-clients.md) | Implemented |
| [How a request through the proxy is tied to an account](account-identification.md) | Decided |
| [Reporting: accounts, installed dependencies and notifications](reporting-accounts-and-notifications.md) | Decided |
| [Metadata is fetched from upstream on every request](no-metadata-cache.md) | Implemented |
| [A yanked file is refused, and the policy can allow it](yanked-files.md) | Implemented |
| [One library crate and one binary, not a workspace](one-crate.md) | Decided |
| [waharoa resolves no version ranges](no-range-resolution.md) | Decided |
| [The PEP 503 HTML index is read, not forwarded](pep-503-html-index.md) | Implemented |
| [PyPI provenance: the index says where the bundle is](pypi-provenance.md) | Implemented, verified by the provenance check |
| [Install scripts are read from the artifact](install-scripts-from-the-artifact.md) | Implemented, the reader |
| [An artifact's analysis is kept under the digest of its bytes](artifact-analysis-store.md) | Implemented, the store |
| [An artifact is analysed in the background, spooled to disk](artifact-spool.md) | Implemented |
| [Attestations are verified with `sigstore-verify`](sigstore-verifier.md) | Implemented |
| [The provenance check refuses a version its attestations contradict](provenance-check.md) | Implemented, npm and PyPI |
| [Tier 1 false-positive rates](tier-1-false-positives.md) | Measured |
| [The Tier 1 controls against the 2025 npm incidents](incident-benchmark.md) | Measured |
| [The proxy reports where it is being bypassed](bypass-self-detection.md) | Implemented |
| [A pinned verdict records its inputs, and `audit verify` decides it again](reproducible-verdicts.md) | Implemented |
| [Observe mode is one switch for the whole proxy, and enforce is the default](observe-mode.md) | Implemented |
| [Upstream traffic honours the forward proxy variables, as reqwest reads them](upstream-forward-proxy.md) | Implemented |
| [The policy reloads on SIGHUP, and each request keeps the policy it started with](policy-reload.md) | Implemented |
| [`waharoa warm` asks a running proxy for what a lockfile locks](warm.md) | Implemented |
| [Install latency through the proxy, measured](latency-benchmarks.md) | Measured, budget not set |
| [Every log value is a field with an OpenTelemetry name, and the daemon can write OpenTelemetry log records](structured-logs.md) | Implemented |
| [`main.rs` holds `main` and the runners](main-is-a-thin-wrapper.md) | Implemented |
| [The coverage floor counts library code, not tests](coverage-counts-library-code-only.md) | Implemented |
| [OSV version ranges and CVSS scores](osv-ranges-and-scores.md) | Implemented |
| [Advisory aliases are matched, not merged](alias-matching.md) | Implemented |
| [GitHub Advisory is a signal stream beside OSV](github-advisory-signal-stream.md) | Decided, being built |
| [The CISA KEV catalogue is a source of its own, joined at lookup](kev-stream.md) | Implemented, `waharoa refresh` |
| [Datadog's npm manifest is a malware source of its own](datadog-stream.md) | Implemented, `waharoa refresh` |
| [Ingestion history: a row per stream per refresh, appended](ingestion-history.md) | Implemented, `waharoa intel history` |
| [Every advisory stream is declared in one table](stream-descriptor-table.md) | Implemented, `waharoa refresh` |
| [Intel schema: surrogate keys and sized types](intel-schema-keys-and-types.md) | Implemented |
| [Policy schema version 1 is frozen](policy-schema-v1-frozen.md) | Decided |
| [`waharoa policy check`](policy-check.md) | Implemented |
| [Readiness endpoint](readiness-endpoint.md) | Implemented |
| [Snapshot identity](snapshot-identity.md) | Implemented; import not built |
| [`policy diff` reads lockfiles](policy-diff-lockfiles.md) | Implemented |
| [`policy diff`: a date per policy, and exit bits](policy-diff-dates-and-exit-bits.md) | Implemented |
| [Reading a packument without changing it](packument-body-inspection.md) | Implemented, Stage 1 |
| [PyPI's simple index is file-keyed](pypi-simple-index.md) | Implemented, parse only |
| [Verifying the artifact digest on the way past](artifact-digest-verification.md) | Implemented, Stage 1 |
| [Rewriting `dist.tarball` to point at the proxy](packument-tarball-url-rewriting.md) | Implemented, Stage 1 |
| [The artifact cache does not skip verification](verified-artifact-cache.md) | Implemented, Stage 1 |
| [Deferral status codes](deferral-status-codes.md) | Measured, decision pending Stage 2 |
| [Policy shape and how a package is judged](policy-tier-resolution.md) | Decided |
| [Advisory stream data licences](advisory-stream-licences.md) | Verified, two streams outstanding |
| [Enforcement tiers](enforcement-tiers.md) | Open question |
| [Terminating TLS: pre-issued certificates](terminating-tls-certificates.md) | Decided, not implemented |
| [Stage structure](stage-structure.md) | Staging |
| [Fetch path branching](fetch-path-branching.md) | Staging |
| [Project name: waharoa](project-name-waharoa.md) | Staging, cultural consultation (Stage 7) |

## Adding one

Name the file after the decision, not the number: numbers are historical and the plan's
index carries them. Record what was rejected and why, so it is not relitigated, and
record the evidence where a measurement settled it.
