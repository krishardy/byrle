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
| [PURL identity rules for npm](purl-identity-rules.md) | Decided |
| [Storage: sqlx over Postgres, no ORM](storage-sqlx-postgres.md) | Implemented, lookup path only |
| [sqlx held at 0.8, RUSTSEC-2023-0071 accepted while `rsa` is not built](sqlx-0-8-and-rsa-advisory.md) | Implemented |
| [Loading OSV malware records](osv-malware-load.md) | Implemented, `waharoa refresh` |
| [Intel in decisions: one lookup per package, fail closed](intel-in-decisions.md) | Implemented |
| [Reading a packument without changing it](packument-body-inspection.md) | Implemented, Stage 1 |
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
