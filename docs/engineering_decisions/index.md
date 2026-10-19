# Engineering decisions

One file per decision, numbered in the order it was written:
`<number>-<name>.md`, with the number in its metadata as `**Number:**`. Each records what
was decided, why, what was rejected, and what it costs. A decision another replaces names
it as `**Superseded by:**`, and this index marks it. `make lint` checks that every file is
listed here under its number.

Status is **Decided**, **Staging**, **Implemented**, **Measured** or **Open question**.
Staging means the decision is made but a gate remains, and the file names the gate.
Implemented means it is in the code, and the file names where.

| Number | Decision | Status | Superseded by |
|---|---|---|---|
| 0001 | [Config format: YAML, loaded by serde-saphyr](0001-config-format-yaml-serde-saphyr.md) | Decided |  |
| 0002 | [Cooldown versus urgent fixes: manual waivers only](0002-cooldown-waivers-manual-only.md) | Decided |  |
| 0003 | [Fetch path: branch before fetching](0003-fetch-path-branching.md) | Decided |  |
| 0004 | [HTTP stack: axum server-side, reqwest upstream](0004-http-stack-axum-reqwest.md) | Decided |  |
| 0005 | [Intel distribution: fetch from origin](0005-intel-distribution-fetch-from-origin.md) | Decided | the ORM half, by [0025](0025-storage-sqlx-postgres.md) |
| 0006 | [Language: Rust](0006-language-rust.md) | Decided |  |
| 0007 | [License: Apache-2.0](0007-license-apache-2.md) | Implemented 2026-09-28 |  |
| 0008 | [NVD role, and per-ecosystem stream capabilities](0008-nvd-role-and-stream-capabilities.md) | Decided |  |
| 0009 | [Package-level overrides and denials](0009-package-override-tier.md) | Decided | [0023](0023-policy-tier-resolution.md) |
| 0010 | [Policy engine: hand-rolled](0010-policy-engine-hand-rolled.md) | Decided |  |
| 0011 | [Project name: waharoa](0011-project-name-waharoa.md) | Superseded 2026-10-01 by project-name-byrle | [0094](0094-project-name-byrle.md) |
| 0012 | [PURL identity rules for npm](0012-purl-identity-rules.md) | Decided |  |
| 0013 | [Quarantine: filter metadata on resolution](0013-quarantine-filter-metadata.md) | Implemented 2026-09-20 |  |
| 0014 | [Stage structure: split transport from policy](0014-stage-structure.md) | Staging |  |
| 0015 | [TLS: reverse proxy first](0015-tls-reverse-proxy-first.md) | Decided |  |
| 0016 | [Reading a packument without changing it](0016-packument-body-inspection.md) | Implemented |  |
| 0017 | [Verifying the artifact digest on the way past](0017-artifact-digest-verification.md) | Implemented | for Maven, the refusal of SHA-1, by [0112](0112-maven-digests.md) |
| 0018 | [Rewriting `dist.tarball` to point at the proxy](0018-packument-tarball-url-rewriting.md) | Decided Sept 2026 |  |
| 0019 | [Enforcement tiers: how requests are made to reach the proxy](0019-enforcement-tiers.md) | Open question |  |
| 0020 | [Terminating TLS: pre-issued certificates, not a CA on the proxy](0020-terminating-tls-certificates.md) | Decided Sept 2026 |  |
| 0021 | [Deferral status codes: what a client does when the proxy says "not yet"](0021-deferral-status-codes.md) | Measured Sept 2026 |  |
| 0022 | [The artifact cache does not skip verification](0022-verified-artifact-cache.md) | Implemented |  |
| 0023 | [Policy shape and how a package is judged](0023-policy-tier-resolution.md) | Decided |  |
| 0024 | [Advisory stream data licences, and what each stream is worth](0024-advisory-stream-licences.md) | Verified Sept 2026 |  |
| 0025 | [Storage: sqlx over Postgres, no ORM](0025-storage-sqlx-postgres.md) | Implemented |  |
| 0026 | [Intel in decisions: one lookup per package, fail closed](0026-intel-in-decisions.md) | Implemented |  |
| 0027 | [Loading OSV malware records](0027-osv-malware-load.md) | Implemented |  |
| 0028 | [sqlx held at 0.8, and RUSTSEC-2023-0071 accepted while `rsa` is not built](0028-sqlx-0-8-and-rsa-advisory.md) | Implemented |  |
| 0029 | [OSV version ranges and CVSS scores](0029-osv-ranges-and-scores.md) | Implemented |  |
| 0030 | [Policy schema version 1 is frozen](0030-policy-schema-v1-frozen.md) | Decided 2026-09-13 |  |
| 0031 | [Intel schema: surrogate keys and sized types](0031-intel-schema-keys-and-types.md) | Implemented 2026-09-13 |  |
| 0032 | [Command line: clap, default features off](0032-cli-parser-clap.md) | Implemented 2026-09-13 |  |
| 0033 | [Environment variables: one module](0033-environment-variables.md) | Implemented 2026-09-13 |  |
| 0034 | [`byrle policy check`](0034-policy-check.md) | Implemented |  |
| 0035 | [Readiness endpoint](0035-readiness-endpoint.md) | Implemented |  |
| 0036 | [Snapshot identity](0036-snapshot-identity.md) | Implemented 2026-09-14 |  |
| 0037 | [`policy diff` reads lockfiles](0037-policy-diff-lockfiles.md) | Implemented |  |
| 0038 | [`policy diff`: a date per policy, and exit bits](0038-policy-diff-dates-and-exit-bits.md) | Implemented |  |
| 0039 | [Advisory aliases are matched, not merged](0039-alias-matching.md) | Implemented |  |
| 0040 | [The CISA KEV catalogue is a source of its own, joined at lookup](0040-kev-stream.md) | Implemented |  |
| 0041 | [Datadog's npm manifest is a malware source of its own](0041-datadog-stream.md) | Implemented |  |
| 0042 | [Ingestion history: a row per stream per refresh, appended](0042-ingestion-history.md) | Implemented |  |
| 0043 | [Every advisory stream is declared in one table](0043-stream-descriptor-table.md) | Implemented |  |
| 0044 | [What CI gates, and what it does not](0044-ci-gates.md) | Implemented |  |
| 0045 | [GitHub Advisory is a signal stream beside OSV, not a replacement for it](0045-github-advisory-signal-stream.md) | Decided 2026-09-16 |  |
| 0046 | [PyPI's simple index is file-keyed, and a packument is not](0046-pypi-simple-index.md) | Implemented and served |  |
| 0047 | [The adapter interface is a descriptor table and four shared modules](0047-adapter-interface.md) | Implemented |  |
| 0048 | [An ecosystem no stream covers fails closed](0048-uncovered-ecosystem-fails-closed.md) | Implemented |  |
| 0049 | [`main.rs` holds `main` and the runners, and nothing else](0049-main-is-a-thin-wrapper.md) | Implemented 2026-09-18 |  |
| 0050 | [A PyPI index is filtered by policy, with or without intel](0050-pypi-index-filtering.md) | Implemented 2026-09-18 |  |
| 0051 | [Each ecosystem's versions order by its own rules; PEP 440 is hand-written](0051-pep440-version-order.md) | Implemented 2026-09-18 |  |
| 0052 | [Policy version ranges are VERS strings, in every ecosystem](0052-policy-version-ranges.md) | Implemented 2026-09-19 |  |
| 0053 | [`doctor` checks pip and uv, and reads uv's TOML configuration](0053-doctor-python-clients.md) | Implemented 2026-09-19 |  |
| 0054 | [How a request through the proxy is tied to an account](0054-account-identification.md) | Decided 2026-09-19 |  |
| 0055 | [Reporting: accounts, installed dependencies and notifications](0055-reporting-accounts-and-notifications.md) | Decided 2026-09-19 |  |
| 0056 | [Metadata is fetched from upstream on every request](0056-no-metadata-cache.md) | Implemented 2026-09-19 |  |
| 0057 | [A yanked file is refused, and the policy can allow it](0057-yanked-files.md) | Implemented 2026-09-20 |  |
| 0058 | [One library crate and one binary, not a workspace](0058-one-crate.md) | Decided 2026-09-20 |  |
| 0059 | [byrle resolves no version ranges](0059-no-range-resolution.md) | Decided 2026-09-20 |  |
| 0060 | [The PEP 503 HTML index is read, not forwarded](0060-pep-503-html-index.md) | Implemented 2026-09-21 |  |
| 0061 | [PyPI provenance: the index says where the bundle is](0061-pypi-provenance.md) | Implemented 2026-09-21 |  |
| 0062 | [Install scripts are read from the artifact, not only from the metadata](0062-install-scripts-from-the-artifact.md) | Implemented 2026-09-21 |  |
| 0063 | [An artifact's analysis is kept under the digest of its bytes](0063-artifact-analysis-store.md) | Implemented 2026-09-22 |  |
| 0064 | [An artifact is analysed in the background, spooled to disk](0064-artifact-spool.md) | Decided 2026-09-22 |  |
| 0065 | [Attestations are verified with `sigstore-verify`, not `sigstore`](0065-sigstore-verifier.md) | Decided 2026-09-26 at 0.13.0 |  |
| 0066 | [The provenance check refuses a version its attestations contradict](0066-provenance-check.md) | Implemented 2026-09-26 for npm and PyPI |  |
| 0067 | [Tier 1 false-positive rates, measured](0067-tier-1-false-positives.md) | Measured 2026-09-26 with `examples/tier1_false_positives.py` |  |
| 0068 | [The Tier 1 controls against the 2025 npm incidents](0068-incident-benchmark.md) | Measured 2026-09-26 |  |
| 0069 | [The proxy reports where it is being bypassed](0069-bypass-self-detection.md) | Implemented 2026-09-26 |  |
| 0070 | [A pinned verdict records its inputs, and `byrle audit verify` decides it again](0070-reproducible-verdicts.md) | Implemented 2026-09-27 |  |
| 0071 | [Observe mode is one switch for the whole proxy, and enforce is the default](0071-observe-mode.md) | Implemented 2026-09-28 |  |
| 0072 | [Upstream traffic honours the forward proxy variables, as reqwest reads them](0072-upstream-forward-proxy.md) | Implemented 2026-09-28 |  |
| 0073 | [The policy reloads on SIGHUP, and each request keeps the policy it started with](0073-policy-reload.md) | Implemented 2026-09-28 |  |
| 0074 | [`byrle warm` asks a running proxy for what a lockfile locks](0074-warm.md) | Implemented 2026-09-28 |  |
| 0075 | [Install latency through the proxy, measured](0075-latency-benchmarks.md) | Measured 2026-09-28 |  |
| 0076 | [Every log value is a field with an OpenTelemetry name, and the daemon can write OpenTelemetry log records](0076-structured-logs.md) | Implemented 2026-09-28 |  |
| 0077 | [The coverage floor counts library code, not tests](0077-coverage-counts-library-code-only.md) | Implemented 2026-09-29 |  |
| 0078 | [Three kinds of source comment](0078-source-comments.md) | Implemented 2026-09-29 |  |
| 0079 | [What an npm packument holds, measured](0079-npm-packument-shapes.md) | Implemented |  |
| 0080 | [Where each npm client keeps its cache, and what a warm one skips](0080-client-caches.md) | Implemented |  |
| 0081 | [A CA bundle for the upstream connection, merged or exclusive](0081-upstream-ca-bundle.md) | Implemented |  |
| 0082 | [Which lockfiles `doctor` checks for the proxy's address](0082-doctor-lockfile-urls.md) | Implemented |  |
| 0083 | [Refusal status](0083-refusal-status.md) | Implemented |  |
| 0084 | [What `byrle explain` prints](0084-explain-output.md) | Implemented |  |
| 0085 | [Default ceilings](0085-default-ceilings.md) | Implemented |  |
| 0086 | [Whether one policy value is stricter than another](0086-strictness-comparison.md) | Implemented |  |
| 0087 | [The audit log](0087-audit-log.md) | Implemented |  |
| 0088 | [Real packages that are safe to test against](0088-live-test-packages.md) | Decided 2026-09-29 |  |
| 0089 | [The watcher analyses new versions of served packages before a client asks](0089-watcher.md) | Implemented 2026-09-29 |  |
| 0090 | [Metadata heuristics report signals and refuse nothing](0090-metadata-heuristics.md) | Implemented 2026-09-29 |  |
| 0091 | [Registry tarball against its source, a weak signal](0091-source-diff.md) | Implemented 2026-09-30, report only |  |
| 0092 | [Detectors report signals, and GuardDog is the first](0092-detectors.md) | Implemented 2026-09-30 |  |
| 0093 | [`byrle lockfile verify` checks a lockfile installs through the proxy](0093-lockfile-verify.md) | Implemented 2026-10-01 |  |
| 0094 | [Project name: byrle](0094-project-name-byrle.md) | Implemented 2026-10-11 |  |
| 0095 | [Every build carries every ecosystem](0095-no-ecosystem-features.md) | Decided 2026-10-11 |  |
| 0096 | [Where the console answers: its own URL, on the proxy's listener or its own](0096-console-listener.md) | Decided 2026-10-11 |  |
| 0097 | [Console login crates: argon2, and jsonwebtoken on aws-lc-rs](0097-console-login-crates.md) | Decided 2026-10-11 |  |
| 0098 | [The console's web interface: Rust, HTML from maud](0098-console-web-interface.md) | Decided 2026-10-11 |  |
| 0099 | [Logs are files, rotated daily, compressed after 3 days, kept 365 days](0099-log-rotation.md) | Decided 2026-10-11 |  |
| 0100 | [The TLS front is nginx, not Caddy](0100-tls-front-nginx.md) | Implemented 2026-10-12 |  |
| 0101 | [The development environment runs in podman-compose](0101-dev-environment-compose.md) | Implemented 2026-10-12 |  |
| 0102 | [`advisory.cached`: when byrle first stored an advisory](0102-advisory-cached.md) | Implemented 2026-10-12 |  |
| 0103 | [Trufflehog findings are allowed by exact value](0103-credential-scan-allowlist.md) | Implemented 2026-10-12 |  |
| 0104 | [VirusTotal reports a signal on an artifact](0104-virustotal.md) | Implemented 2026-10-13 |  |
| 0105 | [Each artifact decision is stored with its features and disposition](0105-artifact-decisions.md) | Implemented 2026-10-13 |  |
| 0106 | [Console login: passwords, sessions and the limit on failures](0106-console-login.md) | Implemented 2026-10-13 |  |
| 0107 | [Console API: an OpenAPI document generated by utoipa](0107-console-openapi.md) | Implemented 2026-10-13 |  |
| 0108 | [Releases and their provenance](0108-release-provenance.md) | Implemented 2026-10-14 |  |
| 0109 | [Every advisory is read, and its kind is a signal of its own weight](0109-advisory-kinds.md) | Implemented |  |
| 0110 | [cargo provenance: what crates.io publishes about who published a version](0110-cargo-provenance.md) | Measured 2026-10-15 |  |
| 0111 | [Each ecosystem is served under a prefix of its own](0111-ecosystem-path-prefixes.md) | Decided by the user 2026-10-15 |  |
| 0112 | [Maven: a jar's digest is its strongest sidecar, SHA-1 included](0112-maven-digests.md) | Implemented 2026-10-17 |  |
| 0113 | [Maven: PGP signatures are decided by `provenance`, a key as the identity](0113-maven-signatures.md) | Implemented 2026-10-17 |  |
| 0114 | [Maven: byrle passes every file through unchanged, so a client can check byrle](0114-maven-files-unchanged.md) | Implemented 2026-10-18 |  |
| 0115 | [Maven: the Gradle plugin portal is a second repository of the Maven row](0115-gradle-plugin-portal.md) | Decided by the user 2026-10-17 |  |
| 0116 | [Every refusal is a weighted signal, refused at one threshold](0116-every-refusal-a-signal.md) | Implemented 2026-10-18 |  |
| 0117 | [Every `packages` entry that matches a version applies, in file order](0117-every-matching-entry-applies.md) | Implemented 2026-10-19 |  |
| 0118 | [The analysis commands are answered by a deployed byrle, through the console API](0118-remote-analysis-commands.md) | Implemented 2026-10-19 |  |
| 0119 | [A request path the proxy does not recognise is refused](0119-unrecognised-paths-refused.md) | Proposed 2026-10-19 |  |
