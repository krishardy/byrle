# waharoa — Staged TODO

Stages are sequential. Each has an exit criterion; do not start the next stage until it
is met. Within a stage, `[!]` marks items that block the exit criterion.

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocks stage exit

A stage carries a **Status** line: `closed` once its exit criterion is met and every item
in it is closed or moved, `open` for the one being worked on, and nothing for a stage not
started.

---

## Ad-hoc

Items that I've added that are not stage-bound.

1. Look at the witchcraft binary collection (from edrazine) and look into integrating wsolver into a fuzzing and formal analysis process of the compiled binary.
2. [x] Add make dev-setup, which will install dev dependencies for this project.
   Done: `scripts/make/dev-setup.sh` installs clippy, rustfmt, cargo-audit and kani,
   and reports whether npm is present. Re-runnable; skips what is already installed.
   `make lint` and `make verify` added at the same time, per CLAUDE.md Finalization.
   `make verify` exits nonzero while no `#[kani::proof]` harnesses exist, so a green
   verify never means "nothing is proved".
3a. [x] Add shellcheck to dev-setup, and wire it into `make lint`.
   Installed via pipx using `shellcheck-py`, which ships the real binary in a platform
   wheel, so it needs no root and behaves the same on Linux and macOS; falls back to
   pip3, then to distro instructions. `make lint` now lints Rust *and* shell, over every
   tracked `*.sh` rather than a hardcoded list. It **requires** shellcheck rather than
   skipping when absent: per CLAUDE.md every recipe is a thin wrapper around a script,
   so real logic lives in shell, and a lint run that quietly covers half the codebase
   while reporting success is the failure worth avoiding.
   Verified after `make dev-setup` installed it: `make lint` is green over 9 scripts.
   It found three real parse errors first, all self-inflicted and worth knowing about: a
   comment whose first word is `shellcheck` is read as a directive and fails SC1073, so
   prose about the tool has to start with another word.
   Note: this widens `make lint` beyond the "(runs clippy)" description in CLAUDE.md.
3. [x] Add make sast, which runs semgrep on the project.
   Done: `scripts/make/sast.sh`. Rulesets are pinned (`p/rust`, `p/secrets`, `p/bash`)
   rather than using `--config=auto`, which resolves rules by uploading a project
   fingerprint to semgrep.dev, and `--metrics=off`: a tool selling "no mandatory
   outbound calls to us" should not quietly make its own. `p/bash` is included because
   `scripts/make/*.sh` is real code that clippy cannot see. `SEMGREP_RULES` points at
   local rules for an offline run.
   NOT verified end to end: semgrep is not installed here, so only the missing-tool
   path was exercised. Run `make dev-setup` then `make sast` to confirm.
4. [x] Add make check-deps, which checks for out of date or vulnerable dependencies.
   Done: `scripts/make/check-deps.sh`, covering both the main crate and the committed
   config-format spike, which sits outside the workspace and pulls four YAML parsers.
   Vulnerable fails the check; merely-outdated reports without failing, because a
   target that is red every week stops being read. `CHECK_DEPS_STRICT=1` fails on
   outdated too and adds `--deny warnings`, making unmaintained crates disqualifying,
   which is the same standard that ruled out `serde_yml` in plan §5.
   Verified end to end after `make dev-setup`: both halves run. cargo-audit flags
   RUSTSEC-2026-0249 (see below).
   Resolved: the spike is audited for vulnerabilities and not checked for freshness. Its
   `Cargo.lock` records the versions the config-format spike ran against; bumping it to
   clear a report would replace that record with versions nobody tested. A vulnerability
   in it still has to be known, so the audit half keeps it.
5. [x] Add trufflehog to make sast.
   Done. `make sast` now runs semgrep then trufflehog, aggregating both rather than
   stopping at the first failure. Two scans: the working tree, and git history, because
   a credential committed and later deleted is gone from the tree and still in the
   repository. `--no-update` stops trufflehog's version phone-home, matching the
   `--metrics=off` choice for semgrep. Credential *verification* is left on and is a
   different thing from telemetry: it authenticates a candidate against the service that
   issued it, which is what separates live credentials from noise. `TRUFFLEHOG_NO_VERIFY=1`
   disables it.
   Three bugs found by running it rather than by reading it:
   - `p/bash` is a 404, as are `p/sh` and `p/shell`. Shell rules live at `r/bash`, the
     registry namespace, which is now in the config: 7 rules, of which curl-pipe-bash
     and ifs-tampering are the ones shellcheck does not already cover. Confirmed by
     planting the patterns; without it the other three packs match nothing whatsoever
     in a shell file, so the earlier coverage claim was wrong.
   - `local rc=$?` captures `local`'s own status, not the command's, so every failure
     was reported as "exited 0". Fixed in both places.
   - semgrep flagged `std::env::args()` in `examples/osv_conformance.rs`. False positive:
     the rule guards against deriving identity from argv. Suppressed at the site with a
     reason, and the marker has to sit on the line immediately above the finding.
   Verified: semgrep runs its rules over the tracked files and the suppression works.
   trufflehog verified too, now running as a native binary on the PATH.
   It previously ran as a wrapper around `docker run -v "$PWD:/pwd"`, and that made the
   working-tree pass worthless without anyone noticing: the image's working directory is
   `/usr/bin`, so `trufflehog filesystem .` scanned the scanner's own binaries, a
   constant 3383 chunks, and reported clean on a repository it never opened. Both passes
   now name the path explicitly, from `TRUFFLEHOG_REPO_ROOT`, which the Makefile sets to
   `$(CURDIR)` and which can be pointed at a mount point for a containerised install.
   `--fail-on-scan-errors` is set so an unreadable path fails instead of passing with
   zero findings. It does not catch a readable path that is the wrong directory, which
   is the case that bit us; naming the path rather than using `.` is what covers that.
   Scanning the real repository required excluding build output: `/target/` holds 2GB of
   `.rmeta`/`.rlib` artifacts with upstream crates' doc examples compiled in, producing
   hundreds of findings about other people's documentation. Patterns are in
   `.trufflehog-exclude`, kept in the repository so a containerised run can see them.
   Three controls, all passing: a planted GitHub PAT fails the target, a bogus
   `TRUFFLEHOG_REPO_ROOT` fails it, and a clean tree passes. Working tree 352 chunks,
   history 174.
6. [x] Split make sast into make trufflehog and make semgrep, and change the sast
   target to use semgrep and trufflehog as prerequisites.
   Done. `scripts/make/sast.sh` is gone, replaced by `semgrep.sh` and `trufflehog.sh`;
   `sast` is now `sast: semgrep trufflehog` with no recipe of its own. Each scanner is
   runnable alone, and each still passes through extra arguments.
   Behaviour change worth knowing: make stops at the first failing prerequisite, so a
   semgrep failure now means trufflehog does not run, where the single script used to
   run both and report once. `make -k sast` restores the old behaviour. trufflehog's
   own two passes still both run and report together, since that aggregation is inside
   its script.
   Env vars are named after the target that owns them: `TRUFFLEHOG_NO_VERIFY` and
   `TRUFFLEHOG_SKIP_HISTORY`, alongside the existing `SEMGREP_RULES`. They were briefly
   `SAST_*`, which stopped naming anything once `sast` became a prerequisite list rather
   than a script.
   Verified: each target alone, `make sast` running both, fail-fast skipping trufflehog
   when semgrep fails, and `make -k sast` running both anyway.
7. [x] In the policy file sample, npm install_scripts setting would be set per package, not set for the entire ecosystem.
8. [x] Make sure that semgrep is logged in during the `make semgrep` run.
   `make semgrep` now refuses to run without a token, the way `make lint` refuses to run
   without shellcheck, and for the same reason: **measured on this repository, same 79
   files and same pinned packs, 57 rules anonymous against 103 logged in.** An anonymous
   scan covers roughly half as much, passes, and says nothing in its output about which of
   the two you got.
   The token is found the way semgrep finds it (`semgrep/app/auth.py`): `SEMGREP_APP_TOKEN`
   first, then the settings file at `SEMGREP_SETTINGS_FILE`, else
   `$XDG_CONFIG_HOME/.semgrep/settings.yml` when that directory exists, else
   `~/.semgrep/settings.yml`. The leading dot under XDG_CONFIG_HOME is semgrep's own doing
   (`semgrep/env.py`), and looking in `~/.semgrep` alone misses a real login, which is what
   happened on the first attempt here.
   A logged-out settings file still carries `api_token`, written as `null`, so the value is
   checked rather than the key.
   `semgrep login` is never invoked by the script: with no token and a TTY it prompts and
   waits, which would hang a build.
   Logging in sends no findings anywhere. Only `semgrep ci` uploads results
   (`semgrep/commands/ci.py`); this runs `semgrep scan`, which has no upload path. What the
   token changes is which rules the registry serves, and rule fetching already contacts
   semgrep.dev either way.
   `SEMGREP_ALLOW_ANONYMOUS=1` runs without one and says what it costs. `make dev-setup`
   reports login state, so it is part of setting a machine up rather than a surprise on the
   first scan.

9. [ ] **Watch: `purl` 0.1.6 pulls `smartstring` 1.0.1, flagged RUSTSEC-2026-0249 as
   unmaintained.** Found by `make check-deps`. Not a vulnerability, and it does not
   reverse the crate choice: `packageurl` is disqualified on correctness, which is the
   worse failure. But it is why `make check-deps` is not clean under
   `CHECK_DEPS_STRICT=1` today. Revisit if it becomes a real advisory; the swap path
   is the same one-line change described under the identity item.
   Checked Sept 2026: `purl` is still 0.1.6, no newer release, and the advisory still
   stands. `make check-deps` passes; `CHECK_DEPS_STRICT=1` fails on it, as designed.

10. [ ] File upstream issues asking npm / pip / uv / cargo to honor `429` + `Retry-After`.
   The evidence is now measured: four of five npm-ecosystem clients ignore
   `Retry-After`, and two treat 429 as terminal. See
   `docs/engineering_decisions/deferral-status-codes.md`.
   Argues on its own merits (a proxy legitimately rate-limiting is a real scenario),
   so it is a small uncontroversial patch. Long lead time — file early.
11. [x] **`cargo build --release` does not compile.** `src/lib.rs` gates `pub mod audit` on
   `#[cfg(debug_assertions)]` (since `95c52b0`), and `src/proxy.rs:58` uses `crate::audit`
   unconditionally, so a release build fails with `could not find audit in the crate root`.
   `src/audit.rs` gives no reason for the gate.
    - Done 2026-09-13: the gate was never meant for `audit`. `95c52b0` put it on
      `pub mod defer`; `d648995` inserted `pub mod audit;` between the attribute and
      `defer`, so `audit` was gated and `defer` was compiled into every build. The gate is
      back on `defer`. The release binary has no `waharoa::defer` symbols (the debug one has
      44) and does not list `WAHAROA_DEFER_TEST` in `--help`. `make lint` now also runs
      clippy with `--release`.
12. [x] In make semgrep, also report on any semgrep exceptions (file, line # and line text)
    - Done 2026-09-13: after the scan, `==> exceptions` lists each finding a `nosemgrep`
      comment suppresses (file, line, rule, line text), comments that suppress nothing, and
      every path not scanned with semgrep's reason. A second pass with `--disable-nosem`,
      5s with rules cached; `scripts/make/lib/semgrep_exceptions.py`. The exit status is
      the scan's.
    - Found: `tests/intel_postgres.rs` is not scanned. With no `.semgrepignore`, semgrep's
      built-in ignore list skips `tests/`.
13. [x] In the code, policy, documentation, etc. change from "CVE" to "VulnAdvisory". (Has CVE should instead be Has Vulnerability, etc.)
    - Decided 2026-09-13: the policy key `cve_ids` becomes `vuln_advisory_ids`, before the
      v1 schema is frozen. `max_cvss` keeps its name: CVSS is the scoring system.
    - Done 2026-09-13: the key, `Rule::VulnAdvisoryIds`, doc comments, the policy flow chart
      and the docs where CVE meant a vulnerability advisory. Kept where a CVE id is meant
      literally: KEV's `cveID`, NVD's join on CVE id, the measured CVE-id counts, and CVE
      ids used as test data.
14. [x] Do NOT use TEXT records for everything in the database schema. Use appropriately sized VARCHARS, date, datetime, etc. fields. Only use TEXT where the length is possibly unbounded. IDs should NEVER be TEXT, they should be serial or UUID.
    - Decided 2026-09-13: this covers publisher ids too. `advisory.id` (`GHSA-...`,
      `MAL-...`) becomes a sized VARCHAR column with a unique index beside a surrogate key,
      and joins use the surrogate key.
    - Decided 2026-09-13: `0001_intel.sql` and `0002_ranges.sql` are rewritten rather than
      followed by a new migration. A value longer than its column fails the refresh.
    - Done 2026-09-13: every table is keyed by a `BIGINT` identity; `advisory.publisher_id`
      and `intel_snapshot.digest` are sized unique columns; timestamps are `TIMESTAMPTZ`;
      `advisory.summary` is the only `TEXT`. See
      [intel-schema-keys-and-types](docs/engineering_decisions/intel-schema-keys-and-types.md).
      A database that applied the old migrations has to be dropped and refreshed.
15. [x] Evaluate command line parsers for Rust, and migrate to the selected one.
    - Decided 2026-09-13: clap 4.6.6, default features off, derive. 4 crates added, against
      lexopt's 1 and default clap's 11.
    - Done 2026-09-13: parsing is `src/cli.rs`, unit-tested; help pinned by
      `tests/fixtures/cli/`. Fixed in passing: `--as-of 2026-01-01` was a usage error, a
      repeated `--as-of` and unknown flags were ignored, `explain --help` was read as a purl,
      `--version` was an unknown command. See
      [cli-parser-clap](docs/engineering_decisions/cli-parser-clap.md).
16. [x] The environment variables, defaults, usage info, loading and parsing should be extracted into a central environment variable module. You should not have any environment variable name in more than one place in the application.
    - Decided 2026-09-13: every mention counts, messages and doc comments included; a value
      that does not parse refuses to start; test-only variables are covered; defaults move
      into the module.
    - Done 2026-09-13: `src/env.rs`. `a_variable_name_appears_only_in_this_module` fails on a
      name anywhere else in `src/`, `tests/` or `examples/`. `--help` renders from the same
      constants. See [environment-variables](docs/engineering_decisions/environment-variables.md).
17. [x] Search for duplicate code or duplicate strings throughout the application and catalog them for later consolidation.
    - Added a rule to CLAUDE.md
    - Done 2026-09-13: [duplication-catalogue](docs/duplication-catalogue.md), 14 production
      Rust, 6 script and 12 test-helper entries, none consolidated yet. `make duplicates`
      re-runs the scan: 30 repeated blocks of 8+ lines, 37 repeated literals of 16+
      characters touching production code.

## Stage 1 — Pass-through proxy (transport)

**Status: closed.** Exit met; every item closed or moved.

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
- [x] rustls + platform verifier for the **upstream** connection, with a custom CA bundle.
      reqwest 0.13's default `rustls` feature pulls `rustls-platform-verifier` 0.7, so the
      upstream leg validates against the OS trust store. Inbound stays plain HTTP on
      loopback, per decision #3.
      - [x] `WAHAROA_CA_BUNDLE` points at a PEM bundle, for a private registry with an
            internal CA or a corporate TLS-inspecting middlebox. `src/tls.rs`.
            `add_root_certificate` is deprecated in reqwest 0.13.5; the replacements are
            `tls_certs_merge` and `tls_certs_only`.
      - [x] `WAHAROA_CA_BUNDLE_EXCLUSIVE=1` trusts **only** the bundle, dropping every
            public root. Worth having on its own terms: it pins the upstream, so a
            compromise of any of the hundreds of public CAs cannot be used to impersonate
            the registry. Verified with a self-signed CA against registry.npmjs.org:
            merged the request succeeds, exclusive it fails at the handshake and the proxy
            answers 502, which is the right code since the upstream is unreachable.
      - [x] Every misconfiguration refuses to start rather than falling back to the
            platform roots without saying so: a missing file, a file with no certificates,
            and a bundle the TLS backend rejects. All three name the file.
      - [x] **Finding: a `CERTIFICATE` block whose base64 decodes to something that is not
            a certificate parses cleanly.** `from_pem_bundle` reports one certificate and
            the failure only appears when the client is built, where it would otherwise
            read as "failed to build HTTP client" with no mention of the file.
            `tls::build` maps it to an error naming the bundle.
      - [x] **Finding: an empty bundle parses as zero certificates rather than failing.**
            So does a file containing only a private key, which is the likely mistake.
            Both would fail quietly: merging nothing changes nothing, and trusting nothing
            exclusively rejects every connection at the handshake, which reads as a
            network fault. `TrustError::Empty` refuses both.
- [x] Serve `npm install lodash` successfully through the proxy. Covered by `make smoke-npm`.
- [x] Block one hardcoded package name with HTTP 403, proving interception. Throwaway, and
      kept deliberately awkward: it was env-only (`WAHAROA_BLOCK`), with no config file
      behind it, so it could not quietly become a feature. **Removed in Stage 2**, which
      replaced it with the policy engine. `make smoke-npm` 6/6 now proves interception
      against a real denial instead.
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
- [x] PURL as internal identity type. `src/identity.rs`: `PackageKey` (versionless, the
      advisory lookup key) and `PackageRef` (key + concrete version, what a verdict is
      about). Built on the `purl` crate from phylum-dev, chosen over `packageurl` because
      `packageurl` lowercases npm names per spec, which loses malware matches. Validated
      against OSV's whole npm corpus, not just unit tests: `cargo run --example
      osv_conformance`. Four findings recorded in plan §4.
      - [x] **Do not lowercase npm names**, despite purl-spec requiring it. 112 uppercase
            names in OSV, all case-preserved, mostly `MAL-` malware records. Also four
            names that differ only by case (`OpenClaw`/`Openclaw`/`openclaw`), so
            case-insensitive keying merges distinct packages.
      - [x] **Key on parsed components, never the purl string.** OSV writes scoped
            packages both as `%40antv/algorithm` (16,904) and `%40antv%2Falgorithm` (855)
            and they parse differently. Caught by the corpus check, invisible to the
            handwritten tests.
      - [x] **Identity comes from the packument `name`**, not the request path.
- [x] **`make check-deps` could not fetch the advisory database at all**, so the
      security half had not been running on this machine. A global
      `url.ssh://git@github.com/.insteadof https://github.com/` with no key makes
      `cargo audit`'s git fetch fail on credentials, which reads as noise and fails the
      whole target.
      - [x] It now probes once, and on a fetch failure downloads the database as a tarball
            over plain HTTPS, where no git configuration applies. 1,243 advisories loaded,
            both manifests scanned.
      - [x] Cached under `target/` so `cargo clean` clears it, refreshed daily. A database
            a week old is worse than useless, because it reports success.
      - [x] The probe is gated on whether a local database is in use, not on the argument
            list being empty: strict mode adds `--deny warnings`, which made the first
            version skip the fallback and fail exactly as before.
- [x] Feed the identity type into the proxy. Every request path is classified by
      `npm::classify_path` into a `PackageKey`, the throwaway block compares keys rather
      than strings (so `/@babel%2fcore` and `/@babel/core` are one package), and every
      log line carries a purl.
- [x] Common package record schema. `src/record.rs`: `PackageRecord`, carrying identity
      (a `PackageRef`), publish time, maintainers, repository, has-install-scripts and
      the script bodies, provenance, and the artifact with its digests. Types only; the
      packument-to-record mapping belongs to the normalizer item below.
      - [x] **Finding: the abbreviated packument is missing most of what Tier 1 needs.**
            npm installs request `application/vnd.npm.install-v1+json`, and a
            pass-through proxy sees only what the client asked for. Publish time,
            maintainers, repository and the `scripts` bodies are all full-packument only,
            so **cooldown cannot be enforced from what npm requests**. At Stage 1 those
            fields are `None` on every record. Closing that is fetch-path work, not a
            schema gap.
      - [x] Every such field is `Option`, qualified by a `source: PackumentDetail` on the
            record. `None` + `Abbreviated` means not fetched; `None` + `Full` means the
            registry does not publish it. A cooldown rule that cannot tell those apart
            reads a missing timestamp as "old enough" and fails open. Deriving that
            distinction is Stage 2 work, against the rule that consumes it.
      - [x] `has_install_scripts` is a plain `bool`, not an `Option`. Abbreviated sets
            `hasInstallScript: true` and omits the key otherwise; the full packument
            never carries that key and needs `scripts` read for preinstall/install/
            postinstall. Verified equivalent across 24,852 version pairs from 47
            packages, no disagreement.
      - [x] `dist.shasum` (SHA-1) is a separate field from `dist.integrity` (SRI
            sha512), not an entry in a shared digest list. SHA-1 is collision-broken and
            should not be reachable by code that thinks it is handling the strong one.
      - [x] `repository` is polymorphic in npm, an object or a shorthand string. The
            normalizer hand-writes that `Deserialize` (`deserialize_any` +
            `visit_str`/`visit_map`); `#[serde(untagged)]` silently defeats
            unknown-field rejection (plan §5). The string form is rare and real: 5 of
            24,852 versions, `bower@1.8.11` through `1.8.14` and `rimraf@1.0.0`.
            `Repository` also gained a `directory` field, which monorepo packages set
            (`@babel/traverse` reports `packages/babel-traverse`) and source diffing
            needs to compare the right tree.
- [x] npm transport + normalizer, written concretely. `src/npm.rs`: private wire types
      mirroring npm's JSON, `normalize_packument()` into `Vec<PackageRecord>`, and a
      `Client` that fetches either document from a registry. No adapter abstraction, per
      the note below.
      - [x] Unknown fields are **ignored** here and rejected in the policy loader. A
            registry adding a field must never break an install; a typo in an operator's
            policy must never disable a rule. Both are deliberate and stated in the
            module docs so neither gets "fixed" into the other.
      - [x] Versions that cannot be normalized land in `NormalizedPackument::skipped`
            with a reason rather than being dropped. A version that disappears between
            the registry and the policy engine is a version nothing gates.
      - [x] Three error kinds kept separate: `FetchError::Transport`,
            `FetchError::Status` and `NormalizeError`. A document shape we failed to
            model is our gap, not an upstream outage, so it must not become a 502.
      - [x] **Finding: `dist.integrity` is not universal.** Two of 24,852 versions lack
            it, both published in 2012 (`event-stream@0.9.1`, `vue@0.8.6`), leaving
            collision-broken SHA-1 as the only digest npm offers. `Artifact::integrity`
            stays `Option` and the fetch path has to handle a version with no strong
            digest. Every version did carry `dist.tarball` and `dist.shasum`.
      - [x] **Finding: `hasInstallScript` is never present and `false`.** 901 of 24,852
            versions carry it, all `true`; absence means no install script. The
            abbreviated and full documents agreed on `has_install_scripts` across all
            24,852 pairs, which raises the earlier 860-pair check by 29x.
      - [x] Corpus check in the tests, gated behind `WAHAROA_NPM_CORPUS` /
            `WAHAROA_NPM_CORPUS_FULL`, plus two `#[ignore]`d live tests against
            registry.npmjs.org covering the scoped-name URL round trip and the 404 path.
      - [x] Wired into the proxy. `src/proxy.rs` buffers packument responses, decodes a
            scratch copy, normalizes it, and forwards the **original encoded bytes**
            unchanged. Tarballs still stream. Normalizing happens before forwarding, not
            in a spawned task: Stage 2 has to decide before forwarding anyway, and a
            background task would make the smoke assertions racy.
            - [x] The proxy moved out of `main.rs` into the library so it can be tested
                  against a fake registry. `main.rs` is now 53 lines of startup.
            - [x] Outbound `Accept-Encoding` is narrowed to gzip-or-identity on packument
                  requests, whichever the client accepts. **registry.npmjs.org serves
                  brotli whenever br is offered**, and npm 9.9.4 offers `gzip,deflate`.
                  Narrowing means one decompressor instead of three, and the client still
                  gets an encoding it asked for. A client accepting neither keeps its own
                  header and its body is not read.
            - [x] `PackumentDetail` comes from the response `Content-Type`, not the
                  request. npm asks with `application/vnd.npm.install-v1+json; q=1.0,
                  application/json; q=0.8, */*`, which names both and settles nothing.
                  Measured across 18 responses (6 packages, scoped and unscoped, three
                  Accept headers): exactly the two media types, no `charset` parameter.
                  A response with any other type is forwarded unread, so a mirror that
                  labels packuments differently would be observed by nothing.
            - [x] Decompression is capped (`WAHAROA_MAX_PACKUMENT_BYTES`, default 32 MiB)
                  against a zip bomb. Over the cap the body is forwarded whole and not
                  parsed: an install must not fail on what the proxy could not inspect.
            - [x] Measured parse cost: 2 ms for lodash (117 versions), 7 ms for
                  @babel/core (230), 252 ms for the full typescript packument (3,822
                  versions, 15.7 MB decoded).
            - [x] `make smoke-npm` gained a third assertion: every installed package, at
                  the version on disk, appears as a purl in the log, and no packument had
                  a skipped version. 69 packages, 71 packuments, 0 skipped. Checked that
                  it bites by crippling the size cap.
      - [x] **Finding: a tarball path does not always spell the version the packument
            does.** 38 of 24,852 tarball URLs differ: every `express` prerelease before
            3.0.0 and every `grunt` prerelease before 0.4.0 drops the hyphen, so
            `express@3.0.0-rc1` is served at `express-3.0.0rc1.tgz`.
            `RequestTarget::Tarball` therefore carries `claimed_version`, not a
            `PackageRef`. Resolving it needs the packument record, which is the
            `dist.integrity`-before-fetch item below.
      - [x] Make the packument tarball URL rewriting a feature flag. Global, not per
            client: `WAHAROA_REWRITE_ARTIFACTS=0` turns it off for every client at once,
            which keeps one behaviour for the ecosystem rather than a user-agent table to
            maintain. The proxy warns at startup when it is off, because pnpm, yarn and
            bun then fetch artifacts without it seeing them, and `make smoke-clients`
            fails in that state, which is how the flag is tested.
- [x] Unit test coverage tooling, for the CLAUDE.md floor. `make coverage` runs
      cargo-llvm-cov over the **library** with
      `--fail-under-lines/-functions/-regions 95`; `COVERAGE_FLOOR` overrides it. The
      library is at 97.5% lines, 97.0% regions, 98.0% functions. `src/main.rs` is printed
      for reference and is not part of the floor: it is startup wiring, covered by
      `make smoke-npm` and `make smoke-clients` running real clients through the binary.
      - [x] The network and corpus tests are compiled out under `cfg(coverage)`, which
            cargo-llvm-cov sets. They do not run in a coverage build, and counting the
            body of a test that cannot run reports a gap that is not one. `cargo test`
            still lists them as ignored, so gating them changed nothing about the suite.
      - [x] `PackageKey::from_registry_name` had an unreachable error arm for an empty
            bare name: the leading empty check and the empty-`rest` check in the scoped
            arm already cover it. Now a `debug_assert!`, because a branch no input can
            reach looks like a hole in the tests forever.
      - [x] **`src/main.rs` was at 0% over 128 lines.** The proxy moved into
            `src/proxy.rs` in the library, which is what the floor measures.
- [x] **`npm ci` requests no packuments at all**, so every artifact was unverified on the
      standard CI path. Measured through the proxy: 69 tarballs, zero packument requests,
      zero digests known. `npm ci` reads `resolved` and `integrity` from
      `package-lock.json` and goes straight to the tarball.
      - [x] Fixed by `proxy::lookup_or_fetch`: on a tarball whose package has no record,
            the proxy fetches the packument itself before forwarding. One mechanism
            closes four gaps: `npm ci`, the 304 case below, a restarted proxy, and an
            evicted entry.
      - [x] Cost measured on the same install: 66 packuments fetched on the proxy's own
            behalf, mean 56 ms and max 236 ms each, 3.7 s of fetch time in total across
            concurrent requests. Wall clock for the install was unchanged at about 1 s.
            Afterwards 69 of 69 tarballs had a known digest and all 69 verified.
      - [x] `make smoke-npm` gained a fifth step covering it, with a fresh proxy and a
            fresh npm cache so the only way a digest can be known is the proxy fetching
            the packument itself.
- [x] **A warm npm cache sends `If-None-Match` and the registry answers 304 with
      no body, so the proxy observes no packument at all.** The resolved graph is fully
      visible only on a cold cache today. The proxy logs the skip and the ETag rather
      than treating an empty body as a parse failure, but Stage 2 cannot gate on a record
      it never saw. The fix is the `npm::Client` already built: on a 304 for a package
      with no cached record, fetch the packument on the proxy's own behalf. Pairs with
      the conditional requests item below.
      - [x] Confirmed both halves against real software: registry.npmjs.org answers 304
            to a matching `If-None-Match`, and npm 9.9.4 sends one once its cached entry
            passes `max-age` (300 s for a packument). Inside that window npm does not ask
            at all, which is the separate cache-bypass item.
      - [x] Closed for the tarball path by `proxy::lookup_or_fetch`, which fetches the
            packument when there is no record.
      - [x] Closed for the packument request too. A 304 carries no body, so when the
            proxy holds no records for that package it fetches the packument itself
            before the artifact requests arrive, rather than one lazy fetch at a time.
            The `held` field on the "not modified" log line says which happened.
      - [x] It only fetches when nothing is held. A 304 revalidates a body **this** proxy
            produced, since only tags it issued are forwarded, so when the records are
            still there they were taken when that body was first served. The case that
            needed closing is a restarted proxy or an evicted entry.
      - [x] Verified against real npm: warm client cache, proxy restarted at the same
            address, `--prefer-online`. The registry answered 304, the proxy logged
            `held=false` and fetched the document itself in 21 ms, 117 versions, and the
            install completed.
- [x] Memory under concurrency, measured. `WAHAROA_MAX_CONCURRENT_PACKUMENTS` (default 8)
      bounds how many packuments are decoded and rewritten at once.
      - [x] Realistic load is fine. A six-package install pulling typescript, eslint,
            webpack, react, @angular/core and @types/node: 165 packuments, peak 127 MB,
            and the limit never engaged. Install time unchanged at 15 s.
      - [x] Adversarial load was not. 24 simultaneous requests for the largest full
            packuments peaked at **1,348 MB** while the encoded bodies totalled 27.6 MB,
            roughly 56 MB per request in flight, with nothing bounding how many there
            were. The cost is the decoded copy plus the JSON value tree the rewrite walks.
      - [x] **The slot is taken after the body is buffered, not before it is read.** With
            the acquire before the read, waiting held the upstream response open until it
            timed out: 18 of 24 concurrent requests failed with "error decoding response
            body". Regression test at a limit of one.
- [x] Rewrite artifact URLs by targeted byte replacement instead of building a
      `serde_json::Value`. The value tree was the dominant allocation.
      - [x] **Peak RSS on 24 simultaneous large packuments: 1,436 MB to 472 MB**, median
            223 MB to 97 MB. The concurrency limit now barely matters (472 MB at 8 against
            456 MB unbounded), because the per-request allocation is small enough that
            allocator retention is small too. The limit stays: it bounds live memory,
            which is the invariant, and it costs nothing when it never engages.
      - [x] The rewrite takes the artifact URLs found during normalisation, so the
            document is not parsed a second time. Each is replaced wherever it appears as
            a complete quoted string. `serde_json`'s `preserve_order` feature is no longer
            needed and has been dropped.
      - [x] **It catches `_resolved`**, an npm internal field repeating `dist.tarball`
            verbatim, which the `dist.tarball`-only rewrite left pointing at the origin
            registry.
      - [x] The output is byte-identical to the upstream apart from the URLs. Checked
            across the corpus: all 94 documents, both kinds, rewrite to the origin they
            already name and come back byte for byte, with every artifact URL found.
      - [x] A URL that cannot be found fails the whole rewrite rather than half of it
            landing, which would send some artifacts to the proxy and leave others
            pointing at the registry.
- [x] Packument size on the proxy's own fetches. `npm::Client` now asks for gzip and
      decodes it with the same decoder the request path uses, under the same ceiling.
      reqwest's `gzip` feature stays off crate-wide so bodies can be forwarded byte for
      byte, which is why this has to be explicit.
      - [x] Measured over the 69 packages of an `express` tree: 1.59 MB uncompressed
            against 0.52 MB gzipped, a 67% saving. `npm ci` makes this request once per
            package because it asks for no packuments of its own, so this is the primary
            CI path.
      - [x] A body past the ceiling is a `FetchError::Undecodable`, not a normalisation
            failure: the bytes never became a document to model.
      - [x] `DEFAULT_MAX_PACKUMENT_BYTES` moved to `http`, where the decoder is, so the
            proxy's own fetches and the bodies it forwards read one value.
- [x] Conditional requests (ETag / If-None-Match) so pass-through stays cheap. A
      rewritten packument gets an `ETag` marked with the proxy's own address, and only a
      tag issued here revalidates. See
      `docs/engineering_decisions/packument-tarball-url-rewriting.md`.
      - [x] The 304 response carries the marked tag, not the upstream's one it relays.
            Four requests for lodash before: 200 (68,970 bytes), 304, 200, 304, because
            the client stored the upstream tag off the 304 and it was dropped next time.
            After: 200, then 304 every time.
      - [x] While rewriting, `If-None-Match` is the only conditional forwarded.
            `If-Match`, `If-Modified-Since`, `If-Unmodified-Since` and `If-Range` are
            dropped: a 304 earned by a date says nothing about which proxy rewrote the
            body the client holds.
      - [x] Measured against real clients over two installs with a warm cache: yarn 4 is
            the only one of the five that revalidates, and it sends `If-Modified-Since`
            alongside `If-None-Match`. Its second run got a 304, saving 247,067 bytes.
            npm, pnpm, yarn 1 and bun sent no conditional at all, serving the second
            install from their own caches.

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
- [x] **Schema constraint from the spike: never `#[serde(untagged)]`** on polymorphic
      rule fields. Carried into the Stage 2 loader, where `ScriptRule` hand-writes
      `Deserialize` with `deserialize_any` + `visit_str`/`visit_map`, delegating the map
      arm so the struct's own `deny_unknown_fields` applies. Applies to every polymorphic
      rule field; `install_scripts` is the only one today, since `cooldown` is always a
      table.
      - [x] **Correction to how this was written down.** Untagged does not silently accept
            a typo'd key: it refuses, in both formats. What it destroys is the diagnosis.
            The error says only "data did not match any variant" and puts the caret on the
            line *above* the typo, which reads as the correct line being wrong. Measured
            twice, by the spike's `poly` binary and again by the loader's own test.
            A test asserting the key appears anywhere in the message does not discriminate
            either, because the error carries a source-context snippet that quotes the
            offending line under both.
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
- [x] **Testing strategy: HTTP-level fixtures.** Decided by doing. Real registry
      responses, trimmed to one version, live in `tests/fixtures/npm/` with a README
      explaining what property each one covers and how to refresh them. Both the
      abbreviated and full document are kept per package, because the difference between
      them is exactly what the record schema had to model. This pairs with the two
      corpus-scale checks already in place, `make smoke-npm` against a real npm client
      and `cargo run --example osv_conformance` against OSV's full npm bundle.
- [x] **Name: `waharoa`.** Registry half done: all four exact-name lookups return 404
      (crates.io, npm, PyPI, the GitHub org), with known-existing controls returning 200
      in the same run to prove the probe works. The name is free.
      Cultural consultation is a **pre-release** gate rather than a Stage 1 one, and has
      moved to Stage 7. Nothing in Stage 1 depends on the answer: the name appears in a
      binary nobody outside this repository runs, and renaming before release costs a
      find-and-replace. Blocking transport work on a human conversation would have stalled
      the stage for a cost that does not arrive until launch.
- [x] Shipped policy template must declare a floor for **every** supported ecosystem.
      Moot: there is no floor tier, and no per-ecosystem configuration at all. See
      `docs/engineering_decisions/policy-tier-resolution.md`. `examples/policy.yaml` is
      the config-format spike's artifact and is rewritten against the new shape as part
      of the Stage 2 deletions.

### Fetch path and status codes
- [x] Read `dist.integrity` from the packument, artifact digest known **before** the
      tarball is fetched. `src/store.rs` holds records from packuments already seen and
      the tarball request looks its own up. Measured on `express + @babel/code-frame`:
      73 of 73 tarballs had a digest from a packument seen earlier in the same run.
      - [x] Three lookup outcomes, not two: `Found`, `NoSuchVersion` (the packument was
            read and does not name this version), `Unknown` (no packument observed).
            `NoSuchVersion` is reachable from a real `npm install express@3.0.0-rc1`,
            whose tarball is served at `express-3.0.0rc1.tgz`.
      - [x] Bounded by total record count (`WAHAROA_MAX_RECORDS`, default 50,000),
            evicting least recently used. A four-package install touches 167 packuments
            and 9,690 records; the largest single packument is typescript at 3,822. A
            packument bigger than the whole budget is still kept, because the tarball
            request that follows it is the reason to store anything.
- [x] `[!]` Cache hit, stream through. `src/verified.rs`, keyed by artifact content
      digest, consulted before the fetch and recorded when the bytes match. Moved forward
      from Stage 5, which keeps the analysis the cache will eventually hold.
      - [x] **A hit does not skip verification.** A hit says these bytes were verified on
            an *earlier* request; the bytes arriving now come from upstream on this one
            and could differ. Skipping the hash would mean a registry that served correct
            bytes once could serve anything afterwards and have it forwarded unchecked,
            which is what `VerifyingStream` exists to catch. §5's table says a hit streams
            through, and streaming through is what verification already does.
      - [x] So in Stage 1 both arms behave identically, because nothing analyses and
            nothing defers. What exists is the branch, the key, the counts and the log
            line. Stage 5 fills in what a hit means.
      - [x] A digest is recorded only when bytes have been hashed against it. A mismatch
            records nothing: that would be recording the attack, and the next request for
            the same digest would read as already seen.
      - [x] Bounded by count, least recently used first, `WAHAROA_MAX_VERIFIED`, default
            50,000. An entry is an algorithm and a digest, so the budget is a few MB.
      - [x] `artifacts_verified` is reported at `/-/waharoa/health`. Verified against the
            real registry: two requests for lodash 4.17.21, `cache="miss"` then
            `cache="hit"` on the same sha512, one entry held.
- [x] Stream the body through a hashing wrapper, and verify what arrives against the
      packument's claim. `src/integrity.rs` parses SRI and hashes incrementally;
      `proxy::VerifyingStream` forwards chunks while hashing them. No mid-stream branch
      into buffering: the digest is known before the fetch.
      - [x] **The last chunk is held back until the digest matches.** Two problems, one
            fix. Forwarding every chunk as it arrives means the client already holds a
            complete, correct-length body when the check fails; and hyper stops polling a
            body once `Content-Length` is satisfied, so the end of the stream is never
            reached and the check never runs at all. Measured on a real tarball fetch:
            all 318,961 bytes forwarded, zero verifications. Holding one chunk keeps
            hyper polling and keeps the artifact incomplete until it passes.
      - [x] **reqwest ends a body with an empty chunk.** It displaced the held chunk and
            released the whole artifact before the comparison. An empty chunk no longer
            counts as "the next chunk arrived". This defeated the hold-back silently, and
            only a byte-level trace found it.
      - [x] **npm's reaction to a mismatch, measured.** Served a tampered tarball through
            the proxy to a real `npm install`: ECONNRESET / "socket hang up", two retries
            with roughly 10 s then 60 s backoff, then the install failed. Nothing was
            written to `node_modules`. So it fails closed, and costs the client about 70
            seconds to do it. Relevant to the `Retry-After` work below.
      - [x] SHA-1 is not verifiable through `integrity`. Two versions in 24,852 publish
            only `dist.shasum`; those artifacts are forwarded unverified and logged,
            rather than checked with a collision-broken hash.
      - [x] SRI multiple-hash and `?options` forms are handled although npm emits
            neither, and the strongest algorithm wins. Zero of 24,852 versions use them,
            so no fixture would ever cover it.
- [x] **A registry can point `dist.tarball` at a host the proxy does not front, and the
      artifact is then fetched directly.** npm rewrites that URL to the configured
      registry only when it names the default registry host. Tested with a controlled
      registry serving the same package both ways: `https://registry.npmjs.org/...` came
      through the proxy, another origin did not, and the proxy saw no tarball request at
      all. This corrects an earlier finding in plan §4 that said npm ignores the host
      outright.
      - [x] `npm::bypassing_origin` reports the origin a client will go to directly, or
            `None` when the request will reach the proxy. The configured upstream and the
            default registry both count as reachable, so a private registry serving its
            own artifacts is not flagged. Scheme and port are part of the origin, so an
            http downgrade and a different port are both reported.
      - [x] Checked at packument time, which is the only moment it is visible: by the
            time the artifact is fetched the request has already gone elsewhere. Logged
            as a warning with the origins and a version count, plus `offsite_versions` on
            the normalize line.
      - [x] No false positives: silent across 67 packuments in a real install and all
            24,852 artifact URLs in the corpus test, and it fires on a controlled
            registry publishing to another origin.
      - [x] Three states, not two. `WAHAROA_ALLOW_DIRECT_ORIGINS` names origins the
            proxy does not serve and permits anyway, so the client fetches those
            artifacts directly. Before it, the only escape from a refusal was
            `WAHAROA_REFUSE_UNSERVABLE=0`, which trades one origin's exemption for every
            origin's. An allowed origin is reported on every packument that uses it: an
            accepted gap that stops being reported outlives the reason it was added.
      - [x] **Only `dist.tarball` needs the policy, for npm.** pacote resolves
            `dist.attestations.url` against the configured registry rather than using it
            as written (`lib/registry.js`: `new URL(...).pathname` joined to
            `this.registry`, commented "Always fetch attestations from the current
            registry host"), so that host is discarded unconditionally and cannot route a
            client anywhere. `homepage`, `repository.url` and `bugs.url` are not fetched
            during an install.
      - [x] Rechecked per client: `make offsite-urls`. A registry serves a working
            package whose `dist.attestations.url`, `dist.signatures`, `homepage`,
            `repository.url` and `bugs.url` all point at a second server that answers 404
            and logs what it was asked for.
            **All five clients installed and none of them made a single request to it.**
            So of the packument fields that carry a URL and could plausibly be fetched
            during an install, `dist.tarball` is the one that routes it, for every client
            rather than for npm alone. Manual target, like `make retry-matrix`; nothing
            runs it automatically.
            Measured fields only: a packument has other URL-bearing fields that this does
            not put a recorder behind.
            - [x] `npm audit signatures` asks the **configured registry** for
                  `/-/npm/v1/keys` and never contacts the host the packument named. It
                  stops at `EMISSINGSIGNATUREKEY` before the attestations fetch, because
                  the fixture has no real signing key, so this narrows where npm looks
                  without settling what it does with a valid one. Source is still the
                  basis for that half.
- [x] `[!]` Status-code split: **502** upstream unreachable/malformed · **503** we are
      not ready (mirror warming, all requests) · **429** we are ready but this one
      artifact is under analysis. The split is decided and each code now has a home.
      - [x] 502 is implemented and tested, for every request kind. The
            `WAHAROA_CA_BUNDLE_EXCLUSIVE` handshake failure exercises it against a real
            registry as well.
      - [x] 503 landed in Stage 2, on the intel store: a store with no snapshot, or one
            that errors, answers 503 on both paths with nothing fetched.
      - [x] 429 is in Stage 4, under the analysis cost tier. It had no cause here:
            nothing held an artifact long enough to defer one.
- [x] `[!]` Never 4xx-that-reads-as-a-block for a not-ready state (same rule as cold
      start). Held by a test that enumerates the statuses the proxy produces of its own
      accord: 502 for an unreachable upstream on every request kind, 200 for health, and
      one 4xx, the policy refusal. Codes forwarded from upstream are the registry's answer
      and are covered separately.
      - [x] The refusal status cannot be seated outside 400..=599: `RefusalStatus` is only
            built by `parse`, which refuses anything else, or by `default`, which is 403.
            That is why there is no configuration surface for a not-ready state to acquire
            a 4xx through.
- [x] `[!]` Test real client retry behavior early. Done: `make retry-matrix`, five
      clients against a deferral the proxy is told to produce (`WAHAROA_DEFER_TEST`, debug
      builds only). Full tables in
      `docs/engineering_decisions/deferral-status-codes.md`.
      - [x] **429 is terminal for yarn 1 and bun; 503 is not.** Both stop after one 429
            and retry a 503. npm, pnpm and yarn 4 make no distinction between the codes.
            Five clients out of five retry 503; three retry 429. This is the evidence for
            "unknown user-agent falls back to 503" below.
      - [x] **Only yarn 4 honours `Retry-After`.** npm and pnpm back off 10s then 60s
            regardless of the header, yarn 1 uses 3s, bun retries six times inside 0.2s
            with no delay at all.
      - [x] **The plan's mitigation aimed at the wrong quantity.** Tuning `Retry-After`
            into npm's window does nothing, because npm ignores the header. What decides
            the outcome is total patience, and the ordering is inverted: npm and pnpm wait
            70s, yarn 1 12s on a packument and 0s on a tarball, yarn 4 3.2s, bun 0.2s.
      - [x] **An 8-second warm-up** is waited out by npm, pnpm and yarn 1, and fails
            yarn 4 and bun.
      - [x] yarn 1 is the only client that varies by request kind: it retries a 503
            packument five times and gives up on a 503 tarball after one.
- [x] Test with npm, yarn, and pnpm, noting where behaviour diverges. `make
      smoke-clients` measures packuments, artifacts and verifications per client.
      - [x] **Finding: pnpm and yarn fetch artifacts directly, bypassing the proxy.**
            Both use the absolute `dist.tarball` URL; npm rewrites it to the configured
            registry. Proven with a controlled registry naming a host where the package
            does not exist: npm installed, pnpm gave `ERR_PNPM_FETCH_404` and yarn a 404,
            both on `https://registry.npmjs.org/...`. Against the real registry the same
            thing shows up as silence: installing `express`, npm sent 67 packuments and
            69 tarballs, pnpm sent 66 packuments and zero tarballs and still installed.
      - [x] So digest verification and all of Stage 3 do not apply to pnpm or yarn.
            Metadata policy still does, since both fetch packuments through the proxy.
            Recorded in README as an honest limit.
      - [x] **Decided: rewrite `dist.tarball` for every client**, reversing plan §4.
            Uniform rather than per-client, so there is one behaviour for the ecosystem
            instead of a user-agent table that would have to be maintained. All three
            clients now fetch artifacts through the proxy and all are digest-verified.
            - [x] Only the origin changes, and only to one the proxy already fronts. An
                  artifact elsewhere is left alone: rewriting it would mean the proxy
                  fetching from an arbitrary host for a client.
            - [x] Release-build cost on the largest packument (typescript, 8.7 MB): 36 ms
                  parse, 1.6 ms rewrite, 10 ms serialise, 18 ms gzip. `Compression::fast`
                  rather than `default` is 18 ms against 117 ms for 2.06 MB against
                  1.69 MB. `serde_json` `preserve_order` keeps key order, so the document
                  differs only in the URLs.
            - [x] Signatures unaffected: pacote signs `${mani._id}:${mani._integrity}`
                  (`lib/registry.js`), which does not cover the URL. `dist.integrity` is
                  never touched.
            - [x] `Content-Length`, `Content-Encoding` and `ETag` are set to describe the
                  body the proxy sends, and the `ETag` carries a tag derived from the
                  proxy's address.
            - [x] **Only a tag this proxy issued at this address may revalidate.** A 304
                  authorises the client to serve what it cached, which is safe only for a
                  body the proxy produced here. Found by testing the upgrade path:
                  enabling rewriting at an address that previously ran without it, npm
                  sent the upstream's own tag, the registry answered 304, and the client
                  kept its unrewritten copy. Harmless for npm, which re-derives artifact
                  URLs from the configured registry, and a silent bypass for pnpm and
                  yarn, which use the URL as written. Costs one packument re-fetch when a
                  client with a warm cache first meets a rewriting proxy.
            - [x] Lockfiles, measured: npm and yarn record the proxy address; pnpm omits
                  the URL and derives it from the configured registry, so its lockfiles
                  become registry-independent. `WAHAROA_PUBLIC_URL` pins the address.
            - [x] **The recorded address is load-bearing.** A lockfile written through a
                  proxy on one port, then `npm ci` against a proxy on another, fails
                  outright: npm goes to the address in `resolved` and does not fall back
                  to the registry given on the command line. The proxy warns at startup
                  when `WAHAROA_PUBLIC_URL` is unset, and the README says so.
            - [x] `make smoke-clients` asserts every client fetches and verifies
                  artifacts. Checked that it bites with `WAHAROA_REWRITE_ARTIFACTS=0`.
- [x] **Refuse artifacts whose origin is not in the proxy configuration.** Tier 3 in
      `docs/engineering_decisions/enforcement-tiers.md`, built before any network-level
      interception: it closes the gap those tiers are wanted for and needs no CA, no root,
      no trust-store changes and nothing per machine. On by default;
      `WAHAROA_REFUSE_UNSERVABLE=0` forwards them instead.
      - [x] Filter, do not block the document, per decision #4
            (`quarantine-filter-metadata.md`). A package can have one old version on
            another origin and every current version on the registry; refusing the
            document would break an install that filtering leaves working.
      - [x] **Filtering is the only control that works here.** The client fetches
            `dist.tarball` from whatever host it names, so refusing the artifact request
            never happens: the request goes somewhere else. The packument is the last
            point the version is visible.
      - [x] A `dist-tags` entry naming a removed version is dropped too, or it resolves to
            nothing and the resolver cannot fall back.
      - [x] Structural, so unlike the URL rewrite it parses the document. That cost is
            paid only when there is something to remove, which no real npmjs.org packument
            has been: 0 of 24,852 artifact URLs measured were off-origin.
      - [x] **Bug found by running it: when nothing survives, the filtered body still has
            to win.** Returning "nothing to rewrite" forwarded the original, putting every
            refused version straight back into the document. An empty `versions` map is
            the right answer.
      - [x] Operator-configured origins. `WAHAROA_ARTIFACT_ORIGINS` is a comma-separated
            list of additional origins the proxy fronts, for a registry that publishes
            artifacts somewhere else, a CDN in front of a private registry being the case
            to expect. The upstream and the default registry are always included. Zero of
            24,852 artifact URLs measured on registry.npmjs.org needed one.
            - [x] `ReachableOrigins` is now one source of truth for two questions that
                  must never disagree: which artifact URLs get rewritten, and which are
                  reported as fetched directly. They were separate before, one taking a
                  slice and the other hardcoding the default registry.
            - [x] An origin that is not an http or https URL with a host is an error at
                  startup rather than being dropped. An operator who names an origin and
                  has it silently ignored would believe those artifacts are covered.
            - [x] **The record now decides where an artifact is fetched from.** Rewriting
                  points the client at the proxy, so the proxy has to know where that
                  stood for. Only origins the operator added are fetched from directly:
                  a packument naming the default registry still routes to the upstream,
                  because a private mirror publishes registry.npmjs.org URLs and is the
                  reason the proxy was pointed at it. Fetching from npmjs.org would go
                  around the mirror.
            - [x] The record lookup moved to before the request is sent, which is what
                  plan §5 asks for anyway: the digest is known before the artifact is
                  fetched, not after its headers arrive.
      - [x] The refusal status is configurable by (ecosystem, client), defaulting to 403.
            `WAHAROA_REFUSAL_STATUS="default=403,npm/pnpm=451"`. Clients bucket status
            codes rather than reading them, so an operator who finds one mishandling 403
            can say so without waiting for a release.
            - [x] The client is the **first token** of the user-agent, never a substring.
                  Measured: `pnpm/10.33.0 npm/? ...` and `yarn/1.22.22 npm/? ...` both
                  contain `npm/`, so searching for "npm" matches all three.
            - [x] An unrecognised or absent user-agent gets the default. That differs from
                  the not-ready codes in §5, where an unknown client falls back to the more
                  widely retried option: a denial is meant to be terminal, so there is
                  nothing to retry toward.
            - [x] Anything outside 400..=599 is refused: a denial answering 2xx is not a
                  denial and a 3xx would send the client somewhere. 5xx is accepted because
                  an operator may need it, and warned about at startup because §5 reserves
                  5xx for the proxy not being ready.
            - [x] One mechanism for every denial, so the throwaway block uses it too and
                  Stage 2's engine has somewhere to plug in.
- [x] Enforcement tier 3 is done here (origin refusal, above). **Tiers 4 and 5 moved
      to Stage 5**, with the client measurements they rest on.
- [x] `make inspect`: one packument request and one artifact request as each of npm, pnpm
      and yarn, with the headers those clients actually send, printed beside what the
      registry served directly. For looking, where `make smoke-clients` asserts. It hashes
      the artifact itself rather than trusting the proxy's report, so the check is
      independent of the thing being checked.
      - [x] Client request headers captured from npm 9.9.4, pnpm 10.33.0 and yarn 1.22.22
            against a recording server rather than guessed. **pnpm offers `br`**, which is
            what the outbound encoding narrowing exists for: the registry would serve
            brotli and the proxy could not decode it.
      - [x] **yarn 1 asks for `application/json` and gets the full packument**, where npm
            and pnpm ask for the abbreviated one. Which document arrived is what qualifies
            every absent field on a record, so the script names it.
- [x] nvm's latest stable node for every target that runs a package manager, via
      `scripts/make/lib/node.sh`. Without it the node in play was whatever the shell's
      profile resolved, which on a machine with both nvm and asdf was not stable between
      invocations: this repository saw node 16 and node 24 from the same PATH minutes
      apart. That decides behaviour, not just versions, since yarn 2+ is skipped entirely
      on node 16.
      - [x] "Latest stable" is `nvm version node`, nvm's own answer, rather than the
            highest directory name.
      - [x] The helper sets `WAHAROA_NODE` rather than printing. A caller capturing its
            output with `$(...)` runs it in a subshell and the new PATH dies with it,
            which is what happened first time: npm stayed at 9.9.4.
      - [x] **corepack is no longer bundled.** Node shipped it from 16.9 until it was
            unbundled in 25, so the latest node has none. dev-setup installs it, and on
            failure retries against registry.npmjs.org and says which of the two
            registries rejected it, because the usual cause is the configured registry
            rather than corepack.
      - [x] All five clients pass on this machine under node v25.8.0 with corepack 0.34.7.
      - [x] `make lint` now runs `shellcheck -x`, so the shared helper is checked in the
            context that sources it rather than reported as unreadable.
- [x] First kani harnesses, so `make verify` passes on merit rather than vacuously.
      `http::is_zero_qvalue` is total and true for exactly the five zero forms RFC 9110
      §12.4.2 allows, over every string up to five bytes from `{0 . 1 a}`. Verified in
      4 seconds.
      - [x] **What is provable is narrower than it looks.** Kani reasons about
            allocation-free code over small domains. `classify_path` exhausted 14 GB and
            was killed; `encoding_to_request` did not finish on three arbitrary bytes in
            two minutes, because it lowercases each token and a heap allocation inside a
            symbolic loop does not scale. The allocation-free decision inside it verifies
            in seconds.
      - [x] The proof compares the function against an explicit list of the zero forms,
            not against a restatement of its own implementation.
      - [x] Writing it replaced `parse::<f32>()` with an explicit grammar check, which is
            better on its own terms: the input is attacker-controlled, comparing against
            zero is the only question asked, and float parsing brings rounding and NaN to
            a decision that has neither.
      - [x] Nine harnesses, `make verify`, 2m01s. Each was checked against a mutation of
            the thing it claims, because a proof that passes vacuously reads as coverage:
            - `http`: `is_zero_qvalue` matches RFC 9110 §12.4.2 exactly, over five bytes
              of `{0 . 1 a}`; an absent `Accept-Encoding` means identity.
            - `integrity`: `Ord` on `Algorithm` is ordering by digest length, which is
              what makes `Sri::parse` pick the strongest hash on offer. Reordering the
              variants would silently prefer the weakest, and every single-algorithm
              fixture would still pass. Also that the name mapping round-trips and every
              algorithm names one of the three real digest lengths.
            - `refusal`: a client name is one lowercase token, carrying no delimiter and
              nothing after one, and a user-agent of only delimiters has no client at all.
              This is the rule the per-client table rests on: `pnpm/10.33.0 npm/? ...`
              and `yarn/1.22.22 npm/? ...` both contain `npm/`. The two cost 53s and 34s
              of the run because `client_name` allocates; the rest are milliseconds.
            - `defer`: a bounded deferral that has lifted never comes back, over every
              scope and every pair of times in order, and an unbounded one never lifts.
              A deferral that came back would turn away a client that had already
              retried successfully.
      - [x] Out of reach, recorded so it is not attempted again: the `ETag` round-trip,
            because `base_tag` hashes with SHA-256, and `encoding_to_request`, which
            lowercases each token and did not complete on three arbitrary bytes in two
            minutes.
      - [x] Paid, Stage 2: the §5.5 action lattice and per-parameter monotonicity, now
            twelve harnesses in `src/policy/strictness.rs`. The whole set is 21.
- [x] Bypass measurements taken here (five clients, `dist.tarball` handling,
      lockfile contents). **The open detection work moved to Stage 5**, carrying
      those findings with it.
- [x] Cache bypass confirmed, per client rather than assumed to work like npm's. Measured
      by installing the same package twice through the proxy with one cache, and counting
      what the proxy saw the second time:
      | Client | Second install |
      |---|---|
      | npm 11, pnpm 10, bun 1.3 | nothing reached the proxy |
      | yarn 1, yarn 4 | the packument did, the artifact did not |
      So the artifact bypass is universal and, for three of the five, so is the metadata
      one. §7 records it as a bypass vector; this is the evidence.
      - [x] `waharoa doctor` checks all four caches it can locate, not just npm's, and
            describes the two behaviours separately because they are different exposures.
      - [x] Each client gets the command that actually clears its cache.
            `npm cache clean --force` is not it for bun or pnpm.
      - [x] Presence and location are reported rather than a count. Every client lays its
            cache out differently, so one number would mean packages for one and files for
            another: the same yarn cache is 12,983 entries or 749,073 files depending on
            which you count.
      - [x] **Which cache is in play is a per-directory question.** `pnpm store path`
            answers with a store on the project's own filesystem, so it is
            `/tmp/.pnpm-store` in a directory under `/tmp` and the user's store elsewhere.
            Doctor already says which directory it checked from.
- [x] `waharoa doctor`. `src/doctor.rs` holds the checks as pure functions; the binary
      reads the files and asks each package manager for its own resolved configuration,
      since the effective registry comes from a project `.npmrc`, then the user's, then
      the global one, and only the client knows which won.
      - [x] Effective client registry for npm, pnpm and yarn.
      - [x] Lockfile evidence, newly possible because artifact URLs are rewritten: npm and
            yarn record the proxy address in `resolved`, so a lockfile shows whether the
            proxy produced it. pnpm omits the URL when it matches the configured registry,
            which is reported as "not evidence either way" rather than as a fault.
      - [x] A lockfile naming **both** the proxy and somewhere else is a `PROBLEM` rather
            than a warning: part of that install does not go through the proxy, and only
            the other part is examined.
      - [x] The public URL check catches the failure measured earlier: `npm ci` fetches
            the address in the lockfile and does not fall back, so a lockfile pinned to a
            proxy address that is no longer served fails the build. `registry.npmjs.org`
            in a lockfile is reported by the client-config check instead, not as a stale
            proxy address.
      - [x] npm cache entry count, since a warm cache is served without consulting the
            registry at all (§7).
      - [x] An unknown subcommand exits 2 rather than falling through to the proxy, and
            `waharoa help` lists every environment variable.
      - [x] Whether the proxy is reachable and answering. `GET /-/waharoa/health` is
            answered by the proxy itself rather than forwarded, so a client can tell a
            waharoa from any other registry.
            - [x] Under `/-/`, the registry's own namespace, where a package name can
                  never live. Everything else under it still goes upstream.
            - [x] It reports the settings that decide what gets examined: the public
                  base, artifact rewriting, the refusal, the served and allowed-direct
                  origins, and what the store holds. Doctor warns on each one that
                  reduces coverage, so a proxy that is running and not looking is
                  reported rather than passing.
            - [x] A mismatch between the address the proxy writes into artifact URLs and
                  the address doctor reached it on is a warning, because the first is
                  what lockfiles record.
            - [x] No secrets: the CA bundle, any upstream credentials and the throwaway
                  block are all absent.
            - [x] **`reqwest::blocking` cannot be used here.** It builds a second tokio
                  runtime, and dropping one inside an async context panics. Doctor runs
                  in the same runtime as everything else, so the fetch is async and the
                  `blocking` feature is not enabled.

**Exit:** a real `npm install` completes through the proxy with the full transitive
graph correctly normalized to PURLs, and the hardcoded block fires before the tarball
is fetched. Leave it running for a week and trust it.

---

## Stage 2 — Decision layer (policy + intel)

**Status: closed 2026-09-16.** Exit met and re-verified live; every item closed or moved
to the stage that can finish it. See the exit record at the end of this stage.

**Goal:** the policy engine and its semantics, on top of a transport you already trust.
The spec gets frozen here.

- [x] `[!]` Pick `serde_yaml` replacement before writing the loader (it is archived).
      Decided by the Stage 1 spike: **`serde-saphyr`**, `default-features = false`,
      `features = ["deserialize"]`, `include`/`include_fs` permanently off, fallback
      `serde_norway`. See `docs/engineering_decisions/config-format-yaml-serde-saphyr.md`.

### Policy engine

The design changed after most of this was built. See
`docs/engineering_decisions/policy-tier-resolution.md`, which supersedes plan §5 and §5.5.
What the old design called tiers is now: global settings, per-package exceptions, and a
decision vector. What was built and then removed is listed at the end of this section, so
the record of why it went survives the deletion.

- [x] `[!]` Pick `serde_yaml` replacement. `serde-saphyr`, `default-features = false`,
      `features = ["deserialize"]`, `include`/`include_fs` permanently off, fallback
      `serde_norway`. See `docs/engineering_decisions/config-format-yaml-serde-saphyr.md`.
- [x] `[!]` YAML loader with **hard error on unknown keys**. `src/policy.rs`,
      `deny_unknown_fields` on every struct, refused at four depths.
      - [x] Never `#[serde(untagged)]` on a polymorphic field. It refuses a typo'd key but
            names neither the key nor the right line; a hand-written `Deserialize` that
            delegates keeps the diagnosis. Measured in both formats by the spike's `poly`
            binary and again by the loader's own test.
            No polymorphic field survives the redesign, so nothing uses it today. The
            measurement stands for the next one.
- [x] `[!]` `version` field; refuse to start on unrecognized version. Read by a probe
      before the body is parsed, so a version 2 document is refused by its version rather
      than by whichever version 1 key it happens to be missing.
- [x] `[!]` Action lattice: `allow < quarantine < block`. Three values, not four: `warn`
      left when provenance became a recorded attribute rather than an action.
      - [x] `Action::strength` is the **combiner**: the disposition is `max` over the
            decision vector. Under the old short-circuit design no two actions were ever
            combined, so the lattice did no work.
- [x] `[!]` Per-parameter monotonicity declarations. One table, `direction_of`, rather
      than a direction at each use site, so a parameter cannot be compared one way in one
      place and the other way in another. `cooldown_days` higher is stricter, `max_cvss`
      lower is stricter, proved mirror images over every pair of values.
- [x] `[!]` Loosening detection, including the incomparable case. Kept, and now serves the
      `packages` tier alone: an entry may only loosen, so tightening has to be detected to
      refuse it.
      - [x] `Strictness::Unset` for a setting nothing above had set, which is neither
            `Same` nor `NotApplicable`.
- [x] `[!]` N/A handling. **More load-bearing after the redesign, not less.**
      `install_scripts` is a global setting asked of every ecosystem, and Go has no install
      step to ask about, so it reports not-applicable rather than a violation.
      `merge::applies` already computes it and its Go test already covers it; that function
      survives the deletion of the rest of `merge.rs`.
- [x] `[!]` **The decision vector.** `src/policy/decide.rs`. Every check runs and appends
      one result; the disposition is the strongest action in the vector.
      - [x] Four results: `passed`, `failed`, `excepted`, `not_applicable`. Three of the
            four contribute `allow` and are distinguished anyway.
      - [x] `excepted` carries the entry that excused the check, so `exceptions_used`
            names the entries doing work and an entry that never appears is dead.
      - [x] `reasons()` returns the failing checks strongest first, because the one that
            will not lapse is the one to act on.
      - [x] A lapsed exception does not match at all, which is what makes an expiry do
            something.
      - [x] Mutation-checked five ways. The most-specific-wins test did not discriminate
            at first: the narrow entry was written last, so "narrowest wins" and "last
            wins" gave the same answer. It now asserts both orders and a package the
            narrow entry does not name.
      - The short circuit in front of expensive analysis moved to Stage 4, under the
        analysis cost tier: there is no expensive analysis to put it in front of yet.
- [x] An entry that changes nothing is **valid**: it warns at load and `doctor` flags it.
      Almost always a selector that no longer matches what it was written for, but not a
      reason to refuse a policy. Startup, `doctor` and `policy check` read one
      `policy::check::Report`.
- [x] List-valued rules replace rather than union. True by construction: the merge takes
      one side or the other and never combines. No setting is list-valued except
      `cve_ids`, which is a set of exceptions rather than a rule value.
- [x] Golden-file tests. The seven merge fixtures in `tests/fixtures/policy/` were
      deleted with the merge: every one of them was a policy in a schema that no longer
      parses. Recreated against the rendered decision vector:
      `tests/fixtures/explain/decisions.txt`, 22 cases covering every state each check can
      reach, the narrowest entry winning, a lapsed entry, and an exception that shortens a
      wait and not enough. `tests/fixtures/explain/policy.txt` pins `explain --policy`,
      `examples/policy.yaml` included. `WAHAROA_BLESS=1` rewrites both.

#### Built, then removed by the redesign

Not failures, and not dead ends either: each was built to the plan as it stood, and three
of them produced findings that outlived the code.

- **The global -> ecosystem merge** (`merge.rs`). There are no per-ecosystem settings, so
  there is nothing to merge. `applies` and `RuleValues` survive; the rest goes.
- **`loosens_global` with required `reason` + `expires`, and its expiry check.** Nothing
  acknowledges, because nothing warns at the ecosystem tier. The finding survives: an
  acknowledgment flag without both fields is worse than no mechanism, since it silences
  the warning and records neither.
- **The floor** (`FloorRules`, `check_floors`, `check_enabled`, the startup failure). Which
  checks may be excepted is fixed by the decision chart rather than configured.
- **`provenance_required`.** Measured at 81% of a real dependency tree lacking provenance
  against 0% carrying an install script, which is what made it a signal rather than a gate.
  Stage 1 already records it.
- **`ScriptDetail` and `ScriptRule`'s hand-written `Deserialize`.** Polymorphic only to
  carry the acknowledgment. A `packages` entry carries its own `reason` and `expires` at
  entry level.
- **`Action::Warn`.**

### The checks

Each is a setting, an exception shape, and an intel source. None exists yet.

- [x] `[!]` `denials`, explicitly forbidden packages. Exact version, no exception.
      Decided in `decide.rs`, turned into a refusal in `policy/enforce.rs`, and enforced by
      the proxy on both paths with `enforce::artifact`:
      `a_denied_version_is_refused_on_a_pinned_fetch_before_the_artifact_is_fetched` and
      `a_denied_version_is_absent_from_the_packument_the_client_receives` in
      `src/proxy.rs`, and `make smoke-npm` step 6 with the real registry.
      - [x] **Matched by parsing the purl, not by comparing the written form.**
            `pkg:npm/%40babel/core@1.0.0` and `pkg:npm/@babel/core@1.0.0` are the same
            package, and the first is what this codebase's own `Display` emits and what
            OSV publishes. String comparison made a denial spelled the canonical way never
            fire, while the same spelling in a `packages` selector matched, because
            `selector::decompose` was already parsing. Denials now use it too.
      - [x] **A denial naming no version does not load.** It would match nothing and read
            as a package that had been dealt with. `PolicyError::DenialNeedsAVersion` says
            what to write instead.
      - [x] **Enforced on a pinned artifact fetch**, verified against the real registry:
            403 with the reason for the denied version, 200 for another version of the
            same package.
      - [x] `[!]` **Resolution-path filtering**, so a refused version is dropped from the
            packument and the resolver picks a clean one. A 200 with fewer versions, never
            a 4xx. Shares one pass with the origin filter, because both remove from the
            same `versions` map and both leave a `dist-tags` entry pointing at nothing.
      - [x] **The throwaway hardcoded block is gone.** `make smoke-npm` 6/6 proves
            interception against a real denial, both halves of decision #4 at once:
            filtered on resolution, 403 on the pinned fetch, artifact never fetched.
- [x] `[!]` Known malware. Not configurable and not exceptable: behaviour, not policy.
      Read from the intel store (`Facts::with_intel`). Verified live against
      registry.npmjs.org: `--hiljson` filtered from its packument and its tarball refused
      403 with `known_malware: reported as malware`, `lodash` served.
      `docs/engineering_decisions/intel-in-decisions.md`.
- [x] `[!]` `cooldown_days`, the age threshold. Produces `quarantine`, which lapses on its
      own, and is a **packument filter** rather than an artifact refusal: Stage 1's
      `npm::filter_unservable_versions` is the mechanism.
      The check is done and tested in `decide.rs`, and `npm::publish_times` supplies the
      fact. Persisting that store across restarts moved to Stage 5, beside the packument
      store it sits next to.
      - [x] **The publish time is not in the document the proxy fetches.** npm sends
            `time` only in the full packument. `npm install` asks for the abbreviated one
            and so does `fetch_and_store`, so `published` is `None` for every record this
            build holds. `decide` treats an unknown publish date as not old enough, which
            is the right direction and makes `cooldown_days` fail every package rather
            than pass it. Held by
            `asking_for_cooldown_on_an_abbreviated_record_fails_every_package`: lodash
            4.17.21, published 2021 and years past any cooldown, quarantines on the
            abbreviated record and passes on the full one.
      - [x] **A cooldown of zero did not turn the check off.** `is_some_and` short
            circuits on a missing publish date, so `cooldown_days: 0`, which is how an
            operator disables the check, still failed every package the registry published
            no time for. Zero days of waiting is satisfied by everything.
      - [x] **A cooldown is enforced on both paths**, verified against the real registry:
            a 10-year cooldown leaves 11 of ms's 32 versions in the packument, and a
            pinned fetch of 2.1.3 answers 403 "held by policy".
      - [x] **An unanswerable check is dropped and reported, never silently passed.**
            `enforce::unenforceable` drops `cooldown_days` when the record cannot answer
            it, and startup says which settings are configured and inert. Without the
            drop, configuring any policy refused every artifact.
      - [x] `[!]` **Fetch the full packument for its `time` map, gated on the policy
            using a cooldown.** `npm::publish_times` parses only the map rather than
            normalising, because building 3,823 records for typescript to read one field
            per version is the part worth not doing. Cached per package, bounded at 1,024.
      - [x] **There is no cheaper source.** `?fields=time` returns the whole document
            unchanged and `/<package>/time` is a 404, both checked against
            registry.npmjs.org. Full against abbreviated, measured on eight packages:
            lodash 3.6x, express 2.4x, eslint 1.7x, debug 2.6x, ms 3.1x, @babel/traverse
            1.9x, react 2.4x, typescript 1.8x (8.7 MB to 15.7 MB). The 32 MB packument
            ceiling already allows for that.
      - [x] **Policy filtering was coupled to `WAHAROA_REWRITE_ARTIFACTS`.** Filtering a
            refused version is a policy question and repointing artifact URLs is a
            transport one. `enforcement-tiers.md` says rewriting is correctly turned off
            once the proxy terminates TLS, which silently stopped the filtering with it.
            Verified in both modes: 11 of ms's 32 versions survive a 10-year cooldown
            either way.
- [x] `[!]` `kev`. `block` or `allow`. Logic in `decide.rs`; the source is CISA's catalogue,
      loaded as `cisa/kev` ([kev-stream](docs/engineering_decisions/kev-stream.md)).
      CISA's catalogue is ecosystem-agnostic because it has no package identifier at all,
      so `kev` is a property of an **advisory**, not of a package, and the engine reads it
      off `Advisory`.
      - [x] A `cve_ids` exception does not reach the KEV answer. The engine reads the
            advisories as they came, never the filtered list, so a KEV'd advisory needs
            both exceptions to pass: the id for its score, `kev: allow` for its
            exploitation. Excepting by id says an advisory is not reachable from this
            code; it says nothing about whether it is being exploited.
      - [x] An exploited advisory still contributes its score, so excusing one does not
            excuse the other. Both are separate results in the vector.
      - [x] "None at all" and "all of them excused" stay distinct, so an exception that
            never had an exploited advisory to excuse is not recorded as having worked.
      - [x] The source itself: a set lookup over CVE ids the advisory stream produced.
            CISA's catalogue, loaded as `cisa/kev`, marks 13 stored npm records exploited.
            [kev-stream](docs/engineering_decisions/kev-stream.md).
- [x] `[!]` `max_cvss`. A number, not a severity band: bands are not stable across CVSS
      versions, where the same score falls in different ones under v2 and v3. Exceptions
      are per CVE id (`cve_ids`), not per package, which is the only exception keyed by
      something other than the package. Decided in `decide.rs`
      (`the_cvss_threshold_allows_what_is_at_or_below_it`), scored from OSV in `osv.rs`,
      and enforced by the proxy with `enforce::artifact`:
      `an_advisory_over_max_cvss_is_refused_on_a_pinned_fetch` and
      `an_advisory_over_max_cvss_is_filtered_from_the_packument_and_one_at_it_is_not` in
      `src/proxy.rs`. Live: `lodash@4.17.21` refused 403 on `max_cvss`. The unscored
      advisories are the `[?]` item under the intel streams.
- [x] `[!]` `install_scripts`. `block` or `allow`. Global setting, asked of every
      ecosystem, reporting not-applicable where the ecosystem has no install step.
      Not-applicable reaching a proxy path moved to Stage 3, which is where a second
      ecosystem exists to report it for.
      Enforced by the proxy on both paths: `an_install_script_is_refused_on_a_pinned_fetch_under_block`
      and `an_install_script_is_filtered_from_the_packument_under_block_only` in
      `src/proxy.rs`, over esbuild 0.28.2, which carries `hasInstallScript`. Measured to be
      silent in normal operation: 0 of 138 packages in a real `express + eslint` tree
      declare one.

### Package tier

- [x] `[!]` `Denial` type with **no** `expires` field. The field does not exist, so
      `deny_unknown_fields` refuses a denial that carries one: an expiring denial is
      unrepresentable rather than discouraged.
- [x] `[!]` Unified `packages` tier; `exceptions` block removed.
- [x] `[!]` `ecosystem` required on every package selector. Not an `Option` in `Selector`.
- [x] `[!]` Loosening requires `reason` + `expires`; no warning emitted. A warning per
      entry would be noise; a required field cannot be ignored the way a warning can.
- [x] `[!]` `expires` ceiling of 90 days from today, configurable. Both the ceiling and
      the day it counts from are arguments, so `policy check --as-of` can ask what a
      policy would be judged as on another day.
- [x] `[!]` `permanent: true` as explicit alternative, requires `reason`. An entry
      carrying both `expires` and `permanent` is refused.
- [x] `[!]` Specificity as strict subset containment, not a score. The vocabulary is
      restricted at load to keep it decidable: a name is `*`, `prefix*` or a literal, a
      version is exact or absent.
      - [x] `purl` and `name`/`version` canonicalised before comparison, since they denote
            one set through different fields.
- [x] `[!]` Incomparable overlaps and exact duplicates are load-time errors, and separate
      ones: a duplicate is comparable and still wrong.
- [x] `[!]` **An entry that tightens is a load-time error.** The refusal names where a
      stricter rule does belong: the global settings, or `denials` for a single package.
- [x] `[!]` Loosening measured against the **global settings**, not a merge.
- [x] `cve_ids`, the per-CVE exception. The only exception keyed by something other than
      the package. Narrower than raising `max_cvss`, which would apply to every advisory
      the package acquires later.
- [x] `explain` shows the decision vector: every check, its result, and for an `excepted`
      one the entry and expiry that excused it. `explain::decision` takes the policy, and
      `max_cvss` names its advisories from `decide::over_max_cvss`, the split the check
      itself made.
      - [x] **A cooldown exception that let a package through was recorded `pass`.** The flow
            chart has `RECORD_cooldown_EXCEPTED`. `decide` compared only against the wait
            that applied, so `@mycompany/*` with `cooldown_days: 0` never reached
            `exceptions_used`, the audit log or `explain`. It is now `Excepted` when the
            global wait fails and the entry's passes.
      - [x] **`explain`, the audit log and `policy diff` took the verdict from every check,
            unenforced ones included.** With no publish times, `explain` printed
            `verdict: quarantine`, the audit line recorded `quarantine`, and the proxy
            served the package. All three now use `enforce::enforced`, the vector the
            proxy acts on.
- [x] `policy check` flags permanently-shadowed selectors. After load refuses duplicates
      and unordered overlaps, one shape is left: `has_install_scripts: true` and `false`
      entries below an entry that sets neither. Reported as "never wins" when neither
      expires, and "shadowed through <date>" when one does. See
      [policy-check](docs/engineering_decisions/policy-check.md).
- [x] `policy check` lists `permanent: true` entries separately
- [x] `policy check` and `doctor` flag entries that change nothing. `--strict` exits 1 on
      an entry that changes nothing or never wins.
- [x] Tests: a denial cannot be undone by any exception. `Check::exceptable` is false
      for it, and a test puts a matching exception beside a denial and checks both hold.
- [x] Tests: known malware cannot be excepted, whatever the policy file says.
- [x] Shipped config template that loads and passes its own rules. `examples/policy.yaml`,
      checked from both sides: it parses, and it satisfies the package-tier rules.

### `waharoa policy diff`

- [x] `[!]` Evaluate two policies against a real package set. `src/policy/diff.rs`,
      `waharoa policy diff <from> <to>`.
- [x] `[!]` Pin `--snapshot` so policy changes are not conflated with intel changes.
      `waharoa refresh` keeps each snapshot in `WAHAROA_SNAPSHOT_DIR`
      (`src/intel/snapshot_dir.rs`, `WAHAROA_SNAPSHOT_LIMIT` 30 by default), and
      `policy diff --snapshot <id>` reads one through `SnapshotIntel`
      (`src/intel/snapshot_intel.rs`) instead of Postgres. See
      `docs/engineering_decisions/snapshot-identity.md`.
- [x] `policy diff --snapshot` peaked at 468 MB for npm, where Postgres took 28 MB. Rows are
      now decoded one at a time and only the audit log's packages are kept: 103 MB. See
      docs/engineering_decisions/snapshot-identity.md.
- [x] `[!]` Package set from lockfiles **and** from the audit log. The audit log is read
      (`audit::packages`): a `pinned` line lists one version, a `resolution` line lists
      every version it removed. `--lockfile <path>`, repeatable, adds each lockfile's
      registry versions (`src/lockfile.rs`): `package-lock.json`, `npm-shrinkwrap.json`,
      `yarn.lock` v1, `pnpm-lock.yaml` 9 and `bun.lock`. See
      `docs/engineering_decisions/policy-diff-lockfiles.md`.
- [x] `[!]` Report transitions both directions, grouped with counts. **Compares decision
      vectors, not verdicts.** Two policies can both answer `block` for different reasons,
      and comparing verdicts reports no change there. Held by
      `two_policies_that_both_block_for_different_reasons_still_show_the_move`.
- [x] `[!]` Nonzero exit on any loosening transition (CI gate). The exit code is the OR of
      1 for a loosening and 2 for a tightening, and 4 alone for an error. Verified: 0, 1, 2,
      3 and 4 live. See `docs/engineering_decisions/policy-diff-dates-and-exit-bits.md`.
      - [x] **A check that stops being enforced is a loosening.** The written policy did
            not loosen, but the package now installs. The gate exists to stop a change
            slipping something through, so that is what it reports.
      - [x] **Incomparable fails the gate too.** §5.5 is fail loud when tightening cannot
            be proven, and a diff that cannot be decided is that case.
      - [x] Reuses `Strictness` and the `allow < quarantine < block` lattice rather than
            inventing a second notion of looser.
- [x] `--as-of <date>` for time-dependent verdicts. Verified to change the answer: with
      cooldowns straddling ms's age, 1 package moves today and 5 by 2027-06-01. Replaced by
      `--from-date` and `--to-date`, one per policy, each `YYYY-MM-DD` or `+<days>d`.
- [x] Scheduled-job recipe: `policy diff policy.yaml policy.yaml --to-date +30d`. Exit 2 is
      an entry lapsing, 1 a package passing its cooldown. Live: an entry expiring
      2026-09-30 tightened `@babel/helper-validator-identifier`, exit 2.
- [x] A packument that could not be read was skipped with a message and not counted, so a
      run where every read failed printed `0 packages evaluated`, `nothing moved`, and exited
      0. Seen with `WAHAROA_UPSTREAM` set to `nope`, `ftp://x` and `http://`. Now a failed
      read, a 404 included, is counted and ORs 4 into the exit, and so does a run that judged
      none of the versions listed: exit 4 for `nope`. Publish times that cannot be read count
      the same, and `explain` exits 1 for them.
- [x] `WAHAROA_UPSTREAM` was read as text. `policy diff` and `explain` sent every request
      to `nope`, and the proxy panicked on it, exit 101. `env::Env::upstream` now refuses a
      value that is not an http or https URL with a host: exit 2, and 4 for `policy diff`.

### Intel — advisory streams
- [x] `[!]` **Verify each stream's data license before implementing it.** Done for every
      stream in the plan, and for Datadog, which is Apache-2.0. Aikido needs a commercial
      account and is deferred to post-v1.
      `docs/engineering_decisions/advisory-stream-licences.md`.
      - [x] **OSV's per-source licences read, 2026-09-13**, at
            <https://google.github.io/osv.dev/data/>. All 17 native sources are permissive.
            Four reach npm. OpenSSF Malicious Packages (Apache-2.0, `MAL-`) and GitHub
            Advisory Database (CC-BY-4.0, `GHSA-`) are 228,949 of the 228,951 npm
            advisories measured, and the other 2 are below. **For npm, attribution is owed
            on GHSA text and nothing else that is stored.** Ubuntu's CC-BY-SA-4.0 is the only share-alike term and is
            an OS source, so it cannot reach an npm verdict; revisit if a Linux-
            distribution ecosystem is ever added.
      - [x] **OSV records carry no licence field**, checked against a live record. OSV
            aggregates, so the terms are whichever source produced the record and the id
            prefix is the only hint: `GHSA-` is CC-BY-4.0 and needs attribution, `MAL-` is
            unstated. We redistribute nothing, so what attaches is attribution in what we
            **display**: a verdict quoting a GHSA summary is quoting CC-BY-4.0 text.
      - [x] GitHub Advisory data is CC-BY-4.0, attribution required.
      - [x] **OSSF Malicious Packages and CISA KEV read by a person, 2026-09-13.** OSSF is
            Apache-2.0 on the data and not only the tooling, which settles the `MAL-`
            records and clears the first stream in the build order. CISA KEV is CC0 1.0,
            an explicit dedication rather than the 17 USC 105 inference recorded before,
            and owes no attribution.
      - [x] The 2 npm advisories that are neither `MAL-` nor `GHSA-`, read 2026-09-15.
            `EEF-CVE-2026-56812` is from the Erlang Ecosystem Foundation CNA (CC-BY-4.0),
            and `GSD-2022-1000008` from the Global Security Database (CC0 1.0). Both are
            skipped. The EEF record's npm `phoenix` ranges are the same as
            `GHSA-63mc-hw7g-86rr`'s, which is loaded. The GSD record lists `faker.js` with
            no version or range, so it would store nothing; `GHSA-5w9c-rv96-fr7g` lists
            `faker` 6.6.6.
      - [x] The prefix-to-licence mapping is npm-only. npm's four prefixes are four
            sources: `MAL-`, `GHSA-`, `EEF-` and `GSD-`. No code decides an obligation from
            a prefix: `osv::parse` reads `MAL-` and `GHSA-` records and skips the rest.
      - [x] **NVD is public domain, 2026-09-13.** It compiles from other sources and
            asserts no licence of its own. What we take from it is CVSS scores, which are
            NIST's own analysis rather than text carried from a source.
      - [x] **Aikido Intel requires a commercial account**, 2026-09-13. Its public
            endpoint returned an empty body because there is no unauthenticated access to
            have. Deferred to post-v1; see below. Every stream that remains in the plan is
            now licence-cleared.
- [x] **Measured what each stream is worth**, which reorders the plan's list.
      - [x] **The npm advisory database is a malware database.** Of 228,951 npm advisories
            in OSV, 221,548 (96.8%) are `MAL-` records and 7,401 are `GHSA-`. So
            `known_malware` has 221,548 records to match against and `max_cvss` has 6,041,
            two orders of magnitude apart. The plan lists OSV first for coverage; the
            stronger reason is that it is the malware feed.
      - [x] **KEV has no package identifier**, across all 1,709 entries, and is operating
            systems and appliances: Microsoft 388, Cisco 97, Apple 94. It can never
            originate a finding, only escalate a CVE another stream found, so it is
            `enrich` like NVD. Type-enforced in `src/intel.rs`: `EnrichStream` returns
            `Enrichment`, which has no conversion to `Finding`.
      - [x] **13 npm CVE ids appear in KEV**, out of 6,032. The check is still worth
            having, because it is a set lookup over ids the CVE step already produced, but
            it goes last.
- [x] `[!]` Advisory stream interface (fetch / refresh / normalize). `src/intel/stream.rs`
      declares one `Stream` per stream in `ALL`, holding source, stream name, URL, byte
      ceiling, `Requirement`, `Grant`s and a `parse` shim returning `Parsed { payload, tally }`.
      `Payload::Advisories` encodes through `load::encode` and `Payload::Exploited` through
      `load::encode_exploited`. `waharoa refresh` loops over `ALL`, and `intel::capabilities_of`
      reads the grants rather than matching on stream names, so neither holds a per-stream
      branch. Fetching stays in `waharoa refresh`: a fetch is network I/O, and everything a
      descriptor holds is decidable from the bytes.
      Mirroring is not part of this item; it is tracked under "Local mirrors for all streams"
      below.
- [x] `[!]` Per-ecosystem capability matrix: `match` / `enrich` / `malware` (`src/intel.rs`,
      `Capabilities::grant` / `has` / `providers`). A grant is per stream per ecosystem, so
      NVD can hold `match` for Maven and only `enrich` for npm.
- [x] `[!]` Type-enforce that `enrich` records cannot originate a finding. `Finding` and
      `Enrichment` are separate types with no conversion between them, and `EnrichStream`
      returns the second. A `compile_fail` doctest holds the property; adding
      `From<Enrichment> for Finding` makes it fail.
- [x] `[!]` `malware` capability gated separately. `Capability::Malware` is not implied by
      `Match`, and `MalwareStream` is its own trait returning `bool` rather than a finding.
- [x] Startup warning + `doctor` check: ecosystem enabled with no `match`-capable stream.
      `intel::capabilities_of` declares `osv/npm` (match, malware) and `cisa/kev` (enrich),
      keyed by the stream a snapshot records, and `LoadedSnapshot::gaps` checks every
      `Ecosystem::ALL`. Warned at startup and by `doctor`. No refresh writes a snapshot with
      a gap today. [nvd-role-and-stream-capabilities](docs/engineering_decisions/nvd-role-and-stream-capabilities.md).
- [x] `[?]` Decide whether an ecosystem with `match` but no `malware` stream is also a
      startup warning. Decided 2026-09-15: yes. `LoadedSnapshot::gaps` reports `match` gaps
      then `malware` gaps, at startup and in `doctor`. `known_malware` is the one check with
      no exception, and it never fires without a `malware` stream.
- [x] Explicit severity precedence config (enrich may escalate `max_cvss`, never originate).
      Settled as a rule rather than config: an enrichment may raise a score and may set
      `exploited`, never the reverse, so the result does not depend on the order streams
      are read in. `Score` records which stream supplied it, for `explain` only.
- [x] Bridge `intel::Finding` to `policy::decide::Advisory`. `Facts::with_intel` groups the
      stored `Record`s by advisory id into one `Advisory` carrying `sources`, every stream
      that reported it, sorted and once each. Two signal streams holding one advisory is
      corroboration, not two vulnerabilities.
      `PackageIntel::for_version` keyed its dedupe on the advisory id alone, which was the
      same key while every stream used its own id space. With `github/npm` publishing the
      `GHSA-` ids OSV imports, the second stream's record was dropped at lookup and never
      reached the decision vector. It now keys on `(source, advisory_id)`.
      Where streams disagree on a score the highest stands, the direction `max_cvss` reads.
      Exploitation from either stream marks the advisory. Held by
      `two_streams_reporting_one_advisory_are_one_advisory_naming_both`.
- [x] `[!]` Common advisory record schema with alias set (CVE, GHSA, OSV, MAL IDs). One
      `advisory` row per `publisher_id` whatever the source, with its other ids in
      `advisory_alias` (`migrations/0001_intel.sql`), read back as `store::Record`: id,
      aliases, source, score, band, exploited, malware. OSV's `MAL-` and `GHSA-` records and
      Datadog's records are stored in it. KEV marks a row exploited by its id or an alias
      (`migrations/0003_exploited.sql`).
      [osv-malware-load](docs/engineering_decisions/osv-malware-load.md),
      [alias-matching](docs/engineering_decisions/alias-matching.md).
- [x] `[!]` OSV.dev stream, lookup by PURL. npm `MAL-` and `GHSA-` records parse
      (`src/intel/osv.rs`) and load (`PgIntel::replace_source`): all 221,217 non-withdrawn
      `MAL-` and all 7,052 `GHSA-`, with 10,357 range rows evaluated at lookup
      (`src/intel/range.rs`). `waharoa refresh` fetches and loads them.
      `docs/engineering_decisions/osv-malware-load.md`,
      `docs/engineering_decisions/osv-ranges-and-scores.md`.
      - [x] 24 `GHSA-` records stored nothing and 4 stored part: their ranges held versions
            such as `13.0` and `2026.04.1`. `range::padded` reads them as osv.dev does,
            `13.0.0` and `2026.4.1`, and they are stored padded: nothing storable 24 to 0,
            ranges 10,326 to 10,357. None is a published version.
      - [x] A packument version that is not SemVer is in no range. None was seen: 0 in 103
            packages. `3.0.0rc1` is `express`'s tarball name; its packument lists `3.0.0-rc1`.
- [x] `[!]` Choose the OSV fetch: `npm/all.zip`, read from memory with `zip` (`deflate-flate2`
      only). 228,951 single-record GETs was the alternative. `npm/modified_id.csv`, which
      lists every record's modified time, is left for an incremental refresh.
- [x] `[!]` `waharoa refresh`: fetch, parse, `replace_source`, snapshot id from the bundle.
      Live against Postgres 17: 220,684 advisories and 232,677 affected rows in 46.6s on a
      debug build. A second run upserts the same snapshot id.
- [x] `[!]` Wire the intel store into `Facts` (`known_malware`, `Intel::Consulted`) in the
      proxy, `explain` and `policy diff`. One `Intel::package` query per package.
      `enforce::artifact` and `enforce::unenforceable` take the intel state from the caller.
- [x] `[!]` `Advisory::cvss` is `f64`, so an unscored advisory is left out of `advisories`.
      Decided 2026-09-15:
      - [x] A record with no CVSS vector is scored at the top of its `database_specific`
            severity band: LOW 3.9, MODERATE 6.9, HIGH 8.9, CRITICAL 10.0. 689 npm `GHSA-`
            records, none in the KEV catalogue. The band is stored (`advisory.severity_band`,
            rows format 2) and `explain` prints `8.9 from band HIGH`. A vector that does not
            parse is not replaced by the band.
            [osv-ranges-and-scores](docs/engineering_decisions/osv-ranges-and-scores.md).
      - [x] A non-malware advisory with no score at all is ingested with `cvss` NULL and
            refused by `max_cvss` until a policy entry gives it a score. The override key is
            added to policy `version: 1`, which the user unfroze for it since nothing is
            deployed. 0 npm records need one today. `kev` reads exploitation whatever the score.
            `Advisory::cvss` is `Option<f64>`. The key is `advisory_scores`, matched by id or
            alias, used only while the advisory has no stored score, and lapsed on `expires`.
            `explain` prints `GHSA-... unscored` and `7.5 from advisory_scores[0]`.
            [osv-ranges-and-scores](docs/engineering_decisions/osv-ranges-and-scores.md).
- [x] `explain --policy` reported `kev` and `max_cvss` as enforced once the store answered.
      `max_cvss` now has 6,340 scored records to read. `kev` is reported
      `unenforced, no exploitation stream`, in `explain --policy` and in every decision.
- [x] `cve_ids` names a CVE, and OSV stores a GitHub advisory under its `GHSA-` id.
      `Advisory::is_named` matches the id or any alias. 5,972 of 7,052 `GHSA-` records carry
      a CVE alias.
- [x] `explain` printed every scored advisory against the version under a failed
      `max_cvss`, including ones under the threshold and ones a `cve_ids` exception excused.
      Live: `lodash@4.17.21` with `max_cvss: 7.0` and `cve_ids: [CVE-2021-23337]` printed
      `GHSA-f23m-r3pf-42rh 6.5, GHSA-r5fr-rjxr-66jc 8.1, GHSA-xxjr-mmjv-4gpg 7.9`, and only
      the 7.9 blocked it. It now prints the advisories over the threshold that count, then
      the ones the entry excused.
- [x] The snapshot id hashes the bundle bytes only. The malware-only loader and this one
      stored different rows from the same bundle under the same id,
      `sha256:cf3822e6036d97297ed303a25fd3330eab20d13671495aea49b5c435f0c3392f`.
      The id is now a hash over every source's stored rows (`load::encode`,
      `load::snapshot_id`, `intel_source`). Live: two refreshes of one bundle recorded
      `sha256:225131ada035512e110d0c18f027cb1832a200dfc231df294931e518d36c40b9` and one
      `intel_snapshot` row. See `docs/engineering_decisions/snapshot-identity.md`.
- [x] `[!]` Alias reconciliation. Aliases are matched, and records are not merged.
      `Finding` carries its aliases and `enriched_by` applies an enrichment naming the id or
      any alias, so a KEV entry keyed on a CVE reaches the `GHSA-` record carrying it:
      `a_kev_entry_reaches_an_osv_finding_through_its_alias_and_only_through_it`.
      `intel::is_named` is the one match, also used by `vuln_advisory_ids` exceptions.
      Merging was dropped: 31 groups of stored npm records share ids by aliases, and
      GitHub links a fix bypass to the advisory it bypasses that way, as separate bugs with
      separate fixed versions (lodash `GHSA-xxjr-mmjv-4gpg` and `GHSA-f23m-r3pf-42rh`). One
      vulnerability never fires three rules: `decide` gives each check one result.
      [alias-matching](docs/engineering_decisions/alias-matching.md).
- [x] `[!]` GitHub Advisory stream (GraphQL, token auth), loaded as `github/npm`. OSV and
      GitHub are both **signal streams**: each is checked independently, each records what it holds, and the full set
      is judged once at `Evaluate_Decision_Vector`. Two streams reporting one vulnerability is
      corroboration, which is what `datadog/npm` already does beside `osv/npm`.
      Overlap measured 2026-09-16: 7,056 not-withdrawn npm advisories on GitHub, 7,055 in the
      bundle, 7,053 in both, 3 GitHub only, 2 OSV only. `GHSA-4j66-8f4r-3pjx` is withdrawn on
      GitHub and live in OSV's bundle.
      Live: all 7,056 stored under source `github`, beside 228,330 `osv` and 48,316
      `datadog` rows, and all three advisories OSV lacks are among them.
      [github-advisory-signal-stream](docs/engineering_decisions/github-advisory-signal-stream.md).
      - [x] `UNIQUE (source, publisher_id)` in place of the global unique on `publisher_id`,
            migration 0006. GitHub publishes the same `GHSA-` ids OSV imports, so the second
            stream to load one failed. `PgIntel::replace` already read keys back per source,
            so the migration was the whole change.
      - [x] `Stream` gains a `transport`: GHSA is a POST with `Authorization: bearer` and
            cursor pagination, where `fetch` is one unauthenticated GET. `fetch_graphql`
            concatenates the pages into one JSON array, so `parse: fn(&[u8])` is unchanged
            and `ceiling` bounds the whole array.
      - [x] The token in `src/env.rs` as `env::GITHUB_TOKEN`, with
            `tests/fixtures/cli/help.txt` regenerated. The stream is `Optional`: without a
            token the other three still load and the refresh exits 1.
      - [x] Severity band for the advisories with no CVSS score, through `osv::band_ceiling`,
            so both streams score one advisory alike. GitHub writes `0.0` for an advisory it
            has not scored, which is not a CVSS 0.0.
      - [x] **Exclusive lower bounds.** `Interval.introduced: Option<V>` became
            `start: Start<V>`, `First` / `Introduced(v)` / `After(v)`, mirroring `End`, so an
            excluded bound with no version is unrepresentable rather than refused at runtime.
            `contains` asks `v > from` for `After`. Migration 0007 adds
            `advisory_range.introduced_excluded`, a CHECK that an excluded bound names a
            version, and the column joins the uniqueness index: `>= 1.0.0, < 2.0.0` and
            `> 1.0.0, < 2.0.0` are different intervals.
            Held by `an_excluded_lower_bound_does_not_cover_its_own_version`.
- [x] OSSF Malicious Packages stream (licence-cleared: Apache-2.0). Loaded as `osv/npm`: OSV
      imports the repository, and all 221,217 non-withdrawn `MAL-` records in `npm/all.zip`
      (2026-09-13) give it as `affected[].database_specific.source`, such as
      `https://github.com/ossf/malicious-packages/blob/main/osv/malicious/npm/cxp-jquery/MAL-2021-1.json`.
      The repository's copy of `MAL-2021-1` has the same id, origins and `modified`; OSV adds
      `purl` and `source`. No separate stream. [advisory-stream-licences](docs/engineering_decisions/advisory-stream-licences.md).
- [x] Datadog malicious-packages (licence-cleared: Apache-2.0). Not ingested by OSSF: no
      `MAL-` record lists it as an origin. Every npm manifest entry is loaded as one
      `DATADOG-npm-<name>` malware record, source `datadog`, stream `datadog/npm` (`match`,
      `malware` for npm), beside OSV's records. `waharoa refresh` prints each package Datadog
      flags at every version and OSV's malware records only at some. A failed fetch keeps the
      last Datadog load and exits 1. [datadog-stream](docs/engineering_decisions/datadog-stream.md),
      [advisory-stream-licences](docs/engineering_decisions/advisory-stream-licences.md).
- [x] CISA KEV stream (licence-cleared: CC0 1.0, nothing owed). `enrich`-only, joined on
      exact CVE ID or an alias. Source `cisa/kev` in `exploited_cve`, loaded by `waharoa
      refresh` in the same transaction as OSV; a failed fetch keeps the last KEV load and
      exits 1; kept snapshot files carry the rows as `waharoa intel exploited 1`. Loaded
      2026-09-15: 1,710 CVE ids mark 13 stored npm `GHSA-` records exploited, all 13 scored.
      [kev-stream](docs/engineering_decisions/kev-stream.md).
      - [x] `explain --policy` reads whether `cisa/kev` is loaded from the newest snapshot's
            streams, and `PgIntel::package` from `intel_source`. A refresh records a stream
            for every source it loads, so both agree today. Read one of them for both.
            Sources: `LoadedSnapshot` carries them (`/-/waharoa/ready` too) and
            `exploitation_loaded` reads them for `explain --policy` and `SnapshotIntel`. A
            kept snapshot records no streams. [kev-stream](docs/engineering_decisions/kev-stream.md).
- [x] Withdrawal propagation. A full load replaces every row a source held, so a withdrawn
      or deleted record is gone after the next load (`a_refresh_replaces_what_the_source_held`).
      Every stream loads in full and none loads incrementally, so there is nothing further to
      do. An incremental refresh would have to delete withdrawn ids itself, and gets this item
      back if one is ever built.
      Upstream propagation is a separate matter and is measured: `GHSA-4j66-8f4r-3pjx` is
      withdrawn on GitHub and live in OSV's bundle, which the two streams now show side by
      side.

### Intel storage
- [x] **Decided: sqlx over Postgres, no ORM.**
      `docs/engineering_decisions/storage-sqlx-postgres.md`. SeaORM's stated justification
      was one codebase for two backends and there is one backend; it is built on sqlx, so
      dropping it removes a dependency rather than swapping one.
- [x] `[!]` Lookup path as `sqlx::query_as!`, checked against the real schema at compile
      time. `PgIntel::lookup` and `PgIntel::snapshot` in `src/intel/postgres.rs`.
- [x] `[!]` Migrations as plain `.sql` under `sqlx::migrate!`. `migrations/0001_intel.sql`.
- [x] `[!]` `cargo sqlx prepare` writes `.sqlx/`, checked in, so a contributor builds with
      no database. `make sqlx-prepare` wraps it. `env -u DATABASE_URL cargo build` succeeds.
- [x] `[!]` CI runs `cargo sqlx prepare --check` so the offline cache cannot drift from the
      migrations. A stale cache must be a CI failure, not a runtime surprise.
      `.github/workflows/ci.yml` runs it as the `sqlx` job, beside `make lint` and `make test`.
      Each job is one `make` target, so what CI checks is what a contributor runs.
      `make sqlx-prepare` starts its own Postgres, so the workflow has no `services:` block.
      `sqlx-cli`'s pin moved to `scripts/make/lib/sqlx-cli.sh`, which `dev-setup.sh` and the
      workflow both call, rather than being written a second time in the YAML.
      `make coverage`, `make verify`, `make test-integration`, `make mutants` and `make sast`
      are not gated; [ci-gates](docs/engineering_decisions/ci-gates.md) says why, and says
      what is still unproven until the first push.
- [x] Add sqlx to `Cargo.toml` and run it through `make check-deps`. Held at 0.8, with
      RUSTSEC-2023-0071 ignored only while `rsa` is not compiled:
      `docs/engineering_decisions/sqlx-0-8-and-rsa-advisory.md`.
- [x] `sqlx-cli` goes in `scripts/make/dev-setup.sh`, not an ad-hoc `cargo install`.
      Pinned to 0.8. An installed CLI of another minor is replaced.
- [x] `[!]` Repository trait in front of storage. Justified by test isolation now, not
      portability: the 95% unit floor excludes corpus and live tests, so everything above
      the storage seam has to be testable with no database. `Intel` in `src/intel/store.rs`.
- [x] `[!]` `make test-integration`: start a Postgres container, run the tests that need
      a database, tear it down. Thin wrapper around `scripts/make/test-integration.sh` per
      CLAUDE.md. 9 tests.
- [x] `scripts/make/test-integration.sh` and `scripts/make/sqlx-prepare.sh` wait on
      `pg_isready`, which answers during initdb's temporary server, before the real one
      accepts connections. Both failed on 2026-09-13 with `expected to read 5 bytes, got 0
      bytes at EOF` and passed on rerun. It will be a CI flake.
      Fixed 2026-09-14: both source `scripts/make/lib/postgres.sh`, which runs
      `pg_isready -h 127.0.0.1`. Measured on one container start: the socket check passed at
      643 ms while TCP got `no response`, and TCP passed at 868 ms, after the temporary
      server shut down.
- [x] `the_only_4xx_this_proxy_produces_is_a_policy_refusal` (`src/proxy.rs`) binds a port,
      drops the listener and expects the port to refuse connections. Failed once on
      2026-09-14 while coverage, lint, kani and the integration tests ran at once, and
      passed 3 of 3 alone. Another process can take the freed port. It will be a CI flake.
      Fixed: it and the two other tests that freed a port use
      `test_support::closing_server`, which keeps the port bound and closes each
      connection unanswered.
- [x] `src/intel/postgres.rs` joins the live-test exclusion. Decided 2026-09-16: it speaks to
      a real database and nothing else, its tests are `tests/intel_postgres.rs` under
      `make test-integration`, and CLAUDE.md excludes live tests from the floor. It had grown
      to 290 lines at 0%. `scripts/make/coverage.sh` ignores it for the floor and prints its
      figure beside `main.rs`, so it is visible rather than excluded quietly. The floor reads
      98.30% lines without it.
- [x] `[!]` Tests that do not need a database must not require the container. Without
      `WAHAROA_TEST_DATABASE_URL`, `tests/intel_postgres.rs` returns early from every test.
- [x] `[!]` Bulk refresh via `COPY FROM STDIN` (`PgCopyIn`). CSV rather than binary; see
      `docs/engineering_decisions/osv-malware-load.md`.
- [x] `[!]` Atomic refresh. One source's rows are deleted and copied in one transaction
      rather than a temp-table swap. `a_failed_refresh_leaves_the_previous_load_in_place`,
      mutation-tested.
- [x] `[!]` Cold start fails closed with **503, never 403** + readiness endpoint with %.
      503 is built: a store with no snapshot, or one that errors, answers 503 on both paths.
      `GET /-/waharoa/ready` answers 503 in exactly those cases and reports the snapshot and
      each stream's digest. No percentage: a refresh is one transaction, so there is no
      partial load to measure. See
      [readiness-endpoint](docs/engineering_decisions/readiness-endpoint.md).

### Carried from Stage 1

Findings Stage 1 recorded as notes on completed work, which name the decision layer as
where they get resolved.

- [x] A document that does not normalise is no longer rewritten either, since the
      URLs come from the records. Without records there is nothing to gate on
      anyway, and it is logged `UNINSPECTED`, but it does mean an unmodellable
      document loses artifact visibility as well as metadata.
      Accepted 2026-09-16: this is the behaviour the decision layer wants. Rewriting a
      document the engine cannot read would point artifacts at a proxy that has no records
      to judge them by, which is visibility without enforcement. `UNINSPECTED` is the
      report, and the item below counts how often it fires.
- [x] Forwarding a packument unrewritten now means every artifact for that package
      is fetched wherever the document says, which for pnpm and yarn is not through
      the proxy. Every such path logs `UNINSPECTED`: unreadable client encodings, no
      `Host` and no configured base, over the size cap, undecodable, unnormalizable,
      unserializable, and per-version artifacts on another origin. Stage 1 forwards
      in all of them. **Stage 2 has to decide whether that stays acceptable.**
      Decided 2026-09-16: it stays, and rewriting is not the mechanism that fixes it.
      `enforcement-tiers.md` already records that URL rewriting is turned off once the
      proxy terminates TLS, which is the recommended deployment, so a decision layer
      resting on rewriting would rest on the tier nobody is told to run. Tier 4 and 5 in
      Stage 5 are where an artifact is reached whatever the document says.
      What this stage owes is that a forward is never silent, and it is not: every path
      above logs `UNINSPECTED`, and `doctor` warns on each setting that reduces coverage.

### Deferral status codes

Moved from Stage 1, where the client behaviour was measured but nothing could produce
a deferral: there was no mirror to warm and nothing analysing. See
`docs/engineering_decisions/deferral-status-codes.md`.

503 is the only one of the three this stage could give a cause, and it has one. Everything
that shapes a **429** moved to Stage 4 with the code itself: which code each client is
given, the bounded wait bun needs, the machine-readable reason and digest, and logging
whether a client returned inside the window. None of them can be settled before something
defers.

- [x] `[!]` Implement 503. Carried from Stage 1, where the split was decided (**502**
      upstream unreachable or malformed, **503** we are not ready, **429** this one
      artifact is under analysis) and only 502 could be built: there was no mirror to warm
      and nothing analysing, so implementing either of the others meant inventing the
      trigger. The intel store gave 503 a cause. 429 moved to Stage 4, under the analysis
      cost tier, which is the detector that holds an artifact long enough to defer one.
      - [x] 503 when the intel store holds no snapshot or errors, on the packument and the
            artifact path, with nothing fetched:
            `a_store_that_cannot_answer_is_a_503_on_both_paths_and_nothing_is_fetched`. The
            body is plain text and there is no `Retry-After`.
            [intel-in-decisions](docs/engineering_decisions/intel-in-decisions.md).
### Observability
- [x] `[!]` Ingestion history log for auditing: every time a vulnerability or malware feed is
      ingested, append an entry. Requested 2026-09-15. `intel_ingestion` (migration 0004)
      gets one row per stream per refresh, never updated or pruned: source, stream, bundle
      sha256, etag and `last-modified`, rows digest, snapshot, when, and the error for a
      stream that did not load. Loaded streams are written in the load's transaction; a
      refresh that loaded nothing writes its streams in their own. `waharoa intel history
      [--limit N]` prints them newest first. [ingestion-history](docs/engineering_decisions/ingestion-history.md).
- [x] `[!]` JSON Lines audit log: `src/audit.rs`, `WAHAROA_AUDIT_LOG`. A separate sink,
      not a tracing layer: tracing output is diagnostic and free to change shape, this is
      what `policy diff` parses.
      - [x] **The unit is a request, not a version.** A packument request evaluates every
            version, and typescript has 3,823. A resolution event names the versions it
            removed and the checks that removed them; per-version reasoning is `explain`.
      - [x] **Allowed decisions are recorded too.** A log holding only refusals cannot
            answer "was this ever evaluated", which is what `policy diff` needs a package
            set for.
      - [x] **Unenforceable checks are named**, so an unenforced `cooldown_days` does not
            read as a passed one.
      - [x] **`intel_snapshot` names the snapshot a decision was reached against**, and is
            absent when no store was consulted.
      - [x] Serialised from `Decision`, not from the refusal message, so the record and
            the text the client reads cannot drift.
      - [x] A write failure warns once and never fails an install. Refusing to open at
            startup is different: an operator who asked for a log and silently did not get
            one would believe decisions were being recorded.
- [x] `[!]` `waharoa explain --policy`. Settings as loaded, plus which checks can fire.
      A check that is off and a check with no fact source are different states, and
      reading the file cannot tell them apart.
- [x] `[!]` `waharoa explain <purl>`. The whole decision vector, not the verdict alone:
      a refusal naming only the strongest reason hides that two others fired and that a
      third was never asked. Five states, none collapsed into another: `pass`, `FAIL`,
      `excepted`, `n/a`, `unenforced`.
      - [x] Asks the same engine the proxy does, so explain and a refusal cannot disagree.
      - [x] Fetches from the upstream registry, not through a running proxy. Explain is a
            question about the policy, and needing the proxy up to ask it is the wrong
            dependency.
      - [x] **`Facts::intel` records whether a stream was asked at all.** An empty
            advisory list with `known_malware` false meant two different things: a package
            nothing is known against, or a build with nothing to ask. `explain` showed
            `known_malware`, `kev` and `max_cvss` as `pass` while `explain --policy` said
            they were unenforced. They now report `unenforced` everywhere, the audit log
            included.

**Exit:** a real package blocked for a real reason, with `explain` naming the rule that
fired; npm enforcing against OSV with a real policy file; `explain` correct across every
merge and loosening case in all tiers; policy schema declared frozen.

| Exit clause | State, 2026-09-13 |
|---|---|
| a real package blocked for a real reason, `explain` naming the rule | done: `lodash@4.17.21` refused on `max_cvss`, `--hiljson@0.0.1-security` on `known_malware`, both live |
| npm enforcing against OSV with a real policy file | done: live against the full `npm/all.zip` load |
| `explain` correct across every merge and loosening case | done: `tests/fixtures/explain/decisions.txt`, 22 cases. "Merge" now means global settings and the narrowest matching `packages` entry: there is no per-ecosystem tier |
| policy schema declared frozen | done: `docs/engineering_decisions/policy-schema-v1-frozen.md`, held by `the_version_1_key_set_is_closed` |

**Met, 2026-09-16.** Re-verified live against the store as it stands, four streams and
migrations 0006 and 0007, rather than on the 2026-09-13 table above:

```text
pkg:npm/lodash@4.17.21          max_cvss        FAIL block  over max_cvss 6.9: GHSA-r5fr-rjxr-66jc 8.1, GHSA-xxjr-mmjv-4gpg 7.9
pkg:npm/--hiljson@0.0.1-security known_malware  FAIL block  reported as malware; this has no exception
pkg:npm/vant@2.13.3             known_malware   FAIL block  reported as malware; this has no exception
                                install_scripts FAIL block  declares an install script
```

Every item this stage held is closed or in the stage that can finish it. Nothing was
deleted: what moved says where it went and why, and the receiving item says where it came
from. The four the stage decided rather than built are the two `UNINSPECTED` notes, the
`postgres.rs` coverage exclusion, and withdrawal propagation.

| Moved to | What |
|---|---|
| Stage 3 | `waharoa status`, range resolution and the install-script count that waits on it, not-applicable reaching a proxy path |
| Stage 4 | 429 and everything that shapes one: per-client code, bounded wait, machine-readable reason, deferral logging |
| Stage 5 | local mirrors, query-on-clean, sqlx 0.9, CI lockfile verification, persisting the publish-time store |
| Stage 7 | stream authoring guide |
| Deferred | five items needing a policy surface beyond frozen v1, and NVD |

---

## Stage 3 — Second ecosystem (PyPI)

**Status: open, started 2026-09-16.**

**Goal:** **extract** the adapter interface, using npm and PyPI as the two shapes to
design against. The interface is an output of this stage, not an input. If PyPI forces
changes to the core, that is the finding — make it now, not after five adapters exist.

- [ ] Defer: single binary vs. workspace crates. Splitting later is cheap; not enough
      information yet.
      Moved from Stage 1: this stage extracts the adapter interface, which is when there
      is enough information to judge.
- [ ] Provenance and attestation fetching for PyPI, which has its own metadata shape.
      Carried from Stage 1, which measured the npm side only: npm asks its own registry
      for `/-/npm/v1/keys` and never contacts the host the packument named.
- [~] `[!]` PEP 503 simple-index transport, written concretely first. `src/pypi.rs` reads
      PEP 691 JSON: name normalisation, the index URL, and one project's files with version,
      kind, hash, upload time and yank state. Standalone on purpose, sharing nothing with
      `src/npm.rs`: the interface is an output of this stage.
      [pypi-simple-index](docs/engineering_decisions/pypi-simple-index.md).
      - [x] Read the shape from the live index rather than the PEPs alone, 2026-09-16.
      - [x] Parse checked against nine real projects, 12,164 files, not fixtures alone:
            `examples/pypi_index.rs`.
      - [x] `pypi::Client` fetches one project's index, the same shape as `npm::Client`
            and sharing no code with it: an `http`, a base, a byte ceiling. Verified live
            against nine projects, where records equal versions for every one.
      - [~] Serve `/simple/<name>/` on the proxy. `route::RequestTarget` is the shared
            classification and `pypi::classify_path` produces it, so both ecosystems now say
            what a path refers to in one vocabulary. What is left is the routing itself: the
            proxy holds one `upstream` and one `registry: npm::Client`, and PyPI serves the
            index from `pypi.org` and the files from `files.pythonhosted.org`. Deciding
            whether `WAHAROA_UPSTREAM` becomes per-ecosystem is what blocks it.
      - [ ] HTML fallback for an index that does not serve PEP 691 JSON. PyPI does, and an
            index that answers HTML is refused rather than read as an empty project.
- [ ] `[!]` Extract the adapter interface (transport + normalizer) from the two working
      implementations — refactor, not upfront design
- [ ] `[!]` Reimplement npm and PyPI on the extracted interface, behavior unchanged
- [ ] `[!]` Handle the backtracking resolver's traffic shape (metadata fetched for
      versions never installed — do not treat as install intent)
- [~] `[!]` PyPI normalizer to the common record. `pypi::records` gives one
      `PackageRecord` per version, naming the file a resolver would take. Three of the four
      candidate core changes turned out not to be changes: the sha256 hex converts to SRI
      through `integrity::Algorithm::Sha256`, `PackumentDetail::Full` already means what a
      simple index is, and a yank is an upstream signal rather than a decision here.
      - [x] **The one real divergence: a record holds one artifact and a PyPI version has
            several files.** Closed: `PackageRecord::artifacts` is a `Vec`, `Artifact` gained
            `filename` and `runs_install_scripts`, and `narrowed_to` gives the record for one
            file. Nothing under `src/policy/` reads `artifact`, so the change stopped at the
            normalisers, the store and the proxy's artifact path.
      - [ ] `PackumentDetail::Abbreviated`/`Full` is npm vocabulary, 88 uses. Renaming it
            belongs to the extraction, not here.
      - [x] `Ecosystem::PyPI` exists; `Ecosystem::ALL` still holds npm alone, because that
            is the served set `doctor` and `/-/waharoa/ready` report on.
- [x] `[!]` sdist vs. wheel distinction for install-script semantics. `Kind` and
      `Project::only_sdist` give the version-level answer: a version offering a wheel is not
      an install-script version, and one offering only an sdist leaves a resolver no choice.
      Wired to the `install_scripts` check through `Artifact::runs_install_scripts` and
      `PackageRecord::narrowed_to`, which `proxy::handle` calls before it builds `Facts`. A
      version cleared because it offers a wheel no longer serves its sdist on that basis.
- [ ] pip and uv both verified
- [ ] Ecosystem-namespaced predicates degrade loudly (report N/A, never silent pass).
      Moved from Stage 2's `install_scripts`, where the engine side is built:
      `merge::applies` and its Go test cover not-applicable, and the flow chart carries
      `RECORD_install_scripts_NOT_APPLICABLE` under the golang branch. What is missing is
      an ecosystem with no install step going through the proxy, which this stage adds.
- [ ] `waharoa status`: adapter maturity and intel coverage as separate axes, per
      ecosystem. Moved from Stage 2, which held two items for this, one under the stream
      capabilities and one under observability. Both wanted the same command and neither
      has anything to report with one ecosystem: maturity is a comparison. The intel axis
      is built and read by `doctor` already (`Capabilities::gaps` and `uncovered_by` warn
      when a served ecosystem has no stream providing a capability).
- [ ] **Range resolution, and the install-script count that waits on it.** Three Stage 2
      items, one piece of work, moved here because the normalizer is what this stage
      extracts and a range resolver designed against npm alone is the thing this stage
      exists to prevent.
      - [ ] Range resolution lives in the normalizer, never in the engine. Nothing resolves
            a range today. `dist-tags.latest` is kept as a string and deliberately not
            resolved: the lodash fixture tags `4.18.1` while the document carries only
            `4.17.21`, so a tag can name a version the `versions` map omits.
      - [ ] `versions_with_install_scripts` in the log counts every version in the
            document, not the version being installed. It needs the tarball request
            correlated against the packument records, the same correlation
            `dist.integrity` already does in `src/store.rs`, applied to a second field.
            It cannot answer for the installed version until a range resolves to one.
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
  - [ ] Short circuit in front of expensive analysis, moved from Stage 2's policy engine:
        an expensive detector runs only if the cheap decision vector has not already
        settled the answer. See `docs/engineering_decisions/policy-tier-resolution.md`,
        "Where the short circuit survives".
  - [ ] Implement **429**, moved from Stage 2. The split was decided in Stage 1 (502
        upstream unreachable or malformed, 503 we are not ready, 429 this one artifact is
        under analysis) and 503 landed in Stage 2 on the intel store. 429 had no cause:
        nothing held an artifact long enough to defer one. This tier is that cause, and
        only an expensive detector may produce the retry.
        The unresolved parts are in Stage 2's "Deferral status codes": which code each
        client is given, the bounded internal wait bun needs, the machine-readable reason
        and digest, and logging whether a client returned inside the window.
        See `docs/engineering_decisions/deferral-status-codes.md`.
  - [ ] Per-client code selection inferred from user-agent (already parsed for dialect);
        shipped table of known clients, operator-forceable global override. Keyed on the
        user-agent the proxy sees, which for yarn 4 is
        `got (https://github.com/sindresorhus/got)` and not yarn at all.
  - [ ] Unknown user-agent falls back to **503**, the more widely retried code.
  - [ ] A bounded internal wait is not a fallback but the main mechanism for bun, which no
        code and no `Retry-After` buys any time from.
  - [ ] Machine-readable reason and artifact digest in the response header and body.
        Neither code distinguishes cold-start from per-artifact analysis on its own.
  - [ ] Log every deferral and whether the client returned inside the window, which turns
        the compatibility table into evidence.
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

- [ ] Enforcement tiers 4 and 5, recorded in
      `docs/engineering_decisions/enforcement-tiers.md`. Both are later than tier 3.
      - [ ] A hosts-file or DNS override needs TLS termination, so it is decision #3
            wearing different clothes rather than a separate option. `dist.tarball` is
            always https, so anything intercepting the URL as written needs a CA.
      - [x] **Settled: pre-issued leaf certificates, no CA key on the proxy.** The
            registry domains are known in advance, so certificates for them are issued out
            of band by whatever CA the organisation already has trusted, and only the
            leaves and their keys go on the proxy. A leaf key signs nothing, and
            ordinary chain validation is all any client has to do, so nothing on the
            recommended path rests on an untested assumption.
            See `docs/engineering_decisions/terminating-tls-certificates.md`.
      - [ ] Implement it. Per-ecosystem configuration naming the certificate and key
            files, with the domains read from each certificate's SANs rather than
            configured separately, so the two cannot disagree and startup can report
            exactly which names the proxy answers for. rustls resolves by SNI.
      - [ ] **Report incomplete coverage at startup.** The domains are sets, not one per
            ecosystem: PyPI serves metadata on `pypi.org` and artifacts on
            `files.pythonhosted.org` (verified Sept 2026), and crates.io uses `crates.io`,
            `index.crates.io` and `static.crates.io`. A certificate for the metadata host
            and not the artifact host reproduces the pnpm failure already measured, seeing
            the package and never the bytes.
      - [ ] In this mode artifact URL rewriting is unnecessary and
            `WAHAROA_REWRITE_ARTIFACTS=0` is correct: `dist.tarball` already names a host
            the proxy answers for, so lockfiles keep the origin registry's URLs and the
            `npm ci` failure measured earlier does not arise.
      - [ ] Onramp (Stage 2): mint certificates on the fly from an **unconstrained** CA
            key held by the proxy. Name constraints are not used and no work is done on
            them, so this is what it looks like: a key on the proxy that can sign for any
            name, and a compromise of it impersonates anything to every client trusting
            that CA, browsers included. Documented as the less secure option, which is
            what it is, and the reason pre-issued leaves are the recommended path.
      - [ ] Leaf keys on the proxy are worth what a compromise of them buys: impersonating
            those domains to anything on a machine trusting the CA, browsers included.
            Check file permissions at startup, never log them, and make loading from a
            secrets manager possible rather than requiring files on disk.
      - [ ] Node has three trust stores to satisfy: the OS store, `NODE_EXTRA_CA_CERTS`,
            and npm's `cafile` and `strict-ssl`.
      - [ ] `HTTPS_PROXY` without termination shows a hostname and nothing else: no
            package, no version. Useless for policy, worth having as a signal that
            something is talking to a registry we do not front.
      - [ ] Only tier 5, no direct egress, covers the non-terminal install paths in §7
            (IDE extensions, MCP servers). Tiers 1 to 3 are not in their path at all.

- [ ] Self-detection of bypass: a packument served with no artifact request following it
      is the signature of the pnpm behaviour, and would have caught it without anyone
      looking. Noisy, since a client may already hold the artifact or resolve a version it
      does not install, so a heuristic rather than a check.
      - [ ] A tarball answered 304 is never hashed, because `VerifyingStream` runs over
            a body and a 304 has none. Safe when the client cached those bytes through
            this proxy, which is the only way it holds a copy it did not fetch directly.
            Same family as the item above, one layer down.
      - [ ] A dependency specified as a git or http(s) URL rather than a version range
            is fetched from wherever it names, by every client, and never touches a
            packument at all. That is a different path from `dist.tarball` and the origin
            policy does not see it. Not measured; `make offsite-urls` covers the fields
            inside a packument, not the specifiers in a manifest.
      - [x] yarn 2+ and bun tested. Both added to `make dev-setup` as optional, and to
            `make smoke-clients`, which now covers five clients.
            - [x] **Both use `dist.tarball` as written**, like pnpm and yarn 1. npm is the
                  only one of the five that rewrites, which is the argument for the proxy
                  doing it for all of them rather than per client. yarn 4.9.1 goes
                  further and records the off-registry URL in its lockfile as
                  `__archiveUrl`.
            - [x] **Lockfiles: bun records the proxy address, yarn 4 does not.** yarn 4
                  writes `resolution: "lodash@npm:4.18.1"` with no URL when it matches
                  the configured registry, the way pnpm does, so its lockfiles stay
                  portable. bun writes the full URL into `bun.lock`.
            - [x] **yarn 2+ does not identify itself.** Its user-agent is
                  `got (https://github.com/sindresorhus/got)`, the HTTP library's default.
                  A refusal rule written `npm/yarn` does not match it; its client name is
                  `got`.
            - [x] **Every client has a cache that skips the proxy.** Measured: bun and
                  yarn 4 both installed successfully having asked the proxy for nothing.
                  bun needs `--cache-dir`; yarn 4 needs `globalFolder` and
                  `enableMirror: false`, not just `enableGlobalCache: false`, because it
                  copies out of its global mirror otherwise.
            - [x] yarn 2+ is selected by a project rather than installed, so
                  `make smoke-clients` sets up corepack shims in its own directory and a
                  `packageManager` field, leaving the yarn on PATH alone. It needs node 18
                  or later, since corepack calls `URL.canParse`, and is skipped with that
                  reason on anything older.
            - [ ] yarn 2+ is skipped on this machine, where the default node is 16. It
                  passes under node 24.
- [ ] **The bound caps live memory, and RSS barely moves: 1,501 MB unbounded against
      1,436 MB at 8, and still 882 MB at 1.** Peak RSS is dominated by glibc holding
      freed allocations rather than by what is live. `MALLOC_ARENA_MAX=1` cuts the
      peak to 919 MB and raises the median from 223 MB to 703 MB, so it trades one
      for the other rather than fixing it. The real lever is allocating less per
      packument.
      Superseded in part: that lever was pulled in Stage 1 (artifact URLs
      rewritten by targeted byte replacement rather than a `serde_json::Value` tree),
      which took peak RSS on 24 simultaneous large packuments from 1,436 MB to 472 MB.
      What is left here is whether the remaining retention is worth chasing.
- [ ] The store is per-process and dies with the proxy. It also holds the whole
      `NormalizedPackument`, not just what the fetch path needs, which makes the
      concurrency-memory item worse rather than better. Measured RSS after an
      `express + @babel/code-frame` install holding 70 packuments and 2,576
      records: 25 MB.
- [ ] The publish-time store is per-process too, so every restart re-fetches every full
      packument a cooldown needs. `npm::publish_times` parses only the `time` map and
      caches per package, bounded at 1,024. Moved from Stage 2's `cooldown_days`, where
      the check and the fetch are built and persistence is all that is left. The full
      document is 1.7x to 3.6x the abbreviated one, measured over eight packages, so a
      restart costs that much again on every package a cooldown is asked about.
- [ ] `waharoa doctor` should check that the configured public URL resolves
      and matches what lockfiles in the project record. This is the failure
      an operator will actually hit.
- [ ] CI lockfile verification: every resolved URL in a project's lockfile points at the
      proxy. Moved from Stage 2, where it predated any CI. The parser is built
      (`src/lockfile.rs` reads `resolved` for npm, pnpm, yarn and bun), and this is the
      check a team runs to catch an install that bypassed the proxy. It sits beside the
      doctor item above, which is the same comparison from the other end.
- [ ] **Local mirrors for every stream**, so a refresh does not tell each upstream which
      packages this organisation asks about. Moved from Stage 2: nothing about it is
      needed to make a decision, and it is a deployment property of a team running the
      proxy in blocking mode. Every stream is fetched from its own origin today
      ([intel-distribution-fetch-from-origin](docs/engineering_decisions/intel-distribution-fetch-from-origin.md)).
  - [ ] Query-on-clean live OSV fallback, opt-in, default fail-open, is the same tradeoff
        from the other side: asking OSV about one package leaks that package. It stays
        opt-in and documented, and a mirror is the answer for anyone who cannot accept it.
- [ ] Move to sqlx 0.9 once a kani release bundles rustc 1.94 or later. kani 0.67.0 bundles
      1.93.0-nightly and sqlx 0.9 requires 1.94. Steps are in
      `docs/engineering_decisions/sqlx-0-8-and-rsa-advisory.md`. Moved from Stage 2: it
      waits on an upstream release, and RUSTSEC-2023-0071 is accepted meanwhile only while
      `rsa` is not compiled.

- [ ] `[!]` Analysis cache keyed by **tarball content digest** (install-script presence,
      source diff, capability analysis — permanently valid). Metadata always passes
      through to upstream; no binary caching.
      The key and the hit/miss branch landed in Stage 1 (`src/verified.rs`), which records
      which digests have been fetched and verified. What is left here is the analysis the
      entry carries, and persistence: the Stage 1 cache is per-process and holds a digest
      and nothing else.
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
- [x] Name availability check across npm, PyPI, crates.io, GitHub. Done in Stage 1: all
      four exact-name lookups return 404, with known-existing controls returning 200 in
      the same run.
- [ ] `[!]` **Cultural consultation on the name `waharoa`.** A human conversation, not a
      lookup, and the remaining gate on the name. Moved here from Stage 1 because it
      blocks release rather than development: until then the name appears only in a binary
      nobody outside this repository runs. If the answer is no, the rename is a
      find-and-replace plus the registry check above run again on the new name, so do this
      early enough in the stage that a rename is not competing with the announcement.
      See the plan header.
- [ ] Migration guide from Socket Firewall Free / pkggate
- [ ] CONTRIBUTING.md, adapter authoring guide, detector authoring guide, and a stream
      authoring guide for third-party advisory sources. The last moved from Stage 2: it
      documents `intel::stream::Stream` and the capability grants for someone outside this
      repository, which is a launch concern rather than a decision-layer one.
      [stream-descriptor-table](docs/engineering_decisions/stream-descriptor-table.md)
- [ ] OSV mirror distribution plan (plan §10.6)
- [ ] Announce: OpenSSF slack, HN, relevant ecosystem security channels

---

## Deferred / post-v1

- [ ] **Everything that needs a policy surface beyond schema v1.** Five Stage 2 items with
      one cause: the v1 key set is closed and held by `the_version_1_key_set_is_closed`, so
      none of them can be configured without a v2.
      [policy-schema-v1-frozen](docs/engineering_decisions/policy-schema-v1-frozen.md).
  - [ ] Per-stream enable/disable.
  - [ ] Per-stream refresh scheduling, rate limits and API key config. `waharoa refresh`
        loads every stream in `intel::stream::ALL` on each run and reads one token from the
        environment.
  - [ ] Plugin-declared capabilities, operator-overridable, promotion harder than demotion.
        `intel::capabilities_of` reads the grants this build declares and an operator cannot
        change them.
  - [ ] Configurable severity precedence when streams disagree on CVSS. Today the highest
        score stands, the direction `max_cvss` reads, set in `Facts::with_intel`.
  - [ ] Configurable fail-open/fail-closed on stream unavailability. Closed is built and is
        the default anyone would want; the setting is what is missing.
- [ ] **NVD stream**, three Stage 2 items with one subject. Licence-cleared: public domain,
      nothing owed. `enrich`-only for npm and PyPI, joined on exact CVE id, because NVD is
      keyed by CPE and cannot be asked about a package.
      [nvd-role-and-stream-capabilities](docs/engineering_decisions/nvd-role-and-stream-capabilities.md).
  - [ ] Its enrichment runs as a background job, never on the hot path.
  - [ ] Revisit the `match` capability if and when the Maven adapter is scoped, where CPE
        coverage is stronger.
  - [ ] Deferred rather than staged: `enrich` has no implemented producer, so NVD would be
        the first, and CISA's KEV catalogue already exercises the same seam at lower cost.
- [ ] Go adapter (`GOPROXY`) — low marginal value, checksum DB already covers tamper-evidence
- [ ] Maven adapter (`settings.xml` mirror)
- [ ] **AI agent profiles** — stricter policy for agent-initiated installs
- [ ] Rate limiting on novel package introduction
- [ ] Approval-request flow as an alternative to hard block
- [ ] Rego escape hatch for complex org policies
- [ ] Install-time sandboxing
- [ ] Hosted intel service (only if there is clear demand and it stays optional)
- [ ] **Aikido Intel stream.** Requires a commercial account, so it is not a free public
      feed and cannot be a dependency of the launch. Revisit after launch, when there is a
      running project to approach them about sponsorship with. It was the highest-value
      non-OSV addition in the original list; what replaces it is OSSF's 221,548 npm malware
      records, which are measured rather than claimed.
