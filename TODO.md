# waharoa — Staged TODO

Stages are sequential. Each has an exit criterion; do not start the next stage until it
is met. Within a stage, `[!]` marks items that block the exit criterion.

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocks stage exit

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
   RUSTSEC-2026-0249 (see below) and cargo-outdated reports `toml 1.1.5 -> 1.1.6` in the
   spike crate, reported without failing, as designed.
   Open question: the spike's `Cargo.lock` is frozen evidence of what the config-format
   spike actually tested, so updating it to silence that report would damage the record.
   Decide whether the spike should be exempt from the freshness half.
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
7. In the policy file sample, npm install_scripts setting would be set per package, not set for the entire ecosystem.

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
- [ ] **Watch: `purl` 0.1.6 pulls `smartstring` 1.0.1, flagged RUSTSEC-2026-0249 as
      unmaintained.** Found by `make check-deps`. Not a vulnerability, and it does not
      reverse the crate choice: `packageurl` is disqualified on correctness, which is the
      worse failure. But it is why `make check-deps` is not clean under
      `CHECK_DEPS_STRICT=1` today. Revisit if it becomes a real advisory; the swap path
      is the same one-line change described under the identity item.
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
      - [ ] Make the npm/yarn/pnpm packument tarbar url rewrite behaviour a feature flag.
      - [ ] `versions_with_install_scripts` in the log counts every version in the
            document, not the version being installed. Stage 2 needs the resolved
            version's answer, which needs the tarball request correlated against the
            packument records. Same correlation as the `dist.integrity` item.
      - [ ] Range resolution still lives nowhere. `dist-tags.latest` is kept as a string
            and deliberately not resolved: the lodash fixture tags `4.18.1` while the
            document carries only `4.17.21`, so a tag can name a version the `versions`
            map omits. See the Stage 2 item.
- [x] Unit test coverage tooling, for the CLAUDE.md 90% floor. `make coverage` runs
      cargo-llvm-cov with `--fail-under-lines/-functions/-regions 90`; `COVERAGE_FLOOR`
      overrides it. The crate is at 95.5% lines, 94.7% regions, 94.2% functions.
      - [x] The network and corpus tests are compiled out under `cfg(coverage)`, which
            cargo-llvm-cov sets. They do not run in a coverage build, and counting the
            body of a test that cannot run reports a gap that is not one. `cargo test`
            still lists them as ignored, so gating them changed nothing about the suite.
      - [x] `PackageKey::from_registry_name` had an unreachable error arm for an empty
            bare name: the leading empty check and the empty-`rest` check in the scoped
            arm already cover it. Now a `debug_assert!`, because a branch no input can
            reach looks like a hole in the tests forever.
      - [x] **`src/main.rs` was at 0% over 128 lines, and the floor excluded it.** The
            proxy moved into `src/proxy.rs` in the library, leaving 53 lines of startup
            in the binary, so the floor now covers the whole crate with no carve-out.
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
- [ ] `[!]` **A warm npm cache sends `If-None-Match` and the registry answers 304 with
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
            packument when there is no record. What remains is the packument request
            itself: a 304 means the proxy does not observe the document the client is
            about to resolve against, so Stage 2 metadata rules still have nothing to
            read at that moment.
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
      - [ ] **The bound caps live memory, and RSS barely moves: 1,501 MB unbounded against
            1,436 MB at 8, and still 882 MB at 1.** Peak RSS is dominated by glibc holding
            freed allocations rather than by what is live. `MALLOC_ARENA_MAX=1` cuts the
            peak to 919 MB and raises the median from 223 MB to 703 MB, so it trades one
            for the other rather than fixing it. The real lever is allocating less per
            packument, below.
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
      - [ ] A document that does not normalise is no longer rewritten either, since the
            URLs come from the records. Without records there is nothing to gate on
            anyway, and it is logged `UNINSPECTED`, but it does mean an unmodellable
            document loses artifact visibility as well as metadata.
- [ ] Packument size on the proxy's own fetches: `npm::Client` sends no `Accept-Encoding`
      because reqwest's `gzip` feature is off crate-wide, so those packuments arrive
      uncompressed. The request path does not have this problem, since the proxy decodes
      gzip itself. Revisit with the fetch path.
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
- [x] **Testing strategy: HTTP-level fixtures.** Decided by doing. Real registry
      responses, trimmed to one version, live in `tests/fixtures/npm/` with a README
      explaining what property each one covers and how to refresh them. Both the
      abbreviated and full document are kept per package, because the difference between
      them is exactly what the record schema had to model. This pairs with the two
      corpus-scale checks already in place, `make smoke-npm` against a real npm client
      and `cargo run --example osv_conformance` against OSV's full npm bundle.
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
      - [ ] The store is per-process and dies with the proxy. It also holds the whole
            `NormalizedPackument`, not just what the fetch path needs, which makes the
            concurrency-memory item worse rather than better. Measured RSS after an
            `express + @babel/code-frame` install holding 70 packuments and 2,576
            records: 25 MB.
- [ ] `[!]` Cache hit, stream through. Nothing is analysed yet, so there is no cache to
      hit; the digest that would key it is now known before the fetch.
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
      - [ ] Recheck that per client and per ecosystem. It is pacote's behaviour, not
            protocol, and pnpm, yarn and PyPI are untested.
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
            - [ ] `waharoa doctor` should check that the configured public URL resolves
                  and matches what lockfiles in the project record. This is the failure
                  an operator will actually hit.
            - [x] `make smoke-clients` asserts every client fetches and verifies
                  artifacts. Checked that it bites with `WAHAROA_REWRITE_ARTIFACTS=0`.
      - [ ] Forwarding a packument unrewritten now means every artifact for that package
            is fetched wherever the document says, which for pnpm and yarn is not through
            the proxy. Every such path logs `UNINSPECTED`: unreadable client encodings, no
            `Host` and no configured base, over the size cap, undecodable, unnormalizable,
            unserializable, and per-version artifacts on another origin. Stage 1 forwards
            in all of them. **Stage 2 has to decide whether that stays acceptable**, since
            the fail-open default is now weaker than it was.
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
- [ ] Enforcement tiers 4 and 5, recorded in
      `docs/engineering_decisions/enforcement-tiers.md`. Both are later than tier 3.
      - [ ] A hosts-file or DNS override needs TLS termination, so it is decision #3
            wearing different clothes rather than a separate option. `dist.tarball` is
            always https, so anything intercepting the URL as written needs a CA.
      - [x] **Settled: pre-issued leaf certificates, no CA key on the proxy.** The
            registry domains are known in advance, so certificates for them are issued out
            of band by whatever CA the organisation already has trusted, and only the
            leaves and their keys go on the proxy. Better than a name-constrained CA on
            two counts: a leaf key signs nothing, and ordinary chain validation needs no
            name-constraint support from the verifier, so the assumption that needed
            testing leaves the recommended path.
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
      - [ ] `[!]` Onramp: mint certificates on the fly from a CA key held by the proxy.
            Less secure, and the only place name constraints matter, which is where an
            assumption that has to be tested belongs. **Verify name-constraint support
            before shipping this**: OpenSSL and NSS honour them, macOS and Windows have
            historically been inconsistent.
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
      - [ ] yarn 2+ (berry) and bun are untested. yarn 1.22.22 is what is installed here.
- [ ] Confirm npm cache bypass behavior; `npm cache clean --force` needed on onboarding
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
      - [ ] Not checked yet: whether the proxy is reachable and answering. Doctor is
            client-side only, so it reports what is configured rather than what works.
- [ ] Confirm npm cache bypass behavior; `npm cache clean --force` needed on onboarding

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
