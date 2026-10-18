# Plan: every refusal a weighted signal (TODO.md ad-hoc #42)

Today a version is refused when any one check fails, and the signals the detectors and the
intel store report sum to a `risk_score` that no verdict reads. After this plan, every
reason the proxy refuses is a signal with a weight, the weights of the signals present sum
to the risk score, and a version is refused when its score reaches the policy's
`risk_threshold`. Written 2026-10-18 from the code at `4036db4`.

## Decisions

Decided by the user 2026-10-18:

| Question | Answer |
|---|---|
| Which refusals become signals | All of them: the policy checks, the metadata filters' removals, and the proxy's own refusals, the integrity cases included |
| How a version is refused | One `risk_threshold`: the sum of the weights of the signals present, refused at or over it |
| Known malware and `denials` | Signals whose default weight is the threshold, so each refuses alone unless the policy lowers its weight |
| Schema | `version: 1` is changed, as for ad-hoc #37, and [policy-schema-v1-frozen](engineering_decisions/0030-policy-schema-v1-frozen.md) amended |

## Where the proxy refuses today

Read from the code on 2026-10-18. Observe mode (`BYRLE_MODE=observe`) serves only group
A's refusals, and removes nothing in group B; it refuses everything in group C, which
`observe_mode_still_refuses_what_cannot_be_assessed` (`src/proxy.rs:5996`) asserts.

### A. The policy's checks: `policy::decide::run` (`src/policy/decide.rs:349`)

Applied to a pinned fetch by `enforce::artifact` (`src/policy/enforce.rs:185`), called from
`Deciding::refusal` (`src/proxy.rs:1812`). A check that cannot be answered, such as a
cooldown with no publish date, is dropped by `enforced` (`enforce.rs:172`), not failed.

| Check | Fails on | Action | Exception |
|---|---|---|---|
| `denials` | a `denials` selector matches | Block | none |
| `known_malware` | the intel store says so | Block | none |
| `cooldown_days` | published fewer days ago | Quarantine, which lapses | `set: { cooldown_days }` |
| `kev` | an advisory in CISA's catalogue | `kev`'s | `set: { kev: allow }` |
| `max_cvss` | an advisory scored over it, or not scored | Block | `ignored_vuln_advisory_ids`, `advisory_scores` |
| `install_scripts` | an install script; a crate's build script or proc-macro; a jar's annotation processor; an archive unreadable or over the spool's ceiling | `install_scripts`' | `set: { install_scripts: allow }` |
| `yanked` | a PyPI file or crate yanked | `yanked`'s | `set: { yanked: allow }` |
| `deprecated` | an npm version deprecated | `deprecated`'s, `allow` by default | `set: { deprecated: allow }` |
| `provenance` | `Unverified`, `Dropped`, `IdentityChanged`; an attestation URL on a refused origin is `Unverified` (`proxy.rs:2574`) | `provenance`'s | `set: { provenance: allow }` |

### B. The metadata filters

`policy_refused_versions` (`src/proxy.rs:4223`) runs group A on every version a document
lists, from what the document says, and each ecosystem removes what it refuses:

| Ecosystem | Removed | Where |
|---|---|---|
| npm | the version from `versions`, a `dist-tags` entry naming it; a version whose tarball is on an origin the proxy does not serve | `npm/rewrite.rs:110`, `:118` |
| PyPI | every file of the version | `pypi/rewrite.rs:118` |
| cargo | its index line | `cargo/inspect.rs:40` |
| Go | its `@v/list` line; `@latest` naming only refused versions is 404 | `go/inspect.rs:61`, `:90` |
| Maven | its `<version>`; `<latest>` and `<release>` moved to the highest left | `maven/inspect.rs:57`, `maven/wire.rs:199` |

### C. The proxy's own refusals, which no policy key controls

| Refusal | Answer | Where | Audited as |
|---|---|---|---|
| no strong digest published: none, SHA-1 only for npm and PyPI, a Go version sum.golang.org holds no record of, a Maven file with no sidecar | refusal status | `proxy.rs:2169` | `no-strong-digest` |
| a Go `.mod` or Maven `.pom` or `.module` with no claim | refusal status | `proxy.rs:3259` | |
| the metadata lists neither the version nor the file | refusal status | `proxy.rs:1865` | `not-listed` |
| the artifact is on an origin the proxy does not serve | refusal status, unless `BYRLE_REFUSE_UNSERVABLE=0` | `proxy.rs:2243` | `unservable` |
| the claim job's bytes are not the claim's | 502 | `proxy.rs:2268` | `upstream-mismatch` |
| the analysis fetch's bytes do not match the digest | 502 | `proxy.rs:2289` | `upstream-mismatch` |
| the served bytes do not match the digest | 200, its last chunk held back | `proxy.rs:763` | `cut-short` |
| a Maven `.pom` or `.module` whose signature fails, or whose bytes are not the claim's | 502 | `proxy.rs:3298`, `:3445` | |

## Design

Every refusal above becomes a signal under the detector `policy` or `proxy`, weighed by
`signal_weights` as the detectors' and the advisories' are. `decide` returns the signals
present and their score; the verdict is a refusal when the score reaches
`risk_threshold`.

| Today | Signal | Default weight |
|---|---|---|
| a denial | `denied` | the threshold |
| known malware | `known_malware` | the threshold |
| inside the cooldown | `cooldown` | the threshold, while inside it |
| KEV | `kev` | the threshold when `kev: block`, 0 when `allow` |
| over `max_cvss` | `max_cvss` | the threshold |
| install scripts | `install_scripts` | as `kev` |
| yanked | `yanked` | as `kev` |
| deprecated | `deprecated` | as `kev`, so 0 by default |
| provenance contradicted | `provenance_unverified`, `provenance_dropped`, `provenance_identity_changed` | as `kev` |
| no strong digest, no claim | `no_strong_digest` | the threshold; 0 since 2026-10-18 |
| origin not served | `unservable` | the threshold, 0 with `BYRLE_REFUSE_UNSERVABLE=0` |
| bytes not as claimed or digested | `digest_mismatch` | the threshold |
| a `.pom` or `.module` signature that fails | `signature_failed` | the threshold |

- **Defaults refuse what they refuse today.** Every former Block, Quarantine and
  integrity refusal weighs the threshold, so with an unedited policy no version is served
  that is refused today, and none refused that is served. Each step is checked against
  that: the explain golden files, `byrle audit verify` over the smoke runs' audit logs, and
  the five smoke tests, each unchanged.
- **Version 1 keeps its meaning.** `install_scripts: block` reads as the
  `install_scripts` signal weighing the threshold and `allow` as 0, and the same for `kev`,
  `yanked`, `deprecated` and `provenance`. A `packages` entry's `set: { x: allow }` sets
  that signal's weight to 0 for the versions it matches, and `cooldown_days` the window the
  `cooldown` signal is present in. `risk_threshold` is added at the top level, and the new
  rules to `signal_weights`.
- **The threshold is over what today's signals can sum to.** Signals already sum with no
  effect: `advisory_malware` 8, `advisory_vulnerability` 4, each detector rule 1. Once a
  threshold refuses, a sum of those could refuse a version served today, so step 2 sets
  the default over the most they can sum to: 100.
- **Where each signal is known.** A metadata filter scores only what the document says:
  denials, malware, cooldown, advisories, yanked, deprecated, and install scripts the
  metadata declares. Detectors, install scripts read from the archive, and every group C
  signal are known only at the pinned fetch. So a version can be listed and its pinned
  fetch refused, as today.
- **Verdicts stay reproducible.** [reproducible-verdicts](engineering_decisions/0070-reproducible-verdicts.md)
  has `byrle audit verify` decide each pinned line again from `Inputs`. Today the signals
  are written beside it (`audit.rs:469`), not in it. Once they decide the verdict, the
  signals present and the weights they were scored with go into `Inputs`.
- **Loosening stays visible.** `policy diff` and `policy check` report a higher
  `risk_threshold`, or a lower weight, as a loosening, and policy-reference's "looser is"
  column has a row for each.

## Steps

1. An engineering decision for the four answers above, superseding the refusal half of
   [policy-tier-resolution](engineering_decisions/0023-policy-tier-resolution.md), and 0030
   amended.
   Done 2026-10-18: [every-refusal-a-signal](engineering_decisions/0116-every-refusal-a-signal.md),
   with 0023's status and 0030 amended.
2. Measure the threshold: the highest `risk_score` over the audit logs of `make
   smoke-npm`, `smoke-python`, `smoke-cargo`, `smoke-go` and `smoke-maven`, and over the
   npm corpus run through `explain`.
   Done 2026-10-18, from the rules instead of the corpus. A rule counts once however often
   it fires, so a version's score from today's signals is at most the sum of every rule's
   default weight:

   | Detector | Rules | Weight | Most |
   |---|---|---|---|
   | metadata | 4 | 1 | 4 |
   | source | 4 | 1 | 4 |
   | virustotal | 1 | 1 | 1 |
   | trustpub | 2 | 1 | 2 |
   | signing | 2 | 1 | 2 |
   | advisory | 5 | 8, 4, 3, 2, 1 | 18 |
   | guarddog, when configured | 64 | 1 | 64 |
   | every one | 82 | | 95 |

   The five smoke runs, each with `BYRLE_AUDIT_LOG` set, wrote 790 lines; 36 carried a
   `risk_score`. The highest was 8, `clinstestpackage`'s `advisory_malware`, refused as
   known malware; the highest of a version served was 4, one `advisory_vulnerability`, for
   rustls 0.23.45, commons-lang3 and commons-text. So `risk_threshold` defaults to 100,
   over the 95 any version can score from today's signals: a policy that sets no weight
   refuses no version on them.
3. `decide` returns signals and a score, group A as signals, the verdict from the
   threshold. `explain`, the audit line's `Inputs` and `audit verify` read it. Defaults
   unchanged, checked as above.
   In three parts:
   1. The checks scored against the threshold, each weighing it. Done 2026-10-18,
      `4ac8570`: every test passed unchanged, and the five smoke runs' 261 audit outcomes
      were the same. `make mutants`: 23 mutants, 18 caught, 3 unviable, 2 timed out on
      the threshold's comparison, which the boundary test also fails.
   2. `risk_threshold` and the checks' rules in `signal_weights`. Done 2026-10-18: a
      check weighs its `signal_weights` entry, else the threshold; a weight on a check its
      setting turns off is refused, as is a threshold of 0. `policy diff` reports a moved
      score or threshold, and a weaker verdict as a loosening. The five smoke runs' audit
      outcomes were the same.
   3. The detectors' and advisories' signals in the pinned verdict, after analysis, and
      the signals and weights in `Inputs`. Done 2026-10-18: a pinned fetch reads the intel,
      builds the signals from the detectors' stored results and the advisories, and
      decides on their weights with the checks'. A refusal names the signals when the
      checks alone were under the threshold. The audit line records their rules in
      `inputs.signals`, and `audit verify` weighs them again; a line written before reads
      as having none. `explain`'s verdict includes the signals it lists, and shows the
      score against the threshold.
4. The metadata filters refuse by the score of what each document says.
   Done 2026-10-18: each version a document lists is decided on its checks and the signals
   of the advisories the intel store holds against it. The detectors' signals are known
   only once the version's artifact is analysed, so a document is filtered without them.
5. Group C as signals, each answered as below when its weight is under the threshold.
   One commit per signal:
   1. `unservable`. Done 2026-10-18: the rules of the proxy's refusals are built in and
      weigh the threshold. A pinned fetch decides twice: on the checks and signals, as
      before, and with the proxy's signals added. When the proxy's weigh the threshold
      alone, the refusal answers as it did; when only the sum does, it is refused in the
      policy's words with the signals named; else it is passed over. Observe mode refuses
      only the first. npm's document removes a version on an origin the proxy does not
      serve only when `unservable` weighs the threshold alone. With
      `BYRLE_REFUSE_UNSERVABLE=0` the signal is not raised at all.
   2. `no_strong_digest`. Done 2026-10-18: raised for an artifact with no strong digest
      and no claim being checked. Under the threshold, its bytes are forwarded unverified,
      and `install_scripts` is dropped as not analysed. A proxy refusal answers in its own
      words only when its rule weighs the threshold alone; one reached by a sum is refused
      in the policy's words, naming the rules. An audit line answered `no-strong-digest`
      records `block` where it recorded `allow`, as the signal now weighs in its decision.
      The user set its default weight to 0 on 2026-10-18: by default such an artifact is
      forwarded unverified and unanalysed, logged at WARN, and its audit line records
      `allow`.
   3. `digest_mismatch`. Done 2026-10-18: raised when a claim job's bytes are not the
      claim's or the analysis fetch's bytes do not match the digest. Under the threshold,
      the first is fetched unverified and the second served. The decision also says whether
      a mismatch found while the body streams would be tolerated, `digest_mismatch` added
      to the rest staying under the threshold; a tolerated one releases the held chunk, is
      logged, and is never recorded as verified.
   4. The manifests, a Go `.mod` and a Maven `.pom` and `.module`, which no check decides.
      Done 2026-10-18: each is refused only when its rule weighs the threshold alone. With
      no claim (`no_strong_digest`) it is forwarded unverified; with bytes the claim does
      not describe (`digest_mismatch`) forwarded as they came, not logged as verified; with
      a signature that fails (`signature_failed`) served against the digest its bytes
      matched.
6. The surprise score for a dropped signature or attestation, the first item #42 names:
   P(unsigned) = (weighted unsigned + 1) / (weighted total + 2) over earlier versions,
   newest weighted most, the signal −log2 P. Its half-life and weight measured on Central's
   and npm's histories first. `gradle-versions-plugin` 0.52.0 is the case: refused today
   as `Dropped { previous: 0.11.1 }` after 44 unsigned versions.

   Measured 2026-10-18 on 57 npm packages' full documents, 63,423 versions, and
   gradle-versions-plugin's 58 on the Gradle plugin portal. A version's history is the
   versions published before it in its release line: the same major, or `0.minor`, and
   both stable or both prerelease. Over all versions instead, the 22 legitimate drops in nx
   score as high as its malicious versions: a backport to an older major, such as next
   12.3.5 after 15.3.0 canaries, is unsigned after a run of signed versions on the current
   one. The most a version can score is log2(1.44h + 2) bits, its whole history signed.

   | Half-life h, versions | Most bits | Legitimate stable drops: highest | Prerelease drops ≥ 4 bits | Malicious, signed history before |
   |---|---|---|---|---|
   | 8 | 3.76 | 3.76, @swc/core 1.5.19 | 0 of 457 | nx 3.70 to 3.79, @rspack/core 3.62, axios 2.72 |
   | 16 | 4.65 | 3.48, @swc/core 1.5.19 | 5 of 457 | nx 4.22 to 4.49, @rspack/core 4.04, axios 2.30 |
   | 32 | 5.59 | 3.47, vitest 3.1.0 | 12 of 457 | nx 4.54 to 4.99, @rspack/core 4.30, axios 1.83 |

   Against today's `provenance_dropped`, counted as any attested version before it, with
   the surprise at h = 16 weighed 25 per bit, so 4 bits reach 100:

   | Refused | Today | 25 per bit, h = 16 |
   |---|---|---|
   | legitimate stable versions | 294 | 0 |
   | legitimate prereleases | 581 | 5 |
   | nx and @nx/devkit, 2025-08-26 and 27 | all 10 | all 10, 105 to 112 |
   | @rspack/core 1.1.7, 2024-12-19 | yes | yes, 101 |
   | axios 1.14.1 and 0.30.4, 2026-03-31 | both | neither: 58 and 0 |
   | eslint-config-prettier 8.10.1, 9.1.1, 10.1.6, 10.1.7, 2025-07-18 | all 4 | none: 0, 0, 12, 12 |
   | @solana/web3.js 1.95.6 and 1.95.7, @ctrl/tinycolor 4.1.1 and 4.1.2, @duckdb/node-api 1.3.3 | none, no version before was attested | none |
   | gradle-versions-plugin 0.52.0 | yes | no, 4 |

   axios 1.14.1 followed signed 1.14.0, but its line has one legitimate drop, 1.13.3, four
   versions before, which raises P(unsigned). axios 0.30.4 and eslint-config-prettier
   8.10.1 and 9.1.1 had no attested version in their own line; 10.1.6 and 10.1.7 followed
   the package's first two attested versions, 10.1.4 and 10.1.5.

   Central gives nothing to calibrate against: of eight artifacts' 1,243 versions
   (commons-lang3, guava, slf4j-api, jackson-databind, okhttp, kotlin-stdlib, netty-handler,
   junit), every version after each one's first signed version has a `.pom.asc`, except
   kotlin-stdlib 1.5.10 to 1.5.30-RC, seven versions.

   Decided by the user 2026-10-18: the surprise sits beside `provenance_dropped`, which
   weighs 50 by default; the half-life is a policy key. In parts:
   1. `provenance_surprise`, weighed per bit, 25 by default, and `provenance_half_life`,
      16 by default, in version 1. `Provenance::Dropped` carries its line's history: the
      versions published before it in its release line, newest first, at most 64 of them,
      each attested or not. The line and whether a
      version is a prerelease come from the ecosystem's `VersionOrder`: the first number of
      the version, or `0.` and the second when the first is 0; a prerelease orders below
      its numeric prefix. The provenance check, failed as dropped, weighs
      `provenance_dropped` plus `provenance_surprise` times the bits, and the audit line's
      facts record the history. npm and PyPI, from the document.
   2. Maven: once an earlier version was signed, the signer asks the `.asc` of those of
      the `BYRLE_PROVENANCE_HISTORY` versions before it in its line, at most 64, eight at a
      time, and `Signature::Dropped` stores the history. A row
      stored before it is asked again, not read as no history.
   3. smoke-maven without its gradle-versions-plugin exception.
7. Docs: policy-reference, request-flow, threat-model, quickstart §4, the README.

Raised beside this plan, and not part of it: the PyPI index keeps a version whose files are
on an origin the proxy does not serve (`pypi/mod.rs:165` passes no `refuse_unservable`),
and Go's `@latest` is 404 for a module with no versions at all (`go/inspect.rs:90`).

## Answered 2026-10-18

| Q | Question | Answer |
|---|---|---|
| Q1 | Observe mode serves what the policy refuses and never what cannot be assessed. Under one score, does it serve a version whose score reaches the threshold on group C signals? | No. Observe mode serves a version over the threshold only when its group C signals alone weigh under it |
| Q2 | A group C signal weighed under the threshold by the policy: what is served? | Each serves what it can. Origin not served: the client fetches it directly, as `BYRLE_REFUSE_UNSERVABLE=0` does today, and the proxy never fetches from an origin it does not serve. No strong digest: served unanalysed, so install scripts and the detectors have no answer. Bytes not as digested: the held last chunk is released. Not listed: refused whatever its weight, as there is no record to fetch it by |
| Q3 | Lowering `known_malware`'s or `denied`'s weight under the threshold | Loads as any weight does; `policy diff` and `policy check` report it as a loosening |
