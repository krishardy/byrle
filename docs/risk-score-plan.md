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
| no strong digest, no claim | `no_strong_digest` | the threshold |
| not listed | `not_listed` | the threshold |
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
6. The surprise score for a dropped signature or attestation, the first item #42 names:
   P(unsigned) = (weighted unsigned + 1) / (weighted total + 2) over earlier versions,
   newest weighted most, the signal −log2 P. Its half-life and weight measured on Central's
   and npm's histories first. `gradle-versions-plugin` 0.52.0 is the case: refused today
   as `Dropped { previous: 0.11.1 }` after 44 unsigned versions.
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
