# Policy reference

Every key a policy file takes, what each does, and which way it loosens. The reasoning is in
[policy-tier-resolution](engineering_decisions/0023-policy-tier-resolution.md).

The file is YAML, named by `BYRLE_POLICY`. The proxy loads it at startup and again on
`SIGHUP` ([break-glass](break-glass.md)). `byrle policy check <file>` loads it as the proxy
does, and exits 1 if the proxy would refuse it. `byrle policy diff <old> <new>` reports
what a change loosens and tightens. An unknown key, or a value of the wrong kind, refuses the
whole file.

## Example

This file loads:

```yaml
version: 1

cooldown_days: 7
max_cvss: 6.9
install_scripts: block
kev: block
yanked: block
deprecated: allow
provenance: block
provenance_window_days: 7

denials:
  - purl: "pkg:npm/event-stream@3.3.6"
    reason: "flatmap-stream payload, 2018"
  - purl: "pkg:npm/ua-parser-js"
    version: "vers:npm/>=0.7.29|<0.7.30"
    reason: "hijacked releases"

packages:
  - match: { ecosystem: npm, name: "@mycompany/*" }
    set: { cooldown_days: 0 }
    reason: "published by our own CI"
    permanent: true

  - match: { ecosystem: npm, name: esbuild }
    set: { install_scripts: allow }
    reason: "downloads its platform binary on install"
    permanent: true
    added_by: "platform team"

  - match: { ecosystem: maven, name: "org.apache.logging.log4j:log4j-core" }
    set: { install_scripts: allow }
    reason: "declares GraalVmProcessor and PluginProcessor, run by javac"
    permanent: true

  - match: { ecosystem: pypi, name: Django, version: "vers:pypi/>=4.2|<5" }
    set: { ignored_vuln_advisory_ids: ["CVE-2024-0000"] }
    reason: "the affected view is not routed"
    expires: "2026-12-01"

advisory_scores:
  - advisory_id: "GHSA-aaaa-bbbb-cccc"
    cvss: 5.3
    reason: "the vendor advisory scores it 5.3"
    expires: "2026-12-01"

signal_weights:
  near_name: 2
  source_install_files: 3
```

## Settings

One value each for the whole deployment.

| Key | Values | Default | Refuses | Looser is |
|---|---|---|---|---|
| `version` | `1` | required | | |
| `cooldown_days` | a whole number of days | 7 | a version published fewer days ago, with `quarantine` | lower |
| `max_cvss` | a number | 6.9 | a version with an advisory scored above it, or scored by no stream and not in `advisory_scores` | higher |
| `install_scripts` | `block` or `allow` | `block` | a version whose artifact runs an install script; for a crate, a build script or a proc-macro; for a Maven jar, an annotation processor. No meaning for a Go module: a build runs none of its code | `allow` |
| `kev` | `block` or `allow` | `block` | a version with an advisory in CISA's known-exploited catalogue | `allow` |
| `yanked` | `block` or `allow` | `block` | a PyPI file its publisher yanked; npm has no yank, and Go's `retract` is not read | `allow` |
| `deprecated` | `block` or `allow` | `allow` | an npm version its publisher deprecated; PyPI has no marker, and Go's `// Deprecated:` is not read | `allow` |
| `provenance` | `block` or `allow` | `block` | an attestation that does not verify, a version with none after one with one, or a repository and workflow no version from before the window used ([provenance-check](engineering_decisions/0066-provenance-check.md)); for a Maven jar, an `.asc` that does not verify, or none after a version with one ([maven-signatures](engineering_decisions/0113-maven-signatures.md)) | `allow` |
| `provenance_window_days` | a whole number of days | 7 | | a shorter window establishes a new repository or workflow sooner |
| `risk_threshold` | a whole number, 1 or more | 100 | a version whose checks' weights sum to it or more ([every-refusal-a-signal](engineering_decisions/0116-every-refusal-a-signal.md)) | higher, where a check is weighed under it in `signal_weights` |

- **`max_cvss`:** a score at or below it is allowed. A value above 10.0 loads, and allows
  every scored advisory.
- **`block` or `allow`:** these five checks take nothing else. `quarantine` is refused, since
  waiting does not change whether a package has an install script.
- **Known malware:** always refused. It is no setting, and no exception releases it.

## `denials`

Versions refused outright, with `block`. No exception releases a denial.

| Key | Required | Value |
|---|---|---|
| `purl` | yes | the package, with `@version` for one version |
| `version` | when `purl` has no `@version` | a VERS range, such as `vers:npm/>=0.7.29\|<0.7.30` |
| `reason` | yes | why |

A `purl` with neither `@version` nor `version` is refused: a denial names versions.

## `packages`

Exceptions: a setting loosened for the packages a selector matches.

| Key | Required | Value |
|---|---|---|
| `match` | yes | the selector, below |
| `set` | yes | the settings it loosens, below |
| `reason` | yes | why |
| `expires` | one of these two, for any entry that loosens | `YYYY-MM-DD`, at most 90 days ahead (`BYRLE_EXPIRY_CEILING_DAYS`) |
| `permanent` | | `true`, for an exception that does not stop being true |
| `added_by` | no | who added it |

### `match`

| Key | Value |
|---|---|
| `ecosystem` | `npm`, `pypi`, `cargo`, `golang` or `maven`. Required: npm `requests` and PyPI `requests` are different projects. Any other is refused, as it would match nothing |
| `name` | a name, `prefix*`, or `*`. A `*` anywhere else is refused |
| `purl` | the package as a purl, with `@version` for one version. Not with `name` |
| `version` | an exact version, or a VERS range |
| `has_install_scripts` | `true` or `false` |

Names and versions compare the ecosystem's way: a PyPI name by PEP 503, so `Django` is
`django`, and a PyPI version by PEP 440, so `1.0` is `1.0.0`. A Go module path compares as
written, case included, and its purl is `pkg:golang/rsc.io/quote@v1.5.2`. A Go range may
write its versions with or without the `v`: `vers:golang/>=v1.5.0|<v1.6.0` and
`vers:golang/>=1.5.0|<1.6.0` both denied `rsc.io/quote@v1.5.2` on 2026-10-16. A Maven
name is `groupId:artifactId`, and its purl `pkg:maven/org.projectlombok/lombok@1.18.42`.
An exception applies to the plugin portal's versions as to Central's: `make smoke-maven`
released gradle-versions-plugin 0.52.0 from `/gradle-plugins/` with `ecosystem: maven`.

maven-dependency-plugin 3.11.0, which `mvn dependency:resolve` runs, depends on
commons-beanutils 1.9.4, which the default `max_cvss` refused on 2026-10-18 for
GHSA-wxr5-93ph-8wr9. This entry releases that advisory for that version; `byrle policy
check` loaded it:

```yaml
packages:
  - match: { ecosystem: maven, name: "commons-beanutils:commons-beanutils", version: "1.9.4" }
    set: { ignored_vuln_advisory_ids: ["GHSA-wxr5-93ph-8wr9"] }
    reason: "maven-dependency-plugin 3.11.0 depends on it; not called by our builds"
    expires: "2026-12-31"
```

### `set`

| Key | Loosens |
|---|---|
| `cooldown_days` | to a lower number |
| `install_scripts`, `kev`, `yanked`, `deprecated`, `provenance` | to `allow` |
| `ignored_vuln_advisory_ids` | `max_cvss` for the advisories listed, by id or alias. It does not release `kev` |

### Rules

- **Loosen only.** An entry that tightens a setting is refused. A setting stricter for
  everyone goes in the settings, and one stricter for one package goes in `denials`.
- **Say when it stops being true.** An entry that loosens carries `expires` or
  `permanent: true`, not both.
- **Expiry.** An entry past its `expires` date matches nothing.
- **The narrowest entry applies, whole.** When two entries match a package, the one whose
  selector matches a strict subset of the other's applies, and the wider one's `set` does
  not merge in. Two entries that overlap with neither inside the other are refused, and
  so are two identical selectors.
- **Entries that do nothing load.** `byrle policy check` reports an entry that changes
  nothing and one that never wins. `--strict` exits 1 on either.

## `advisory_scores`

Scores for advisories no stream scored, which `max_cvss` refuses until an entry here names
them.

| Key | Required | Value |
|---|---|---|
| `advisory_id` | yes | matched against an advisory's id and each alias |
| `cvss` | yes | 0.0 to 10.0 |
| `reason` | yes | why |
| `expires` or `permanent` | one of them | as for `packages` |
| `added_by` | no | who added it |

The same advisory scored twice is refused.

## `signal_weights`

What each kind of signal adds to a version's risk score. The score is the sum of the weights
of the kinds present, each kind once however often it fires. A version is refused when the
weights of the checks that failed, and of the other signals present, sum to `risk_threshold`. Each check weighs the threshold
unless weighed here, so it refuses alone, as before scores. A lower weight is a loosening,
which `byrle policy diff` reports. A weight on a check its setting turns off, such as
`install_scripts` under `install_scripts: allow`, is refused, as it would never be added.

The other rules' weights add to the same score on a pinned fetch, from the detectors'
results stored by then and the advisories against the version, and the refusal names them
when the checks alone would not have refused. With their defaults they sum to at most 95, so
they refuse only with a check, or with weights the policy raises. A metadata document is
filtered on the checks and the advisories' signals, which are all it can know. The audit line records each rule in its `inputs`, so `byrle
audit verify` weighs them again.

| Key | Signal | Default |
|---|---|---|
| `denied` | a `denials` entry names the version | `risk_threshold` |
| `known_malware` | the intel store reports it as malware | `risk_threshold` |
| `cooldown` | it was published fewer than `cooldown_days` ago. Quarantines rather than blocks when the score needs it | `risk_threshold` |
| `kev` | an advisory against it is in CISA's catalogue | `risk_threshold` |
| `max_cvss` | an advisory against it scores over `max_cvss`, or has no score | `risk_threshold` |
| `install_scripts` | it runs an install script | `risk_threshold` |
| `yanked` | its file was yanked | `risk_threshold` |
| `deprecated` | its publisher deprecated it; weighed only with `deprecated: block` | `risk_threshold` |
| `provenance_unverified` | an attestation or signature failed verification | `risk_threshold` |
| `provenance_dropped` | it has none, after a version with one | `risk_threshold` |
| `provenance_identity_changed` | its attestation names another repository or workflow than the version before it | `risk_threshold` |
| `unservable` | its artifact is on an origin the proxy does not serve, while `BYRLE_REFUSE_UNSERVABLE` is on. Under the threshold, the version stays in the document and its fetch goes on; the proxy never fetches from that origin | `risk_threshold` |
| `no_strong_digest` | no strong digest is published for its artifact. Weighed from [risk-score-plan](risk-score-plan.md) step 5 | `risk_threshold` |
| `digest_mismatch` | its bytes are not the ones its digest or claim names. Weighed from step 5 | `risk_threshold` |
| `signature_failed` | a Maven `.pom` or `.module` whose signature fails. Weighed from step 5 | `risk_threshold` |
| `new_package` | the first version was published under 30 days ago | 1 |
| `new_publisher` | no earlier version was published by this account | 1 |
| `no_repository` | a full npm document names no repository | 1 |
| `near_name` | a package this proxy served has a name one edit away | 1 |
| `source_install_scripts` | install scripts the source lacks or has otherwise | 1 |
| `source_dependencies` | dependencies the source lacks | 1 |
| `source_install_files` | install files the source lacks or has otherwise | 1 |
| `source_differing` | files that differ from the source | 1 |
| `virustotal_detected` | a VirusTotal engine called the artifact malicious or suspicious | 1 |
| `trustpub_dropped` | a cargo version was published without trusted publishing after one published with it | 1 |
| `trustpub_repository_changed` | trusted publishing published a cargo version from another provider or repository than the latest earlier version it published | 1 |
| `signing_key_new` | a Maven version's `.pom` was signed by a primary key that signed no version published 7 or more days before it | 1 |
| `signing_key_expired` | the key, or the subkey, that signed a Maven version's `.pom` had expired when it signed | 1 |
| `advisory_malware` | an advisory reports the version as malware | 8 |
| `advisory_vulnerability` | an advisory reports a vulnerability in it | 4 |
| `advisory_unsound` | RustSec reports unsound code in it | 3 |
| `advisory_unmaintained` | RustSec reports the crate unmaintained | 2 |
| `advisory_notice` | RustSec published a notice about it, or a kind this build does not know | 1 |

`unservable`, `no_strong_digest`, `digest_mismatch` and `signature_failed` are the proxy's
own refusals. Observe mode still refuses a version when they weigh the threshold alone; a
version the metadata does not list is refused whatever is weighed.

The keys above are the rules of the policy's checks, of the proxy's refusals, of the five detectors built in,
`metadata`, `source`, `virustotal`, `trustpub` and `signing`, and of the advisories the
intel store holds, which are named without the detector. An unsound, unmaintained or notice advisory refuses
nothing: it is a signal only. A vulnerability or malware advisory is also refused by
`max_cvss` or `known_malware`. Another detector's rule is weighed as `detector.rule`, such
as `guarddog.threat-process-hooks: 3`, 1 unless set. A rule the detector does not have is refused, as an unknown key is. The rules
are in [detectors](engineering_decisions/0092-detectors.md).

Each weight is a whole number, 0 or more. The signals are in
[metadata-heuristics](engineering_decisions/0090-metadata-heuristics.md),
[source-diff](engineering_decisions/0091-source-diff.md) and
[virustotal](engineering_decisions/0104-virustotal.md).

## Actions

A decision is `allow`, `quarantine` or `block`, in that order of strictness.
`quarantine` comes only from `cooldown_days` and lapses as the version ages. A version
refused either way is removed from the metadata document, and a pinned fetch of it is
refused ([quarantine-filter-metadata](engineering_decisions/0013-quarantine-filter-metadata.md)).
