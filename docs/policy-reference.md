# Policy reference

Every key a policy file takes, what each does, and which way it loosens. The reasoning is in
[policy-tier-resolution](engineering_decisions/policy-tier-resolution.md).

The file is YAML, named by `WAHAROA_POLICY`. The proxy loads it at startup and again on
`SIGHUP` ([break-glass](break-glass.md)). `waharoa policy check <file>` loads it as the proxy
does, and exits 1 if the proxy would refuse it. `waharoa policy diff <old> <new>` reports
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

  - match: { ecosystem: pypi, name: Django, version: "vers:pypi/>=4.2|<5" }
    set: { vuln_advisory_ids: ["CVE-2024-0000"] }
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
| `install_scripts` | `block` or `allow` | `block` | a version whose artifact runs an install script | `allow` |
| `kev` | `block` or `allow` | `block` | a version with an advisory in CISA's known-exploited catalogue | `allow` |
| `yanked` | `block` or `allow` | `block` | a PyPI file its publisher yanked; npm has no yank | `allow` |
| `deprecated` | `block` or `allow` | `allow` | an npm version its publisher deprecated; PyPI has no marker | `allow` |
| `provenance` | `block` or `allow` | `block` | an attestation that does not verify, a version with none after one with one, or a changed repository or workflow ([provenance-check](engineering_decisions/provenance-check.md)) | `allow` |
| `provenance_window_days` | a whole number of days | 7 | | a shorter window compares fewer earlier versions |

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
| `expires` | one of these two, for any entry that loosens | `YYYY-MM-DD`, at most 90 days ahead (`WAHAROA_EXPIRY_CEILING_DAYS`) |
| `permanent` | | `true`, for an exception that does not stop being true |
| `added_by` | no | who added it |

### `match`

| Key | Value |
|---|---|
| `ecosystem` | `npm` or `pypi`. Required: npm `requests` and PyPI `requests` are different projects |
| `name` | a name, `prefix*`, or `*`. A `*` anywhere else is refused |
| `purl` | the package as a purl, with `@version` for one version. Not with `name` |
| `version` | an exact version, or a VERS range |
| `has_install_scripts` | `true` or `false` |

Names and versions compare the ecosystem's way: a PyPI name by PEP 503, so `Django` is
`django`, and a PyPI version by PEP 440, so `1.0` is `1.0.0`.

### `set`

| Key | Loosens |
|---|---|
| `cooldown_days` | to a lower number |
| `install_scripts`, `kev`, `yanked`, `deprecated`, `provenance` | to `allow` |
| `vuln_advisory_ids` | `max_cvss` for the advisories listed, by id or alias. It does not release `kev` |

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
- **Entries that do nothing load.** `waharoa policy check` reports an entry that changes
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
of the kinds present, each kind once however often it fires. It is logged, written to the
audit line as `risk_score`, and printed by `explain`. No verdict reads it, so a weight loosens
and tightens nothing.

| Key | Signal | Default |
|---|---|---|
| `new_package` | the first version was published under 30 days ago | 1 |
| `new_publisher` | no earlier version was published by this account | 1 |
| `no_repository` | a full npm document names no repository | 1 |
| `near_name` | a package this proxy served has a name one edit away | 1 |
| `source_install_scripts` | install scripts the source lacks or has otherwise | 1 |
| `source_dependencies` | dependencies the source lacks | 1 |
| `source_install_files` | install files the source lacks or has otherwise | 1 |
| `source_differing` | files that differ from the source | 1 |

A detector's rule is weighed as `detector.rule`, such as `guarddog.threat-process-hooks: 3`,
1 unless set. A rule the detector does not have is refused, as an unknown key is. The rules
are in [detectors](engineering_decisions/detectors.md).

Each weight is a whole number, 0 or more. The signals are in
[metadata-heuristics](engineering_decisions/metadata-heuristics.md) and
[source-diff](engineering_decisions/source-diff.md).

## Actions

A decision is `allow`, `quarantine` or `block`, in that order of strictness.
`quarantine` comes only from `cooldown_days` and lapses as the version ages. A version
refused either way is removed from the metadata document, and a pinned fetch of it is
refused ([quarantine-filter-metadata](engineering_decisions/quarantine-filter-metadata.md)).
