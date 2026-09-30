# Detectors report signals, and GuardDog is the first

- **Status:** Implemented 2026-09-30, report only. `src/analysis/detector.rs` (the trait and
  the command adapter), `src/analysis/run/detecting.rs` (running them), `version_detection`
  (migration 0014), measured by `examples/detector_rates.rs`.
- **Related:** [metadata-heuristics](metadata-heuristics.md), [source-diff](source-diff.md),
  [policy-reference](../policy-reference.md#signal_weights), [threat-model](../threat-model.md)

## Decision

Decided with the user 2026-09-30.

| Part | What it is |
|---|---|
| `Detector` | a trait: a name, a version, and `detect`, which reports the rules that fired on a package version |
| role | report only. A detector's rules are signals in the risk score and refuse nothing. The install-script reader and attestation verification decide verdicts and defer the client; they are not detectors |
| running | in the background, never deferring a request: 2 slots of their own, one run per version and detector at a time. A decision reads the stored results, and starts the detectors that have none unless the policy blocks the version. The watcher does the same for a new version |
| result | kept by detector, ecosystem, registry name and version, and read back only for the detector version that wrote it. A run that could not be made stores nothing, and runs again on the next decision |
| weight | each rule fired is a signal `detector.rule`, weighing 1 unless `signal_weights` says otherwise. A key naming a rule the detector does not have is refused at load |

The metadata heuristics and the source comparison are signals too, but are not behind the
trait: the heuristics read the metadata synchronously, and the source comparison is keyed
by the artifact's digest.

## The command adapter

`WAHAROA_DETECTORS` names each detector as `name=program argument...`, separated by `;`.
`{ecosystem}`, `{name}` and `{version}` in the arguments are replaced. GuardDog's:

```
guarddog=/opt/guarddog/bin/guarddog {ecosystem} scan {name} --version={version} --output-format=json
```

The command prints a JSON object whose `results` maps each rule to what it found, empty or
`null` when nothing, and whose `errors` maps a rule to why it did not run: GuardDog's output.

| Rule | Why |
|---|---|
| `program --version` runs at startup, and its last line is the detector's version | a new version reruns every version; one that prints none refuses the start |
| no shell; the arguments are split on whitespace when configured | a package name reaches the program as one argument |
| a name or version starting with `-` is refused | it cannot be read as an option. `--version={version}` is one argument either way |
| the environment is cleared, then `PATH`, `HOME`, `SOCKS` and the forward proxies are passed | `WAHAROA_GITHUB_TOKEN` and `DATABASE_URL` do not reach a program run on untrusted names |
| each run has a directory of its own, removed after | nothing a run writes is read by the next |
| killed after 300 s, or past 16 MiB on either stream | `detector::TIMEOUT`, `detector::MAX_OUTPUT_BYTES` |

Decided with the user: a detector that fails fails open, since it refuses nothing. This
amends plan §5's "detector failure defaults to fail closed", which now holds for the
detectors that decide verdicts.

## GuardDog

[GuardDog](https://github.com/DataDog/guarddog) 3.2.0, Apache-2.0, Python 3.10 or later.
63 rules for npm and 61 for PyPI: 54 read the source code, the others the registry's
metadata. `detector::guarddog::RULES` lists all 64 names.

Decided with the user: GuardDog scans by name, so its metadata rules run. That costs:

- GuardDog downloads the package itself, from `registry.npmjs.org` or `pypi.org`, which it
  hardcodes. Behind a private mirror it scans the public package of the same name. Its
  findings describe bytes the proxy did not check against a digest.
- It fetches `hugovk.github.io`, which redirects to `hugovk.dev`, and `packages.ecosyste.ms`
  for its lists of popular packages. The registries and these hosts learn which packages the
  organisation uses.
- `potentially_compromised_email_domain` and `unclaimed_maintainer_email_domain` look up
  maintainers' email domains by WHOIS, TCP port 43, through `python-whois`. Without that
  access both fail on every run. `SOCKS=host:port` sends them through a SOCKS5 proxy, which
  needs PySocks installed beside GuardDog. This sandbox has no SOCKS5 proxy yet, so the two
  rules are not measured below.

`django` 6.1.1's wheel is never scanned. GuardDog refuses it as "multiple
End-Of-Central-Directory records (possible scan evasion)": the four signature bytes occur by
chance in the compressed data of `django/conf/locale/sw/LC_MESSAGES/django.po`. The error is
stored with the result, and no rule fires.

## Measured

The lockfiles of [source-diff](source-diff.md), 694 npm and 34 PyPI versions, through the
command adapter, 2026-09-30.

| | npm | PyPI |
|---|---|---|
| runs that failed | 0 | 0 |
| median run | 1.2 s | 1.4 s |
| slowest run | 40.0 s | 6.9 s |
| versions any rule fired on | 400 (58%) | 25 (74%) |
| versions a `threat-*` rule fired on | 28 (4.0%) | 9 (26%) |
| rules fired per version, mean | 1.14 | 2.91 |

| Rule | npm | PyPI |
|---|---|---|
| `capability-network-outbound` | 212 | 14 |
| `capability-process-spawn` | 127 | 17 |
| `bundled_binary` | 99 | 0 |
| `capability-process-hooks` | 85 | 0 |
| `capability-filesystem-read` | 80 | 21 |
| `capability-network-download` | 54 | 7 |
| `capability-filesystem-delete` | 35 | 13 |
| `metadata_mismatch` | 16 | 1 |
| `threat-process-hooks` | 7 | 0 |
| `threat-runtime-environment-read` | 7 | 0 |
| `threat-runtime-obfuscation-unicode` | 2 | 5 |

The npm versions a `threat-*` rule fired on include `esbuild`, `core-js`, `node-gyp`,
`next`, `sqlite3` and `bcrypt`; the PyPI ones `numpy`, `pandas`, `flask` and `werkzeug`.
None is reported as malicious.

At weight 1 for every rule, GuardDog adds 1.14 to the mean npm score and 2.91 to the PyPI
one. The eight built-in signals add about 0.12 per npm version: 73 from the heuristics and
about 11 from the source comparison over the same versions.

## Tests

| Test | Covers |
|---|---|
| `detector.rs` | the version from `--version`, the rules that fired and those that did not, errors, the environment given and nothing else, the run's own directory, an option-like name or version, output that is not JSON, output over the limit, a run past its timeout killed as its pid shows, and each spec refused |
| `detecting.rs` | a run stored and read back, a stored result not run again, a run in flight not started twice, a failing or slow detector and a store that fails storing nothing |
| `a_detectors_rules_are_reported_on_a_later_request` | the audit line's signals on the second decision, a blocked version starting nothing, the watcher starting a detector and running a failed one again |
| `a_detection_is_kept_under_its_version` | `version_detection` in Postgres |
| `a_detector_is_asked_its_version_or_refuses_the_start` | startup |

18 hand mutants, each caught.

To rerun, with GuardDog installed:

```
cargo run --release --example detector_rates -- \
  "guarddog=$(which guarddog) {ecosystem} scan {name} --version={version} --output-format=json" \
  */package-lock.json */uv.lock
```
