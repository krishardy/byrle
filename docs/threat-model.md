# Threat model

What byrle defends against, what it trusts, and what it does not cover. Written
2026-09-28 from the code as it stands. Each control names where it is implemented or
decided.

## What it protects

A developer's or CI machine's installs from npm and PyPI. byrle sits between the
package manager and the registry, and serves an artifact only after deciding on it:

- a version the policy refuses is removed from the metadata document, so the resolver
  picks another, and a pinned fetch of it is refused;
- an artifact is served only when its bytes match the digest its metadata published, and
  only after its analysis has finished;
- every decision on a pinned artifact is written to an audit log that can be replayed.

## Trust

| Party | Trusted for | Not trusted for |
|---|---|---|
| The operator | the policy file, the environment, the host | |
| The registry (npm, PyPI, or a mirror) | serving the metadata a publisher uploaded | the bytes: each artifact is checked against the digest the metadata published |
| A package's publisher | nothing | everything: this is who the policy and the analysis are about |
| The intel streams (OSV, GitHub advisories, CISA KEV, Datadog) | what they report | completeness: a package no stream reports is not known to be clean |
| sigstore and the npm and PyPI attestation endpoints | an attestation that verifies against the pinned trust root | an attestation that does not verify, which counts as none |
| The client machine | nothing beyond pointing at the proxy | its configuration: see Bypasses |
| Whoever can reach the proxy's port | using it as a registry | nothing else; there is no account or credential yet |

## Threats and controls

| Threat | Control | Where |
|---|---|---|
| A known-malicious version | `known_malware` refuses it, with no exception | `policy::decide`, [intel-in-decisions](engineering_decisions/intel-in-decisions.md) |
| A version published minutes ago by a hijacked account | `cooldown_days` quarantines it | [quarantine-filter-metadata](engineering_decisions/quarantine-filter-metadata.md) |
| An install script, declared or not | `install_scripts: block`, decided from the artifact's own `package.json` or sdist | [install-scripts-from-the-artifact](engineering_decisions/install-scripts-from-the-artifact.md) |
| A release published outside the project's CI | `provenance: block` refuses a dropped attestation, a changed identity, and one that does not verify | [provenance-check](engineering_decisions/provenance-check.md) |
| A known vulnerability, or one being exploited | `max_cvss`, `kev` | `policy::decide` |
| A registry, mirror or network path serving other bytes than the metadata describes | the digest is checked on the way through; the last chunk is held until it matches | [artifact-digest-verification](engineering_decisions/artifact-digest-verification.md) |
| An artifact on an origin the proxy does not serve, which the client would fetch directly | the version is removed from the metadata, and a pinned fetch is refused | [enforcement-tiers](engineering_decisions/enforcement-tiers.md), tier 3 |
| Serving before anything was checked | nothing is served until its analysis has finished; no strong digest, or no metadata, is not served | [request-flow](request-flow.md) |
| The intel store cannot answer | 503, not a serve | [uncovered-ecosystem-fails-closed](engineering_decisions/uncovered-ecosystem-fails-closed.md) |
| An artifact built from other code than its repository holds | reported, not refused: each npm tarball, PyPI wheel and sdist is compared with GitHub's archive of the commit or tag it names, and what it adds is a signal in the log and the audit line. The publisher chooses the repository and the commit, so a publisher can name a repository that matches, which is why it is a signal | [source-diff](engineering_decisions/source-diff.md) |
| A verdict that cannot be explained later | each pinned audit line records every input; `byrle audit verify` decides it again | [reproducible-verdicts](engineering_decisions/reproducible-verdicts.md) |

## Attacks on the proxy itself

Every metadata document and artifact is untrusted input, parsed by the proxy.

| Input | Bound | Where |
|---|---|---|
| A metadata document | 64 MiB, applied to the decoded size, so a compression bomb stops at the limit; one over it is forwarded unread and logged `UNINSPECTED` | `BYRLE_MAX_METADATA_BYTES`, `http::decode_for_parsing` |
| An archive member read into memory | 4 MiB | `analysis::MAX_MEMBER_BYTES` |
| An artifact spooled for analysis | 1 GiB; one over it is stored as unreadable, which `install_scripts: block` refuses | `BYRLE_MAX_ARTIFACT_BYTES` |
| An analysis job | 600 s | `analysis::run::DEADLINE` |
| Concurrent work | 8 metadata documents and 8 analyses at once | `BYRLE_MAX_CONCURRENT_METADATA`, `BYRLE_MAX_CONCURRENT_ANALYSES` |
| An upstream that stops sending | 10 s to connect, 30 s between reads | `http::client_builder` |
| A URL the metadata names | fetched only on an origin the proxy serves: the upstream, the default registry, or `BYRLE_ARTIFACT_ORIGINS`; attestations too | [enforcement-tiers](engineering_decisions/enforcement-tiers.md) |
| A package name and version a detector is run on | no shell; one argument each; a value starting with `-` is refused. The program gets `PATH`, `HOME`, `SOCKS` and the forward proxies, nothing else, a directory of its own, 300 s and 16 MiB of output | [detectors](engineering_decisions/detectors.md) |
| A repository and reference the metadata names | fetched only from `BYRLE_SOURCE_ARCHIVES`, `https://codeload.github.com` by default, as `/{owner}/{repo}/tar.gz/{ref}`; owner and repository are GitHub's name characters, `gitHead` 40 hex characters, and a tag has no `..`, `//` or characters outside `A-Z a-z 0-9 . _ - @ / +`. `off` fetches nothing | `analysis::source` |
| A source archive | spooled under `BYRLE_MAX_ARTIFACT_BYTES`, and read only while its members state 512 MiB or less; each member is hashed as it streams | `analysis::source::MAX_SOURCE_BYTES` |

- **Credentials.** The client's `Authorization` header is never forwarded upstream.
- **What the health endpoint shows.** `/-/byrle/health` reports configuration and
  counters. It holds no credentials.
- **Default exposure.** The proxy listens on `127.0.0.1:8080` unless `BYRLE_LISTEN`
  says otherwise. Anyone who can reach the port can use it; it has no authentication.
- **The audit log.** A local JSON Lines file. It is not signed, so whoever can write the
  file can change it.

- **Detectors.** GuardDog downloads each version it scans from `registry.npmjs.org` or
  `pypi.org` itself, and fetches `hugovk.dev` and `packages.ecosyste.ms`. Those hosts learn
  which packages the organisation uses, as the intel streams do
  ([detectors](engineering_decisions/detectors.md)).

## Bypasses

Each of these is a way for a package to be installed without byrle deciding on it.

| Bypass | What happens | Mitigation |
|---|---|---|
| A client pointed back at the public registry | nothing reaches the proxy | `byrle doctor` checks the client configuration; an npm or yarn lockfile records the proxy's address, so CI can check it |
| A client's own cache | npm, bun and yarn 4 install from their caches without asking | `byrle doctor` warns; clear the cache when onboarding |
| Installs outside a package manager: IDE extensions, browser extensions, MCP servers | never pass through a configured registry | out of scope; only egress control, tier 5, covers them |
| An origin in `BYRLE_ALLOW_DIRECT_ORIGINS` | the client fetches those artifacts directly, by the operator's choice | reported by `byrle doctor` and in `/-/byrle/health` |
| `BYRLE_REFUSE_UNSERVABLE=0` | versions on origins the proxy does not serve are forwarded | a startup warning and `byrle doctor` |
| `BYRLE_MODE=observe` | what the policy refuses is served and logged | a startup warning and `byrle doctor`; never serves what cannot be assessed |
| Break-glass installs | an install pointed at the registry while the proxy is down | [break-glass](break-glass.md); a lockfile the bypass changed must not be committed |
| pnpm's lockfile | records no artifact URL, so it cannot evidence that the proxy was used | none in the lockfile |
| A dependency named by URL, git or path | npm fetches it from where it points | logged `BYPASS` and counted: [bypass-self-detection](engineering_decisions/bypass-self-detection.md) |

## Out of scope

- An attacker who already controls the developer's or CI machine.
- Malware nobody has reported, beyond what the cooldown, install-script, provenance and
  analysis checks catch. byrle does not claim to find novel malware before the research
  community does.
- Code that runs when a package is imported rather than installed. The install-script
  check does not see it: of the 2025 npm incidents measured, chalk/debug and xrpl.js ran
  their payloads on import ([incident-benchmark](engineering_decisions/incident-benchmark.md)).
- Ecosystems other than npm and PyPI.
