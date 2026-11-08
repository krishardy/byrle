# Threat model

What byrle defends against, what it trusts, and what it does not cover. Written
2026-09-28 from the code as it stands. Each control names where it is implemented or
decided.

## What it protects

A developer's or CI machine's installs from npm, PyPI, crates.io, the Go module proxy, Maven
Central and the Gradle plugin portal. byrle sits between the
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
| The registry (npm, PyPI, crates.io, the Go module proxy, Maven Central, the Gradle plugin portal, or a mirror) | serving the metadata a publisher uploaded | the bytes: each artifact is checked against the digest the metadata published, for Go the one sum.golang.org holds, and for Maven the strongest of the `.sha512`, `.sha256` and `.sha1` beside it ([maven-digests](engineering_decisions/0112-maven-digests.md)). A Maven sidecar comes from the repository that serves the file, so it checks the path, not the repository; the PGP signature checks the repository |
| keys.openpgp.org and keyserver.ubuntu.com | the public key for a fingerprint that made a Maven `.asc` | whether the key is the publisher's: a key neither holds fails verification, and a key no earlier version used is the `signing_key_new` signal ([maven-signatures](engineering_decisions/0113-maven-signatures.md)) |
| services.gradle.org | nothing: `byrle doctor` reads its list of releases to check a project's Gradle wrapper | the wrapper's download, which does not pass through byrle |
| sum.golang.org | each Go module version's `h1:` for its zip and its `go.mod`, once its signed tree head verifies with the Go team's key and the record's inclusion and the tree's consistency are proved ([go-plan](go-plan.md) Q3) | a version it holds no record of, which has no strong digest |
| index.golang.org | each entry's `Timestamp`, which places sum.golang.org's records in time to date a Go version ([go-versions-dated-by-the-checksum-database](engineering_decisions/0125-go-versions-dated-by-the-checksum-database.md)). Its answers are not signed | which version an entry names: its record number comes from a lookup sum.golang.org proves. Unreachable, a Go version older than the cooldown's start is dated by its `.info` `Time` |
| A package's publisher | nothing | everything: this is who the policy and the analysis are about |
| The intel streams (OSV, GitHub advisories, CISA KEV, Datadog) | what they report | completeness: a package no stream reports is not known to be clean |
| VirusTotal, when `BYRLE_VIRUSTOTAL_API_KEY` is set | its engines' counts, a signal weighed in the risk score | anything else. It learns the SHA-256 of each artifact asked about, and with `BYRLE_VIRUSTOTAL_MODE=upload` it receives the bytes of an artifact it does not know from npm's or PyPI's public registry, which joins its dataset ([virustotal](engineering_decisions/0104-virustotal.md)) |
| sigstore and the npm and PyPI attestation endpoints | an attestation that verifies against the pinned trust root | an attestation that does not verify, which counts as none |
| The client machine | nothing beyond pointing at the proxy | its configuration: see Bypasses |
| Whoever can reach the proxy's port | using it as a registry | nothing else; there is no account or credential yet |
| Other users on the host | nothing | the spool: `Spool::open` refuses a spool directory that is a link, owned by another user, or writable by every user, and reads only the inode it wrote ([artifact-spool](engineering_decisions/0064-artifact-spool.md#another-users-directory)); a detector runs in a new, randomly named `0700` directory |

## Threats and controls

| Threat | Control | Where |
|---|---|---|
| A known-malicious version | `known_malware` weighs `risk_threshold`, so refuses alone, and no `packages` entry releases it; a policy that weighs it lower is reported as a loosening by `byrle policy diff` | `policy::decide`, [intel-in-decisions](engineering_decisions/0026-intel-in-decisions.md) |
| A version published minutes ago by a hijacked account | `cooldown_days` quarantines it | [quarantine-filter-metadata](engineering_decisions/0013-quarantine-filter-metadata.md) |
| An install script, declared or not | `install_scripts: block`, decided from the artifact's own `package.json`, sdist, a `.crate`'s `Cargo.toml`: a build script or a proc-macro, or the annotation processors of a Maven jar, or of any other Maven file that opens as a zip. Before a `.crate` or a `.jar` is read, its version's is `not analyzed`. A Go build runs no module's code, so the check has no meaning for Go | [install-scripts-from-the-artifact](engineering_decisions/0062-install-scripts-from-the-artifact.md) |
| A release published outside the project's CI | `provenance: block` refuses a changed identity and an attestation that does not verify, and for a Maven jar an `.asc` that does not verify. A dropped attestation, or a jar with no `.asc` after a version with one, weighs half `risk_threshold` and a quarter of it per bit of surprise over its release line's history ([risk-score-plan](risk-score-plan.md) step 6): nx's 10 versions of 2025-08-26 score 155 to 162, @rspack/core 1.1.7 151, and axios 1.14.1, published with a stolen token on 2026-03-31, 108. crates.io and the Go module proxy serve no attestations, so it decides nothing for a crate or a module. Its unsigned `trustpub_data` is read for the `trustpub_dropped` and `trustpub_repository_changed` signals ([cargo-provenance](engineering_decisions/0110-cargo-provenance.md)) | [provenance-check](engineering_decisions/0066-provenance-check.md) |
| A known vulnerability, or one being exploited | `max_cvss`, `kev` | `policy::decide` |
| A registry, mirror or network path serving other bytes than the metadata describes | the digest is checked on the way through; the last chunk is held until it matches | [artifact-digest-verification](engineering_decisions/0017-artifact-digest-verification.md) |
| An artifact on an origin the proxy does not serve, which the client would fetch directly | the version is removed from the metadata, and a pinned fetch is refused | [enforcement-tiers](engineering_decisions/0019-enforcement-tiers.md), tier 3 |
| A file a client installs at a path the proxy cannot read, such as a PyPI `.tgz` sdist or an npm tarball not named `<name>-<version>.tgz` | refused as an unrecognised path: only path shapes an adapter lists are forwarded unread, and any other is refused, or forwarded and logged at WARN in observe mode | [unrecognised-paths-refused](engineering_decisions/0119-unrecognised-paths-refused.md) |
| Serving before anything was checked | nothing with a strong digest is served until its analysis has finished; no metadata is not served | [request-flow](request-flow.md) |
| An advisory stream served empty or cut short, by its host or a mirror under `BYRLE_STREAM_URLS` | a stream that parses to under half its source's stored rows is not loaded, and its last load stays, unless `byrle refresh --force <stream>` | [shrunk-stream-not-loaded](engineering_decisions/0130-shrunk-stream-not-loaded.md) |
| The intel store cannot answer | 503, not a serve | [uncovered-ecosystem-fails-closed](engineering_decisions/0048-uncovered-ecosystem-fails-closed.md) |
| An artifact built from other code than its repository holds | reported, not refused: each npm tarball, PyPI wheel and sdist is compared with GitHub's archive of the commit or tag it names, and what it adds is a signal in the log and the audit line. The publisher chooses the repository and the commit, so a publisher can name a repository that matches, which is why it is a signal | [source-diff](engineering_decisions/0091-source-diff.md) |
| A verdict that cannot be explained later | each pinned audit line records every input; `byrle audit verify` decides it again | [reproducible-verdicts](engineering_decisions/0070-reproducible-verdicts.md) |

A client can check byrle from outside it. byrle passes each Maven file and sidecar through
byte for byte, but a `maven-metadata.xml` it filters and that file's `.sha1` and `.md5`
([maven-files-unchanged](engineering_decisions/0114-maven-files-unchanged.md)). Gradle's
`verification-metadata.xml`, with `<verify-signatures>` and keys from key servers, then
catches byrle changing a jar: with `slf4j-api-2.0.17.jar` answered with 2.0.16's bytes,
Gradle failed, "One artifact failed verification". `byrle doctor` warns of a build with no
such file, or one that checks digests only.

## Attacks on the proxy itself

Every metadata document and artifact is untrusted input, parsed by the proxy.

| Input | Bound | Where |
|---|---|---|
| A request path | 400 for a `.` or `..` segment, `%2e` in any case, split on `/` or `\`, so the path asked upstream is the path classified | `route::rewritten_by_url_parser` |
| A metadata document | 64 MiB, applied to the size sent and to the decoded size, so a compression bomb stops at the limit; one over it, or one that cannot be decoded, is answered 502 and logged `UNINSPECTED`, and forwarded unread in observe mode | `BYRLE_MAX_METADATA_BYTES`, `http::decode_for_parsing` |
| A sidecar the proxy reads: a checksum, an `.asc`, a Go `.info`, a sumdb answer | 64 KiB as sent; an `.asc` over it fails to verify, and one LRU of 8,192 `.asc`s keeps at most 512 MiB | `http::MAX_SIDECAR_BYTES` |
| A key server's copy of a key | 1 MiB; a longer copy is not used. A certification by another key, which keyserver.ubuntu.com accepts from anyone, is rejected by its issuer before any hashing (`pgp` 0.21.0 `match_identity`) | `maven::keys::MAX_KEY_BYTES` |
| An archive member read into memory | 4 MiB | `analysis::MAX_MEMBER_BYTES` |
| An artifact spooled for analysis | 1 GiB; one over it is stored as unreadable, which `install_scripts: block` refuses | `BYRLE_MAX_ARTIFACT_BYTES` |
| An analysis job | 600 s; a job past it stops reading its file on the blocking thread, as a source comparison and a signature check do | `analysis::run::DEADLINE`, `util::blocking::run` |
| Concurrent work | 8 metadata documents and 8 analyses at once | `BYRLE_MAX_CONCURRENT_METADATA`, `BYRLE_MAX_CONCURRENT_ANALYSES` |
| A remote `policy diff` | 10,000 package versions sent; one diff at a time, and another sent meanwhile is 429 | `BYRLE_MAX_DIFF_VERSIONS` |
| An upstream that stops sending | 10 s to connect, 30 s between reads | `http::client_builder` |
| A URL the metadata names | fetched only on an origin the proxy serves: the upstream, the default registry, or `BYRLE_ARTIFACT_ORIGINS`; attestations too | [enforcement-tiers](engineering_decisions/0019-enforcement-tiers.md) |
| A package name and version a detector is run on | no shell; one argument each; a value starting with `-` is refused. The program gets `PATH`, `HOME`, `SOCKS` and the forward proxies, nothing else, a directory of its own, 300 s and 16 MiB of output | [detectors](engineering_decisions/0092-detectors.md) |
| A repository and reference the metadata names | fetched only from `BYRLE_SOURCE_ARCHIVES`, `https://codeload.github.com` by default, as `/{owner}/{repo}/tar.gz/{ref}`; owner and repository are GitHub's name characters, `gitHead` 40 hex characters, and a tag has no `..`, `//` or characters outside `A-Z a-z 0-9 . _ - @ / +`. `off` fetches nothing | `analysis::source` |
| A source archive | spooled under `BYRLE_MAX_ARTIFACT_BYTES`, and read only while its members state 512 MiB or less and number 200,000 or fewer, and a tar decompresses to 512 MiB plus 4 KiB per member; each member is hashed as it streams | `analysis::source::CEILING` |

- **What reaches the registry.** Of the client's headers, only `Accept`,
  `Accept-Encoding`, `If-None-Match` and `If-Modified-Since` are sent upstream
  (`proxy::FORWARDED`, since 2026-10-13). `Authorization`, `X-Byrle-Token`, `Cookie`,
  `User-Agent`, `Referer`, npm's `npm-session` and `npm-command`, `X-Forwarded-For` and
  anything nginx adds stop at the proxy. The registry sees `User-Agent: byrle/<version>`.
- **What the health endpoint shows.** `/-/byrle/health` reports configuration and
  counters. It holds no credentials.
- **Default exposure.** The proxy listens on `127.0.0.1:8080` unless `BYRLE_LISTEN`
  says otherwise. Each request needs a token from `byrle token create`, answered 401
  without one, unless `BYRLE_REQUIRE_TOKEN=0`, when anyone who can reach the port can use
  it ([account-identification](engineering_decisions/0054-account-identification.md)).
- **The audit log.** A local JSON Lines file, naming the account behind each request. It
  is not signed, so whoever can write the file can change it, and whoever can read it or
  the database's `served_version` can read who installed what.

- **Detectors.** GuardDog downloads each version it scans from `registry.npmjs.org` or
  `pypi.org` itself, and fetches `hugovk.dev` and `packages.ecosyste.ms`. Those hosts learn
  which packages the organisation uses, as the intel streams do
  ([detectors](engineering_decisions/0092-detectors.md)).

## The console

The console is on when `BYRLE_CONSOLE_URL` is set, and needs the database
([admin-plan](admin-plan.md) §4, [console-login](engineering_decisions/0106-console-login.md)).

| Exposure | Control |
|---|---|
| The login form | Argon2id hashes; 5 failures per account and 20 per address in 15 minutes, then 429 unchecked, each login counted before its password is checked; an unknown account takes as long as a known one; passwords hashed 2 at a time off the threads that answer requests |
| Who a request is from | the address of the peer, or the last `X-Forwarded-For` entry when the request carries `BYRLE_RP_KEY`, which nginx sets and a client cannot ([fronting-tls](fronting-tls.md)) |
| Sessions and tokens | stored as their SHA-256, never as themselves; a session ends at logout, after `BYRLE_SESSION_HOURS`, or when its account is disabled |
| The session cookie | `HttpOnly; Secure; SameSite=Strict`, under the console's path |
| A request from another site | a console request other than `GET` or `HEAD` with another `Origin` is 403, whatever its credential (`routes::guarded`); a request with the session cookie that changes something needs its CSRF token, as `X-Byrle-CSRF` or a form's `csrf` |
| Pages | `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'`; text from registries and logs, such as a username someone tried, is escaped |
| Permissions | every route is in one table with its guard; a test checks each that needs a permission is 401 without credentials and 403 to an account without the role |
| `GET api/v1/health` | answers without credentials, naming components, never addresses or errors; its checks run at most once per 5 s however often it is asked |
| `GET api/v1/openapi.json` | answers without credentials; it describes the API and holds no data |
| `GET api/v1/config` | secrets are shown as `set`; `BYRLE_DATABASE_URL` without its password, and not at all unless it reads as a URL with a host |
| OIDC | the issuer fixed in `BYRLE_OIDC_ISSUER`; `state`, `nonce` and PKCE; the token's algorithm from a configured list with no shared-secret algorithm; `iss`, `aud`, `azp`, `exp` and `sub` checked. An identity logs in only as the account an admin linked it to with `byrle account link` |
| The account event log | logins, failed logins, logouts and changes to accounts and tokens; not signed, as the audit log is not |

## Bypasses

Each of these is a way for a package to be installed without byrle deciding on it.

| Bypass | What happens | Mitigation |
|---|---|---|
| A client pointed back at the public registry | nothing reaches the proxy | `byrle doctor` checks the client configuration; an npm or yarn lockfile records the proxy's address, so CI can check it |
| A client's own cache | npm, bun, yarn 4 and go install from their caches without asking: go 1.27.2 added a version the proxy refused from its module cache | `byrle doctor` warns; clear the cache when onboarding |
| Installs outside a package manager: IDE extensions, browser extensions, MCP servers | never pass through a configured registry | out of scope; only egress control, tier 5, covers them |
| An origin in `BYRLE_ALLOW_DIRECT_ORIGINS` | the client fetches those artifacts directly, by the operator's choice | reported by `byrle doctor` and in `/-/byrle/health` |
| `BYRLE_REFUSE_UNSERVABLE=0` | versions on origins the proxy does not serve are forwarded | a startup warning and `byrle doctor` |
| An artifact with no strong digest: an npm or PyPI file with SHA-1 only, a Go version sum.golang.org holds no record of, a Maven file with no sidecar | forwarded unverified and unanalysed, as `no_strong_digest` weighs 0 by default | `signal_weights: { no_strong_digest: 100 }` refuses it; each is logged at WARN |
| A dropped attestation in a line with few attested versions before it | weighs under `risk_threshold` and is served: axios 0.30.4, of 2026-03-31, scores 50, and eslint-config-prettier's four of 2025-07-18, 50 to 62. Each was refused before the score | `signal_weights: { provenance_dropped: 100 }` refuses every drop alone, as before |
| A weight lowered, or `risk_threshold` raised, in the policy | what it weighed under is served | `byrle policy diff` reports it as a loosening |
| A metadata document over `BYRLE_MAX_METADATA_BYTES` or undecodable, or an npm packument or PyPI index the proxy could not read, filter or repoint, in observe mode | forwarded with the artifact URLs the upstream wrote: pnpm, yarn, bun and pip then fetch those artifacts from the origin. npm's default `replace-registry-host` sends its fetch to the proxy | logged `UNINSPECTED` and counted in `/-/byrle/health`; enforce mode answers 502 |
| A metadata document answered in a media type the adapter does not read, such as an npm packument as `text/plain` | forwarded as written in either mode: refused versions stay listed and its artifact URLs are not repointed. Each artifact fetch that reaches the proxy is still decided. A 502 would refuse a mirror serving `maven-metadata.xml` without a type the adapter lists | logged `UNINSPECTED` and counted in `/-/byrle/health` |
| `BYRLE_MODE=observe` | what the policy refuses is served and logged | a startup warning and `byrle doctor`; never serves what cannot be assessed |
| Break-glass installs | an install pointed at the registry while the proxy is down | [break-glass](break-glass.md); a lockfile the bypass changed must not be committed |
| pnpm's lockfile | records no artifact URL, so it cannot evidence that the proxy was used | none in the lockfile |
| `Cargo.lock` | records crates.io as each crate's source whichever registry replaced it | `byrle doctor` reads `.cargo/config.toml` |
| A cargo `[patch]`, git or path dependency | cargo fetches it from where it points | `byrle lockfile verify` names a git dependency's source |
| `GOPROXY` with `\|direct` after the proxy | go asks the module's origin after any error, a refusal included: go 1.27.2 asked `https://rsc.io` for a version the proxy answered 403. After a `,` it asks only on a 404 or 410, and did not after any refusal measured | `byrle doctor` reports the entries after a `\|` as a PROBLEM |
| `GONOPROXY`, which `GOPRIVATE` sets | go fetches the modules it matches from their origin | `byrle doctor` warns |
| `-mod=vendor`, or a `vendor/` directory | go builds from the vendored copies and fetches no module | `byrle doctor` warns of `-mod=vendor` in `GOFLAGS` |
| `go.sum` | records a hash and no URL, so it cannot evidence that the proxy was used | `byrle doctor` reads `go env` |
| A Maven mirror of `central` alone | mvn asks each other repository a pom declares at its own URL | `byrle doctor` reports it as a PROBLEM |
| mvn's local repository | mvn keeps it by the mirror's id, so a mirror repointed at the proxy under the id it had serves everything cached before: 0 requests on 2026-10-17 | `byrle doctor` warns; give the mirror a new id, or clear `~/.m2/repository` |
| `-s` in `MAVEN_ARGS` or `.mvn/maven.config` | mvn reads that settings file in place of `~/.m2/settings.xml` | `byrle doctor` reads the file each names |
| A Gradle build without the init script, or a repository it does not replace | Gradle asks the repository the build declares | `byrle doctor` reports an init script that names no `/maven/` or `/gradle-plugins/` URL |
| Gradle's module cache | a jar cached from the proxy is used without asking: 0 requests on 2026-10-18 | `byrle doctor` warns; `--refresh-dependencies` asks again |
| `./gradlew`'s download of Gradle | it fetches the distribution from `services.gradle.org` itself, not through the proxy, and runs it | `byrle doctor` checks `gradle-wrapper.jar` against every release's `wrapperChecksum`, `distributionSha256Sum` against the release's, and the release's build time against `cooldown_days` |
| `./mvnw`'s download of mvn | from the `distributionUrl` in `.mvn/wrapper/maven-wrapper.properties`, or `MVNW_REPOURL` | `byrle doctor` reports one not at the proxy's `/maven`, and no `distributionSha256Sum` |
| Gradle's lockfiles, and mvn, which writes none | record no URL, so they cannot evidence that the proxy was used | `byrle doctor` reads the init scripts and `settings.xml` |
| A dependency named by URL, git or path | npm fetches it from where it points | logged `BYPASS` and counted: [bypass-self-detection](engineering_decisions/0069-bypass-self-detection.md) |

## Out of scope

- An attacker who already controls the developer's or CI machine.
- Malware nobody has reported, beyond what the cooldown, install-script, provenance and
  analysis checks catch. byrle does not claim to find novel malware before the research
  community does.
- Code that runs when a package is imported rather than installed. The install-script
  check does not see it: of the 2025 npm incidents measured, chalk/debug and xrpl.js ran
  their payloads on import ([incident-benchmark](engineering_decisions/0068-incident-benchmark.md)).
- Ecosystems other than npm, PyPI, crates.io, Go and Maven.
