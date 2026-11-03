# Request flow

How the proxy answers one request, and where each status code comes from. Every path
below is read from below `BYRLE_PROXY_URL`'s path: `/registry/npm/lodash` is `/npm/lodash`
under `https://h/registry/`. Each ecosystem is served under its own prefix, `/npm/`,
`/pypi/`, `/cargo/`, `/go/` and `/maven/`, and the Gradle plugin portal under
`/gradle-plugins/` ([ecosystem-path-prefixes](engineering_decisions/0111-ecosystem-path-prefixes.md)).
Read from
`handle`, `admit` and `Exchange`, `decide_artifact` and `Deciding`, and `filtered_document`
in `src/proxy.rs`, on 2026-09-28, `admit` on 2026-10-11, Go's claim on 2026-10-16, and
Maven's on 2026-10-17 ([maven-plan](maven-plan.md) step 4.3), and `unrecognised` on
2026-10-19. Checked against the code at `3ade87d` on 2026-10-19 for
[logic-flow](logic-flow.md).

With `BYRLE_MODE=observe`, a refusal by policy is logged at WARN and the request goes on
to the next check, and a metadata document keeps the versions the policy refuses, and an unrecognised path is
forwarded, logged at WARN. Every other answer is the same in both modes
([observe-mode](engineering_decisions/0071-observe-mode.md)).

The policy's checks, the detectors' and advisories' signals, and the proxy's own refusals
are each a signal with a weight, and a version is refused when the weights present sum to
`risk_threshold` ([every-refusal-a-signal](engineering_decisions/0116-every-refusal-a-signal.md)).
The proxy's own, `unservable`, `no_strong_digest`, `digest_mismatch`, `signature_failed`
and `cooldown_unanswered`, answer as drawn below when one weighs the threshold alone, which each
does by default but `no_strong_digest`, 0; reached only by a sum, the refusal is the
policy's; under it, each serves what it can, as
[policy-reference](policy-reference.md#signal_weights) says.

"Refusal status" is `BYRLE_REFUSAL_STATUS`: 403 by default, settable per ecosystem and
client to any code from 400 to 599. Every 503 carries `Retry-After` and
Every 503 the proxy writes, but `/-/byrle/ready`'s, carries `Retry-After` and
`x-byrle-not-ready` naming the case. `Retry-After` is 1, but `BYRLE_CLAIM_RETRY_AFTER`, 2 by
default, while a claim is checked, and for a download waiting on an awaited detector that
detector's runs in flight times one run's time. An `artifact-analysis` 503 also carries
`x-byrle-digest`, the digest of the artifact it waits on, as its log lines name it.

```mermaid
flowchart TD
    REQ([request]) --> DOTS{a . or .. segment,<br/>%2e in any case,<br/>split on / or \?}
    DOTS -->|yes| D400[400]
    DOTS -->|no| MOUNT{under BYRLE_PROXY_URL's path?}
    MOUNT -->|no| M404[404: outside the proxy's path]
    MOUNT -->|yes, read below it| OWN{path}
    OWN -->|/-/byrle/health| H200[200: counters]
    OWN -->|/-/byrle/ready| READY{policy and intel store set,<br/>and intel not loaded<br/>or with a gap?}
    READY -->|no| R200[200]
    READY -->|yes| R503[503]
    OWN -->|anything else| PREFIX{under /npm/, /pypi/,<br/>/cargo/, /go/, /maven/<br/>or /gradle-plugins/?}
    PREFIX -->|no| P404[404: under no<br/>ecosystem's prefix]
    PREFIX -->|yes| TOKEN{token required?<br/>BYRLE_REQUIRE_TOKEN}
    TOKEN -->|no| KIND{what the path names}
    TOKEN -->|yes| HELD{account store}
    HELD -->|cannot answer| T503[503 account-store]
    HELD -->|no token, or one unknown,<br/>revoked or of a disabled account| T401[401: WWW-Authenticate<br/>Basic realm=byrle]
    HELD -->|valid| KIND

    KIND -->|cargo index/config.json| CFG[200, written by the proxy;<br/>400 without Host]
    KIND -->|Maven maven-metadata.xml<br/>.sha1 or .md5| MSC[digest of the filtered<br/>document, or forwarded]
    KIND -->|artifact GET, or<br/>Maven artifact HEAD| LOOKUP{metadata for the package<br/>held, or fetched now}
    KIND -->|metadata document| FWD
    KIND -->|Go sumdb/sum.golang.org/supported| SUP[200, written by the proxy]
    KIND -->|Go sumdb/sum.golang.org/<br/>latest, lookup/, tile/| FWD
    KIND -->|Go .mod, Maven<br/>.pom or .module, GET| MOD{claim: sum.golang.org's,<br/>or the sidecar's}
    MOD -->|no proved answer| M503[503 checksum-database]
    MOD -->|no record| MREF[forwarded unverified;<br/>refusal status while<br/>no_strong_digest weighs<br/>the threshold]
    MOD -->|a record| MFWD[fetched; 502 when its h1:<br/>is not the one claimed]
    KIND -->|an artifact or manifest asked<br/>with a method but GET or HEAD| METH{BYRLE_MODE}
    METH -->|enforce| M405[405, Allow: GET, HEAD]
    METH -->|observe, logged at WARN| FWD
    KIND -->|any method to a metadata<br/>or listed path, a HEAD but a<br/>Maven artifact's| FWD
    KIND -->|a path of no shape<br/>the adapter lists| UNREC{BYRLE_MODE}
    UNREC -->|enforce| UREF[refusal status:<br/>unrecognised path]
    UNREC -->|observe, logged at WARN| FWD

    LOOKUP -->|registry gave none| A502M[502: the registry gave<br/>no metadata]
    LOOKUP -->|does not list the version| AREF1[refusal status:<br/>cannot be assessed]
    LOOKUP -->|record found; a file it does not<br/>name is decided as its first| CLAIM{Go: sum.golang.org's claim<br/>for the zip; Maven: its sidecar's}
    CLAIM -->|no proved answer| C503[503 checksum-database]
    CLAIM -->|a record, no record,<br/>or neither| INTEL{intel store, when a<br/>policy and a store are set}

    INTEL -->|cannot answer| A503I[503 intel-store]
    INTEL -->|no stream covers<br/>the ecosystem| A503E[503 no-stream-for-ecosystem]
    INTEL -->|answers, or none set| POLICY{policy on what is known}

    POLICY -->|risk score reaches risk_threshold:<br/>denial, cooldown, advisory, KEV,<br/>malware, install scripts, provenance,<br/>yanked, deprecated, detectors| AREF2[refusal status:<br/>refused by policy]
    POLICY -->|under it| ORIGIN{artifact on an origin<br/>the proxy does not serve?}
    ORIGIN -->|yes, unservable weighs<br/>the threshold| AREF3[refusal status]
    ORIGIN -->|no| DIGEST{strong digest published,<br/>or for Go and Maven claimed?}
    DIGEST -->|no, and no_strong_digest<br/>weighs the threshold| AREF4[refusal status:<br/>cannot be assessed]
    DIGEST -->|no, by default| FWD
    DIGEST -->|yes| ANALYSIS{analysis of these bytes}

    ANALYSIS -->|last fetch did not<br/>match the digest; a Go zip<br/>not the one claimed| A502X[502: bytes the metadata<br/>does not describe]
    ANALYSIS -->|not finished, or never<br/>stored: upstream 404,<br/>fetch failed, past deadline| A503A[503 artifact-analysis<br/>job started]
    ANALYSIS -->|stored, or nothing to read| AWAITED{awaited detector<br/>result stored?}
    AWAITED -->|no: cargo's trustpub| A503D[503 artifact-analysis<br/>lookup started]
    AWAITED -->|yes, or none| FWD

    FWD[fetch from upstream] --> SENT{upstream answered?}
    SENT -->|connect failed, or 10 s<br/>without connecting| U502[502]
    SENT -->|yes| STATUS{upstream status}

    STATUS -->|not 2xx, or 304| PASS[upstream status,<br/>body forwarded]
    STATUS -->|2xx| BODY{metadata document<br/>the proxy reads?}

    BODY -->|artifact 200| VERIFY{bytes match<br/>the digest?}
    VERIFY -->|yes| V200[200]
    VERIFY -->|no| CUT[200 sent, body cut off<br/>before its last chunk]

    BODY -->|other, or not readable| PASS
    BODY -->|document| BUF{buffered under<br/>BYRLE_MAX_METADATA_BYTES?}
    BUF -->|over it| PASS
    BUF -->|body failed, or 30 s<br/>without a byte| D502[502]
    BUF -->|yes| DINTEL{intel store}
    DINTEL -->|cannot answer, or no stream<br/>covers npm| D503[503]
    DINTEL -->|answers, or no stream covers<br/>PyPI, cargo, Go or Maven,<br/>and their files answer 503| FILTER[upstream's 2xx: refused versions removed;<br/>npm and PyPI: a version with a file on<br/>an unserved origin removed, artifact<br/>URLs pointed here]
```

## Status codes

| Code | Produced by | When |
|---|---|---|
| 200 | proxy | health; ready; a verified artifact; a filtered and rewritten metadata document; Go's `sumdb/sum.golang.org/supported`, empty; cargo's `index/config.json`; a `maven-metadata.xml`'s `.sha1` or `.md5`, computed |
| 400 | proxy | the path has a `.` or `..` segment, which the upstream URL would remove; cargo's `index/config.json` asked with no `Host` |
| 401 | proxy | a token is required and the request has none in a form read; its token is unknown, revoked or of a disabled account; or its Basic username is not the token's account |
| 404 | proxy | the path is outside `BYRLE_PROXY_URL`'s path, or under no ecosystem's prefix; a Go `@latest` naming a version the policy refuses |
| 405 | proxy | an artifact or manifest asked with a method but GET or HEAD, in enforce mode; `Allow: GET, HEAD` |
| 304 and every other upstream status | upstream | forwarded unchanged, including a 404 for a missing document or artifact |
| refusal status, 403 by default | proxy | the path is of no shape its adapter lists, such as a PyPI `.tgz` ([unrecognised-paths-refused](engineering_decisions/0119-unrecognised-paths-refused.md)); the version's risk score reaches `risk_threshold`; its artifact is on an origin the proxy does not serve; no strong digest, while `no_strong_digest` weighs the threshold; under a cooldown, nothing dates the file, while `cooldown_unanswered` weighs the threshold; the metadata does not list the version; Go's checksum database holds no record of a `go.mod`'s version, while `no_strong_digest` weighs the threshold |
| 502 | proxy | the upstream could not be reached, or stalled before answering; a metadata body failed; the registry gave no metadata for an artifact's package; the analysis job's fetch of the artifact did not match its digest; a Go `go.mod` is not the one the checksum database claims; a Go zip that is not the one claimed, is no zip, or is over the spool's ceiling, until the process restarts; a Go version's `.info` cannot be read; a Maven `.pom` or `.module` that is not the one its sidecar claims, or whose `.asc` does not verify |
| 503 | proxy | not ready: `account-store`, `intel-store`, `no-stream-for-ecosystem`, `checksum-database`, `artifact-analysis`; `/-/byrle/ready` while a policy is set and intel has not loaded or has a gap |

An artifact whose bytes do not match the digest has already been sent a 200. The last
chunk is held back, so the body ends short and the client's install fails. A body that
fails, or stalls 30 s, after its 200 also ends short. The 502 for a
mismatch comes from the analysis job's own fetch of the same digest, which is remembered
in process.

With no stream covering PyPI, a simple index is filtered without intel rather than
answered 503, because pip reports an index 503 as `No matching distribution found`. Its
files are answered 503 ([pypi-index-filtering](engineering_decisions/0050-pypi-index-filtering.md)).
Cargo, Go and Maven documents are filtered the same way.

A Maven file's claim is the first of the `.sha512`, `.sha256` and `.sha1` beside it
([maven-digests](engineering_decisions/0112-maven-digests.md)). A `.pom` and a `.module`
are never refused by policy. With an analyser, a `.pom`'s or `.module`'s first fetch is
503 `artifact-analysis` while a job checks it against its sidecar and its `.asc`; without
one it is checked in the request against its sidecar. A jar's
first fetch is 503 `artifact-analysis` while a job reads its sidecar, its `.asc` and the
key; a jar with none of the three sidecars has no strong digest, and is forwarded unverified
unless `no_strong_digest` weighs the threshold. A sidecar and an `.asc` are forwarded. A
`HEAD` of a jar is decided as its GET is; one of a `.pom` or `.module` is forwarded.
`maven-metadata.xml` is filtered as a metadata document, and its `.sha1` and `.md5` are
computed from what the proxy serves. Under `/gradle-plugins/`, a portal 303 to `plugins-artifacts.gradle.org` names
the file's sha256 in its path, which is the claim; one to Central is decided as under
`/maven/`.

## Tokens

Unless `BYRLE_REQUIRE_TOKEN=0`, every request except `/-/byrle/health` and
`/-/byrle/ready` carries a token from `byrle token create`. The proxy reads the first of
these it finds, and only that one:

| Order | Form | Sent by |
|---|---|---|
| 1 | `X-Byrle-Token: <token>` | a client that sets a custom header; `byrle warm` with `BYRLE_TOKEN` |
| 2 | `Authorization: Bearer <token>` | npm, pnpm, yarn 1 and bun with `_authToken` or `token`; mvn and Gradle with an `Authorization` header, which was not run |
| 3 | `Authorization: Basic`, the account as username and the token as password | pip and uv with `account:token@` in the index URL; go with it in `GOPROXY`, over https only; mvn from a `<server>`, Gradle from `credentials { }` and `./mvnw` from `MVNW_USERNAME` and `MVNW_PASSWORD`, each after the 401's `WWW-Authenticate` |
| 4 | `Authorization: <token>`, the token alone, starting `byrle_` | cargo, with `auth-required` in the proxy's `config.json` |

Each request asks the account store, and keeps no answer: a revoked token or a disabled
account is refused from the next request. Neither header is sent upstream: only
`Accept`, `Accept-Encoding`, `If-None-Match` and `If-Modified-Since` are. Observe mode
does not change a 401. A store that cannot answer is 503 `account-store`, after the
database pool's wait for a connection: 30.0 s per request with Postgres stopped, measured
2026-10-11. The intel store uses the same pool.

A request the policy refuses is refused before anything is fetched, but for the detectors'
signals, known once its artifact is analysed. A version the policy
refuses is also removed from the metadata document, so a resolver picks another version
and never asks for it.

Debug builds also answer `BYRLE_DEFER_TEST`'s scripted deferrals, after the token check,
the proxy-written files and the unrecognised-path refusal, and before anything else. See
[deferral-status-codes](engineering_decisions/0021-deferral-status-codes.md).
