# Request flow

How the proxy answers one request, and where each status code comes from. Read from
`handle` and `Exchange`, `decide_artifact` and `Deciding`, and `filtered_document` in
`src/proxy.rs`, on 2026-09-28.

"Refusal status" is `WAHAROA_REFUSAL_STATUS`: 403 by default, settable per ecosystem and
client to any code from 400 to 599. Every 503 carries `Retry-After: 1` and
`x-waharoa-not-ready` naming the case.

```mermaid
flowchart TD
    REQ([request]) --> OWN{path}
    OWN -->|/-/waharoa/health| H200[200: counters]
    OWN -->|/-/waharoa/ready| READY{intel store configured<br/>and not loaded?}
    READY -->|no| R200[200]
    READY -->|yes| R503[503]
    OWN -->|anything else| KIND{what the path names}

    KIND -->|artifact, GET| LOOKUP{metadata for the package<br/>held, or fetched now}
    KIND -->|metadata document| FWD
    KIND -->|artifact HEAD, or anything else| FWD

    LOOKUP -->|registry gave none| A502M[502: the registry gave<br/>no metadata]
    LOOKUP -->|names neither the version<br/>nor the file| AREF1[refusal status:<br/>cannot be assessed]
    LOOKUP -->|record found| INTEL{intel store, when a<br/>policy and a store are set}

    INTEL -->|cannot answer| A503I[503 intel-store]
    INTEL -->|no stream covers<br/>the ecosystem| A503E[503 no-stream-for-ecosystem]
    INTEL -->|answers, or none set| POLICY{policy on what is known}

    POLICY -->|refuses: denial, cooldown,<br/>advisory, KEV, malware,<br/>install scripts, provenance,<br/>yanked, deprecated| AREF2[refusal status:<br/>refused by policy]
    POLICY -->|passes| ORIGIN{artifact on an origin<br/>the proxy does not serve?}
    ORIGIN -->|yes| AREF3[refusal status]
    ORIGIN -->|no| DIGEST{strong digest<br/>published?}
    DIGEST -->|no| AREF4[refusal status:<br/>cannot be assessed]
    DIGEST -->|yes| ANALYSIS{analysis of these bytes}

    ANALYSIS -->|last fetch did not<br/>match the digest| A502X[502: bytes the metadata<br/>does not describe]
    ANALYSIS -->|not finished, or never<br/>stored: upstream 404,<br/>fetch failed, past deadline| A503A[503 artifact-analysis<br/>job started]
    ANALYSIS -->|stored, or nothing to read| FWD

    FWD[fetch from upstream] --> SENT{upstream answered?}
    SENT -->|connect failed, or 10 s<br/>without connecting| U502[502]
    SENT -->|yes| STATUS{upstream status}

    STATUS -->|not 2xx, or 304| PASS[upstream status,<br/>body forwarded]
    STATUS -->|2xx| BODY{metadata document<br/>the proxy reads?}

    BODY -->|artifact 200| VERIFY{bytes match<br/>the digest?}
    VERIFY -->|yes| V200[200]
    VERIFY -->|no| CUT[200 sent, body cut off<br/>before its last chunk]

    BODY -->|other, or not readable| PASS
    BODY -->|document| BUF{buffered under<br/>WAHAROA_MAX_METADATA_BYTES?}
    BUF -->|over it| PASS
    BUF -->|body failed, or 30 s<br/>without a byte| D502[502]
    BUF -->|yes| DINTEL{intel store}
    DINTEL -->|cannot answer, or no stream<br/>covers npm| D503[503]
    DINTEL -->|answers, or no stream covers PyPI<br/>and its files answer 503| FILTER[200: refused versions removed,<br/>artifact URLs pointed here]
```

## Status codes

| Code | Produced by | When |
|---|---|---|
| 200 | proxy | health; ready; a verified artifact; a filtered and rewritten metadata document |
| 304 and every other upstream status | upstream | forwarded unchanged, including a 404 for a missing document or artifact |
| refusal status, 403 by default | proxy | the policy refuses the version; its artifact is on an origin the proxy does not serve; no strong digest; the metadata names neither the version nor the file |
| 502 | proxy | the upstream could not be reached or stalled; a metadata body failed; the registry gave no metadata for an artifact's package; the analysis job's fetch of the artifact did not match its digest |
| 503 | proxy | not ready: `intel-store`, `no-stream-for-ecosystem`, `artifact-analysis`; `/-/waharoa/ready` before intel has loaded |

An artifact whose bytes do not match the digest has already been sent a 200. The last
chunk is held back, so the body ends short and the client's install fails. The 502 for a
mismatch comes from the analysis job's own fetch of the same digest, which is remembered
in process.

With no stream covering PyPI, a simple index is filtered without intel rather than
answered 503, because pip reports an index 503 as `No matching distribution found`. Its
files are answered 503 ([pypi-index-filtering](engineering_decisions/pypi-index-filtering.md)).

A request the policy refuses is refused before anything is fetched. A version the policy
refuses is also removed from the metadata document, so a resolver picks another version
and never asks for it.

Debug builds also answer `WAHAROA_DEFER_TEST`'s scripted deferrals before any of this. See
[deferral-status-codes](engineering_decisions/deferral-status-codes.md).
