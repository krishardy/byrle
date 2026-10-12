# VirusTotal reports a signal on an artifact

- **Status:** Implemented 2026-10-13, decided with the user 2026-10-12. TODO Ad-hoc #31.
  `src/analysis/virustotal.rs`, `src/analysis/run/virustotal.rs`,
  `src/analysis/detector/virustotal.rs`, `migrations/0017_artifact_virustotal.sql`.
- **Related:** [detectors](detectors.md), [source-diff](source-diff.md),
  [artifact-analysis-store](artifact-analysis-store.md), [threat-model](../threat-model.md)

## Decision

| Part | What it is |
|---|---|
| role | report only. A detection is the built-in `virustotal` detector's rule `virustotal_detected`, a signal in the risk score that refuses nothing |
| off | when `BYRLE_VIRUSTOTAL_API_KEY` is unset. The startup log says which, as it does for the watcher |
| `BYRLE_VIRUSTOTAL_MODE=hash` | the default. The artifact's SHA-256 is looked up; nothing is uploaded |
| `BYRLE_VIRUSTOTAL_MODE=upload` | as `hash`, and an artifact VirusTotal does not know is uploaded, only when it came from a public registry (below) |
| running | in the background, never deferring a request, at most one job per artifact digest, behind a limiter of `BYRLE_VIRUSTOTAL_PER_MINUTE` (4) and `BYRLE_VIRUSTOTAL_PER_DAY` (500) requests |
| stored | by the artifact's digest: its SHA-256, the counts, and when it was asked. Every request made is logged in the database, so a restart does not reset the day's budget |

## The SHA-256 is computed from the bytes

VirusTotal looks a file up by MD5, SHA-1 or SHA-256. npm publishes SHA-512, and its
packument's SHA-1 `shasum` is a claim the proxy never checks. The job fetches the artifact
again from where the proxy fetched it, verifies the digest the metadata published, and
hashes the verified bytes. Decided with the user: every artifact is fetched again, not only
those analysed before this change. The spool file a request wrote is deleted when the
request ends, and a job waits for the limiter, so there are no bytes left to hash. At 500
lookups a day, that is at most 500 downloads a day.

## What may be uploaded

Files uploaded to VirusTotal join its dataset, which its subscribers can download. An
artifact is uploaded only when its URL is on `https://registry.npmjs.org`,
`https://files.pythonhosted.org` or `https://pypi.org` with no user information in it.
Anything from another upstream, a mirror or `BYRLE_ARTIFACT_ORIGINS` is looked up by hash
only. The proxy removes the client's `Authorization` before every upstream request
(`proxy::upstream_headers`), so it fetches no package that needs a credential. Up to 32 MB
goes to `POST /files`; up to 650 MB through `/files/upload_url`; larger is looked up only.

## When it is asked again

| Stored | Asked again after |
|---|---|
| known, with counts | 7 days: engines add detections to files they scanned before |
| unknown, not uploaded | 1 day |
| uploaded, analysis queued | 5 minutes, at `/analyses/{id}`, until completed |
| a 429 or a failed request | nothing stored; the next decision starts it again |

## The API, as documented on 2026-10-12

| | |
|---|---|
| lookup | `GET /api/v3/files/{sha256}`, header `x-apikey`; counts at `data.attributes.last_analysis_stats`: `malicious`, `suspicious`, `undetected`, `harmless`, `timeout`, `confirmed-timeout`, `failure`, `type-unsupported` |
| unknown | 404, `{"error": {"code": "NotFoundError", ...}}` |
| quota | 429, `QuotaExceededError` or `TooManyRequestsError` |
| key | 401, `WrongCredentialsError` or `AuthenticationRequiredError` |
| upload | `POST /api/v3/files`, `multipart/form-data`, field `file`, up to 32 MB; answers `data.id`, an analysis id |
| analysis | `GET /api/v3/analyses/{id}`: `data.attributes.status` `queued`, `in-progress` or `completed`, and `data.attributes.stats` |
| public quota | 4 requests a minute, 500 a day |

The public API's terms say it "must not be used in commercial products or services". A
commercial deployment needs a premium key; the limits are settings for that reason.

## The signal

`virustotal_detected` fires when `malicious` plus `suspicious` is above 0, with the detail
`N malicious, M suspicious of T engines`. It weighs 1 unless `signal_weights` says
otherwise, as every rule does. A stored result older than the recheck time is still read,
and a new job is started.

## Tested

Against local servers standing in for the artifact's origin and VirusTotal's API, in
`src/analysis/run/virustotal.rs`: a lookup's counts stored with its SHA-256; an unknown
file left unknown in `hash` mode, uploaded in `upload` mode, uploaded through an upload URL
above the direct limit, not uploaded above the maximum or from an origin not listed; a
queued analysis polled; nothing stored on a 429, a fetch that fails, a digest mismatch or a
file over the spool's ceiling. `src/proxy.rs` reports the signal on the request after the
lookup ends, asks nothing about a blocked version, and the watcher asks about a new one.

Mutation: with the origin check replaced by `true`,
`an_unknown_artifact_is_uploaded_only_when_allowed` fails with `left: Queued("an-1")` against
`right: Unknown`, "a private origin is never uploaded from".
