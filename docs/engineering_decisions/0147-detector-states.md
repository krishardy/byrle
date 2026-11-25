# A decision records each detector with no result, and why

- **Number:** 0147
- **Status:** Implemented 2026-11-26. `src/analysis/decision.rs` (`NotRun`, `Unrun`),
  `src/analysis/decision/readable.rs`, `src/analysis/run.rs` (`FailedRun`),
  `src/analysis/run/detecting.rs`, `src/analysis/run/sourcing.rs`,
  `src/analysis/run/virustotal.rs`, `src/proxy.rs` (`Deciding::not_run`).
- **Related:** [artifact-decisions](0105-artifact-decisions.md),
  [artifact-show-output](0145-artifact-show-output.md), [detectors](0092-detectors.md),
  [virustotal](0104-virustotal.md), [source-diff](0091-source-diff.md)

## The case

`artifact show --npm express@5.3.0` printed, on 2026-11-25:

```
  detectors
    metadata    no findings
    source      no findings
    archive     no findings
    virustotal  not asked
```

VirusTotal had been asked. The decision was recorded at 07:35:45, and VirusTotal answered
at 07:50:48, behind 4 lookups a minute. All five decisions on 5.3.0 had `virustotal:
null`. A detector with no result was absent from `detectors`. One that failed, or was not
set, was absent too. A source comparison stored as not compared fired nothing, so it
printed `no findings`.

## Decision

`features.not_run` lists each detector with no result when the decision was made:

| `state` | When | `artifact show` prints |
|---|---|---|
| `off` | it is not set: no analyser, no `BYRLE_VIRUSTOTAL_API_KEY`, no source comparison | `off` |
| `pending` | it is set and had stored no result: running, waiting for its turn, or not started | `no result when decided` |
| `did-not-run`, with `why` | it cannot run on this artifact, or its last run in this process failed | `did not run: <why>` |

```json
"not_run":[{"detector":"source","state":"did-not-run","why":"the metadata names no source repository it reads"},{"detector":"virustotal","state":"pending"}]
```

A detector that ran is in `detectors`, as before, and prints `no findings` or what it
found. Each detector is in one of the two lists. A detection by a detector in `not_run`
is left out of `detectors`.

| Detector | `did-not-run` when |
|---|---|
| `source` | the metadata published no digest; it names no source repository the comparison reads; the comparison does not read the file; or it stored `NotCompared`, with that reason |
| `archive` | no digest; no install-script reader reads the file; the stored analysis could not read the archive; or the last fetch did not match the digest |
| `virustotal` | no digest, or its last lookup in this process failed |
| any other | its last run in this process failed, or ran past the deadline |

`virustotal` prints once. Its answer, when there is one, is printed over its run in
`detectors`. A decision recorded before this change has no `not_run`. Its VirusTotal row
prints `no result when decided`, which is what its `null` meant.

## Failures are kept in this process only

A detector run or VirusTotal lookup that fails stores nothing, so it runs again on the
next request. The analyser keeps why each one last failed, by detector run or by digest, in
an LRU map bounded like the mismatched digests. A run that succeeds is forgotten. After a
restart a failed run reads as `pending` until it fails again.

A source comparison that fails without storing, such as an archive that was not fetched
or no tag found yet, reads as `pending`. It is tried again on the next request.

## Not done

`artifact show` prints what the decision recorded. It does not read the analysis store for
VirusTotal's answer since. A remote `artifact show` reads `GET /api/v1/artifact`, which
returns decisions only, so that would need the API to return the current answer too.
