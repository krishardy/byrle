# `byrle artifact reanalyse` deletes an artifact's stored results

- **Number:** 0148
- **Status:** Implemented 2026-11-26. `src/analysis/store.rs` (`Analyses::forget_analyses`),
  `src/analysis/postgres.rs` (`delete_analyses`), `src/analysis/decision/command.rs`
  (`reanalyse`), `src/cli.rs`.
- **Related:** [artifact-analysis-store](0063-artifact-analysis-store.md),
  [detectors](0092-detectors.md), [artifact-show-output](0145-artifact-show-output.md)

## Decision

`byrle artifact reanalyse <--digest|--purl|--npm>` deletes what was found in each artifact
it names. The proxy reads the analysis store on every fetch and analyses an artifact with
no result, so the next fetch, by `byrle warm` or an install, runs each analysis again.

| Deleted | Kept |
|---|---|
| `artifact_analysis` and, by its foreign key, `artifact_install_script`: install scripts and archive anomalies | `artifact_decision`, `artifact_disposition`: what was decided |
| `artifact_source`: the source comparison | `artifact_first_seen`: when each file was first seen, which dates it under a cooldown |
| `artifact_attestation`, `artifact_signature` | `artifact_claim`, `checksum_tree` |
| `artifact_virustotal` | |
| `version_detection`: each detector's result, in every repository of the version's ecosystem | |

The artifacts are those an `artifact_decision` or an `artifact_analysis` row names. The
watcher analyses versions no client has asked for, which have no decision. The deletes
run in one transaction.

It prints each digest and how many results were deleted, and exits 1 when nothing names
the artifact. With `BYRLE_REMOTE_URL` set it exits 2: the console offers no delete.

On 2026-11-26, against the development database with `BYRLE_DETECTORS` running GuardDog in
its container ([guarddog-container](0146-guarddog-container.md)):

```
$ byrle artifact reanalyse --npm express@5.3.0
sha512-qCqy1x...
5 stored results deleted. The next fetch of each artifact through the proxy analyses it again, such as `byrle warm` or an install
```

The next fetch of `express-5.3.0.tgz` was answered 503 while it was analysed, then 200.
The analysis, source, attestation and VirusTotal rows were written again, and GuardDog's
`version_detection` row followed, reporting `capability-network-outbound`.

## Rejected

- **A `--detector` filter.** Every result on the artifact goes. A detector's version
  already reruns its own results when it changes.
- **Deleting `artifact_first_seen`.** A file first seen again today would restart its
  cooldown.
