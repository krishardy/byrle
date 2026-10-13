# Each artifact decision is stored with its features and disposition

- **Status:** Implemented 2026-10-13, decided with the user 2026-10-13. TODO Ad-hoc #32, #33.
  `src/analysis/decision.rs`, `src/analysis/decision/command.rs`,
  `src/analysis/run/recording.rs`, `migrations/0018_artifact_decision.sql`.
- **Related:** [audit-log](audit-log.md), [artifact-analysis-store](artifact-analysis-store.md),
  [detectors](detectors.md), [virustotal](virustotal.md), [admin-plan](../admin-plan.md)

## Decision

Decided with the user: a row per decision, and the latest decision per artifact, read by
the console, by an export and by a command.

| Part | What it is |
|---|---|
| `artifact_decision` | one row per pinned audit line about an artifact, whether or not `BYRLE_AUDIT_LOG` is set |
| `artifact_disposition` | a view: the latest row for each digest |
| features | the facts the policy read, each detector's result (findings and errors), and VirusTotal's state and counts |
| disposition | the action, what the request was answered, the mode, the checks against it, the risk score, and the policy digest, intel snapshot, day and build it was decided under |
| `byrle artifact show <digest or purl>` | the latest row for each artifact named, as JSON Lines. Exits 1 when none is recorded |
| `byrle artifact export [--since] [--until]` | every row between the two days, oldest first, as JSON Lines |
| console | `Analyser::dispositions` and `Analyser::decisions` read the store. No route serves them until the console has logins (Stage 4.9 R1, R2) |

## A row is the audit line, with what the line leaves out

The audit line already holds `inputs.facts`, the action, `answered`, the account, the
policy digest and the snapshot. A row is built from the final line, at the point it is
written, so `answered` is what the client got:

| Line written | Row |
|---|---|
| refused, unservable, deferred, mismatched | when the proxy answers |
| served | once the upstream answers 2xx or 304 |
| `upstream-status`, `upstream-unreachable` | the served line, changed, as the log writes it |
| `cut-short` | a second row, with the served row's features and disposition |

A row adds three things to the line: the digest the metadata published, the mode, and the
detector and VirusTotal results the decision read. A detector with no entry had not run on
the version. One with an entry and no findings ran and found nothing. `errors` lists the
rules that could not run. VirusTotal is `null` until it has been asked, and `unknown` or
`queued` carry no counts.

## The features are those the decision read

VirusTotal and the detectors start when the proxy decides, and their results arrive after
it. A row records what was held when the decision was made, so the first decision on an
artifact usually has neither. Results that arrive later appear on the next decision.

The alternative was a view joining the latest decision with the newest result in
`artifact_virustotal` and `version_detection`. It was rejected: the features in a row would
then not be the ones its disposition was decided on, and a label that does not match its
features is wrong for training.

## Writing never delays a request

Each row goes onto a queue of 4,096 (`util::batched::QUEUE`). One task writes up to 256 at
a time (`util::batched::BATCH`) in one `INSERT`, every column read from the row's JSON. A row is
dropped when the queue is full or the write fails. Each drop is logged at WARN and counted
in `decisions_unrecorded` on `/-/byrle/health`.

Without `BYRLE_DATABASE_URL`, rows are kept in memory: the newest `BYRLE_MAX_VERIFIED`, as
the other analysis results are.

## Rows are deleted after `BYRLE_DECISION_RETENTION_DAYS`

Decided with the user 2026-10-13: a variable of its own, apart from
`BYRLE_LOG_RETENTION_DAYS`. The default is 365.

At startup and every 24 hours after, the proxy deletes each row decided before the UTC day
`BYRLE_DECISION_RETENTION_DAYS` before today. That day's rows are kept, as the log file
of the same age is. Each proxy on one database runs the same `DELETE`. A second run deletes
nothing. A failure is warned about, and the next day's run deletes what it left.

The latest row on an artifact is deleted with the rest. An artifact not requested within the
period is not in `artifact_disposition`, and `byrle artifact show` exits 1 for it.

## A row without a digest is kept, and not in the view

A version whose metadata publishes no strong digest is refused with `no-strong-digest` and
never analysed. Its row has `digest: null`. It is in the export and not in
`artifact_disposition`, which is keyed by the digest.

## Measured

On 2026-10-12 UTC, `npm install debug@4.4.1` through a proxy with a fresh intel store and the
default policy wrote four rows:

```
deferred|2
served|2
```

Two artifacts were in `artifact_disposition`. A row's JSON averaged 1,066 bytes.
`byrle artifact show pkg:npm/ms@2.1.3` printed:

```
{"at":"2026-10-12T18:11:47.82958612Z","digest":"sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA==","ecosystem":"npm","name":"ms","version":"2.1.3","account":null,"features":{"facts":{"published":"2020-12-08","known_malware":false,"advisories":[],"intel":"consulted","has_install_scripts":false,"yanked":null,"deprecated":null,"provenance":{"state":"consistent"}},"detectors":[{"detector":"metadata","findings":[],"errors":[]},{"detector":"source","findings":[],"errors":[]}],"virustotal":null},"disposition":{"action":"allow","answered":"served","mode":"enforce","checks":[],"unenforceable":[],"exceptions_used":[],"risk_score":null,"upstream_status":null,"policy_digest":"sha256:09bfcc6a14b83e2192b8673677725c84883ee9cd0c70e45c9ec09daa8f2b2847","intel_snapshot":"sha256:691c529e663cf6d78a707109a9c405e31da820e4e5d3ac6cea2ddf985d8de8ec","as_of":"2026-10-12","build":"0.1.0","reader":"install-scripts 2","verifier":"sigstore-verify 0.13.0; root sha256:6494e21ea73fa7ee"}}
```

## Not covered

| What | Why |
|---|---|
| metadata requests | a resolution line decides many versions and has no artifact, so it has no row |
| `served_version` in [admin-plan](../admin-plan.md) §4.3 | a table of its own, decided by the user 2026-10-13. It is not deleted after `BYRLE_DECISION_RETENTION_DAYS`, so R3 and R4 keep each version an account was served after its decision rows are deleted |
