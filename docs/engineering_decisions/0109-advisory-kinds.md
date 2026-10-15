# Every advisory is read, and its kind is a signal of its own weight

- **Number:** 0109
- **Status:** Implemented, decided by the user 2026-10-14

Decided by the user 2026-10-14, while adding cargo ([cargo-plan](../cargo-plan.md) Q6):
read every RustSec advisory, and give the risk vector a feature for each kind of advisory,
with different weights.

## What OSV's crates.io bundle holds, measured 2026-10-14

3,584,713 bytes: 1,601 `GHSA-`, 1,295 `RUSTSEC-` and 21 `MAL-` records. RustSec writes a
record's kind in `affected[].database_specific.informational`, null for a vulnerability:

| Kind | `RUSTSEC-` records, not withdrawn | With no GHSA alias |
|---|---|---|
| vulnerability | 794 | 113 |
| unmaintained | 257 | 251 |
| unsound | 213 | 55 |
| notice | 6 | 3 |

105 of the vulnerabilities have no score, and no alias with one. `max_cvss` refuses an
unscored advisory, so each refuses its crate's versions until `advisory_scores` scores it.

rustls 0.23.45's four advisories of 2026-10-14, RUSTSEC-2026-0346 to 0349, were in the
bundle only as `RUSTSEC-` records. Their CVSS 3.1 scores are 4.0, 2.3, 3.7 and 3.7, so the
default `max_cvss: 6.9` serves 0.23.45 and `max_cvss: 3.9` refuses it.

## Decision

| Kind | Stored as | Refused by | Signal | Default weight |
|---|---|---|---|---|
| malware | `advisory.malware` | `known_malware` | `advisory_malware` | 8 |
| vulnerability | neither column | `max_cvss`, `kev` | `advisory_vulnerability` | 4 |
| unsound | `advisory.informational` | nothing | `advisory_unsound` | 3 |
| unmaintained | `advisory.informational` | nothing | `advisory_unmaintained` | 2 |
| notice, or a kind this build does not know | `advisory.informational` | nothing | `advisory_notice` | 1 |

`Facts::with_intel` leaves informational advisories out, so none reaches `max_cvss`: none
of the 476 is scored, and each would otherwise refuse its crate. The signals come from the
same intel lookup as the verdict, so the audit line's `risk_score` includes them.

The kind belongs to the advisory, not to cargo: every npm and PyPI version with a
vulnerability or malware advisory now carries a signal too, and a higher risk score.

`advisory.informational` is migration 0024, with no `CHECK`. The rows encoding carries it
as an eighth `advisory` column, so the format line is `byrle intel rows 3` and a kept
`rows 2` file is refused, as `rows 1` was in
[osv-ranges-and-scores](0029-osv-ranges-and-scores.md).
