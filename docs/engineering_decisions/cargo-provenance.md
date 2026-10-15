# cargo provenance: what crates.io publishes about who published a version

- **Status:** Measured 2026-10-15. Decided by the user 2026-10-15: `trustpub_data` is read
  as a risk signal. Implemented as the `trustpub` detector:
  `src/analysis/detector/trustpub.rs`, `src/ecosystem/cargo/trustpub.rs`.
- **Related:** [provenance-check](provenance-check.md),
  [pypi-provenance](pypi-provenance.md), [advisory-kinds](advisory-kinds.md),
  [detectors](detectors.md)

## Decision

`provenance` stays reported unenforced for cargo. The `trustpub` detector, built in, reads
`trustpub_data` and refuses nothing:

| Rule | Fires on a cargo version when | Detail |
|---|---|---|
| `trustpub_dropped` | it has no `trustpub_data`, and an earlier version has | `published by <login>; 0.3.0 was published from github RustCrypto/utils`, for cpufeatures 0.3.1 |
| `trustpub_repository_changed` | its provider and repository differ from the latest earlier version with `trustpub_data` | `published from github rust-random/rand_core; 0.10.0-rc-2 was from github rust-random/core` |

Earlier is by `created_at`. Each rule weighs 1, the default for a rule `signal_weights` does
not set.

| Part | What it is |
|---|---|
| asked | `/api/v1/crates/{name}/versions?per_page=100&sort=date`, following `meta.next_page` until a page reaches before 2025-07, at most 20 pages |
| when | in the background, as a command detector runs, on each cargo version a decision serves and has no stored result for. A version the policy blocks is not asked about |
| pace | one request each `BYRLE_CRATES_API_INTERVAL_MS`, 1000 by default, across all runs |
| which API | `BYRLE_CRATES_API`. Unset, `https://crates.io` when `BYRLE_UPSTREAM_CARGO` is crates.io's index, else none: a mirror's crates are not looked up on crates.io under the same names. `off` asks nothing |
| stored | the detection, by detector version, as a command's is. A version listed nowhere since 2025-07 is stored with nothing fired when the pages reached before it, and not stored otherwise |
| failure | a 429, a 5xx, a 404 or a page that does not parse stores nothing, and the next decision asks again |
| User-Agent | `byrle/<version> (https://github.com/krishardy/byrle)` |

npm publishes signed attestations, which the `provenance` check verifies and refuses on, so
npm's `_npmUser.trustedPublisher` is not read as a signal.

## Where it is published

| Source | `trustpub_data` | Cost |
|---|---|---|
| Sparse index line | absent: `cksum`, `deps`, `features`, `features2`, `name`, `pubtime`, `rust_version`, `v`, `vers`, `yanked` | none |
| Daily database dump | `"private"` in crates.io's `dump-db.toml`: "until we can guarantee a stable data schema" | none |
| API, `/api/v1/crates/{name}/versions?per_page=100` | on each version | one request per crate per 100 versions, at most 1 a second |
| Attestation or Sigstore endpoint | none in `https://crates.io/api/openapi.json` | |

`trustpub_data` is crates.io's record of the trusted publishing token a version was
published with. Nothing signs it. For GitHub it holds `provider`, `repository`, `run_id`
and `sha`, and no workflow file. GitLab's form holds a `project_path`.

On the crate, `trustpub_only: true` makes crates.io refuse any publish of it that is not
by trusted publishing.

## Measured 2026-10-15

`examples/cargo_trustpub.py` read the newest 100 versions of the 500 most-downloaded
crates, 20,466 versions. None of the 46 crates with 100 or more versions had a version
since 2025-07-09 cut off. Trusted publishing opened in 2025-07.

| Month | Versions | With `trustpub_data` |
|---|---|---|
| 2025-07 | 93 | 1 |
| 2025-08 | 158 | 13 |
| 2025-09 | 252 | 18 |
| 2025-10 | 182 | 26 |
| 2025-11 | 122 | 25 |
| 2025-12 | 140 | 11 |
| 2026-01 | 210 | 22 |
| 2026-02 | 245 | 52 |
| 2026-03 | 169 | 27 |
| 2026-04 | 135 | 42 |
| 2026-05 | 109 | 39 |
| 2026-06 | 137 | 57 |
| 2026-07 | 181 | 25 |
| 2026-08 | 134 | 41 |
| 2026-09 | 143 | 51 |
| 2026-10 | 90 | 36 |

486 of the 2,500 versions since 2025-07 carry `trustpub_data`, from 70 crates. Each of
the 486 has `published_by: null`. Each of the other 2,014 names a user. 54 of the 70 crates
set `trustpub_only`.

### What the provenance check's rules would refuse

Read with the identity as provider and repository:

| Rule | Versions | Crates |
|---|---|---|
| none after one with it | 21 | 9 |
| another repository from the version before | 1 | 1 |

Every one of the 21 was published from a crate owner's account:

| Crate | Versions |
|---|---|
| `rand_core` | 0.10.0-rc-3, 0.9.4, 0.9.5, 0.10.0-rc-4, and 0.4.3, 0.3.2, 0.2.3, 0.1.1 on 2026-09-02 |
| `rand` | 0.10.0-rc.9, 0.10.0 |
| `pest`, `pest_derive`, `pest_meta`, `pest_generator` | 2.8.6, 2.8.7 each |
| `getrandom` | 0.2.17 |
| `cpufeatures` | 0.3.1 |
| `zip` | 9.0.2, between 9.0.1 and 9.0.3, both attested |

The change is `rand_core` 0.10.0-rc-5: `rust-random/core` to `rust-random/rand_core`.

On npm the same dropped-provenance rule refused 1 version in the sets of
[tier-1-false-positives](tier-1-false-positives.md).

## What the check could read, and not

| Case of the provenance check | cargo |
|---|---|
| an attestation that does not verify | nothing to verify |
| none after one with one | `trustpub_data` null after one set, as crates.io says |
| a repository and workflow file not established | the repository only |

A pinned fetch whose provenance is not known answers 503 under `provenance: block`. A
cold `cargo build` of 300 crates would need 300 API requests, 300 seconds at 1 a second.
cargo gave up after 4 attempts in about 3.1 seconds when it was measured on 2026-10-14.
