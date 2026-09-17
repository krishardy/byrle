# An ecosystem no stream covers fails closed

- **Status:** Implemented. `intel_for` and `snapshot_named` in `src/proxy.rs`,
  `LoadedSnapshot::uncovered` in `src/intel/store.rs`, `store::for_command` in `src/intel/store.rs`.
- **Related:** [intel-in-decisions](intel-in-decisions.md),
  [nvd-role-and-stream-capabilities](nvd-role-and-stream-capabilities.md),
  [adapter-interface](adapter-interface.md)

## The defect

Every advisory stream this build loads is npm's. A PyPI lookup against that store returned
the snapshot and no rows, because `PgIntel::package` selects the snapshot and `LEFT JOIN`s
the advisories. `intel_for` read that as "nothing known", the policy allowed the file, and
the audit entry recorded the snapshot as used. A PyPI package with a known vulnerability
was served and the log said it had been checked.

## Decision

With a policy and a store, a package whose ecosystem has a gap in the snapshot is answered
503, like a store that cannot answer:

| Snapshot, for the package's ecosystem | Proxy answers |
|---|---|
| a stream provides `match` and one provides `malware` | decides with what the store knows |
| no stream provides `match`, or none provides `malware` | 503, body names the ecosystem |
| replaced by a refresh between reading the records and reading the streams | 503, as a store that cannot answer |

A gap is what `LoadedSnapshot::gaps` already reports at startup and in `waharoa doctor`,
for one ecosystem: `LoadedSnapshot::uncovered`. `malware` is required as well as `match`
because `known_malware` is the one check with no exception, and a snapshot with only
`github/npm` has a `match` stream and no `malware` stream.

No decision is made, so no audit entry is written. The log gets one ERROR line per gap:

```text
ERROR `pypi` is served with no stream providing match, so a policy answers 503 for its
      packages. Nothing can originate a finding for it; answering 503
```

## What is refused

A PyPI decision is made when a file is fetched, so a file request gets the 503. The simple
index is still served: nothing is decided on it and it is not filtered. `pip install`
therefore resolves and then fails on the first file.

An npm packument is decided on, so under a gap it gets the 503 too. A refresh that cannot
load `osv/npm` loads nothing, so a snapshot without an npm `match` and `malware` stream is
not written by this build.

Readiness is unchanged: `ready` is false when the store holds no snapshot or cannot
answer. A gap in one ecosystem leaves the others decidable, and marking the proxy not ready
would take npm out of a load balancer with it. `doctor` reports the gap as a warning.

Measured 2026-09-17 against Postgres after `waharoa refresh` loaded `osv/npm`,
`datadog/npm` and `cisa/kev`, with `cooldown_days: 0`:

| Request | Result |
|---|---|
| `GET /-/waharoa/ready` | 200, `"ready":true` |
| `GET /lodash` | 200 |
| `pip install idna` through the proxy | exit 1; each file request logged the two gaps and was answered 503 |
| `waharoa explain pkg:npm/lodash@4.17.21` | exit 0 |
| `waharoa explain pkg:pypi/idna@3.10` | exit 1, printing both gaps |

## Reading coverage once per snapshot

`PackageIntel::snapshot` is the digest the records came from. The proxy keeps the last
`LoadedSnapshot` it read and asks the store for a new one only when a lookup returns a
different digest. The streams are read from the snapshot the records came from, and the
store is asked once per refresh rather than once per request.

A refresh between the two reads makes the newest snapshot differ from the records' digest.
That lookup is answered 503.

## The commands

`waharoa explain` exits 1 for a package with a gap and prints the gap. `waharoa policy
diff` prints it, counts the package as unread, and compares the rest.

A kept snapshot records no streams, so `policy diff --snapshot` does not check coverage.
A PyPI package judged against a kept snapshot still reads as "nothing known".

## What this does not fix

PyPI is not servable under a policy with a store until its streams are loaded. That is
step 4 of the module-directory item in `TODO.md`.

An artifact whose metadata the proxy has not seen and cannot fetch is forwarded
unverified and undecided, whatever the ecosystem. That predates this decision.
