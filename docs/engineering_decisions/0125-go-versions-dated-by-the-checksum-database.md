# A Go version is dated by its record in sum.golang.org, placed in time by index.golang.org

- **Number:** 0125
- **Status:** Decided by the user 2026-10-30, for finding 4 of the security review
  (TODO.md ad-hoc #50). Implemented 2026-10-30: `Heads` in `src/ecosystem/go/heads.rs`,
  `date`, `record` and `lookup` in `src/ecosystem/go/transport.rs`, `Answer::Known` in
  `src/ecosystem/go/sumdb.rs`, `latest` in `src/ecosystem/go/wire.rs`,
  `Policy::cooldown_start` in `src/policy.rs`.
- **Related:** [go-plan](../go-plan.md) Q3 and Q5,
  [quarantine-filter-metadata](0013-quarantine-filter-metadata.md)

## Decision

| What | Was | Is |
|---|---|---|
| a Go version's date, under a cooldown | its `.info` `Time` | the time of the first row that holds its record, below |
| `@latest`'s version | dated by the `Time` in its body | dated as a list's versions are, which takes the place of the body's `Time`; the body's when that fails |
| a pinned `.zip` or `.mod` | its own `.info` `Time` | the same rule, through `Fetch::version` with the cooldown's start |
| `byrle explain` and `byrle policy diff` | the `.info` `Time` | the same: their clients have no setting for the index or sum.golang.org |

sum.golang.org's log only appends. A tree head of size `S` holds records `0` to `S - 1`,
so a tree of size `S` seen at time `t` shows every record below `S` was public by `t`.
`Heads` keeps rows of `(size, time)`:

| Row | From |
|---|---|
| each tree head a lookup proves | `(tree size, now)`. A larger one within a minute of the newest row replaces it |
| an index entry | `index?since=<t − 1 h>&limit=1` gives `Path`, `Version` and `Timestamp`. Its lookup gives record `N`. The row is `(N, Timestamp + 1 h)` |

| Where record `N` falls | Its date |
|---|---|
| below every row | the earlier of its `.info` `Time` and the oldest row's time |
| between two rows | the time of the first row above `N`, after splitting: while the rows around `N` are more than 1 hour apart, an index entry at their midpoint is read and added |

Before a record is dated, a seed row at or before the cooldown's start is read:
`now − longest_cooldown`, at most 36,500 days. A record below the seed was public before
the cooldown started, so its `.info` `Time` can only be wrong about how much older it is.

When the index cannot be read, the seed is logged, and a record below every row is dated
by its `.info` `Time`, as before. When a split cannot be read, the record is dated by the
row above it. After either fails, no row is read for 5 minutes, so an index that drops
packets costs one 10 s connect timeout, not one per request. When sum.golang.org does not
answer, or has no record of the version, the `.info` `Time` dates it, logged. A version
dated before this change is still dated.

## Why

The go command fills `.info` `Time` from `%ct`, the committer date (`codehost/git.go`,
Go 1.27.3). `GIT_COMMITTER_DATE=2020-01-01T00:00:00Z git commit`, then a new tag, passes
any cooldown.

A record number is given out when sum.golang.org adds the record, which a publisher cannot
choose. Measured 2026-10-29:

| Check | Result |
|---|---|
| 1,200 index entries in 3 windows (2026-07-31, 10-22, 10-29), each looked up | 1,200 found. Records rise with `Timestamp`; the widest gap between two out of order is 5.41 s |
| `/latest` read at 18:48:48Z, size 70,413,096, then the 427 index entries of the next 5 minutes looked up | 0 records below 70,413,096 |
| the first published head holding each of 164 index entries | 10.2 s to 119.8 s after its `Timestamp`, median 82.3 s |
| the tree's growth | 637,000 records from 10-22 to 10-29, about 91,000 a day |

The 1-hour margin is 30 times the 119.8 s measured. The seed is read at `before − 1 h`, so
its row, `Timestamp + 1 h`, is at or before `before`.

## Rejected

| Option | Why not |
|---|---|
| a `sumdb_tree` table with `/latest` read on each watcher pass, and one seed | every record between the seed and the first head seen is dated at that head, so each version of the last `cooldown_days` is refused a full cooldown after install, and after each restart without a database. With the watcher off, a record is dated at its first lookup |
| dating by when this proxy first saw a version (`served_version.first_served`) | it is this proxy's date, not a public one, with the same gap at install |
| index.golang.org alone | it has no lookup by module, only a feed by time |
| refusing every version below the seed | the user chose to fall back to the `.info` `Time` when the index cannot be read |

## Cost

| What | How much |
|---|---|
| per version dated | one sum.golang.org lookup, with its tiles; full tiles and record numbers are kept |
| per split | one index read and one lookup; up to 20 for one record, about 8 for a week |
| per process | one seed read, again when the policy's longest cooldown grows |
| memory | up to 65,536 rows of 16 bytes |

A version is dated by when it became public on proxy.golang.org, not by its commit. A
pseudo-version of an old commit first fetched today is dated today:
`github.com/NYULibraries/dlts-finding-aids-ead-go-packages@v0.0.0-20230411191734-977beced97cd`
has a record added on 2026-10-22.

index.golang.org's answers are not signed. A wrong `Timestamp` would date records older or
newer than they are; it is trusted, as the threat model says.
