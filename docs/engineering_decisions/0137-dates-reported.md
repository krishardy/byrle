# `explain` and `policy diff` date a version as the proxy does, and print each date read

- **Number:** 0137
- **Status:** Implemented 2026-11-08, for TODO.md ad-hoc #53: `src/dating.rs`
  (`date`, `Dating`, `Reader`), `Heads::placed` in `src/ecosystem/go/heads.rs`,
  `Fetch::version`'s `Versioned` in `src/ecosystem.rs`, `Analyses::sighted` in
  `src/analysis/store.rs` and `src/analysis/postgres.rs`.
- **Related:** [go-versions-dated-by-the-checksum-database](0125-go-versions-dated-by-the-checksum-database.md),
  [undated-files-first-seen](0129-undated-files-first-seen.md),
  [pep-503-html-index](0060-pep-503-html-index.md)

## Context

`byrle explain` and `byrle policy diff` passed `before: None` to `Clients::version_of`, so a
Go version was dated by its `.info` `Time`, the committer date. The proxy dates it by its
record in sum.golang.org (0125). `explain` reported a backdated version as allowed while the
proxy refused it. Neither command asked the file host's `Last-Modified` or read a first
sighting (0129), so both reported an undated version as having no date.

Neither printed where a date came from.

## Decision

The proxy, `explain` and `diff` call one function, `dating::date`. It reads the sources in
the proxy's order and returns each one read, what it gave, and the one used:

| Order | Source | Read by `explain` and `diff` | Read by the proxy |
|---|---|---|---|
| 1 | the record's own time, as its client read it. Go: the `.info` `Time` and the checksum database's record; Maven: the POM's `Last-Modified`; others: the metadata's time | always | always |
| 2 | the full document's time | always | when 1 gave none |
| 3 | the file host's `Last-Modified`, for a file on an origin the proxy serves | under a cooldown, when 1 and 2 gave none | the same |
| 4 | the file's first sighting | under a cooldown | under a cooldown, when 1 to 3 gave none |

`explain` and `diff` pass a cooldown start, as the proxy does: `explain` now's, `diff` the
earlier of each policy's as of its date. A Go version is then dated by its checksum record.

`explain` and `diff` read a first sighting with `Analyses::sighted`, which records nothing. Only
the proxy records one. `explain` reads it from `BYRLE_DATABASE_URL` on the command line and
from the proxy's store on the console.

`explain` prints the block after the checks. `diff` prints it under each package that moved:

```
  dates for widget-1.0.0.tgz, * the one used:
      the metadata's publish time    the metadata carries none
      the full document's time       its times do not list this version
    * the file host's Last-Modified  2026-09-17T00:00:00Z
      the file's first sighting      none stored
```

For Go, the checksum database's line names the record. Its time is the first tree head kept
that holds the record, or the oldest row for a record below every row; `*` marks the
`.info` `Time` when it is earlier (`Heads::placed`).

## Rejected

| Option | Why not |
|---|---|
| a `BYRLE_*` setting for index.golang.org and sum.golang.org, which #53 proposed for the tests | the tests build their Go client with `with_sumdb` and `with_index` through `Clients::with`, and stay off the network without it |
| asking the file host when an earlier source answered | a HEAD per listed version for a date not used, and one to the real registry in each test with a cooldown |

## Costs

`explain` and `diff` read the full document for every ecosystem that has one, `diff` now
also under a policy with no cooldown, and the first sighting under a cooldown. Each asks a
file host for a version that steps 1 and 2 leave undated.

`byrle policy check --fetch` still reads only the full document's times.
