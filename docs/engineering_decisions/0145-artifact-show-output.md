# `byrle artifact show` prints a list unless asked for `-o json`

- **Number:** 0145
- **Status:** Implemented 2026-11-25. `src/cli.rs` (`Output`), `src/analysis/decision/readable.rs`,
  `src/main.rs`.
- **Related:** [artifact-decisions](0105-artifact-decisions.md),
  [explain-by-npm-name](0143-explain-by-npm-name.md)

## Decision

| `--output`, `-o` | Prints |
|---|---|
| `text`, the default | each decision as a list: the purl, then `disposition`, `facts`, `detectors` and `decided under` |
| `json` | the JSON line the analysis store keeps, as before |

`artifact show --npm express@5.3.0` printed, on 2026-11-25:

```
pkg:npm/express@5.3.0
  digest   sha512-qCqy1x...
  decided  2026-11-25T05:32:50.34343553Z
  account  krishardy

  disposition
    action           allow
    answered         served
    ...
  detectors
    metadata    no findings
    source      no findings
    archive     no findings
    virustotal  not asked
```

A detector with nothing found prints `no findings`. Since 2026-11-26 a detector with no
result prints `off`, `no result when decided` or `did not run: <why>`, and the decision
above prints `virustotal  no result when decided`
([detector-states](0147-detector-states.md)).

`command::show` still writes JSON lines, and `readable::lines` renders them. `main.rs`
renders after `show` locally, and after a remote answer when `BYRLE_REMOTE_URL` is set, so
`GET /api/v1/artifact` is unchanged and one function prints both. A line that is not a
decision is printed as it came.

`artifact export` stays JSON Lines only: it is read by programs, a line per decision.
