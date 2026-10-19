# The allocator returns freed memory at once

- **Number:** 0120
- **Status:** Decided by the user 2026-10-19, option C. Implemented 2026-10-19:
  `BYRLE_ALLOCATOR_PURGE_DELAY_MS`, `allocator::set_purge_delay`, called by `byrle daemon`.
- **Related:** [default-ceilings](0085-default-ceilings.md),
  [release-provenance](0108-release-provenance.md),
  [environment-variables](0033-environment-variables.md)

## Decision

`byrle daemon` sets mimalloc's `purge_delay` to `BYRLE_ALLOCATOR_PURGE_DELAY_MS`, 0 by
default, before it allocates for a request. mimalloc then returns a freed page to the
system when it is freed. The variable overrides mimalloc's own `MIMALLOC_PURGE_DELAY`.
Other commands keep mimalloc's default.

## Why

mimalloc v3, from `libmimalloc-sys` 0.1.49, purges after 1000 ms by default, and only when
the thread that freed the memory next allocates. A tokio worker that finished the last
document of a load allocates nothing more, so RSS stayed at its peak while idle. In the vite
load, RSS sampled every 0.2 s was 576 MB at the end of the load and 616 MB for each of the
next 30 s.

`make memory`, 2026-10-19, at `9cb58b9`, `target/release` (glibc, mimalloc v3), idle 30 s
after the load, in MB:

| Load | mimalloc's default | `MIMALLOC_PURGE_DELAY=0` | this change |
|---|---|---|---|
| `npm ci`, 207 packages | 193 | 124 | 130 |
| `uv pip install`, 18 packages | 136 | 94 | 115 |
| 8 at once: vite's full document | 410 | 67 | 67 |
| 24 at once: the 8 largest documents | 336 | 109 | 101 |

Base vite peaks were 469, 564 and 616 MB over three runs, so one run each does not show a
peak change.

`make bench`, median of 3 runs, in seconds, both within the latency budget:

| Set | proxy cold, default / 0 | analysed, default / 0 | warm cache, default / 0 |
|---|---|---|---|
| npm, 207 packages | 16.4 / 16.7 | 12.6 / 12.4 | 2.9 / 2.9 |
| pypi, 18 packages | 12.5 / 13.0 | 10.4 / 10.5 | 0.1 / 0.1 |

`libmimalloc-sys` names no constant for the option, so `allocator.rs` uses its index in v3's
`mi_option_e`, 15. A test runs a fresh process with `MIMALLOC_PURGE_DELAY=7` and reads 7 at
index 15; with 14 it fails.

`make mutants` over the change: 5 mutants, 3 caught, 1 unviable, 1 missed. The miss replaces
`run_daemon` in `main.rs` with a default exit code, which no unit test runs
([main-is-a-thin-wrapper](0049-main-is-a-thin-wrapper.md)). `make memory` shows the call
takes effect: the "this change" column.

## Rejected

| Option | Why not |
|---|---|
| `MIMALLOC_PURGE_DELAY=0` in the Containerfiles, compose file and runbook | a binary run alone keeps the default |
| `mi_option_set` with no variable | an operator could not trade RSS back for fewer system calls |
| `MALLOC_ARENA_MAX=2` | glibc's allocator only; the binary has used mimalloc since 2026-10-14 |
