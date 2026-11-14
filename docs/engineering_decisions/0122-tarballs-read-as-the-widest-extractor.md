# A tarball is read as the extractor that reads the most would read it, and its odd shapes are a signal

- **Number:** 0122
- **Status:** Decided by the user 2026-10-29, for findings 1 and 6 of the security review
  (TODO.md ad-hoc #50). Implemented 2026-10-29: `walk`, `Unpacked`, `installed` and
  `Anomaly` in `src/analysis.rs`, `src/analysis/detector/archive.rs`,
  `migrations/0031_artifact_anomaly.sql`.
- **Related:** [install-scripts-from-the-artifact](0062-install-scripts-from-the-artifact.md),
  [artifact-spool](0064-artifact-spool.md), [detectors](0092-detectors.md),
  [every-refusal-a-signal](0116-every-refusal-a-signal.md)

## Decision

| Change | Replaces |
|---|---|
| Every gzip member is decoded, in turn | the first member only (`flate2::read::GzDecoder`) |
| After the first zero block, the walk goes on with `ignore_zeros` and visits what follows | stopping at the first zero block |
| Every entry is visited | stopping at the first matching `package.json` |
| npm: the scripts of every entry that extracts to `package.json`, after `strip: 1` and with empty and `.` components dropped | the first `<top>/package.json` |
| cargo: what every `<top>/Cargo.toml` names | the first |
| A tarball decompressing past `MAX_UNPACKED_BYTES`, 4 GiB, is `TooLarge` | no bound on the whole |
| The shapes below are stored with the analysis, and are the signal `archive_suspicious`, weight 1 unless weighed | nothing |

| `Anomaly` | What it is |
|---|---|
| `GzipMembers(n)` | more than one gzip member |
| `AfterGzip` | bytes after the last member that do not start another |
| `AfterEnd` | entries or bytes after a zero block |
| `Duplicate(path)` | a second entry extracting to `path`, as npm extracts |

An anomaly does not make the archive `Unreadable`. Bytes that do not decode as gzip or as
a tar header before the first zero block still do, and still count as install scripts.

## Why

Measured 2026-10-29 with npm 11.21.1's node-tar and Python 3's `tarfile`, which pip
unpacks an sdist with:

| Tarball | node-tar | `tarfile` | before |
|---|---|---|---|
| a tar with no end blocks, continued in a second gzip member | both entries | both | the first |
| one member, a single zero block between entries | both | the first | the first |
| a whole second tar in a second member | the first | the first | the first |
| `package/package.json`, then `package/./package.json`, `package//package.json` or `other/package.json` | the second, at `package.json` | | the first |

In the first row pip runs a `setup.py` that only the second member holds. In the last,
npm installs the second manifest, and pnpm, yarn and bun run its scripts.

Reading the union of what every extractor sees means no one extractor's reading is missed.
A packer writes none of these shapes: npm pack, cargo package and the sdist builders each
write one gzip member, one tar and one entry per path.

## Rejected

| Option | Why not |
|---|---|
| Refuse bytes after the first gzip member | misses the single-zero-block case, which is one member |
| Count an anomaly as install scripts | the user, 2026-10-29: flag it, not treated as running scripts |
| Read the last copy of a manifest | the last for node-tar is not the last for every client; the union holds for all |

## Cost

Every member of every npm and cargo tarball is decompressed, where a read used to stop at
`package.json`. A digest is analysed once per `READER`, which is now `install-scripts 5`,
so every artifact is read again once.
