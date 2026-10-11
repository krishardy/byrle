# `doctor` checks pip and uv, and reads uv's TOML configuration

- **Status:** Implemented 2026-09-19. `src/ecosystem/pypi/clients.rs`, `RegistrySource`,
  `check_extra_indexes` and `CacheBypass::None` in `src/doctor.rs`,
  `origin::without_credentials`.
- **Related:** [environment-variables](environment-variables.md),
  [deferral-status-codes](deferral-status-codes.md)

## Decision

PyPI's registry row lists pip and uv, and `byrle doctor` checks each for three things: the
index it installs from, any other index it also asks, and its cache.

| | pip 26.1.1 | uv 0.12.5 |
|---|---|---|
| index read from | `pip config list`: `:env:.index-url`, then `install.index-url`, then `global.index-url`, else pypi.org | its variables (`UV_DEFAULT_INDEX`, then `UV_INDEX_URL`), then the nearest `uv.toml` or `pyproject.toml` `[tool.uv]`, the user's `uv/uv.toml`, `/etc/uv/uv.toml`, else pypi.org |
| extra indexes | every `extra-index-url` key | `UV_EXTRA_INDEX_URL`, `UV_INDEX`, `extra-index-url`, and each `[[index]]` without `default = true` |
| warm cache, second install through the proxy | the index and the files reach the proxy again: `CacheBypass::None`, reported ok | nothing reaches the proxy: `CacheBypass::Complete`, reported as a warning |

An extra index is a problem: pip with an `extra-index-url` fetched every file from that index
on 2026-09-16, and the proxy saw no `/packages/` request.

## Why each is read rather than asked

npm, pnpm and yarn print the registry they resolve to with `config get`. Neither Python client
has an equivalent:

- `pip config get global.index-url` answered `No such key` for a key `pip config list` showed
  set. `pip config list` does list values, and includes pip's own variables as `:env:` keys.
- uv has no command that prints its configuration.

## Credentials are not printed

`pip config list` prints values as written, and an index URL can carry a user and a password.
Running it on the development machine on 2026-09-19 put one in a session transcript. Every URL
`doctor` prints goes through `origin::without_credentials`, which drops `user:password@`.
`doctor` on that machine reported the extra index with its host and path, and no
credential.

## The TOML parser

uv's configuration is TOML, and no crate in the tree read TOML. `toml` 1.1.6 was added with
default features off and `parse` and `serde` on. It adds five crates, all from the `toml-rs`
and `winnow` projects. `make check-deps` reported no vulnerable dependency after it.

| Crate | Version | Downloads, 90 days, 2026-09-19 |
|---|---|---|
| `toml` | 1.1.6 | 221,937,541 |
| `toml_parser` | 1.1.3 | 127,754,558 |
| `toml_datetime` | 1.1.1 | 240,889,140 |
| `serde_spanned` | 1.1.1 | 167,680,359 |
| `winnow` | 1.0.4 | 265,630,875 |

| Alternative | Why not |
|---|---|
| uv's variables only | A `uv.toml` with an extra index would go unreported |
| Run `uv pip install --dry-run --verbose` and read which indexes it logs | Depends on uv's log text, which is not an interface |

A file that is not TOML is skipped: uv refuses it, so it configures nothing.

## Not done

- The 2026-09-16 finding that pip's cache supplies an install without asking any index was
  against pypi.org. Through the proxy, pip asked again. Why is not measured.
- pip's configuration precedence between files (site, user, global) is not read:
  `pip config list` does not say which file a key came from.
