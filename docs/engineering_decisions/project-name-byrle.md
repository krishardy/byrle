# Project name: byrle

- **Status:** Implemented 2026-10-11. The code and docs use `byrle`.
- **Plan reference:** decision #13, and the plan header.
- **Supersedes:** [project-name-waharoa](project-name-waharoa.md).

## Decision

`byrle`. Decided by the user 2026-10-01. It replaces the working name `waharoa`, after an
informal cultural consultation on that name, in September 2026, was not in favour of it
([project-name-waharoa](project-name-waharoa.md#consultation-result)). A te reo Māori name
may be revisited if the project gains support and local Māori engineers become involved.

## Why the name

`byrle` (also `byrele`) is Old English for cupbearer, the servant who poured for the
household and checked what was in the cup before it was drunk. byrle checks what a
registry serves before it is installed.

## Registry check

Run 2026-10-11 by exact-name lookup, the same probe as for `waharoa`:

| Registry | `byrle` | Control | Control status |
|---|---|---|---|
| crates.io | 404 | `serde` | 200 |
| npm | 404 | `lodash` | 200 |
| PyPI | 404 | `requests` | 200 |
| GitHub | 200 | `rust-lang` | 200 |

The GitHub handle `byrle` is a user account created 2021-11-11, with no public
repositories, no name and no followers.

## Rename

Done 2026-10-11. `waharoa` became `byrle` in the crate and binary, the environment
variables (`WAHAROA_*` to `BYRLE_*`), the `x-byrle-*` headers, the `byrle.*` log fields,
the `/-/byrle/` paths, the `byrle-detector-` scratch directories, the scripts and the docs.
The old names are not accepted.

Left as `waharoa`:

| Where | Why |
|---|---|
| `migrations/*.sql` | sqlx checksums each applied migration, comments included, and refuses a database whose applied file changed. `0012` also matches the stored string `WAHAROA_GITHUB_TOKEN is unset, ...` |
| [project-name-waharoa](project-name-waharoa.md) and the text about the old name | It records the old name |

## GitHub home

`github.com/krishardy/byrle`, decided by the user 2026-10-11, since the `byrle` handle is
taken.
