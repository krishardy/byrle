# Project name: byrle

- **Status:** Staging. The code still uses `waharoa`; the rename is in Stage 4.5 of `TODO.md`.
- **Plan reference:** decision #13, and the plan header.
- **Supersedes:** [project-name-waharoa](project-name-waharoa.md).

## Decision

`byrle`. Decided by the user 2026-10-01. It replaces the working name `waharoa`, after an
informal cultural consultation on that name, in September 2026, was not in favour of it
([project-name-waharoa](project-name-waharoa.md#consultation-result)). A te reo Māori name
may be revisited if the project gains support and local Māori engineers become involved.

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

## Outstanding gate

The rename itself. `waharoa` is in the crate and binary, the `WAHAROA_*` environment
variables, the `x-waharoa-*` headers, the `waharoa.*` log fields, the `/-/waharoa/` paths,
the `waharoa-detector-` scratch directories and the docs.

## GitHub home

`github.com/krishardy/byrle`, decided by the user 2026-10-11, since the `byrle` handle is
taken.
