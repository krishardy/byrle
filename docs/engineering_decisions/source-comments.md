# Three kinds of source comment

- **Status:** Implemented 2026-09-29 for the checker; files leave the baseline as they are
  brought under it. `scripts/make/comments.py`, `scripts/make/comments-baseline.txt`.
- **Related:** TODO item 23

## Decision

Source code carries three kinds of comment, and `make lint` refuses any other.

| Kind | Limit |
|---|---|
| `//!` module documentation | 4 lines per file |
| `///` on a function | 2 lines on what it does, plus 1 per parameter other than `self`, 1 for a return value, and 1 more for a `Result` |
| `///` on a type, field, variant, constant, `impl`, trait or module | 1 line |

An environment variable is a constant in `src/env.rs`, so it gets 1 line. Blank `///` lines
count toward the limit. A `//` comment, whole-line or trailing, is refused, except
`// nosemgrep:`, which semgrep reads as a directive. Test code is held to the same rules.

A comment that explains behaviour the code does not show marks the code to change until
it does: a name, a helper, a constant, or an `expect` message. The reasoning behind a choice,
and the measurement that settled it, goes in a record here.

## Why

On 2026-09-28 `src/` held 866 `//` lines, 5,148 `///` lines and 1,189 `//!` lines in 50,873
lines of code. Much of it restated the code or recorded a decision already written here, and
a comment is not checked against the code it describes.

## How it is enforced

`scripts/make/comments.py` reads each file in `src/` and `tests/`. It finds `//` comments
with a small lexer that skips strings, raw strings and character literals, and finds the
item a `///` block documents by looking past `#[..]` attributes.

Files that do not pass yet are listed in `comments-baseline.txt` and are not checked. A
listed file that passes is an error, so the list only shrinks, and the rule applies to a
file from the commit that removes it from the list.

`src/cli.rs` is the one file where a doc comment is behaviour: clap reads `///` on a command
or argument as its `--help` text. Help text longer than the limit moves into
`#[command(about = ...)]` or `#[arg(help = ...)]`, and text within it stays a `///` line.
Every `--help` page was byte-identical before and after.
