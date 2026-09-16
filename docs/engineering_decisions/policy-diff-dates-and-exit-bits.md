# `policy diff`: a date per policy, and exit bits

- **Status:** Implemented. `When` and `exit_code` in `src/cli.rs`; `exit_bits` and the bits
  in `src/policy/diff.rs`; `run_policy_diff` in `src/main.rs`.
- **Plan reference:** §3, policy impact analysis: an unchanged policy compared with itself
  30 days on "shows exactly which packages break when entries lapse", the renewal workflow's
  scheduled job; and "Nonzero exit on any loosening transition".

## Decision

`--as-of` judged both policies at one date, so the same policy on both sides never moved.
It is replaced by a date per policy:

| Option | Judges | Takes | Default |
|---|---|---|---|
| `--from-date <DATE>` | `<FROM>` | `YYYY-MM-DD` or `+<days>d` | today, UTC |
| `--to-date <DATE>` | `<TO>` | `YYYY-MM-DD` or `+<days>d` | today, UTC |

When the two dates differ, stderr says so: `waharoa policy diff: <FROM> as of 2026-09-14,
<TO> as of 2026-10-14`.

The scheduled job compares a policy with itself 30 days on:

```
waharoa policy diff policy.yaml policy.yaml --to-date +30d --lockfile package-lock.json
```

The exit code is the OR of two bits, or 4 on its own:

| Bit | Set when |
|---|---|
| 1, `LOOSENED` | a check got looser, or cannot be compared (`Strictness::Incomparable`) |
| 2, `TIGHTENED` | a check got stricter |
| 4, `ERROR` | a listed version could not be read, or none was judged. An error before the report, such as a policy that does not load, exits 4 alone |

| Exit | Meaning for the scheduled job |
|---|---|
| 0 | nothing moves in 30 days |
| 1 | something loosens: a package ages past its cooldown |
| 2 | something tightens: an entry lapses |
| 3 | both |
| 4 to 7 | 4 OR-ed with the above: a version could not be read, or none was judged. 4 alone when the run stopped before a report |

A command line clap refuses exits 2 by default, which would read as a tightening. A refused
command line that starts `policy diff` exits 4 (`cli::exit_code`), and so does a variable
`policy diff` reads that does not parse (`or_exit_with`). Every other command keeps exit 2.

`main` reads the arguments with `std::env::args_os` to choose that code, which semgrep's
`rust.lang.security.args-os.args-os` flags. The arguments choose only an exit code, and the
program path is skipped, so the line carries a `nosemgrep` comment saying so.

| Asked of the user | Chosen | Not chosen |
|---|---|---|
| How to judge one policy at two dates | `--from-date` and `--to-date`, replacing `--as-of` | `--to-as-of` beside `--as-of`; one policy argument with `--as-of`; a `policy expiries` subcommand |
| Exit codes | bits, OR-ed: 1 loosening, 2 tightening, 4 error | tightening 3; loosening winning over tightening; tightening winning |
| Incomparable | the loosening bit, as the gate treated it | its own bit, 8; the error code |
| A store that cannot answer after some packages are judged | stop, exit 4, no report | report the error, continue, OR in 4 |
| A packument or publish times that cannot be read | report it, go on, OR in 4 | stop, exit 4 |
| A 404 for a packument | a read that failed | a skip, as for a version no longer published |
| Every listed version skipped, for any reason | OR in 4 | exit 0 |
| Publish times that cannot be read, in `explain` | exit 1 | `cooldown_days` reported unenforced |
| Which usage errors exit 4 | `policy diff` only | every command |

## What moves between two dates

| Between today and a later date | Direction |
|---|---|
| A `packages` entry with `expires` lapses | stricter: the check it excused applies again |
| A version ages past `cooldown_days` | looser: it is no longer quarantined |

`one_policy_at_two_dates_tightens_as_an_entry_lapses_and_loosens_as_a_cooldown_passes` has
both in one package: `install_scripts` goes from `excepted by packages[0]` to `FAIL block`,
and `cooldown_days` from `FAIL quarantine` to `pass`.

## Evidence

Live, debug build, `WAHAROA_AUDIT_LOG` unset, over `tests/fixtures/lockfiles/npm/package-lock.json`
and the kept npm snapshot, on 2026-09-14. `@babel/helper-validator-identifier` 7.29.7 was
published 2026-05-25, `@babel/highlight` 7.25.9 on 2024-10-22 and `picocolors` 1.1.1 on
2024-10-16.

A policy with `cooldown_days: 200` and a `packages` entry setting `cooldown_days: 0` for
`@babel/helper-validator-identifier`, expiring 2026-09-30, compared with itself at
`--to-date +30d`:

```
waharoa policy diff: <FROM> as of 2026-09-14, <TO> as of 2026-10-14
15 packages evaluated
1 moved

      1  cooldown_days stricter

pkg:npm/@babel/helper-validator-identifier@7.29.7  allow -> quarantine
    cooldown_days     excepted by packages[0] -> FAIL quarantine  (stricter)

waharoa policy diff: 0 loosened, 0 incomparable, 1 tightened
```

Exit 2. The same entry with `cooldown_days: 700`:

```
15 packages evaluated
3 moved

      2  cooldown_days LOOSER
      1  cooldown_days stricter

pkg:npm/@babel/helper-validator-identifier@7.29.7  allow -> quarantine
    cooldown_days     excepted by packages[0] -> FAIL quarantine  (stricter)
pkg:npm/@babel/highlight@7.25.9  quarantine -> allow
    cooldown_days     FAIL quarantine -> pass  (LOOSER)
pkg:npm/picocolors@1.1.1  quarantine -> allow
    cooldown_days     FAIL quarantine -> pass  (LOOSER)

waharoa policy diff: 2 loosened, 0 incomparable, 1 tightened
```

Exit 3.

| Run | Exit |
|---|---|
| that policy compared with itself, no dates | 0, `nothing moved` |
| `max_cvss: 7.0` to `max_cvss: 9.0`, no dates | 1, `2 loosened, 0 incomparable, 0 tightened` |
| a policy file that does not exist | 4 |
| no audit log and no lockfile, a policy that does not exist | 4 |
| `--as-of 2026-01-01` | 4, `unexpected argument '--as-of' found` |
| `--to-date tomorrow` | 4, ``invalid value 'tomorrow' for '--to-date <DATE>': `tomorrow` is neither YYYY-MM-DD nor +<days>d`` |
| `waharoa doctr` | 2 |
| `policy diff --help` | 0 |

Each mutation below was caught:

| Mutation | Caught by |
|---|---|
| `+<days>d` refused | `a_date_is_a_calendar_date_or_days_after_today` |
| `+<days>d` read without its `d` | the same |
| Days past jiff's last date give today | the same |
| A calendar date ignored | the same |
| `policy diff --help` exits 4 | `a_malformed_policy_diff_exits_its_error_bit_and_other_commands_exit_2` |
| Every refused command line exits 4 | the same |
| The program name read as the command | the same |
| Incomparable sets no bit | `not_applicable_against_anything_else_is_incomparable_and_fails_the_gate` |
| Tightening sets no bit | `everything_tightening_sets_only_the_tightening_bit`, `one_policy_at_two_dates_tightens_as_an_entry_lapses_and_loosens_as_a_cooldown_passes` |
| A loosening hides a tightening | the two-date test |
| `tightened` reads the wrong direction | both tests above |
| The tightening bit not 2 | `the_exit_bits_are_1_2_and_4` |
| The error code not 4 | the same |

The two dates reaching `decide`, the stderr lines and `or_exit_with` are in `src/main.rs`,
which no test runs. The runs above are their evidence.

## Reads that fail

Before this, a packument that could not be read was skipped and not counted, and a publish-time
read that failed made `cooldown_days` unenforced on both sides, so it did not move. With
`WAHAROA_UPSTREAM` set to `nope`, `ftp://x` or `http://`, which it then accepted as text, every read
failed and the run printed `0 packages evaluated` and `nothing moved`, exit 0.

Now `npm::fetched` says which request failed and how, `Report::unread` counts it, and `Report::judged_none` is
true when versions were listed and none was judged. Either ORs 4 into the exit. A version the
registry does not list is still `no longer published` and sets no bit, unless it leaves nothing
judged. `explain` exits 1 for publish times it cannot read, as it does for a packument. The
proxy is unchanged: a publish-time read that fails there makes the check unenforceable, as its
comment at `publish_times_for` records.

`max_cvss: 7.0` to `max_cvss: 9.0` over the kept npm snapshot, live:

| Lockfile | Report | Exit |
|---|---|---|
| `lodash` 4.17.20, `waharoa-no-such-package-3b7f9e` 1.0.0, `minimist` 0.0.0-never-published | `1 packages evaluated`, `1 could not be read`, lodash LOOSER | 5 |
| only `minimist` 0.0.0-never-published | `0 packages evaluated`, `none of the 1 package versions listed was judged` | 4 |
| the 15 fixture versions, `WAHAROA_UPSTREAM=nope` | `15 could not be read`, `none of the 15 package versions listed was judged` | 4 |
| the 15 fixture versions | `2 loosened, 0 incomparable, 0 tightened, 0 could not be read` | 1 |

The 404 reads `packument could not be fetched: registry answered 404 Not Found`, and `nope`
reads `packument could not be fetched: registry request failed: builder error`. No live run
failed at publish times alone. `explain` and `run_policy_diff` read them with `npm::fetched`,
the same as the packument.

The counting and the reads in `run_policy_diff` are in `src/main.rs`, which no test runs; the
runs above are their evidence. Each mutation below was caught:

| Mutation | Caught by |
|---|---|
| An unread version sets no error bit | `a_version_not_read_or_nothing_judged_sets_the_error_bit` |
| Nothing judged sets no error bit | the same |
| Nothing listed read as nothing judged | the same |
| The error bit never set | the same |
| The report hides unread versions | the same |
| An unreadable body called a failed request | `a_failed_request_and_an_unreadable_body_are_told_apart` |
| A failed request called an unreadable body | the same |
| A read value refused | the same |

`WAHAROA_UPSTREAM_NPM`, which this command reads and which was called `WAHAROA_UPSTREAM`
when the run below was measured, is now refused unless it is an http or https URL with a host, so `nope`
exits 4 before any read. See [environment-variables](environment-variables.md).
