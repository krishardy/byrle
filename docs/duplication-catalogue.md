# Duplication catalogue

Repeated code and repeated strings in the application, measured 2026-09-13 at `bf9f292`.
Nothing here has been consolidated yet. The DRY rule in CLAUDE.md applies to new changes;
this file is the backlog for code that already exists.

## Method

`make duplicates` runs `scripts/make/duplicates.py`. It reports and always exits 0.

| Scan | Unit | Threshold | Scope | Result |
|---|---|---|---|---|
| Blocks | consecutive lines, whitespace collapsed; blank, comment and bracket-only lines skipped | 8 lines | `.rs`, `.sh`, `.py` under `src/`, `tests/`, `examples/`, `scripts/`, fixtures excluded | 30 blocks: 5 production, 25 test |
| Strings | Rust string literals | 16 characters, 2 occurrences | `.rs` in the same directories | 37 touching production code; 131 test-only, 470 occurrences |

Rust after `#[cfg(test)]`, and everything under `tests/`, counts as test. The tables below
combine both scans with grep. P1, S2 to S5, T7 to T10 are blocks. P2, P4 to P12 and the two
literal tables are strings. P3, P5's counts, P13, S1, S6 and T1 to T6, T11, T12 are below
the thresholds, or are same-named functions, and were found with grep.

The Action column uses three values:

| Action | Meaning |
|---|---|
| consolidate | copies that can change independently and disagree without a test failing |
| helper | identical copies; one shared function replaces them |
| leave | the copies differ, are one line, or a test already pins the text |

## Production Rust

| # | What | Where | Action | Suggested |
|---|---|---|---|---|
| P1 | Packument GET: `Accept`, `Accept-Encoding: gzip`, status check, `Content-Encoding`, `decode_for_parsing`. 13 lines | `npm.rs:1236-1266` (`packument`), `npm.rs:1278-1300` (`publish_times`) | consolidate | one private fetch taking the `Accept` value, returning decoded bytes |
| P2 | Lock `.expect` messages: `"record store lock"` 6, `"verified artifacts lock"` 3, `"publish times lock"` 2 | `proxy.rs:294, 597, 608, 629, 989, 1126`; `308, 455, 816`; `1313, 1339` | helper | one method per mutex on the proxy state that locks and expects |
| P3 | Today's date: `jiff::Timestamp::now().to_zoned(TimeZone::UTC).date()` | `main.rs:189-193` (`run_policy_diff`), `main.rs:404-406` (`run_explain`), `proxy.rs:1289` (`fn today`) | done | `policy::today()`, with `policy check`. `report_policy` used `jiff::Zoned::now().date()`, local time, and now uses it too |
| P4 | User agent `concat!("waharoa/", env!("CARGO_PKG_VERSION"))` | `main.rs:555`, `main.rs:708` | consolidate | one `const USER_AGENT` |
| P5 | Command error output: 20 `eprintln!("waharoa <command>: ...")` and 23 `ExitCode::from(n)`. Repeated literals: `"waharoa explain: {e}"` (324, 345, 396), `"waharoa refresh: {e}"` (560, 568, 599), `"waharoa policy diff: {}: {e}"` (205, 215, 231), `"waharoa refresh: nothing loaded: {e}"` (576, 608) | `main.rs` | helper | a function taking the command name, message and exit code, alongside `or_exit` |
| P6 | `"packument is not valid JSON: {e}"` | `npm.rs:439`, `npm.rs:756` (`NormalizeError::Json`) | consolidate | one `const` or a shared `Display` arm |
| P7 | `"delete the lockfile and node_modules, then install again through the proxy"` | `doctor.rs:208`, `doctor.rs:219` | consolidate | `const` |
| P8 | Finding title `"proxy public URL"` | `doctor.rs:362`, `doctor.rs:376` | consolidate | `const` |
| P9 | `builder.build()` then `"<invalid purl: {e}>"` in two `Display` impls | `identity.rs:185-189`, `identity.rs:269-272` | helper | one function writing a builder result |
| P10 | ETag parsing: strip `W/`, then strip the quotes | `http.rs:236-240` (`mark_etag`), `http.rs:271-275` (`unmark_if_none_match`) | helper | one function returning the weak prefix and the inner tag |
| P11 | `format!("packages[{index}]")` | `main.rs:77`, `policy/packages.rs:155` | done | `packages::label()`, with `policy check` |
| P12 | `"the registry published no time for this version"` | `policy/facts.rs:105`, `policy/facts.rs:111` | consolidate | `const`, or merge the two match arms |
| P13 | serde `Visitor` with `expecting` and `visit_str` | `policy.rs:159-175`, `policy.rs:411-415`, `npm.rs:956-960` | leave | three small impls with different error text |
| P14 | `"over max_cvss {}: {}"` | `explain.rs:133`, `explain.rs:140` | leave | two arms of one `match` with different arguments |

### Production constants that tests repeat as literals

| Constant | Value | Test copies | Action |
|---|---|---|---|
| `npm::ABBREVIATED_ACCEPT` (`npm.rs:61`) | `application/vnd.npm.install-v1+json` | 43 | consolidate where the test means "what the proxy sends"; keep the literal where it checks the wire value |
| `npm::DEFAULT_REGISTRY` (`npm.rs:67`) | `https://registry.npmjs.org` | 13 | same |
| `npm::FULL_ACCEPT` (`npm.rs:64`) | `application/json` | 5 | same |
| `http::HOP_BY_HOP` entry (`http.rs:17`) | `proxy-authorization` | 2 | same |

### Production messages that tests assert

A reworded message fails these tests, so the copies cannot drift. Action: leave.

| Literal | Production | Tests |
|---|---|---|
| `the abbreviated packument carries no publish times` | `policy/facts.rs:109` | 6, in `audit.rs`, `explain.rs`, `policy/enforce.rs` |
| `the registry published no time for this version` | `policy/facts.rs:105, 111` | `policy/facts.rs:347, 374` |
| `expected <ecosystem>/<client>=<status> or default=<status>`, `status is not a number`, `expected <ecosystem>/<client>`, `unknown ecosystem` | `refusal.rs:96-123` (`parse`) | `refusal.rs:336-340` |
| `scheme is not http or https` | `npm.rs:257` | `npm.rs:2533, 3001` |
| `` version has no `dist` object ``, `` version has no `dist.tarball` `` | `npm.rs:1054, 1059` | `npm.rs:1694, 1698` |
| `this exact version is denied`, `which this policy does not have`, `unenforced, no advisory stream` | `explain.rs:97, 155, 180` | `explain.rs:266, 690, 377` |
| `no intel store was consulted, so nothing was asked`, `no exploitation stream is loaded, so no advisory is marked exploited` | `policy/enforce.rs:112, 121` | `explain.rs:606`, `policy/diff.rs:659` |
| `upstream request failed`, `x-forwarded-proto` | `proxy.rs:948, 573` | `proxy.rs:2773, 3544` |

## Scripts

`scripts/make/lib/node.sh` is the existing precedent for a sourced helper.

| # | What | Where | Action | Suggested |
|---|---|---|---|---|
| S1 | `note() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }` | `check-deps.sh:25`, `lint.sh:19`, `semgrep.sh:114`, `sqlx-prepare.sh:18`, `test-integration.sh:18`, `update-deps.sh:19` | helper | `scripts/make/lib/note.sh` |
| S2 | Postgres container: start, `pg_isready` wait, cleanup trap. 17 lines | `sqlx-prepare.sh:26-45`, `test-integration.sh:24-43` | done | `scripts/make/lib/postgres.sh`, with the `pg_isready` fix |
| S3 | Proxy start and wait for `waharoa listening`. 21 lines | `retry-matrix.sh:57-84`, `smoke-clients.sh:41-74`; the wait alone in `inspect.sh`, `smoke-npm.sh` | consolidate | `scripts/make/lib/proxy.sh` |
| S4 | `mktemp -d` work directory and a cleanup trap that kills the proxy. 11 lines | `retry-matrix.sh:39-54`, `smoke-clients.sh:24-38` | helper | with S3 |
| S5 | `package.json` and `.yarnrc.yml` heredocs. 9 lines | `offsite-urls.sh:66-74`, `retry-matrix.sh:86-94`, `smoke-clients.sh:76-88` | consolidate | one function writing a client project directory |
| S6 | `repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"` | 17 scripts | leave | one line, and it must run before anything can be sourced |

## Test helpers

| # | What | Where | Action | Suggested |
|---|---|---|---|---|
| T1 | `fn fixture(name) -> Vec<u8>` reading `tests/fixtures/npm/` | `npm.rs:1339`, `policy/facts.rs:139`, `proxy.rs:1615` | helper | identical; a `#[cfg(test)]` module beside `src/golden.rs` |
| T2 | OSV fixture loaders | `intel/refresh.rs:219` (bytes), `intel/osv.rs:306` (parsed), `tests/intel_postgres.rs:288` `osv_fixture` (rows) | helper | share the path only; return types differ, and `tests/` cannot use a `#[cfg(test)]` library module |
| T3 | `CARGO_MANIFEST_DIR` path formatting, 13 sites | `golden.rs:7` and the loaders above | helper | removed by T1 and T2 |
| T4 | `fn facts() -> Facts` for `lodash` | `audit.rs:264`, `explain.rs:204`, `policy/diff.rs:255` | helper | identical |
| T5 | `fn loaded(yaml) -> Policy` | `explain.rs:217`, `policy/enforce.rs:219` | helper | identical |
| T6 | `async fn serve(router) -> String` | `npm.rs:2206`, `proxy.rs:1641` | helper | differ only in `expect` against `unwrap` |
| T7 | Test server: bind `127.0.0.1:0`, route `/lodash` to the fixture. 14 lines | `npm.rs:1831-1851`, `npm.rs:1869-1889` | helper | use T6 |
| T8 | `upstream_serving(StatusCode::OK, "application/vnd.npm.install-v1+json", None, fixture("lodash-4.17.21.abbrev.json"))`, 8 to 13 lines each | `proxy.rs:1829, 1862, 1884, 2347, 2385, 2532, 2559, 2601, 2643, 2689, 3561, 3597, 3634` | helper | one `lodash_upstream()` returning the upstream and its recorder |
| T9 | Recorder router answering `304` for `W/"abc123"`. 19 lines | `proxy.rs:2864-2883`, `proxy.rs:2929-2950`; the `304` builder also at `proxy.rs:3001-3016`; recorder setup at `proxy.rs:3423-3431` | helper | one router builder |
| T10 | `.send().await.unwrap(); assert_eq!(...)` | `proxy.rs:2177, 2194, 2225, 3053, 3085` | leave | the assertions differ after the shared lines |
| T11 | `fn malware_everywhere` | `policy/enforce.rs:223` returns `PackageIntel`; `proxy.rs:2415` returns `Arc<dyn Intel>` over the same records | helper | the proxy one wraps the enforce one |
| T12 | `fn sri_of` | `integrity.rs:263` takes an `Algorithm`; `proxy.rs:3177` is sha512 only | helper | the proxy one calls the integrity one with sha512 |

### Test-only literals

131 literals, 470 occurrences. Action: leave, except where a helper above removes them. A
test that names its own input can be read without opening another file.

| Literal | Count | Removed by |
|---|---|---|
| `lodash-4.17.21.abbrev.json` | 40 | T8, partly |
| `https://npm.corp.example` | 13 | |
| `pkg:npm/lodash@4.17.21` | 12 | |
| `http://127.0.0.1:8080` | 12 | |
| `{base}/widget/-/widget-1.0.0.tgz` | 12 | |
| `cooldown_days: 0` | 11 | |
| `fixture is missing` | 9 | T1, T2 |
| `policy should load` | 7 | T5 |
