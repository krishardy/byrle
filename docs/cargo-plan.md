# Stage 6 plan: cargo, and an adapter interface that does not change

Stage 6's exit is five protocols, npm, PyPI, cargo, Go and Maven, on one unchanged
interface. This plans cargo, and the interface work before it. Written 2026-10-14.

## What crates.io serves, measured 2026-10-14

| | Measured |
|---|---|
| Sparse index root | `https://index.crates.io/config.json`: `{"dl": "https://static.crates.io/crates", "api": "https://crates.io"}` |
| Index file | `/se/rd/serde`, `text/plain`, one JSON line per version: `name`, `vers`, `cksum` (sha256 of the `.crate`), `yanked`, `deps`, `features`, `rust_version`, `pubtime`. serde's is 316 lines, 164,874 bytes, `max-age=600`, with an ETag |
| Publish times | `pubtime` on every line of serde's, back to 0.0.0 in 2014, so a cooldown needs no second request |
| Download | `{dl}/serde/1.0.229/download`, 83,669 bytes; its sha256 is the line's `cksum` |
| Provenance | no Sigstore attestation. The API's version record has `trustpub_data`, trusted publishing, `null` for serde 1.0.229 |
| Advisories | OSV's `crates.io/all.zip`, 3,579,876 bytes, which includes RustSec |
| Build-time code | of the 100 most-downloaded crates, 21 have a build script, among them `serde`, `libc`, `proc-macro2`, `quote`, `thiserror`, `anyhow`; 2 are proc-macros |

## The interface today

The `Registry` table in `src/ecosystem.rs:160` holds 19 per-ecosystem fields. Outside the
two adapters, about 30 places still branch on npm against PyPI, among them:

| Where | Branches on |
|---|---|
| `ecosystem.rs:25` | `Clients` holds an `npm::Client` and a `pypi::Client` as fields |
| `proxy.rs:1074`, `proxy.rs:1136`, `proxy.rs:3187` | reading and rewriting a document, through a `Read` enum with one variant per ecosystem |
| `proxy.rs:2246` | the attestation reader |
| `route.rs:26` | `DocumentKind`, one variant per ecosystem |
| `analysis.rs:77`, `analysis/source.rs:408`, `analysis/run/sourcing.rs:51` | how an artifact is read and compared with its source |
| `warm.rs:166`, `warm.rs:246` | upstream paths, and PyPI's wheel filter |
| `doctor.rs:371`, `doctor.rs:916` | PyPI's index format check |
| `intel/stream.rs`, `intel/range.rs` | a stream constant per ecosystem, and SemVer or PEP 440 |

Adding cargo to each of those would change the interface a third time, and Go and Maven
twice more.

## Decisions

Answered by the user 2026-10-14: Q1 yes; Q3 yes, on any path; Q4 as `install_scripts`, not
the check of its own recommended; Q5 deferred until there are measurements and a reliable
source of attestation data. Q2 and Q6 are taken as recommended.

| | Question | Recommended |
|---|---|---|
| Q1 | Move the branch points behind the adapter before cargo? | Yes: an `Adapter` per ecosystem, holding what each branch point asks, with npm and PyPI's behaviour unchanged and their tests passing as they are. Then cargo is a new adapter and a row in the table |
| Q2 | Where cargo is served | Under `/cargo/`: `sparse+https://byrle.example.com/cargo/` as the registry, the index at `/cargo/config.json` and `/cargo/se/rd/serde`. Index paths such as `/1/a` and `/se/` would otherwise meet npm's names at the root |
| Q3 | How cargo sends a token | With `"auth-required": true` in the proxy's `config.json`, cargo sends the token in `Authorization` with no scheme. Accept that form, `Authorization: byrle_…`, beside `Bearer`, `Basic` and `X-Byrle-Token` |
| Q4 | Build scripts and proc-macros | A check of their own, `build_scripts: allow`, read from the `.crate`'s `Cargo.toml`, reported as a signal. Not `install_scripts`, whose default `block` would refuse 21 of the top 100 crates |
| Q5 | Provenance | Unenforced for cargo, and said so, until crates.io serves attestations. Comparing `trustpub_data` would need an API request per version |
| Q6 | Advisories | `osv/cargo`, from OSV's crates.io bundle |

## Steps

1. The adapter interface (Q1): each branch point above becomes a question the adapter
   answers. npm and PyPI move onto it with no change in behaviour.
2. The cargo adapter: `config.json` with `dl` pointed at the proxy and `auth-required`,
   index files read into records and filtered by removing refused versions' lines,
   downloads verified against `cksum`.
3. The `.crate` reader: its `Cargo.toml` for a build script and `proc-macro`, which
   `install_scripts` refuses under the default `block` (Q4).
4. `osv/cargo` (Q6), and `Cargo.lock` for `warm`, `explain`, `policy diff` and
   `lockfile verify`.
5. `byrle doctor` for `~/.cargo/config.toml` and `CARGO_REGISTRIES_*`, and the startup line.
6. `make smoke-cargo`: real `cargo build` and `cargo install` through the proxy, with a
   token, a refused version and a cooldown.
7. Docs: quickstart, policy-reference, threat-model, runbook.
8. Q5, later: measure how many versions carry `trustpub_data`, and whether it can be read
   reliably without a request per version, before deciding.

## Exit

`cargo build` of a real project and `cargo install` of a real binary, through the proxy
with a token, enforcing the defaults: a refused version is not chosen, a pinned one
answers 403, and an advisory from `osv/cargo` refuses what it names. npm and PyPI pass
their smoke tests unchanged.
