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

## What cargo sends, measured 2026-10-14

cargo 1.99.0 ran `cargo fetch` against a stub registry on `http://127.0.0.1`, with
`[source.crates-io] replace-with` pointing at it:

| Stub | cargo |
|---|---|
| `"auth-required": true`, 401 on `config.json` without a token | asked `config.json` without one, then again with `Authorization: byrle_x`, and sent it on the index file and the download |
| the same, no `credential-provider` configured | refused: "authenticated registries require a credential-provider to be configured" |
| 401 on `config.json`, no `auth-required` | sent the token on the index file and none on the download |
| no token asked for, no `auth-required` | fetched with no token |
| `CARGO_SOURCE_CRATES_IO_REPLACE_WITH` set instead of `config.toml` | ignored: fetched from crates.io |
| `config.json` with no `api` key | fetched |

static.crates.io answers `/crates/Inflector/0.11.4/download` and refuses
`/crates/inflector/0.11.4/download` with 403.

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

## The adapter, checked against five ecosystems

Each branch point is one of the questions below. A cell the adapter cannot answer would
make the interface change again, so each is checked before any code. npm, PyPI, cargo and
Go were measured 2026-10-14; Maven Central answers this machine's forward proxy with 403,
so its column is from its documented repository layout, unmeasured.

| Question | npm | PyPI | cargo | Go | Maven |
|---|---|---|---|---|---|
| Route a path to metadata or artifact | packument, tarball | simple page, file | index line file, `.crate` | `@v/list`, `.info`, `.mod`, `.zip` | `maven-metadata.xml`, `.pom`, `.jar` |
| Read and filter a document | JSON object of versions | JSON or HTML list of files | JSON lines, one per version | text, one version per line | XML `<versions>` |
| Publish time | full packument, a second request | the file's `upload-time`, or the host's `Last-Modified` | `pubtime` on each line | `Time` in `@v/<ver>.info`, a request per version | the artifact's `Last-Modified`, a request per version |
| Artifact digest | SRI in the document, checked while streaming | sha256 in the document, streaming | `cksum`, sha256, streaming | `h1:`, a hash over the zip's files, from `sum.golang.org`: checked after the whole zip is read | `.sha1` or `.sha256` beside the file, a second request |
| Code run at install or build | `package.json` scripts | an sdist's build | build script, proc-macro (Q4) | none | none: a dependency's plugins do not run |
| Source to compare with | `repository` | none today | `.cargo_vcs_info.json` names the commit | the zip is the repository at a tag | `-sources.jar` |
| Attestations | Sigstore | Sigstore (PEP 740) | none; `trustpub_data` (Q5) | none; the checksum database | PGP `.asc` |
| Lockfile | `package-lock.json` and others | `requirements.txt`, `uv.lock` | `Cargo.lock` | `go.sum` | none standard |
| Client configuration | `.npmrc` | `pip.conf`, `uv.toml` | `~/.cargo/config.toml` source replacement | `GOPROXY` | `settings.xml` mirror |
| Token sent as | `Bearer`, `Basic` | `Basic` | bare `Authorization` (Q3) | `Basic`, from `.netrc` | `Basic`, from `settings.xml` |
| Version order | SemVer | PEP 440 | SemVer | SemVer with `v` and pseudo-versions | Maven's own |
| Advisories | OSV `npm` | OSV `PyPI` | OSV `crates.io` | OSV `Go` | OSV `Maven` |

So the adapter answers each row with its own types:

- Fetching and reading a document, and filtering it, is a trait object per ecosystem:
  the `Clients` fields, `Read` and `DocumentKind` become one value the adapter returns.
- Publish times are asked per document or per pinned version, not chosen between two
  ways: npm, Go and Maven each need a second request, of a different shape.
- A digest is checked while streaming, or after the artifact is spooled: Go's `h1:` and
  Maven's sidecar file cannot be checked as the bytes pass.
- The rest are fields of the `Registry` table, as now: each returns `None` where an
  ecosystem has nothing, such as Go's install-time code.

`DocumentDetail` (`record.rs:11`), npm's abbreviated and full packuments, is used in shared
code at `analysis.rs:207`, `detector/metadata.rs:91`, `policy/facts.rs:138` and
`record.rs:205`; it becomes the adapter's own. A test asserts that no `ecosystem::npm`,
`ecosystem::pypi` or `Ecosystem::Npm`/`PyPI` arm appears outside `src/ecosystem/`, with
today's sites on an allow-list that each commit shortens. Step 1 is done when it is empty.

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
   answers. npm and PyPI move onto it with no change in behaviour. Done 2026-10-14
   ([adapter-interface](engineering_decisions/adapter-interface.md)).
2. The cargo adapter: `config.json` with `dl` pointed at the proxy and `auth-required`,
   index files read into records and filtered by removing refused versions' lines,
   downloads verified against `cksum`. Done 2026-10-14. `osv/cargo` came with it, because
   `/-/byrle/ready` answers 503 while any served ecosystem has no `match` or `malware`
   stream.
3. The `.crate` reader: its `Cargo.toml` for a build script and `proc-macro`, which
   `install_scripts` refuses under the default `block` (Q4). Done 2026-10-14
   ([install-scripts-from-the-artifact](engineering_decisions/install-scripts-from-the-artifact.md)).
4. `RUSTSEC-` records in `osv/cargo` (Q6): done 2026-10-14, all kinds, as the user asked.
   A vulnerability is refused as any other. `unmaintained`, `unsound` and `notice` refuse
   nothing, and each is a signal of its own weight, beside `advisory_vulnerability` and
   `advisory_malware`. `Cargo.lock` for `warm`, `policy diff` and `lockfile verify`: done
   2026-10-14. `explain` takes a purl, and reads `pkg:cargo/...`.
5. `byrle doctor` for `~/.cargo/config.toml` and `CARGO_REGISTRIES_*`, and the startup line.
   Done 2026-10-14 for the configuration files and the cache. `CARGO_REGISTRIES_*` is not
   read: cargo ignored the replacement from the environment, so it is in a file.
6. `make smoke-cargo`: real `cargo build` through the proxy, with a token, a refused
   version, a cooldown, `rustls` 0.23.45 refused under `max_cvss: 3.9`, and `serde`
   and `serde_derive` refused under `install_scripts: block`. Written 2026-10-14;
   `cargo install` remains.
7. Docs: quickstart, policy-reference, threat-model, runbook.
8. Q5, later: measure how many versions carry `trustpub_data`, and whether it can be read
   reliably without a request per version, before deciding.

## Exit

`cargo build` of a real project and `cargo install` of a real binary, through the proxy
with a token, enforcing the defaults: a refused version is not chosen, a pinned one
answers 403, and an advisory from `osv/cargo` refuses what it names. npm and PyPI pass
their smoke tests unchanged.
