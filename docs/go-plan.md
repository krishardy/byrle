# Stage 6 plan: Go

Go is the fourth row of the adapter table, after cargo ([cargo-plan](cargo-plan.md)). Written
2026-10-15. Every measurement below was made that day, with go 1.27.2 against
proxy.golang.org, sum.golang.org, and a stub proxy relaying to proxy.golang.org.

## What the module proxy serves

| | Measured |
|---|---|
| Version list | `/golang.org/x/text/@v/list`: text, one version per line, unordered, no times. 51 lines, `max-age=60` |
| Version info | `/@v/v0.20.0.info`: `{"Version", "Time", "Origin": {"VCS", "URL", "Hash", "Ref"}}`, `max-age=10800` |
| Latest | `/@latest`: the same JSON for the newest release |
| `go.mod` and zip | `/@v/v0.43.0.mod`, and `/@v/v0.43.0.zip`, 7,337,809 bytes, answered directly |
| A large zip | `golang.org/toolchain@v0.0.1-go1.27.1.linux-amd64`, 75,704,807 bytes: a 302 to a signed `storage.googleapis.com` URL |
| Case | upper case escaped: `github.com/!burnt!sushi/toml` |
| Digest | none in the proxy's answers. `sum.golang.org/lookup/golang.org/x/text@v0.20.0` answers `h1:` for the zip and for `go.mod`, in a note signed by `sum.golang.org` |
| Checksum database through the proxy | `/sumdb/sum.golang.org/supported` answers 404 at proxy.golang.org |
| Toolchains | `golang.org/toolchain` is a module of 6,915 versions, fetched through `GOPROXY` when `go.mod` asks for a newer go |
| Not reachable here | `index.golang.org` and `vuln.go.dev` answer this machine's forward proxy with 403 |

## What the go command does, measured against the stub

`GOPROXY=http://127.0.0.1:18755/go`, a fresh `GOPATH` and `GOTOOLCHAIN=local`:

| Stub | go |
|---|---|
| relaying | `go get golang.org/x/text@latest` asked `@v/list` for `golang.org`, `golang.org/x` and `golang.org/x/text`, then `.info`, `.mod`, `/sumdb/sum.golang.org/supported`, and the zip. 4.4 s |
| v0.43.0 left out of `@v/list` | resolved v0.42.0 |
| the same, `@v0.43.0` asked for | fetched v0.43.0: a version left out of the list is still served when named |
| every version left out of `@v/list` | asked `@latest`, and fetched what it named |
| that, and `@latest` 404 | failed |
| the zip answered 503, `Retry-After: 1`, once | failed after 409 ms: no retry |
| the zip answered after 90 s | waited, and fetched it in 94.7 s |
| 401, a token in `GOPROXY`'s userinfo, over http | refused: "refusing to pass credentials to insecure URL", to 127.0.0.1 too |
| the same over https | sent `Authorization: Basic` on every request |
| 401, `~/.netrc` naming `localhost` or `127.0.0.1`, https on port 18755 | sent nothing |
| `~/.netrc` naming `localhost:18755` | sent `Basic` |

## Advisories, OSV's `Go/all.zip`

12,337,458 bytes, 9,618 records: 4,632 `GO-`, 4,965 `GHSA-`, 20 `MAL-`, 1 `OSV-`; 177
withdrawn. Ranges are `SEMVER` (14,730) and `ECOSYSTEM` (145).

| | Records |
|---|---|
| `GO-`, not withdrawn | 4,595, none with a `severity` of its own |
| of those, no score and no scored alias in the bundle | 383 |
| of those, only `stdlib` or `toolchain` | 192 |

`stdlib` and `toolchain` name the Go distribution, not a module: 187 and 34 records name
them. The other 191 unscored records name modules, and `max_cvss` refuses an unscored
advisory, as with 105 RustSec records ([advisory-kinds](engineering_decisions/0109-advisory-kinds.md)).

## The adapter, checked again

Go's column of [cargo-plan](cargo-plan.md)'s table, with what was measured since:

| Question | Go | What the interface lacks |
|---|---|---|
| Route a path | `@v/list`, `@latest`, `.info`, `.mod`, `.zip`, under `/go/` | nothing: `classify_path` |
| Read and filter a document | `@v/list` lines, and `@latest`'s JSON | `@latest` is a second document kind that names one version |
| Publish time | `.info`'s `Time`, a request per version | a time asked per version, newest first, as npm's full packument is asked per document |
| Artifact digest | `h1:` from sum.golang.org, over the zip's files | a digest the proxy fetches, and checks after the whole zip is spooled |
| Decide without 503 | go does not retry a 503 | an answer held open while the artifact is analysed |
| Code run at fetch or build | none: `go generate` is never run by a build | `meaningless` gains `install_scripts` |
| Lockfile | `go.sum` | none |
| Client configuration | `GOPROXY`, `GONOSUMDB`, `GOPRIVATE`, `GOFLAGS`, `~/.netrc` | `doctor` reads `go env` |

## Decisions

Answered by the user 2026-10-15. Q1 follows from
[ecosystem-path-prefixes](engineering_decisions/0111-ecosystem-path-prefixes.md); Q4, Q5,
Q7 and Q8 as recommended; Q2, Q3 and Q6 otherwise.

| | Question | Decided |
|---|---|---|
| Q1 | Where Go is served | Under `/go/`: `GOPROXY=https://byrle.example.com/go` |
| Q2 | How a download is held while it is checked | 503, as npm, PyPI and cargo are, with `Retry-After` and `x-byrle-not-ready`. go 1.27.2 failed on the first 503 in 409 ms, so a module not analysed yet fails the go command until it is run again. Held open was recommended |
| Q3 | Where the `h1:` comes from | sum.golang.org, verified in full by byrle: the note's signature with the Go team's key, and the record's inclusion proof against the signed tree head, from the log's tiles. A module sum.golang.org does not know is refused, as an artifact with no strong digest is. The lookup alone, with proofs left to the go command, was recommended |
| Q4 | The checksum database, for the go command | Relayed: `/go/sumdb/sum.golang.org/*` answered from sum.golang.org, so a network that reaches only the proxy still builds. The note is signed, so a relay cannot change it |
| Q5 | Publish times and cooldown | `.info` asked newest version first, in the go command's order of preference (below), until one is older than `cooldown_days`. `@v/list` and `@latest` lose what the policy refuses; `@latest` names the newest version left, or answers 404 |
| Q6 | Advisories | `osv/go`, from OSV's `Go/all.zip`. `stdlib` records are not matched to modules. `toolchain` records are matched to `golang.org/toolchain` downloads by the Go version in the module version, `v0.0.1-go1.27.1.linux-amd64` being go 1.27.1. Skipping both was recommended |
| Q7 | Toolchains | Served as any module, from proxy.golang.org with `storage.googleapis.com` as an artifact origin. Its zip's `h1:` is in sum.golang.org |
| Q8 | Tokens | `Basic` over https. The setup line puts the token in `GOPROXY`'s userinfo; `.netrc` needs `machine host:port` when the port is not 443 |

## Version order and publish times, measured 2026-10-15

Every version's `.info` read, `+incompatible` versions left out:

| Module | Versions | Published after a higher version |
|---|---|---|
| `golang.org/x/text` | 51 | 0 |
| `github.com/stretchr/testify` | 31 | 1: v1.2.3 on 2026-05-15, after v1.11.1 |
| `google.golang.org/grpc` | 247 | 126: backports such as v1.83.2 after v1.84.0, and releases after `-dev` pre-releases |
| `k8s.io/client-go` | 656, and 15 `+incompatible` | 652: v1.5.2, from 2017, is the highest version, and every v0.x came after it |

So Q5's newest first is the go command's own order of preference, the one `@latest`
follows: the highest release, a pre-release only when there is no release, `+incompatible`
last. `k8s.io/client-go@latest` is v1.5.2 by that order. A backport below a newer release
is left in `@v/list` unchecked: go picks it only when a `go.mod` names it, and then the
pinned fetch asks that version's own `.info`, never a date read from the list.

## How the hooks are built

| Part | How |
|---|---|
| The `h1:` of a zip | computed in the analysis job, over the spooled zip, and the sha256 of the same bytes kept with it. The retry is served with the existing streaming check against that sha256, so the proxy never holds a whole zip in memory |
| The `h1:` of a `go.mod` | checked in the request: the body is small, and `.mod` and `.info` are metadata, never deferred. go reads both for versions whose zips it never fetches, and fails on the first 503 |
| The claim | asked of sum.golang.org before the fetch is planned, once per `module@version` and kept: one lookup holds both `h1:` lines. Unreachable is 503; unknown to sum.golang.org is refused, as no strong digest is |
| A pinned version's time | its own `.info`. One that cannot be read is 503, as a cold intel store is |
| Code | the dirhash and the sum.golang.org client in `src/ecosystem/go/`; `integrity.rs` and `proxy.rs` stay ecosystem-neutral. The hooks land with the Go row, so each is covered by its tests |

## Steps

1. The `h1:` dirhash over a module zip and over a `go.mod`, in `src/ecosystem/go/`, checked
   against sum.golang.org's lines for real modules. Done 2026-10-15: `ecosystem::go::dirhash`, `zip_h1` and
   `go_mod_h1`, matching sum.golang.org's lines for `rsc.io/quote` v1.5.2. A zip entry's
   name is hashed as its bytes, and one that is not UTF-8 is refused, as Go's module zips
   require.
2. The checksum database client: lookup, note signature, tiles and inclusion proof (Q3).
   Done 2026-10-15: `ecosystem::go::note`, `tlog` and `sumdb`. A lookup is believed when
   sum.golang.org's key signs its tree head, the record is proved in that tree, and the
   tree is proved consistent with the largest one seen before, by RFC 9162's proofs read
   from the log's tiles. Against sum.golang.org, `rsc.io/quote` v1.5.2 was proved in a
   tree of 69,104,914 records, and a second lookup's tree consistent with it, in 5.4 s.
   The relay (Q4) needs the `/go/` row, and comes with it in step 3.
3. The Go adapter, with the hooks of "How the hooks are built": paths, `@v/list` and `@latest`
   filtered, `.info` read for times, the claim asked before the fetch, the zip's `h1:` in
   the analysis job, `.mod` checked in the request, the checksum database relay (Q4),
   `osv/go` with toolchain matching (Q6),
   `BYRLE_UPSTREAM_GO`. npm, PyPI and cargo unchanged. In five parts, each refusing what
   it cannot yet check:
   1. The row, `/go/` paths, `@v/list` and `@latest` filtered, `supported` written, the
      relay, `osv/go` and `BYRLE_UPSTREAM_GO`. Every zip is refused as publishing no
      strong digest. Done 2026-10-15.
   2. The claim from sum.golang.org, and `.mod` checked against it.
   3. The zip's `h1:` in the analysis job, its sha256 kept by the analysis store.
   4. Cooldown from `.info`, newest first, and a pinned version's own `.info`.
   5. `toolchain` advisories matched to `golang.org/toolchain`.
4. `go.sum` for `warm`, `policy diff` and `lockfile verify`.
5. `byrle doctor` for `go env`: `GOPROXY`, `GOSUMDB`, `GONOSUMDB`, `GOPRIVATE`, `GOFLAGS`.
6. `make smoke-go`: `go build` of a real module through the proxy over https, with a token,
   a refused version, a cooldown, an advisory, and a toolchain download. A first fetch
   answered 503 is run again, as Q2 leaves it.
7. Docs: quickstart, policy-reference, threat-model, request-flow.

## Exit

`go build` of a real module through the proxy with a token, enforcing the defaults: a
refused version is not chosen, a pinned one answers 403, and an advisory from `osv/go`
refuses what it names. npm, PyPI and cargo pass their smoke tests unchanged.
