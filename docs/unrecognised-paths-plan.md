# Plan: refuse a request path the proxy does not recognise (TODO.md ad-hoc #45)

Today a request under an ecosystem's prefix that `classify_path` cannot read as metadata, a
manifest or an artifact is `RequestTarget::Other`, and `handle` forwards it upstream and
passes the response back unread. An artifact path that does not parse is therefore served
with no policy decision, no digest check and no analysis. After this plan, `Other` is split
in two. A path of a shape the adapter lists is forwarded as today. Any other path is
refused. Written 2026-10-19 from the code at `56cb005`.

## Decisions

Decided by the user 2026-10-19:

| Question | Answer |
|---|---|
| `BYRLE_MODE=observe` | forwards an unrecognised path and logs it at WARN, so an operator can see their clients' paths before refusing |
| A switch that turns the refusal off | none: a missing shape is fixed by listing it, and observe mode is the way to roll out |
| Status | the refusal status, `BYRLE_REFUSAL_STATUS`, as a policy refusal |

## Why

Paths that are `Other` today and name code a client installs, read from `classify_path`:

| Ecosystem | Path | Why it is `Other` |
|---|---|---|
| PyPI | `/pypi/packages/.../foo-1.0.tgz`, `.../foo-1.0.tar` | `filename_parts` reads `.whl`, `.tar.gz`, `.zip`, `.tar.bz2` and `.tar.xz`; pip also installs `.tgz` and `.tar` |
| PyPI | a wheel filename with fewer than 5 `-` fields | `filename_parts` is `None` |
| npm | `/npm/foo/-/bar-1.0.0.tgz` | the filename does not start with the package's name |
| every | a name `split_name` refuses | `from_registry_name` errs |

PyPI's `other_is_probe: true` also logs each of them at DEBUG as a resolver probe, so an
operator at INFO sees nothing.

## Inventory

Each `return RequestTarget::Other` in the five `classify_path` functions, and what it
becomes. "Forward" is a listed shape; "refuse" is unrecognised.

| Ecosystem | Path shape | Asked by | Becomes |
|---|---|---|---|
| npm | `/-/ping`, `/-/whoami` | npm, yarn, pnpm | forward |
| npm | `/-/v1/search` | `npm search` | forward |
| npm | `/-/npm/v1/security/advisories/bulk`, `/-/npm/v1/security/audits/quick` | `npm install` and `npm audit` without `--no-audit` | forward |
| npm | `/-/npm/v1/keys`, `/-/npm/v1/attestations/<name>@<version>` | `npm audit signatures` | forward |
| npm | `/-/package/<name>/dist-tags` | `npm dist-tag ls` | forward |
| npm | any other `/-/...`, the registry root | | refuse |
| npm | a name `split_name` refuses, `<name>/-/<file>` not `.tgz`, a tarball not named `<name>-<version>.tgz` | | refuse |
| PyPI | `/simple/` | the project list | forward |
| PyPI | `<file>.metadata` under `/simple/` or `/packages/` | pip, PEP 658 | forward |
| PyPI | any other file whose name `filename_parts` cannot read, any path outside `/simple/` and `/packages/` | | refuse |
| Cargo | `index/config.json` | cargo | written by the proxy before the check, as today |
| Cargo | `api/v1/crates?q=` | nothing: `config.json` names no `api` | refuse |
| Cargo | an index path that is not its crate's, a download with a bad name | | refuse |
| Go | `<module>/@v/<version>.info` | go | forward |
| Go | `sumdb/<db>/supported`, `/lookup/...`, `/tile/...` | go, with `GOSUMDB` set | forward |
| Go | a bad module path or version, any other file kind | | refuse |
| Maven | `.sha1`, `.md5`, `.sha256`, `.sha512`, `.asc` beside an artifact | mvn, Gradle | forward |
| Maven | `maven-metadata.xml.sha1` and `.md5` | mvn, Gradle | written by `sidecar` before the check, as today |
| Maven | empty segments, a bad coordinate, a path too short for a version, under `/maven/` or `/gradle-plugins/` | | refuse |

The list is what the code and each client's documentation say. Step 2 checks it against
the clients.

## Design

- **A variant, not a predicate.** `RequestTarget::Unrecognised` beside `Other`, returned by
  each `classify_path`, so one parser decides both. `resolver_probe` then counts PyPI's
  `.metadata` paths alone.
- **Where.** In `handle`, after `admit`, `written` and `sidecar`: a request with no token is
  still 401, and Cargo's `config.json` and Maven's metadata sidecars are still answered.
- **Not a signal.** [every-refusal-a-signal](engineering_decisions/0116-every-refusal-a-signal.md)
  weighs each refusal toward `risk_threshold`. An unrecognised path names no version to
  score, so it is refused outright.
- **No audit line.** `audit_refused` writes none for a request that names no package. The
  refusal is logged at WARN with its path and client.

## Steps

1. `Unrecognised` in each `classify_path`, logged at WARN as `unrecognised path` and still
   forwarded. Unit tests per ecosystem, from the inventory.
2. Run every smoke. Keep each `proxy.log`. Add each path a client asks that the
   inventory lacks, or say why it is refused.
3. Refuse. A test per ecosystem that the refusal status comes back and a scripted
   upstream with no answers is not asked; a listed shape is still forwarded.
4. Each smoke fails on an `unrecognised path` line, so a client update that asks a new
   path fails CI before it fails a user.
5. Docs: `request-flow.md` diagram, decision 0047's `other_is_probe` row and its probe
   paragraph, `threat-model.md`, TODO #45 done.

Done 2026-10-19, steps 1 to 5 together. Every smoke passed with the refusal on and no
`unrecognised path` line: `smoke-npm`, `smoke-npm-clients` (npm now runs with its audit,
and asked `/-/npm/v1/security/advisories/bulk`), `smoke-python`, `smoke-cargo`,
`smoke-go`, `smoke-maven` and `smoke-console`. The inventory needed no path added. The
plan's `api/v1/crates?q=` row is not listed: the `config.json` the proxy writes names no
`api`, so `cargo search` does not ask the proxy.
