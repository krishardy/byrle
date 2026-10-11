# The proxy reports where it is being bypassed

- **Status:** Implemented 2026-09-26. `proxy::report_direct_dependencies`,
  `proxy::Traffic` and `Proxy::report_traffic`, the 304 branch of `Exchange::forward_artifact`, and five
  counters in `/-/byrle/health`.
- **Related:** [packument-body-inspection](packument-body-inspection.md),
  [packument-tarball-url-rewriting](packument-tarball-url-rewriting.md),
  [artifact-digest-verification](artifact-digest-verification.md)

## Decision

Each signal is logged and counted in `/-/byrle/health`, and none refuses anything. Each
says what the proxy did not see, which a check cannot decide on.

| Signal | Certain or heuristic | Log | Health |
|---|---|---|---|
| A metadata document forwarded without being read or rewritten, oversized or undecodable | certain: the artifacts it lists are fetched from where they point | WARN `UNINSPECTED`, as before | `documents_uninspected` |
| A version depending on a package by URL, git or path | certain: npm fetches those from where they point | WARN `BYPASS`, once per artifact request, naming each dependency | `artifacts_with_direct_dependencies` |
| An artifact answered 304 | certain that this request's bytes were not hashed; the client cached them earlier | INFO | `artifacts_revalidated` |
| A client reading metadata documents and fetching no artifact in a 10-minute window | heuristic | INFO when the window closes | `clients_without_artifacts`, the last window's |

## Dependencies by URL, git or path

A specifier is direct when npm's own parser, npm-package-arg, fetches it from where it
points: `git+…`, `git://`, `github:`, `gitlab:`, `bitbucket:`, `gist:`, `owner/repo`,
`http:`, `https:`, `file:`, `./`, `../`, `/` and `~/`. An `npm:` alias resolves through the
registry. `dependencies`, `optionalDependencies` and `peerDependencies` are read, from both
packument forms, which carry all three. `devDependencies` are not: a dependency's dev
dependencies are never installed.

Only the direct entries are kept, as the packument is decoded, so a record holds an empty
list for nearly every version: 24 bytes, measured with `examples/record_memory.rs` as
`typescript`'s 1,056 bytes a record rising to 1,080. Eight concurrent requests for `vite`'s
full packument peaked at 742 to 942 MB before and 645 to 994 MB after, two runs each: within
the run-to-run spread.

It is reported on the artifact request, once, and not per version of a packument, which
would repeat it for every version a document lists.

PyPI refuses an upload whose metadata names a dependency by URL, in warehouse's
`forklift/metadata.py`: "Can't have direct dependency". The PyPI adapter records none. A
private index that accepts one is not covered: the simple index does not carry
`Requires-Dist`.

## A 304 on an artifact

A client revalidating an artifact it cached gets a 304 and installs its own copy. The proxy
hashed those bytes when the client first fetched them through it, if it did; on the 304 it
hashes nothing. INFO, not WARN: every warm-cache install makes one per artifact.

Finding it showed a defect, fixed in `c6aaf91`: every response for an artifact with a
published digest was hashed, whatever its status, so a 404's error body was reported as a
digest mismatch and the response cut off. Only a 200 is verified now.

## Clients reading documents and fetching no artifact

pnpm and yarn 1 fetch `dist.tarball` as written. With rewriting off, a proxy sees their
packuments and none of their artifacts. So does a proxy in front of a client whose cache or
registry setting takes artifacts elsewhere.

It is also what a client looks like that resolved and installed nothing new, so it is
reported at INFO. npm does not produce it: measured with `express` through the proxy, a
warm cache made no request at all, and `npm install --prefer-online` with a lockfile made
one document request and two artifact requests.

Counts are kept by the client name the user-agent gives, `refusal::client_name`. The server
does not keep the peer address, and behind a load balancer it would be the balancer's, so
every machine running one client shares a count. `BYRLE_MAX_TRAFFIC_CLIENTS`, 256 by
default, bounds the names a window counts apart; past it a new name counts as `other`. HEAD
requests and bun's resolver probes are not counted.
