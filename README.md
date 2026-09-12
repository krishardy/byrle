# waharoa

**A dependency firewall.** A self-hosted proxy that evaluates packages against a
security policy *before* they are downloaded, extracted, or executed. Blocks known
malware and policy violations across multiple package ecosystems from a single YAML
configuration.

> `waharoa` is a working name: te reo Māori for the carved gateway of a pā, literally
> the *long entrance*. The gate you pass through before you are inside the walls.

## Stack

Language: Rust

Configuration: YAML, loaded by `serde-saphyr`. Chosen over TOML on readability and error
message quality, once the assumption that TOML was the only pure-Rust option turned out
to be stale. The loader hard-errors on unknown keys, because a typo'd rule that silently
does nothing is worse than no tool at all. Rationale and the evidence behind it are in
[docs/project_plan.md](docs/project_plan.md); the spike is re-runnable with
`make spike-config`.

## Status

**Pre-implementation.** There is no working proxy yet, no binary, and nothing to
install. The design is settled enough to build against; the code is not written.
See [TODO.md](TODO.md) for the staged plan and current position.

## Problem

Package managers execute untrusted code at install time. By the time an npm
`postinstall` script runs, it already has access to source code, SSH keys, cloud
credentials, environment variables, and CI tokens. Scanning after installation is too
late for the developer workstation.

The window between a malicious version being published and being detected by threat
intelligence is where most successful supply-chain attacks land. Any defense wired
purely to known-malware feeds is structurally reactive and blind during exactly that
window.

## How it works

waharoa sits in front of a package registry. The package manager is pointed at it, and
every resolution and fetch passes through four layers:

```
package manager
      |
      v
[ transport adapter ]   speaks one registry protocol (npm, PEP 503, sparse index...)
      |
      v
[ normalizer ]          registry metadata -> common package record
      |
      v
[ policy engine ]       ecosystem-agnostic; operates only on the common record
      |
      v
[ analysis cache ]      keyed by tarball digest, permanently valid, offline-capable
      |
      v
upstream registry (allow) | HTTP 403 + audit log (block)
```

Only the first two layers are rewritten per ecosystem. Package identity is PURL
throughout the core.

## What is different about it

**Controls that need no threat intelligence at all.** Cooldown periods on newly
published versions, lifecycle script policy, provenance enforcement, and
registry-versus-source diffing all cover the publish-to-detection gap that feed-driven
tools cannot see into.

**Pluggable advisory streams, from day one.** OSV, GitHub Advisory, OSSF Malicious
Packages, CISA KEV, and NVD are all free and public, and between them carry 221,548 npm
malware records. No commercial vendor will aggregate every free feed, because each is
selling their own. Every stream is mirrored locally, so
lookups never leak your dependency graph upstream.

**A policy engine you can read.** `waharoa explain` (planned) shows the effective merged
policy and the exact rule that produced a verdict. Policy engines nobody can inspect
stay stuck in warn mode forever.

## Ecosystem support

Every ecosystem carries a published maturity tier: `enforcing`, `observe-only`, or
`experimental`. Nothing has reached one yet.

| Ecosystem | Interception mechanism | Maturity |
|---|---|---|
| npm | registry URL | planned, first |
| PyPI | `--index-url`, PEP 503 | planned, second |
| cargo | source replacement, sparse index | planned, third |
| Go | `GOPROXY` | deferred |
| Maven | mirror in `settings.xml` | deferred |

npm and PyPI carry effectively all the malware volume, so they ship first. Breadth buys
far less security than the ecosystem count implies.

## Policy

A single YAML file: global defaults, per-ecosystem overrides, package-level rules, and a
non-overridable floor.

```yaml
version: 1

defaults:
  known_malware: block
  cooldown:
    action: quarantine
    days: 7
  install_scripts: warn
  provenance_required: false
```

Warn mode is the default. One blocked legitimate build and the tool gets disabled
permanently, so adopters ratchet from observe to enforce on their own schedule.
Exceptions are cheap to add and expire by default. The full schema, merge semantics, and
evaluation order are in [docs/project_plan.md](docs/project_plan.md).

## Non-goals

* Competing on proprietary malware detection or behavioral ML
* Being a package registry or artifact store (we sit in front of one)
* SBOM generation, license compliance reporting, runtime protection
* Replacing SCA tooling for already-installed dependencies

## Known bypass vectors

A tool that intercepts every dependency install is itself a supply-chain risk, and it
has honest limits:

* **Reverse proxy mode is advisory, not mandatory.** A developer who resets their
  registry URL defeats it entirely.
* **Non-terminal install paths are invisible.** IDE extensions, browser extensions, and
  MCP servers install packages without going through a configured package manager.
  A registry proxy cannot see any of it.
* **npm serves from its local cache without consulting the registry**, so a pre-existing
  cache silently skips enforcement. Artifacts that do arrive are still checked: when a
  client asks for a tarball without having requested its packument, as `npm ci` always
  does, the proxy fetches the packument itself. What it cannot see is an install served
  entirely from cache, where no request reaches it at all.
* **A registry can publish artifacts on a host the proxy does not sit in front of.**
  Those versions are removed from the packument, so a resolver picks one that can be
  examined, and a pinned fetch of one is refused. Removal is the only control that works:
  the client fetches that URL from whatever host it names, so the proxy never sees the
  request. Name the host in `WAHAROA_ARTIFACT_ORIGINS` to have the proxy serve it, or in
  `WAHAROA_ALLOW_DIRECT_ORIGINS` to accept that it is fetched unexamined. The second is
  reported on every packument that uses it, because an accepted gap that stops being
  reported outlives the reason it was added.

We do not stop an attacker who already controls the developer's machine, and we do not
claim to detect novel malware ahead of the research community.

## Checking it is actually being used

Every mode below a controlled network is advisory, so the question worth asking is not
whether the proxy is running but whether anything is using it.

```
waharoa doctor
```

reports whether the proxy is there and answering, what each installed package manager is
configured to talk to, what the lockfiles
in the current directory record about where their artifacts came from, and what would
silently skip the proxy. It exits non-zero when installs are not going through it.

The proxy answers `GET /-/waharoa/health` for itself, which reports what it forwards to
and which settings are reducing what it examines. That is what `doctor` reads, and it is
worth curling directly when a client says something unexpected.

To see what the proxy does to a request rather than whether it is being used:

```
make inspect                      # lodash
make inspect PACKAGE=@babel/core
```

sends one packument request and one artifact request as each of npm, pnpm and yarn, with
the headers those clients actually send, and prints the responses beside what the registry
served directly. It verifies the artifact digest itself rather than trusting the proxy's
report. `make smoke-clients` is the one that asserts; this one is for looking.

## Deployment note

Artifact URLs are rewritten to point at the proxy, so package managers record the proxy's
address in lockfiles. npm's `resolved` and yarn's `resolved` both do; pnpm instead omits
the URL and derives it from the configured registry, which makes its lockfiles more
portable than before, not less.

**Set `WAHAROA_PUBLIC_URL` to a stable name** everyone who consumes the lockfile can
reach, rather than letting it default to whatever `Host` a client happened to use. This is
close to mandatory: measured, `npm ci` against a lockfile whose recorded address is no
longer reachable fails outright, and does not fall back to the registry it was given on
the command line. The proxy warns at startup when it is unset.

The consequence cuts both ways: a lockfile committed from behind the proxy cannot be
installed without it, so CI cannot silently skip enforcement, and the proxy becomes
something CI depends on being reachable.

## License

Apache-2.0, with DCO sign-off rather than a CLA. The patent grant matters for security
tooling, and adapter contributions are the scarce resource.

## Documentation

* [docs/project_plan.md](docs/project_plan.md) covers detection strategy, policy
  semantics, the threat model, and milestones.
* [docs/engineering_decisions/](docs/engineering_decisions/) holds one file per
  decision: what was chosen, what was rejected, and what it costs.
* [TODO.md](TODO.md) is the staged, sequential task list with exit criteria.
