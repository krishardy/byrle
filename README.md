# byrle

**A dependency firewall.** A self-hosted proxy that evaluates packages against a
security policy *before* they are downloaded, extracted, or executed. Blocks known
malware and policy violations across multiple package ecosystems from a single YAML
configuration.

> `byrle` replaces the working name `waharoa`
> ([project-name-byrle](docs/engineering_decisions/project-name-byrle.md)).

## Stack

Language: Rust

Configuration: YAML, loaded by `serde-saphyr`. Chosen over TOML on readability and error
message quality, once the assumption that TOML was the only pure-Rust option turned out
to be stale. The loader hard-errors on unknown keys, because a typo'd rule that silently
does nothing is worse than no tool at all. Rationale and the evidence behind it are in
[docs/project_plan.md](docs/project_plan.md); the spike is re-runnable with
`make spike-config`.

## Status

**Pre-release, enforcing for npm and PyPI.** The proxy runs, decides on every metadata
document and artifact, and refuses what its policy refuses. No outside team has run it
yet: that is the exit criterion of the current stage. There is no published release;
build it with `cargo build --release` and follow [docs/quickstart.md](docs/quickstart.md). See
[TODO.md](TODO.md) for the staged plan and current position.

| Ecosystem | Tier | Clients measured through it |
|---|---|---|
| npm | **enforcing** | npm, pnpm, yarn 1, yarn 4, bun |
| PyPI | **enforcing** | pip, uv |
| cargo, Go, Maven | not built | |

A tier is what the proxy does for the ecosystem today:

| Tier | Meaning |
|---|---|
| `enforcing` | every policy check runs; a refused version is removed from the metadata and its artifact refused; an artifact is served only after its analysis has finished, and only when its bytes match its published digest |
| `observe-only` | checks run and are logged; nothing is refused |
| `experimental` | some checks run; what is missing is listed |

`BYRLE_MODE=observe` runs an enforcing ecosystem in observe mode, for the whole proxy.
`byrle status` lists what the build does for each ecosystem and which intel streams
cover it.

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

byrle sits in front of a package registry. The package manager is pointed at it, and
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
upstream registry (allow) | refusal status, 403 by default, + audit log (block)
```

Only the first two layers are rewritten per ecosystem. Package identity is PURL
throughout the core.

## What is different about it

**Controls that need no threat intelligence at all.** Cooldown periods on newly
published versions, lifecycle script policy, provenance enforcement, and
registry-versus-source diffing all cover the publish-to-detection gap that feed-driven
tools cannot see into.

**Pluggable advisory streams.** OSV (which carries the OSSF malicious-packages records),
GitHub advisories, Datadog's malicious-packages dataset and CISA KEV are all free and
public. `byrle refresh` loads them into a local Postgres store, and the proxy asks only
that store, so a lookup never tells an upstream which packages you use. No commercial
vendor will aggregate every free feed, because each is selling their own.

**A policy engine you can read.** `byrle explain` shows the policy in force, and for a
package, the verdict and each check that produced it. Policy engines nobody can inspect
stay stuck in observe mode forever.

## Ecosystem support

| Ecosystem | Interception mechanism | Tier |
|---|---|---|
| npm | registry URL; artifact URLs rewritten to the proxy | enforcing |
| PyPI | `--index-url`, PEP 691 and PEP 503 | enforcing |
| cargo | source replacement, sparse index | not built |
| Go | `GOPROXY` | not built |
| Maven | mirror in `settings.xml` | not built |

npm and PyPI carry effectively all the malware volume, so they ship first. Breadth buys
far less security than the ecosystem count implies.

## Policy

A single YAML file: global settings, and per-package exceptions to them.

```yaml
version: 1

cooldown_days: 7
install_scripts: block
provenance: block
kev: block
max_cvss: 9.0

packages:
  - match: { ecosystem: npm, name: esbuild }
    set: { install_scripts: allow }
    reason: downloads its platform binary on install
    permanent: true
```

The proxy enforces by default. `BYRLE_MODE=observe` serves what the policy would refuse
and logs it, so adopters can move from observe to enforce on their own schedule.
Exceptions are cheap to add and expire by default. Every key, its default and which way
it loosens are in [docs/policy-reference.md](docs/policy-reference.md).

## Non-goals

* Competing on proprietary malware detection or behavioral ML
* Being a package registry or artifact store (we sit in front of one)
* SBOM generation, license compliance reporting, runtime protection
* Replacing SCA tooling for already-installed dependencies

## Known bypass vectors

A tool that intercepts every dependency install is itself a supply-chain risk, and it
has honest limits. Each way a package can be installed without byrle deciding on it is
listed, with its mitigation, in [docs/threat-model.md](docs/threat-model.md). The ones that
matter most:

* **Pointing at the proxy is advisory.** A developer who resets their registry URL, or a
  client that installs from its own cache, never asks the proxy. `byrle doctor` checks
  both. An npm or yarn lockfile records the proxy's address, so CI can check it; pnpm's
  records none.
* **Installs outside a package manager are invisible.** IDE extensions, browser
  extensions and MCP servers install packages without a configured registry. Only
  egress control reaches them.
* **Operator settings can open gaps**: `BYRLE_ALLOW_DIRECT_ORIGINS`,
  `BYRLE_REFUSE_UNSERVABLE=0` and `BYRLE_MODE=observe`. Each is warned about at
  startup and reported by `byrle doctor`.
* **Code that runs on import, not install**, is not seen by the install-script check.

We do not stop an attacker who already controls the developer's machine, and we do not
claim to detect novel malware ahead of the research community.

## Checking it is actually being used

Every mode below a controlled network is advisory, so the question worth asking is not
whether the proxy is running but whether anything is using it.

```
byrle doctor
```

reports whether the proxy is there, answering and ready to decide on packages, what each
installed package manager is configured to talk to, what the lockfiles in the current
directory record about where their artifacts came from, and what would silently skip the
proxy. It exits non-zero when installs are not going through it.

The proxy answers `GET /-/byrle/health` for itself, which reports what it forwards to
and which settings are reducing what it examines. That is what `doctor` reads, and it is
worth curling directly when a client says something unexpected.

`GET /-/byrle/ready` answers 200 when the proxy can decide on packages and 503 when it
cannot: a policy and an intel store are configured, and the store holds no snapshot or
cannot be reached. Point an orchestrator's readiness probe at it. The body reports the loaded
snapshot and each stream's digest.

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

**Set `BYRLE_PUBLIC_URL` to a stable name** everyone who consumes the lockfile can
reach, rather than letting it default to whatever `Host` a client happened to use. This is
close to mandatory: measured, `npm ci` against a lockfile whose recorded address is no
longer reachable fails outright, and does not fall back to the registry it was given on
the command line. The proxy warns at startup when it is unset.

The consequence cuts both ways: a lockfile committed from behind the proxy cannot be
installed without it, so CI cannot silently skip enforcement, and the proxy becomes
something CI depends on being reachable.

## License

Apache-2.0 ([LICENSE](LICENSE)), with DCO sign-off rather than a CLA
([CONTRIBUTING.md](CONTRIBUTING.md)). The patent grant matters for security tooling, and
adapter contributions are the scarce resource.

## Documentation

* [docs/quickstart.md](docs/quickstart.md) takes npm and PyPI installs from observe mode to
  enforcing.
* [docs/project_plan.md](docs/project_plan.md) covers detection strategy, policy
  semantics, the threat model, and milestones.
* [docs/request-flow.md](docs/request-flow.md) charts how the proxy answers a request,
  and when it returns each status code.
* [docs/fronting-tls.md](docs/fronting-tls.md) puts the proxy behind Caddy or nginx on
  TLS, with configurations `make smoke-tls-front` tests.
* [docs/break-glass.md](docs/break-glass.md) says how to install when the proxy is down,
  and how to release a package it refuses without a restart.
* [docs/threat-model.md](docs/threat-model.md) says what byrle defends against, what it
  trusts, and the known ways around it.
* [docs/policy-reference.md](docs/policy-reference.md) lists every policy key, its default,
  and which way it loosens.
* [CONTRIBUTING.md](CONTRIBUTING.md) asks for a DCO sign-off on every commit. byrle is
  Apache-2.0: [LICENSE](LICENSE).
* [docs/engineering_decisions/](docs/engineering_decisions/) holds one file per
  decision: what was chosen, what was rejected, and what it costs.
* [TODO.md](TODO.md) is the staged, sequential task list with exit criteria.
