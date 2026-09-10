# waharoa

**A dependency firewall.** A self-hosted proxy that evaluates packages against a
security policy *before* they are downloaded, extracted, or executed. Blocks known
malware and policy violations across multiple package ecosystems from a single YAML
configuration.

> `waharoa` is a working name: te reo Māori for the carved gateway of a pā, literally
> the *long entrance*. The gate you pass through before you are inside the walls.

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
Packages, and Aikido Intel are all free and public. No commercial vendor will aggregate
every free feed, because each is selling their own. Every stream is mirrored locally, so
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
  cache silently skips enforcement.

We do not stop an attacker who already controls the developer's machine, and we do not
claim to detect novel malware ahead of the research community.

## License

Apache-2.0, with DCO sign-off rather than a CLA. The patent grant matters for security
tooling, and adapter contributions are the scarce resource.

## Documentation

* [docs/project_plan.md](docs/project_plan.md) covers detection strategy, policy
  semantics, the threat model, milestones, and the decision record.
* [TODO.md](TODO.md) is the staged, sequential task list with exit criteria.
