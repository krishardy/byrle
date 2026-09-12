# Enforcement tiers: how requests are made to reach the proxy

- **Status:** Open question, framing recorded Sept 2026
- **Plan reference:** decisions #3 and #4, §7 bypass vectors
- **Related:** [tls-reverse-proxy-first](tls-reverse-proxy-first.md),
  [packument-tarball-url-rewriting](packument-tarball-url-rewriting.md),
  [quarantine-filter-metadata](quarantine-filter-metadata.md)

Pointing a client at the proxy is not one decision. It is a stack of mechanisms with
different costs, different privileges, and different things they fail to cover. This
records the stack so the next one is chosen deliberately.

## The constraint that shapes the stack

`dist.tarball` is always an `https://` URL. Any mechanism that intercepts the URL *as
written*, meaning a hosts-file entry, a DNS override, or `HTTPS_PROXY`, has to terminate
TLS, which means a CA in the client's trust store. Without one the handshake fails and
nothing installs.

Rewriting the URL is therefore the only mechanism that gets full request visibility
without a CA. It is not one option among equals.

Node makes the CA path heavier than usual: the OS store, Node's own bundle
(`NODE_EXTRA_CA_CERTS`), and npm's `cafile` and `strict-ssl` are three places to get
right on every machine.

## The tiers

| Tier | Mechanism | Privilege needed | What still escapes |
|---|---|---|---|
| 1 | Registry config | none | artifacts for every client except npm |
| 2 | Artifact URL rewriting | none | `dist.tarball` on an origin the proxy does not front |
| 3 | Refuse artifacts on unconfigured origins (**done**) | none | clients that ignore the registry config |
| 4 | hosts / DNS override plus trusted certificates | root, trust-store changes | hosts not listed |
| 5 | Egress control, no direct outbound | network control | nothing |

Tier 1 alone was measured as insufficient: installing `express`, pnpm sent 66 packuments
and zero tarballs, and installed successfully. Tiers 2 and 3 are implemented.

Only tier 5 is complete. It is also the only tier that covers the bypass already recorded
in §7: IDE extensions and MCP servers that install packages without a configured package
manager are invisible to tiers 1 through 3, because none of those are in their path.

## Tier 3 comes first

**Refusing artifacts whose origin is not in the proxy configuration should be built before
any of the network-level tiers.** It closes the gap those tiers were being considered for,
and it costs nothing operationally:

- No CA, no root, no trust-store changes, no network changes, nothing per machine.
- The information already exists. `npm::bypassing_origin` computes it on every packument
  today and logs `UNINSPECTED`. Tier 3 is that warning turned into a refusal.
- The mechanism is already decided. [quarantine-filter-metadata](quarantine-filter-metadata.md)
  filters unwanted versions out of resolution metadata and hard-fails a pinned fetch,
  rather than blocking the document. The same filtering applies here: drop versions whose
  artifacts we cannot see, let the client's own resolver pick one we can, and fail a pinned
  fetch of a filtered version.

Filtering rather than refusing the whole packument matters, because a package may have one
old version on another origin and every current version on the registry. Refusing the
document would break an install that filtering leaves working.

What it needs that does not exist yet:

- ~~An operator-configured list of origins the proxy fronts.~~ Done:
  `WAHAROA_ARTIFACT_ORIGINS`. The upstream and the default registry are always included,
  and only origins the operator adds are fetched from directly, so a private mirror
  publishing registry.npmjs.org URLs still routes to the mirror.
- ~~A decision on the default.~~ Refusing is on, and the status is configurable by
  (ecosystem, client) with 403 as the default: `WAHAROA_REFUSAL_STATUS`. Clients bucket
  status codes rather than reading them, so an operator who finds one mishandling 403 can
  say so without waiting for a release. A 5xx is accepted and warned about, because §5
  reserves those for the proxy not being ready.

## Where enforcement is recorded, which is the real trade

Tiers 2 and 3 record enforcement **in the artifact**. The lockfile names the proxy, so a
CI runner without the proxy fails. Measured: `npm ci` against a lockfile whose recorded
address is unreachable fails outright and does not fall back to the registry it was given
on the command line. Enforcement cannot be silently skipped, and the cost is lockfile
portability.

Tiers 4 and 5 record enforcement **in the environment**. Lockfiles stay portable. A fresh
container or a new laptop without the hosts entry installs happily and unprotected. It
fails open on absence.

That is the same property with the sign flipped, and it is the choice, not a detail.

One asymmetry on top: **configuration-based enforcement is overridable by design.** A
project `.npmrc` beats the user's, which beats the global one, so a developer can point
`registry` anywhere. Changing `/etc/hosts` needs root. If the threat model ever extends
past "malicious package" toward "developer routes around the tool", only the network tiers
hold.

## Suggested posture per deployment

- **Developer laptop.** Tiers 1 to 3. No root, no CA, works in containers. Weak against
  deliberate circumvention, which is consistent with a threat model of malicious packages
  rather than malicious developers.
- **Organisation CI.** Tier 5, a container whose only egress route is the proxy. This is
  the one that closes the off-origin case completely. Here `WAHAROA_REWRITE_ARTIFACTS=0`
  earns its place: lockfiles are committed and shared, and egress control already
  guarantees what rewriting was buying.
- **Managed fleet.** Tier 4 with the CA pushed by MDM. Rewriting off, portable lockfiles.

## Open questions

~~A CA on the proxy.~~ Settled: the registry domains are known in advance, so the proxy
holds **pre-issued leaf certificates** for them and no CA key at all. A leaf key signs
nothing, and ordinary chain validation is all any client has to do. Constraining a CA to
the registry names is not used and is not being evaluated; the minting onramp holds an
unconstrained CA key, which is why it is the less secure option. See
[terminating-tls-certificates](terminating-tls-certificates.md).

**Whether `HTTPS_PROXY` without termination is worth anything.** With CONNECT and no TLS
termination the proxy sees a hostname and nothing else: no package, no version. Useless
for policy. It would detect "something is talking to a registry we do not front", which is
a signal worth having and not a substitute for a tier.

**Self-detection of bypass.** A packument served with no artifact request following it is
the exact signature of the pnpm behaviour, and would have caught it without anyone looking.
It is noisy, since a client may already hold the artifact or may resolve a version it does
not install, so it is a heuristic rather than a check.
