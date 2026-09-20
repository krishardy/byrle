# Quarantine: filter metadata on resolution

- **Status:** Implemented 2026-09-20. `proxy::policy_refused_versions`,
  `proxy::mark_filtered`, `enforce::lifts_on`.
- **Plan reference:** decision #4

## Decision

Filter quarantined versions out of resolution metadata. Hard fail on a pinned fetch of
a quarantined version.

## Rationale

Substituting a different version breaks lockfile integrity hashes. Filtering the
metadata instead lets the client's own resolver pick a clean version, which is the
behaviour resolvers already implement.

A pinned fetch has no resolution step to influence, so there is nothing to filter and
the request fails. The refusal names the day the quarantine lifts, measured from the
version's publish date and the wait that applied, which is the package entry's
`cooldown_days` where one set it:

```
waharoa: pkg:npm/lodash@4.17.21 is held by policy
  - cooldown_days: published too recently, installable on 2026-10-12
```

## A filtered document says so

The client resolves against a document this proxy changed, so the response carrying it says
what went:

```
x-waharoa-filtered-versions: 1
x-waharoa-filtered-checks: denials
```

Both are absent when the policy removed nothing. An absent header is a document the policy
left alone, not one nobody looked at: whether this proxy inspects at all is what
`/-/waharoa/health` answers. The same removal is a `resolution` event in the audit log,
with the versions by name, and `waharoa explain` gives the per-check reasons.

## See also

- [cooldown-waivers-manual-only](cooldown-waivers-manual-only.md) for the escape route
  when a quarantined version is genuinely needed.
