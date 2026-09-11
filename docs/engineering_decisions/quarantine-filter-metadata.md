# Quarantine: filter metadata on resolution

- **Status:** Decided
- **Plan reference:** decision #4

## Decision

Filter quarantined versions out of resolution metadata. Hard fail on a pinned fetch of
a quarantined version.

## Rationale

Substituting a different version breaks lockfile integrity hashes. Filtering the
metadata instead lets the client's own resolver pick a clean version, which is the
behaviour resolvers already implement.

A pinned fetch has no resolution step to influence, so there is nothing to filter and
the request fails.

## See also

- [cooldown-waivers-manual-only](cooldown-waivers-manual-only.md) for the escape route
  when a quarantined version is genuinely needed.
