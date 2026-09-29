# What an npm packument holds, measured

- **Status:** Implemented. `src/ecosystem/npm/wire.rs`, `src/ecosystem/npm/normalize.rs`.
- **Related:** [adapter-interface](adapter-interface.md),
  [config-format-yaml-serde-saphyr](config-format-yaml-serde-saphyr.md),
  [artifact-digest-verification](artifact-digest-verification.md)

## Decision

The npm wire types ignore keys they do not model. npm adds fields to packuments without
notice, and a registry doing that must never break an install passing through the proxy.
The policy loader takes the opposite position and refuses unknown keys, because a typo in
an operator's policy must fail loudly rather than disable a rule.

A version that cannot be normalised is kept in `PackageMetadata::skipped` rather than
dropped. A version that vanishes between the registry and the policy engine is a version
nothing gates.

## What was measured

24,852 versions across 47 packages, each fetched as both the abbreviated and the full
document, September 2026. The set mixes current packages with ones published in 2011 and
2012, where npm's metadata stops being uniform.

| Field | Found | So |
|---|---|---|
| `dist.tarball` | on every version | a version without one is a document defect and is skipped |
| `dist.shasum` | on every version | |
| `dist.integrity` | missing on 2, both from 2012: `event-stream@0.9.1`, `vue@0.8.6` | `Artifact::integrity` is an `Option` |
| `versions` key against the version's own `version` | never disagreed | the key is the authority, because npm resolves a range against it |
| `hasInstallScript` | `true` on 901 versions, absent on the rest, never `false` | absence reads as no install script |
| `repository` | an object 24,477 times, a string 5 times (`bower@1.8.11`–`1.8.14`, `rimraf@1.0.0`) | its deserializer takes both |
| install scripts, abbreviated against full | agreed on all 24,852 pairs | |

`real_packuments_normalise_without_skipping_anything` checks this against a corpus on disk.
