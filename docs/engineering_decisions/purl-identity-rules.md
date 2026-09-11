# PURL identity rules for npm

- **Status:** Decided
- **Plan reference:** plan §4. No number; taken during Stage 1, Sept 2026.
- **Implementation:** `src/identity.rs`
- **Conformance check:** `cargo run --example osv_conformance`

## Decision

Package identity is PURL throughout the core, using the `purl` crate from phylum-dev.
Two types: `PackageKey` (versionless, the advisory lookup key) and `PackageRef` (key
plus concrete version). npm names are not lowercased. Lookups key on parsed components,
never on the purl string. Identity is read from the packument's `name` field.

`packageurl` was rejected: it lowercases npm names per purl-spec, which loses matches
against OSV.

## Rationale


"Keys on PURL" hides four decisions that each cost advisory matches if taken the
obvious way. All four were measured against OSV's full npm bundle: 228,941 advisories,
224,743 distinct package names, and a live OSV API for confirmation.

**1. Two types, because OSV has two shapes.** Every one of the 231,533 npm entries
carries a *versionless* purl (`pkg:npm/lodash`), with version ranges in a separate
field. Zero carry a version. So the lookup key is versionless, and version matching is
a second step. `PackageKey` is the versionless lookup key; `PackageRef` is a key plus a
concrete version, which is what a verdict is about and what §5.5 `denials` match on.
Conflating them means the lookup path cannot express a key.

**2. Do not lowercase npm names, despite the spec.** purl-spec says npm names MUST be
lowercased. OSV does not, and OSV is what we have to match. 112 npm names in the corpus
contain uppercase and all 112 are case-preserved in OSV's own purl. The great majority
are `MAL-` records, which are malicious-package advisories. §5.5 pins
`known_malware: block` to the non-overridable floor:

```text
pkg:npm/AdultJS  ->  MAL-2025-14119
pkg:npm/adultjs  ->  no match
```

OSV also holds four npm names that differ only by case, one of them three ways
(`OpenClaw`, `Openclaw`, `openclaw`). Case-insensitive keying merges their advisories.
The deviation from purl-spec is documented at the top of `src/identity.rs`.

**3. OSV writes scoped packages two ways, and they do not parse alike.** 16,904 scoped
entries use `pkg:npm/%40antv/algorithm` and 855 use `pkg:npm/%40antv%2Falgorithm`.
Under strict purl parsing the first is namespace `@antv` + name `algorithm` and the
second is no namespace + name `@antv/algorithm`. OSV's API normalizes them; a local
mirror holds the raw strings and does not. **So the mirror keys on parsed components,
never on the purl string**, and the parser rejoins an encoded scope. Missing this
silently orphans those 855 records, which are disproportionately malware.

**4. Identity comes from the packument's `name`, not the request path.** The registry
is case-sensitive (`/adultjs` 404s where `/AdultJS` returns 200), so for npm the two
agree, but the body is the canonical spelling and the path also carries percent-encoding
and query strings. Read identity from the body.

Guard: `cargo run --example osv_conformance` checks that a key built from the registry
name and a key parsed from OSV's purl are the same key, for all 224,743 packages. The
invariant is deliberately not "we emit OSV's bytes", since OSV is not self-consistent.

