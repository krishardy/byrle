# Spike: config format (YAML vs. TOML)

Resolved Sept 2026. **Outcome: YAML, loaded by `serde-saphyr`.** Full findings and
rationale live in `docs/project_plan.md` §5 ("Configuration format"); decision #11 in
the decision record. This directory is the evidence, kept so the decision can be
re-run rather than re-argued.

Run it with `make spike-config` from the repo root.

## What it does

One schema (`src/schema.rs`) expresses the real §5.5 policy: `denials`, per-ecosystem
`floor`, `defaults`, `ecosystems`, and `packages` with `match` / `set` / `reason` /
`expires` / `permanent`. It uses plain `serde` derives with `deny_unknown_fields` and
**no crate-specific attributes**, which is what lets all four candidates deserialize the
identical type. That is also the argument that switching loaders later is cheap.

| Binary | Question it answers |
|---|---|
| `cfgspike` (default) | Loads every file in `policies/` with every candidate. The main matrix: readability, unknown-key rejection at four depths, error quality. |
| `probe` | How each parser resolves the bare token `no` (the Norway problem) against `bool` and `String` targets. |
| `bomb` | Whether an alias bomb expands unbounded. Deserializes into a **recursive value type** on purpose: an earlier version used a narrow struct, and the lazy struct-directed path skipped the fields that would have expanded, making everything look safe. That result was invalid. |
| `poly` | Whether `#[serde(untagged)]` destroys unknown-key rejection, and whether a hand-written `Deserialize` restores it. It does, in both formats. |

## The policy files

`policies/policy.yaml` and `policies/policy.toml` are the same policy, written honestly
in each format. The TOML is deliberately **not** flattened to make it look better than it
is: `[[packages]]` genuinely requires scalar keys before sub-tables, and `bad_order.toml`
demonstrates what happens when you write an entry in its natural reading order.

`bad_*` files each isolate one failure: unknown keys at four depths, YAML tab and missing
colon, TOML unclosed bracket and duplicate table, a typo'd `[[package]]`, and the Norway
cases. `bad_norway_str.yaml` is a probe rather than a malformation; every loader accepts it.

## Re-running the dependency audit

The audit is not part of `make spike-config`, since it needs the RustSec database:

```
cargo audit
```

All four candidates were clean. The method was validated by confirming `cargo audit`
still flags RUSTSEC-2025-0068 against `serde_yml`, the crate this spike excluded up front.
If your git config rewrites GitHub HTTPS to SSH, `cargo audit`'s fetch fails; fetch the
database over HTTPS separately and point at it with `--db <path> -n`.
