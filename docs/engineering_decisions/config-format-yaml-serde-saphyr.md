# Config format: YAML, loaded by serde-saphyr

- **Status:** Decided
- **Plan reference:** decision #11
- **Spike:** `make spike-config`, evidence kept in `spikes/config-format/`

## Decision

YAML, loaded by `serde-saphyr` with `default-features = false` and
`features = ["deserialize"]`. `include` and `include_fs` stay off permanently. Fallback
loader is `serde_norway`. The schema never uses `#[serde(untagged)]`.

## Rationale


`serde_yaml` is archived, and every successor has a real defect:

| Option | Status |
|---|---|
| `serde_yml` | ❌ **RUSTSEC-2025-0068**, unsound and unmaintained, repo archived. Disqualifying on its own; unshippable for a tool that consumes the advisory DB flagging it. |
| `serde_norway` | Hard fork via `unsafe-libyaml-norway`; named by RustSec as a maintained alternative. Fixes the Norway problem (bare `no` parsing as boolean false, relevant given keys like `provenance_required`). Still C FFI. |
| `serde-yaml-ng` | Direct continuation of dtolnay's original: battle-tested, familiar API. But uses unmaintained `unsafe-libyaml`: C FFI with an unmaintained upstream, awkward to defend in our own audit output. |
| `serde-saphyr` | ✅ **Chosen.** Pure Rust, no C FFI. Zero `unsafe` in its own code and in its parser, both carrying `forbid(unsafe_code)`. Panic-free on malformed input, no tag-driven object construction (the classic YAML RCE vector), configurable nesting/size budgets, parses straight to Rust types with no intermediate document model. **Corrected Sept 2026: now 1.2.0, not 0.0.10** (1.0.0 released July 2026 after two RCs, steady cadence since). It also no longer depends on `saphyr` at all, having vendored its own `granit-parser`, so the "upstream calls serde support soon-to-be" objection is void. Residual risk: single maintainer, and a 26-crate tree that pulls `encoding_rs` (SIMD, plenty of `unsafe`). |
| `toml` | Pure Rust, well maintained by the toml-rs team, Rust's own format, no Norway problem, and by far the smallest tree (6 crates). `toml_parser` gates its own `unsafe` behind an opt-in feature, off by default, though `winnow` beneath it carries 44 `unsafe` blocks that are not feature-gated. Rejected on the two format criteria, not on dependencies. See the findings below. |

#### Spike result (Sept 2026): **YAML, loaded by `serde-saphyr`**

The spike was run as specified: the real §5.5 policy (2 denials, per-ecosystem floor,
3 package entries with selectors, `set` blocks, `reason`, `expires`, `permanent`) written
in both formats, plus 16 malformed or probing variants, loaded by all four candidates
through one identical `deny_unknown_fields` schema.

**The premise that framed this decision was wrong, and that is what changed the answer.**
The tiebreak assumed TOML was the only pure-Rust option. `serde-saphyr` is now 1.2.0
rather than 0.0.10, has dropped `saphyr` for its own `granit-parser`, and carries zero
`unsafe` in both crates. So the "pure Rust versus readable" trade no longer exists, and
YAML wins on both format criteria without paying a dependency penalty.

**1. Readability.** YAML 50 lines, TOML 70. Verbosity is not the real cost. Inside
`[[packages]]`, TOML requires the scalar keys (`reason`, `expires`, `permanent`,
`added_by`) to precede the `[packages.match]` and `[packages.set.*]` sub-tables, so the
justification must be written before the thing it justifies. Writing an entry in its
natural reading order is a parse error, and a misleading one: the trailing keys get
absorbed into the still-open cooldown table, producing ``unknown field `added_by`,
expected `action` or `days` ``. Every package entry an operator writes is exposed to this.

**2. Unknown-key rejection.** Survives in all four loaders at all four depths tested
(root, inside a `match` selector, inside a `set` block, inside the polymorphic rule
struct). A tie, with one important exception recorded as a schema constraint below.

**3. Error quality.** `serde-saphyr` is clearly best: source excerpt, caret, and plain
language (`tabs disallowed within this context (block indentation)` where libyaml-based
crates say `found character that cannot start any token`). `toml` has good spans but two
misleading-error classes, both from table syntax rather than from serde: the ordering
case above, and a typo'd `[[package]]` for `[[packages]]`, which reports `duplicate key`
against a correct line six lines further down instead of naming the unknown table.
`serde_norway` and `serde-yaml-ng` are byte-identical in output, adequate for serde
errors and poor for syntax errors.

**Dependency and security posture.** All four are clean under `cargo audit` (method
validated by confirming it still flags RUSTSEC-2025-0068 against the excluded
`serde_yml`). `serde-saphyr` plus `granit-parser` carry zero `unsafe` and both set
`forbid(unsafe_code)`; the cost is a 26-crate tree that pulls `encoding_rs`. `toml` is
6 crates. The libyaml pair carry C FFI.

**Two assumptions the spike falsified, recorded so they are not re-derived:**

- **Alias bombs are not a discriminator.** All three YAML crates refuse a 9^8 expansion.
  libyaml has its own repetition limit and refuses in ~9ms; `serde-saphyr` refuses via
  its node budget but takes ~100ms and emits a genuinely bad message (`budget breached:
  Nodes { nodes: 250001 }` followed by five repeated position clauses). A known wart.
  Note the first version of this test was invalid: the lazy struct-directed path skipped
  fields the target type never demanded, so everything appeared to parse. The valid test
  deserializes into a recursive value type that forces full materialization.
- **The Norway problem is dissolved by a type-directed parser, not by `serde_norway`.**
  `serde-saphyr` resolves the bare token `no` against the target type: `false` for a
  `bool` field, `"no"` for a `String` field. Both are what the author meant.
  `serde_norway` and `serde-yaml-ng` always yield the string, so the entirely natural
  `provenance_required: no` is a hard type error.

**Schema constraint, load-bearing: never `#[serde(untagged)]`.** Rule fields are
polymorphic (`install_scripts: warn` or a table carrying the §5 acknowledgment). Modelled
with `untagged`, a typo inside the table form degrades to `data did not match any variant
of untagged enum ScriptRule` in *every* loader, in both formats, silently defeating the
fail-closed guarantee that unknown keys are a hard error. A hand-written `Deserialize`
that calls `deserialize_any` and dispatches `visit_str` to the bare form and `visit_map`
to the table form restores the exact message (``unknown field `expiress`, expected one of
action, loosens_global, reason, expires``) with correct spans in both YAML and TOML. This
applies to every polymorphic rule field added later, not just `install_scripts`.

**Feature posture.** `default-features = false`, `features = ["deserialize"]`: we only
ever read config, never write it. `include` and `include_fs` stay **off** permanently.
File inclusion in the policy file of a security tool is attack surface, not convenience.

**Residual risk and the exit.** `serde-saphyr` is a single-maintainer crate about six
weeks past 1.0. That risk is bounded because the schema uses plain `serde` derives with
zero crate-specific attributes: all four candidates deserialized the identical `Policy`
type in the spike, so switching loaders is a one-line change. **`serde_norway` is the
named fallback**, being the alternative RustSec itself points to.

