# What `byrle explain` prints

- **Status:** Implemented. `src/explain.rs`.
- **Related:** [policy-tier-resolution](policy-tier-resolution.md)

## Decision

`byrle explain <purl>` prints every check in the decision vector with its own outcome, and
then the verdict. A refusal that named only the strongest reason would hide the other checks
that fired and the ones that were never asked.

| State | Means |
|---|---|
| `pass` | the check ran and found nothing |
| `FAIL` | the check ran and found something |
| `excepted` | it found something and a `packages` entry excused it |
| `n/a` | the check has no meaning for this ecosystem |
| `unenforced` | the fact it needs is not available in this build or store |

`n/a` and `unenforced` both mean the check did not decide, and neither is shown as `pass`.

The verdict is the strongest answer among the checks, not a separate judgement. An
`unenforced` line is not one of the answers, because the proxy drops it before it acts
(`enforce::enforced`).

For `cooldown_days`, an `excepted` line names the global wait the package failed. A `FAIL`
line names the wait that applied, which a `packages` entry may have shortened.

Under the verdict, the signals, which refuse nothing: each with its weight from the policy's
`signal_weights`, and the risk score they sum to. `explain` holds no served names, so it
reports no near name, and it compares no source. The policy view lists every weight.

## Where the answer comes from

`explain` reads the same policy as the proxy and uses the same engine, so its answer and
the proxy's refusal agree. Metadata is fetched from the package's own registry, not through
a running proxy: the question is about the policy, and it does not need a proxy to be up.
Publish times are fetched only when the policy needs them, the same condition the proxy
uses. If they cannot be fetched, `explain` exits 1 rather than answer without them.
