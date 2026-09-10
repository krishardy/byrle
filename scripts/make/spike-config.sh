#!/usr/bin/env bash
# Re-run the config-format spike (plan §5, decision #11).
# Evidence for "YAML via serde-saphyr", kept runnable so the decision can be
# re-checked rather than re-argued.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
spike_dir="$repo_root/spikes/config-format"

run() {
    local bin="$1" what="$2"
    printf '\n########## %s: %s\n\n' "$bin" "$what"
    cargo run --quiet --manifest-path "$spike_dir/Cargo.toml" --bin "$bin"
}

run cfgspike "load every policy file with every candidate loader"
run probe    "how each parser resolves the bare token 'no'"
run bomb     "does an alias bomb expand unbounded"
run poly     "does #[serde(untagged)] defeat unknown-key rejection"

cat <<'NOTE'

##########

The dependency audit is deliberately not run here, since it needs the RustSec
database. See spikes/config-format/README.md for how to reproduce it.
NOTE
