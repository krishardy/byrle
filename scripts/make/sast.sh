#!/usr/bin/env bash
# Static analysis with semgrep.
#
# Complements `make lint`: clippy knows Rust semantics and catches misuse, semgrep
# matches taint and pattern rules across languages and also covers the shell scripts
# in this directory, which clippy cannot see at all.
#
# Rulesets are pinned explicitly rather than using `--config=auto`, which resolves
# rules by uploading a project fingerprint to semgrep.dev. Metrics are off for the
# same reason: a tool whose pitch is "no mandatory outbound calls to us" should not
# quietly make some of its own. Rule *fetching* still needs the network on first run;
# set SEMGREP_RULES to a local path to work fully offline.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! command -v semgrep >/dev/null 2>&1; then
    echo "semgrep is not installed. Run 'make dev-setup'."
    exit 1
fi

# Override with e.g. SEMGREP_RULES="--config /path/to/rules" for an offline run.
if [[ -n "${SEMGREP_RULES:-}" ]]; then
    read -r -a rules <<<"$SEMGREP_RULES"
else
    rules=(
        --config p/rust       # Rust-specific patterns
        --config p/secrets    # credentials committed by accident
        --config p/bash       # scripts/make/*.sh are real code too
    )
fi

cd "$repo_root"
exec semgrep \
    "${rules[@]}" \
    --metrics=off \
    --error \
    --exclude=target \
    --exclude='*.lock' \
    "$@" \
    .
