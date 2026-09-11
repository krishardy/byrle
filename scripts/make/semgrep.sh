#!/usr/bin/env bash
# Pattern-based static analysis with semgrep.
#
# Complements `make lint`: clippy knows Rust semantics and catches misuse, semgrep
# matches taint and pattern rules across languages.
#
# Shell rules come from `r/bash`, the registry namespace, because semgrep publishes no
# `p/` pack for shell: p/sh, p/bash and p/shell are all 404. It is seven rules, and the
# two that earn their place here are curl-pipe-bash and ifs-tampering; the unquoted
# expansion rules overlap with shellcheck, which `make lint` already runs. Verified
# against planted patterns rather than assumed: without r/bash the other three packs
# match nothing at all in a shell file.
#
# `--metrics=off`, and rulesets are pinned rather than using `--config=auto`, which
# resolves rules by uploading a project fingerprint to semgrep.dev. Rule *fetching*
# still needs the network on first run; set SEMGREP_RULES to a local path for a fully
# offline run.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

if ! command -v semgrep >/dev/null 2>&1; then
    echo "semgrep is not installed. Run 'make dev-setup'."
    exit 1
fi

# Override with e.g. SEMGREP_RULES="--config /path/to/rules" for an offline run.
if [[ -n "${SEMGREP_RULES:-}" ]]; then
    read -r -a rules <<<"$SEMGREP_RULES"
else
    rules=(
        --config p/rust            # Rust-specific patterns
        --config p/secrets         # credentials committed by accident
        --config p/security-audit  # cross-language audit rules
        --config r/bash            # shell: see the note above on why r/ not p/
    )
fi

exec semgrep "${rules[@]}" --metrics=off --error \
    --exclude=target --exclude='*.lock' "$@" .
