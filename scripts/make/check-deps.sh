#!/usr/bin/env bash
# Dependency health: what is vulnerable, and what is out of date.
#
# The two are treated differently on purpose. A vulnerable dependency fails the
# check, because shipping one in a tool that exists to flag other people's vulnerable
# dependencies is indefensible. Merely-outdated is reported but does not fail, because
# a target that is red every week stops being read. Set CHECK_DEPS_STRICT=1 to fail on
# outdated too, which is the right setting for a release gate.
#
# Both the main crate and the committed config-format spike are checked. The spike is
# real committed code that pulls four YAML parsers, so it is exactly where a vulnerable
# dependency would otherwise sit unnoticed outside the workspace.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifests=("$repo_root/Cargo.toml" "$repo_root/spikes/config-format/Cargo.toml")

failed=0
note() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# `cargo audit` fetches the RustSec database from GitHub over git. If a global
# url.insteadOf rewrites GitHub HTTPS to SSH and no key is available, that fetch fails
# with a credentials error that looks nothing like a dependency problem. Point
# WAHAROA_ADVISORY_DB at a local checkout to skip fetching.
audit_args=()
if [[ -n "${WAHAROA_ADVISORY_DB:-}" ]]; then
    audit_args+=(--db "$WAHAROA_ADVISORY_DB" -n)
    echo "using advisory database at $WAHAROA_ADVISORY_DB (no fetch)"
fi

# In strict mode, "unmaintained" is also disqualifying. This project rejected
# serde_yml on exactly that ground (plan §5), so it would be inconsistent to let an
# unmaintained crate through our own gate silently.
[[ "${CHECK_DEPS_STRICT:-0}" == "1" ]] && audit_args+=(--deny warnings)

# The GitHub fetch fails confusingly when a global url.insteadOf rewrites HTTPS to SSH.
# Say so, because the error text mentions credentials and nothing about dependencies.
if [[ -z "${WAHAROA_ADVISORY_DB:-}" ]] \
    && git config --get-regexp 'url\..*\.insteadof' 2>/dev/null | grep -qi 'github'; then
    echo "note: your git config rewrites GitHub URLs (url.*.insteadOf). If the advisory"
    echo "      database fetch below fails on credentials, clone it over HTTPS and set"
    echo "      WAHAROA_ADVISORY_DB to that path."
fi

if ! cargo audit --version >/dev/null 2>&1; then
    echo "cargo-audit is not installed. Run 'make dev-setup'."
    exit 1
fi

note "vulnerable dependencies (cargo audit)"
for manifest in "${manifests[@]}"; do
    lock="${manifest%/Cargo.toml}/Cargo.lock"
    printf -- '--- %s\n' "${manifest#"$repo_root"/}"
    if [[ ! -f "$lock" ]]; then
        echo "    no Cargo.lock; run 'cargo generate-lockfile' for this manifest"
        failed=1
        continue
    fi
    if ! cargo audit "${audit_args[@]}" --file "$lock"; then
        failed=1
    fi
done

note "outdated dependencies (cargo outdated)"
if ! cargo outdated --version >/dev/null 2>&1; then
    echo "cargo-outdated is not installed. Run 'make dev-setup'."
    echo "Skipping the outdated check; the vulnerability check above still applies."
    [[ "${CHECK_DEPS_STRICT:-0}" == "1" ]] && failed=1
else
    for manifest in "${manifests[@]}"; do
        printf -- '--- %s\n' "${manifest#"$repo_root"/}"
        # --root-deps-only: what we chose, not what our dependencies chose. Transitive
        # churn is not actionable here, and a vulnerable transitive is the audit's job.
        if ! cargo outdated --manifest-path "$manifest" --root-deps-only --exit-code 1; then
            if [[ "${CHECK_DEPS_STRICT:-0}" == "1" ]]; then
                failed=1
            else
                echo "    (outdated, not failing; set CHECK_DEPS_STRICT=1 to enforce)"
            fi
        fi
    done
fi

note "result"
if [[ "$failed" -ne 0 ]]; then
    echo "FAIL: see above."
    exit 1
fi
echo "OK: no vulnerable dependencies."
