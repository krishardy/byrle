#!/usr/bin/env bash
# Static analysis: semgrep for code patterns, trufflehog for credentials.
#
# Complements `make lint`. clippy knows Rust semantics and catches misuse; semgrep
# matches taint and pattern rules across languages; trufflehog looks for committed
# credentials, which neither of the others detect.
#
# Shell rules come from `r/bash`, the registry namespace, because semgrep publishes no
# `p/` pack for shell: p/sh, p/bash and p/shell are all 404. It is seven rules, and the
# two that earn their place here are curl-pipe-bash and ifs-tampering; the unquoted
# expansion rules overlap with shellcheck, which `make lint` already runs. Verified
# against planted patterns rather than assumed: the three packs above match nothing at
# all in a shell file.
#
# Outbound calls are controlled deliberately in both tools:
#
#   semgrep     --metrics=off, and pinned rulesets rather than `--config=auto`, which
#               resolves rules by uploading a project fingerprint to semgrep.dev.
#   trufflehog  --no-update, to stop the version phone-home.
#
# trufflehog's credential *verification* is left on, and is a different thing from
# telemetry: it authenticates a candidate secret against the service that issued it, to
# separate live credentials from noise. That is the feature worth having. Set
# SAST_NO_VERIFY=1 to turn it off.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

failed=0
note() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# trufflehog --fail exits 183 when it finds something, which we translate rather than
# letting `set -e` kill the run before the other scanner gets to report.
run_scanner() {
    local label="$1"; shift
    local rc=0
    # Assign in a separate step: `local rc=$?` would capture `local`'s own status.
    "$@" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        echo "    $label exited $rc"
        failed=1
    fi
    return 0
}

note "code patterns (semgrep)"
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
run_scanner semgrep semgrep "${rules[@]}" --metrics=off --error \
    --exclude=target --exclude='*.lock' .

note "credentials (trufflehog)"
if ! command -v trufflehog >/dev/null 2>&1; then
    echo "trufflehog is not installed. Run 'make dev-setup'."
    exit 1
fi

th=(trufflehog --no-update --no-color --fail)
[[ "${SAST_NO_VERIFY:-0}" == "1" ]] && th+=(--no-verification)

echo "--- working tree"
# Scanned as `.` from the repo root rather than by absolute path: trufflehog skips
# binaries itself, so the ignored build output costs almost nothing to walk.
run_scanner "trufflehog (working tree)" "${th[@]}" filesystem .

# History matters separately: a credential committed and then deleted is gone from the
# working tree and still in the repository. Skippable because it clones to a temp
# directory, which not every sandbox permits.
if [[ "${SAST_SKIP_HISTORY:-0}" == "1" ]]; then
    echo "--- git history: SKIPPED (SAST_SKIP_HISTORY=1)"
else
    echo "--- git history"
    rc=0
    "${th[@]}" git "file://$repo_root" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        if [[ "$rc" == "183" ]]; then
            failed=1
        else
            echo "    trufflehog could not scan history (exit $rc)."
            echo "    It clones to a temp directory; if this environment blocks that,"
            echo "    set SAST_SKIP_HISTORY=1 and scan history in CI instead."
            failed=1
        fi
    fi
fi

note "result"
if [[ "$failed" -ne 0 ]]; then
    echo "FAIL: see above."
    exit 1
fi
echo "OK: no findings."
