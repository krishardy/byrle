#!/usr/bin/env bash
# Credential scanning with trufflehog.
#
# Two passes, because they cover different ground. The working tree catches a secret
# not yet committed; history catches one committed and later deleted, which is gone
# from the tree and still in the repository.
#
# `--no-update` stops the version phone-home. Credential *verification* is left on and
# is a different thing from telemetry: it authenticates a candidate secret against the
# service that issued it, which is what separates live credentials from noise. Set
# TRUFFLEHOG_NO_VERIFY=1 to turn it off.
#
# Both passes run even if the first fails, so one report covers everything.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

if ! command -v trufflehog >/dev/null 2>&1; then
    echo "trufflehog is not installed. Run 'make dev-setup'."
    exit 1
fi

failed=0

# trufflehog --fail exits 183 when it finds something. Capture it rather than letting
# `set -e` end the run before the second pass gets to report.
th=(trufflehog --no-update --no-color --fail "$@")
[[ "${TRUFFLEHOG_NO_VERIFY:-0}" == "1" ]] && th+=(--no-verification)

echo "--- working tree"
# Scanned as `.` from the repo root rather than by absolute path: trufflehog skips
# binaries itself, so the ignored build output costs almost nothing to walk.
rc=0
"${th[@]}" filesystem . || rc=$?
if [[ "$rc" -ne 0 ]]; then
    echo "    working-tree scan exited $rc"
    failed=1
fi

if [[ "${TRUFFLEHOG_SKIP_HISTORY:-0}" == "1" ]]; then
    echo "--- git history: SKIPPED (TRUFFLEHOG_SKIP_HISTORY=1)"
else
    echo "--- git history"
    rc=0
    "${th[@]}" git "file://$repo_root" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        if [[ "$rc" != "183" ]]; then
            echo "    trufflehog could not scan history (exit $rc)."
            echo "    It clones to a temp directory; if this environment blocks that,"
            echo "    set TRUFFLEHOG_SKIP_HISTORY=1 and scan history in CI instead."
        fi
        failed=1
    fi
fi

if [[ "$failed" -ne 0 ]]; then
    echo "FAIL: see above."
    exit 1
fi
echo "OK: no credentials found."
