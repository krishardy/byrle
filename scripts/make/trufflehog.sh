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
#
# TRUFFLEHOG_REPO_ROOT is the repository path as trufflehog sees it. For a native
# binary that is the real path, which the Makefile supplies and this script falls back
# to. It exists because a containerised trufflehog sees the repository at its mount
# point instead, and passing a host path to one of those fails.
#
# Both passes name that path explicitly and never use `.`. Under the container wrapper
# this project used previously, the image's working directory was /usr/bin, so
# `trufflehog filesystem .` scanned the scanner's own binaries and reported a clean
# repository it had never opened. `--fail-on-scan-errors` now turns an unreadable path
# into a failure, though it cannot catch a readable path that is the wrong directory.
#
# Exclusions live in .trufflehog-exclude in the repository rather than a temp file, so
# a containerised run can still see them.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

repo_uri="${TRUFFLEHOG_REPO_ROOT:-$repo_root}"

if ! command -v trufflehog >/dev/null 2>&1; then
    echo "trufflehog is not installed. Run 'make dev-setup'."
    exit 1
fi

failed=0

# trufflehog --fail exits 183 when it finds something. Capture it rather than letting
# `set -e` end the run before the second pass gets to report.
th=(trufflehog --no-update --no-color --fail --fail-on-scan-errors "$@")
[[ "${TRUFFLEHOG_NO_VERIFY:-0}" == "1" ]] && th+=(--no-verification)

echo "--- working tree"
# Both passes use $repo_uri, never `.`. Under the container wrapper the working
# directory is the image's own /usr/bin, so `trufflehog filesystem .` silently scans
# the scanner's binaries and reports the repository clean no matter what is in it.
rc=0
"${th[@]}" filesystem "$repo_uri" -x "$repo_uri/.trufflehog-exclude" || rc=$?
if [[ "$rc" -ne 0 ]]; then
    echo "    working-tree scan exited $rc"
    failed=1
fi

if [[ "${TRUFFLEHOG_SKIP_HISTORY:-0}" == "1" ]]; then
    echo "--- git history: SKIPPED (TRUFFLEHOG_SKIP_HISTORY=1)"
else
    echo "--- git history"
    rc=0
    "${th[@]}" git "file://$repo_uri" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        if [[ "$rc" != "183" ]]; then
            echo "    trufflehog could not scan history (exit $rc) at file://$repo_uri"
            echo "    If it cannot find the repository there, set TRUFFLEHOG_REPO_ROOT"
            echo "    to the path trufflehog itself sees. TRUFFLEHOG_SKIP_HISTORY=1"
            echo "    skips this pass."
        fi
        failed=1
    fi
fi

if [[ "$failed" -ne 0 ]]; then
    echo "FAIL: see above."
    exit 1
fi
echo "OK: no credentials found."
