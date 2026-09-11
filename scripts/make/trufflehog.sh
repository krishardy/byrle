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
# TRUFFLEHOG_REPO_ROOT is the repository path *as trufflehog sees it*, which is not
# always the path we see. The usual install here is a wrapper around
# `docker run -v "$PWD:/pwd"`, so inside the container the repository is at /pwd and
# nothing else on this machine is visible: an absolute host path fails to resolve and
# the clone for the history pass fails with it. The Makefile supplies the value;
# running this script directly falls back to the real path, which is what a native
# trufflehog wants.
#
# Never pass `.` instead. That container's working directory is /usr/bin, so `.` scans
# the scanner's own binaries: 45MB of them, a constant 3383 chunks, and a clean bill of
# health for a repository it never opened.
#
# Exclusions come from .trufflehog-exclude in the repository, not a temp file, for the
# same reason: the container cannot see anything outside the mount.
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
th=(trufflehog --no-update --no-color --fail "$@")
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
