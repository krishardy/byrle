#!/usr/bin/env bash
# Pattern-based static analysis with opengrep, in place of `make semgrep`: the same rules, excludes, `nosemgrep` suppressions and exceptions report, from
# scripts/make/lib/semgrep_scan.sh. See
# docs/engineering_decisions/0138-opengrep-trial.md.
#
# Not part of `make sast`: the trial in 0138 ended with semgrep kept.
#
# opengrep has no login. It fetches the pinned packs from the semgrep registry as an
# anonymous client, which is the rule set `SEMGREP_ALLOW_ANONYMOUS=1` gives semgrep.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

if ! command -v opengrep >/dev/null 2>&1; then
    echo "opengrep is not installed. Run 'make install-opengrep'."
    exit 1
fi

# shellcheck source=scripts/make/lib/semgrep_scan.sh
. "$repo_root/scripts/make/lib/semgrep_scan.sh"
semgrep_scan opengrep "$@"
