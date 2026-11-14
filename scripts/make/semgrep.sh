#!/usr/bin/env bash
# Pattern-based static analysis with semgrep.
#
# Complements `make lint`: clippy knows Rust semantics and catches misuse, semgrep
# matches taint and pattern rules across languages.
#
# The rules, excludes and exceptions report are in scripts/make/lib/semgrep_scan.sh, which
# `make opengrep` runs too.
#
# A login is required, because an anonymous run silently resolves fewer rules from the
# same pinned packs and still reports success. Measured on this repository, same 79 files
# and same packs: 57 rules anonymous against 103 logged in. That is the same failure
# `make lint` refuses for shellcheck, a scan covering less than it appears to and passing,
# except here nothing in the output says which of the two you got.
#
# Logging in does not send findings anywhere. Only `semgrep ci` uploads results
# (semgrep/commands/ci.py); this runs `semgrep scan`, which does not. What the token
# changes is which rules the registry serves. Rule fetching already contacts semgrep.dev
# either way.
#
# SEMGREP_ALLOW_ANONYMOUS=1 runs without one, for an environment where logging in is not
# possible. It says what it costs.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

if ! command -v semgrep >/dev/null 2>&1; then
    echo "semgrep is not installed. Run 'make dev-setup'."
    exit 1
fi

# Where semgrep keeps its token, resolved the way semgrep resolves it
# (semgrep/env.py): SEMGREP_SETTINGS_FILE, else $XDG_CONFIG_HOME/.semgrep/settings.yml
# when that directory exists, else ~/.semgrep/settings.yml. Note the leading dot even
# under XDG_CONFIG_HOME, which is semgrep's own doing.
semgrep_settings_file() {
    if [[ -n "${SEMGREP_SETTINGS_FILE:-}" ]]; then
        printf '%s\n' "$SEMGREP_SETTINGS_FILE"
        return
    fi
    local parent="$HOME"
    if [[ -n "${XDG_CONFIG_HOME:-}" && -d "$XDG_CONFIG_HOME" ]]; then
        parent="$XDG_CONFIG_HOME"
    fi
    printf '%s\n' "$parent/.semgrep/settings.yml"
}

# The token, in the order semgrep looks for it (semgrep/app/auth.py): the environment
# first, then the settings file. `semgrep login` is never called here: with no token and
# a TTY it prompts and waits, which would hang a build.
semgrep_token() {
    if [[ -n "${SEMGREP_APP_TOKEN:-}" ]]; then
        printf 'env\n'
        return
    fi
    local file value
    file="$(semgrep_settings_file)"
    [[ -f "$file" ]] || return 1
    value="$(sed -nE 's/^[[:space:]]*api_token:[[:space:]]*//p' "$file" | head -1 \
        | tr -d '"'"'"'[:space:]')"
    # A logged-out settings file still carries the key, written as null.
    [[ -n "$value" && "$value" != "null" && "$value" != "~" ]] || return 1
    printf '%s\n' "$file"
}

if source="$(semgrep_token)"; then
    echo "semgrep: logged in (token from $source)"
elif [[ "${SEMGREP_ALLOW_ANONYMOUS:-0}" == "1" ]]; then
    echo "semgrep: NOT logged in, and SEMGREP_ALLOW_ANONYMOUS=1."
    echo "         The registry serves fewer rules to an anonymous client, so this scan"
    echo "         covers less than a logged-in one and still reports success."
else
    cat <<'NOTE'
semgrep is not logged in.

The registry serves fewer rules to an anonymous client, so an anonymous scan covers less
than it appears to and still passes. Log in with:

    semgrep login

It does not send findings anywhere: only `semgrep ci` uploads results, and this runs
`semgrep scan`. Set SEMGREP_ALLOW_ANONYMOUS=1 to run without one anyway.
NOTE
    exit 1
fi

# shellcheck source=scripts/make/lib/semgrep_scan.sh
. "$repo_root/scripts/make/lib/semgrep_scan.sh"
semgrep_scan semgrep "$@"
