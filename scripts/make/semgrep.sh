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
#
# After the scan, `==> exceptions` lists what it was told to leave alone: each finding a
# suppression comment hides (file, line, rule, line text), suppression comments that hide
# nothing, and each path not scanned with semgrep's reason. It is a report and does not
# change the exit status. See scripts/make/lib/semgrep_exceptions.py.
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

# bad_syntax_*.yaml are the config-format spike's deliberately malformed policies, which
# semgrep reports as parse errors.
excludes=(--exclude=target --exclude='*.lock' --exclude='bad_syntax_*.yaml')

note() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

status=0
semgrep "${rules[@]}" --metrics=off --error \
    "${excludes[@]}" "$@" . || status=$?

# What the scan above was told to leave alone. semgrep reports a finding that a suppression
# comment hides only when suppressions are off, so this is a second pass with
# `--disable-nosem`, and `--verbose` is what adds the skipped paths to its JSON. With the
# rules cached it took 5s over this repository. The exit status stays the first pass's,
# unless this pass fails and the list cannot be shown.
note "exceptions"
json="$(mktemp)"
errors="$(mktemp)"
trap 'rm -f "$json" "$errors"' EXIT
pass=0
semgrep "${rules[@]}" --metrics=off --disable-nosem --json --verbose \
    "${excludes[@]}" "$@" . >"$json" 2>"$errors" || pass=$?
if [[ "$pass" == 0 ]]; then
    python3 "$repo_root/scripts/make/lib/semgrep_exceptions.py" "$json"
else
    echo "the exceptions pass exited $pass, so they are not listed. semgrep said:"
    grep -iE 'error|fail|invalid|timed? ?out' "$errors" | tail -10 || tail -10 "$errors"
    [[ "$status" == 0 ]] && status=1
fi
exit "$status"
