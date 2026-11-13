#!/usr/bin/env bash
# The scan `make semgrep` and `make opengrep` run: the same rules, excludes and exceptions
# report, so the two engines' results can be compared line for line. Sourced, not executed.
#
# Shell rules come from `r/bash`, the registry namespace, because semgrep publishes no
# `p/` pack for shell: p/sh, p/bash and p/shell are all 404. It is seven rules, and the
# two that earn their place here are curl-pipe-bash and ifs-tampering; the unquoted
# expansion rules overlap with shellcheck, which `make lint` already runs. Verified
# against planted patterns rather than assumed: without r/bash the other three packs
# match nothing at all in a shell file.
#
# Rulesets are pinned rather than using `--config=auto`, which resolves rules by uploading
# a project fingerprint to semgrep.dev. Both engines fetch the rules from semgrep.dev on
# first run; set SEMGREP_RULES to a local path for a fully offline run.
#
# After the scan, `==> exceptions` lists what it was told to leave alone: each finding a
# suppression comment hides (file, line, rule, line text), suppression comments that hide
# nothing, and each path not scanned with the engine's reason. It is a report and does not
# change the exit status. See scripts/make/lib/semgrep_exceptions.py.

# Scan the repository with engine $1 (semgrep or opengrep), passing the rest of the
# arguments to it. Returns the scan's status, or 1 when the exceptions pass fails.
semgrep_scan() {
    local engine="$1"
    shift
    local repo_root
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

    local -a rules
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

    # semgrep sends usage metrics unless told not to. opengrep has no metrics, and refuses
    # the flag.
    local -a engine_flags=()
    [[ "$engine" == semgrep ]] && engine_flags=(--metrics=off)

    # bad_syntax_*.yaml are the config-format spike's deliberately malformed policies,
    # which the engines report as parse errors.
    local -a excludes=(--exclude=target --exclude='*.lock' --exclude='bad_syntax_*.yaml')

    local status=0
    "$engine" scan "${rules[@]}" "${engine_flags[@]}" --error \
        "${excludes[@]}" "$@" . || status=$?

    # What the scan above was told to leave alone. `--verbose` is what adds the skipped
    # paths to the JSON, and the SARIF keeps each finding a suppression comment hides. With
    # the rules cached it took 5s over this repository. The status stays the first
    # pass's, unless this pass fails and the list cannot be shown.
    printf '\n\033[1m==> %s exceptions\033[0m\n' "$engine"
    local json sarif errors pass=0
    json="$(mktemp)"
    sarif="$(mktemp)"
    errors="$(mktemp)"
    "$engine" scan "${rules[@]}" "${engine_flags[@]}" --json --verbose \
        --sarif-output="$sarif" "${excludes[@]}" "$@" . >"$json" 2>"$errors" || pass=$?
    if [[ "$pass" == 0 ]]; then
        python3 -I "$repo_root/scripts/make/lib/semgrep_exceptions.py" "$json" "$sarif"
    else
        echo "the exceptions pass exited $pass, so they are not listed. $engine said:"
        grep -iE 'error|fail|invalid|timed? ?out' "$errors" | tail -10 || tail -10 "$errors"
        [[ "$status" == 0 ]] && status=1
    fi
    rm -f "$json" "$sarif" "$errors"
    return "$status"
}
