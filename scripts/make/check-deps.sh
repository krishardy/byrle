#!/usr/bin/env bash
# Dependency health: what is vulnerable, and what is out of date.
#
# The two are treated differently on purpose. A vulnerable dependency fails the
# check, because shipping one in a tool that exists to flag other people's vulnerable
# dependencies is indefensible. Merely-outdated is reported but does not fail, because
# a target that is red every week stops being read. Set CHECK_DEPS_STRICT=1 to fail on
# outdated too, which is the right setting for a release gate.
#
# Both the main crate and the committed config-format spike are audited for
# vulnerabilities. The spike is real committed code that pulls four YAML parsers, so it is
# exactly where a vulnerable dependency would otherwise sit unnoticed outside the
# workspace.
#
# Only the main crate is checked for freshness. The spike's Cargo.lock is the record of
# what the config-format spike actually tested, and bumping it to silence a report would
# replace that record with a claim about versions nobody ran. A vulnerability in it still
# has to be known, which is why the two halves treat it differently.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifests=("$repo_root/Cargo.toml" "$repo_root/spikes/config-format/Cargo.toml")

failed=0
note() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# `cargo audit` fetches the RustSec database from GitHub over git. A global
# url.insteadOf rewriting GitHub HTTPS to SSH, with no key available, makes that fetch
# fail with a credentials error that mentions nothing about dependencies. Left alone it
# fails the whole target, so the advisory half stops running and the failure gets read as
# noise.
#
# BYRLE_ADVISORY_DB points at a local checkout. Otherwise the fallback below fetches the
# database over plain HTTPS, where no git configuration applies.
audit_args=()
# Tracked separately from audit_args: strict mode adds flags of its own, so "are we using
# a local database" cannot be read off whether the array is empty.
local_db=""
if [[ -n "${BYRLE_ADVISORY_DB:-}" ]]; then
    local_db="$BYRLE_ADVISORY_DB"
    audit_args+=(--db "$local_db" -n)
    echo "using advisory database at $local_db (no fetch)"
fi

# The database as a tarball, which needs no git and no credentials.
advisory_tarball="https://codeload.github.com/RustSec/advisory-db/tar.gz/refs/heads/main"
advisory_cache="$repo_root/target/advisory-db"

fetch_advisory_db_over_https() {
    # Kept under target/ so `cargo clean` clears it, and refreshed daily: an advisory
    # database a week old is worse than useless, because it reports success.
    if [[ -d "$advisory_cache/crates" ]] \
        && [[ -n "$(find "$advisory_cache/.fetched" -newermt '-1 day' 2>/dev/null)" ]]; then
        echo "    using the copy fetched within the last day"
        return 0
    fi
    command -v curl >/dev/null 2>&1 || { echo "    curl is required"; return 1; }
    echo "    fetching it over HTTPS instead"
    rm -rf "$advisory_cache"
    mkdir -p "$advisory_cache"
    curl -sSL --max-time 300 "$advisory_tarball" | tar xz -C "$advisory_cache" --strip-components=1 \
        || return 1
    [[ -d "$advisory_cache/crates" ]] || return 1
    touch "$advisory_cache/.fetched"
    return 0
}

# In strict mode, "unmaintained" is also disqualifying. This project rejected
# serde_yml on exactly that ground (plan §5), so it would be inconsistent to let an
# unmaintained crate through our own gate silently.
[[ "${CHECK_DEPS_STRICT:-0}" == "1" ]] && audit_args+=(--deny warnings)

if ! cargo audit --version >/dev/null 2>&1; then
    echo "cargo-audit is not installed. Run 'make dev-setup'."
    exit 1
fi

# RUSTSEC-2023-0071 is against `rsa`, which reaches Cargo.lock through `sqlx-mysql`.
# We build Postgres only, so `rsa` is never compiled: `cargo tree -e normal --target all`
# finds no `rsa`. cargo-audit reads the lockfile rather than the build, so it reports a
# crate that is not shipped.
#
# The premise is asserted rather than trusted. Enabling a MySQL feature would put `rsa` in
# the build and this check fails loudly instead of the ignore quietly covering it.
note "RUSTSEC-2023-0071 premise: rsa is not compiled"
if cargo tree -e normal --target all 2>/dev/null | grep -q 'rsa v'; then
    echo "    rsa IS in the build. The RUSTSEC-2023-0071 exception no longer holds."
    echo "    Remove the --ignore below and deal with the advisory."
    failed=1
else
    echo "    ok: rsa is in Cargo.lock via sqlx-mysql and is not built"
    audit_args+=(--ignore RUSTSEC-2023-0071)
fi

note "vulnerable dependencies (cargo audit)"

# One probe, so the fallback is chosen by what actually happens rather than by guessing
# at the cause. A fetch failure is fast, so the cost when it succeeds is one extra run of
# the first manifest.
if [[ -z "$local_db" ]]; then
    probe="$(cargo audit --file "$repo_root/Cargo.lock" 2>&1 || true)"
    if grep -q "couldn't fetch advisory database" <<<"$probe"; then
        echo "    the advisory database could not be fetched over git"
        if fetch_advisory_db_over_https; then
            local_db="$advisory_cache"
            audit_args+=(--db "$local_db" -n)
        else
            echo "    and HTTPS failed too, so no advisory check ran"
            failed=1
        fi
    fi
fi
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
    printf -- '--- %s\n' "Cargo.toml"
    # --root-deps-only: what we chose, not what our dependencies chose. Transitive churn
    # is not actionable here, and a vulnerable transitive is the audit's job.
    if ! cargo outdated --manifest-path "$repo_root/Cargo.toml" --root-deps-only --exit-code 1; then
        if [[ "${CHECK_DEPS_STRICT:-0}" == "1" ]]; then
            failed=1
        else
            echo "    (outdated, not failing; set CHECK_DEPS_STRICT=1 to enforce)"
        fi
    fi
    echo "--- spikes/config-format/Cargo.toml"
    echo "    not checked for freshness: its lock is the record of what the spike ran."
    echo "    It is still audited for vulnerabilities above."
fi

note "pinned tools"
# shellcheck source=scripts/make/lib/shellcheck.sh
. "$repo_root/scripts/make/lib/shellcheck.sh"
latest="$(curl -sSf https://api.github.com/repos/koalaman/shellcheck/releases/latest \
    | sed -n 's/^  "tag_name": "\(.*\)",$/\1/p' || true)"
if [[ -z "$latest" ]]; then
    echo "shellcheck: the latest release could not be read; pinned $shellcheck_version"
elif [[ "$latest" != "$shellcheck_version" ]]; then
    echo "shellcheck: $latest is out; scripts/make/lib/shellcheck.sh pins $shellcheck_version"
    echo "    (outdated, not failing)"
else
    echo "shellcheck: $shellcheck_version is the latest release"
fi

note "result"
if [[ "$failed" -ne 0 ]]; then
    echo "FAIL: see above."
    exit 1
fi
echo "OK: no vulnerable dependencies."
