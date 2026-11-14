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

# The crates byrle depends on directly that `$1`, a `cargo tree -i` spec, is built under, one
# per line. Every path is read (`--no-dedupe`), so a second route to it is not hidden.
built_under() {
    cargo tree -e normal --target all -i "$1" --prefix depth --no-dedupe 2>/dev/null \
        | awk 'match($0, /^[0-9]+/) {
                   depth = substr($0, 1, RLENGTH) + 0
                   split(substr($0, RLENGTH + 1), words, " ")
                   if (words[1] == "byrle") print parent[depth - 1]
                   parent[depth] = words[1]
               }' | sort -u || true
}

# Ignore advisory $1, against crate $2, only while byrle builds $2 under `pgp` alone, which
# byrle calls only to verify Maven signatures with public keys. The premise is asserted
# rather than trusted: any other route to $2 fails this check instead of the ignore quietly
# covering it.
accept_under_pgp() {
    local advisory="$1" crate="$2" under
    note "$advisory premise: $crate is built only for pgp"
    under="$(built_under "$crate")"
    if [[ -n "$under" && "$under" != "pgp" ]]; then
        echo "    $crate is built for $(echo "$under" | paste -sd, -), not pgp alone."
        echo "    The $advisory exception no longer holds; deal with the advisory."
        failed=1
    else
        echo "    ok: $crate is built for ${under:-nothing}, which only verifies"
        audit_args+=(--ignore "$advisory")
    fi
}

# `rsa`'s private-key operations leak timing (Marvin). It is in Cargo.lock through
# `sqlx-mysql` as well, which is not built
# (docs/engineering_decisions/0028-sqlx-0-8-and-rsa-advisory.md).
accept_under_pgp RUSTSEC-2023-0071 rsa
# `crypto-bigint` 0.5's constant-time operations vary in time. `pgp` 0.21 reaches it through
# `elliptic-curve` 0.13 and `cx448`, and verifying reads no secret
# (docs/engineering_decisions/0128-crypto-bigint-advisory.md).
accept_under_pgp RUSTSEC-2026-0387 crypto-bigint@0.5.5

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
# The newest release $2 of tool $1 against its pin $3 in $4. An empty $2 is a release that
# could not be read. Outdated is reported, not failed on.
report_pin() {
    local tool="$1" latest="$2" pinned="$3" file="$4"
    if [[ -z "$latest" ]]; then
        echo "$tool: the latest release could not be read; pinned $pinned"
    elif [[ "$latest" != "$pinned" ]]; then
        echo "$tool: $latest is out; $file pins $pinned"
        echo "    (outdated, not failing)"
    else
        echo "$tool: $pinned is the latest release"
    fi
}

# A GitHub release's tag_name, from its JSON on one line or many.
tag_name() { grep -oE '"tag_name": *"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/'; }

# shellcheck source=scripts/make/lib/shellcheck.sh
. "$repo_root/scripts/make/lib/shellcheck.sh"
report_pin shellcheck "$(curl -sSf https://api.github.com/repos/koalaman/shellcheck/releases/latest \
    | tag_name || true)" \
    "$shellcheck_version" scripts/make/lib/shellcheck.sh

# shellcheck source=scripts/make/lib/opengrep.sh
. "$repo_root/scripts/make/lib/opengrep.sh"
report_pin opengrep "$(curl -sSf https://api.github.com/repos/opengrep/opengrep/releases/latest \
    | tag_name || true)" \
    "$opengrep_version" scripts/make/lib/opengrep.sh

# shellcheck source=scripts/make/lib/java.sh
. "$repo_root/scripts/make/lib/java.sh"
report_pin JDK "$(curl -sSf https://api.github.com/repos/adoptium/temurin21-binaries/releases/latest \
    | tag_name || true)" \
    "$jdk_release" scripts/make/lib/java.sh
report_pin Maven "$(curl -sSf https://dlcdn.apache.org/maven/maven-3/ \
    | grep -oE '>3\.[0-9]+\.[0-9]+/<' | tr -d '<>/' | sort -V | tail -1 || true)" \
    "$maven_version" scripts/make/lib/java.sh

# shellcheck source=scripts/make/lib/gradle.sh
. "$repo_root/scripts/make/lib/gradle.sh"
report_pin Gradle "$(curl -sSf https://services.gradle.org/versions/current \
    | sed -n 's/^  "version" : "\(.*\)",$/\1/p' || true)" \
    "$gradle_version" scripts/make/lib/gradle.sh

note "result"
if [[ "$failed" -ne 0 ]]; then
    echo "FAIL: see above."
    exit 1
fi
echo "OK: no vulnerable dependencies."
