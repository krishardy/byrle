#!/usr/bin/env bash
# List the commits that fail a check, and with FIX=1 rewrite them until none does. The checks:
#
#   credits    the message has no `Co-Authored-By: Claude ...`, `Claude-Session: ...` or
#              `Generated with [Claude Code]` line
#   signature  the commit carries a signature
#   sign-off   the message has a `Signed-off-by:` with the author's email, the Developer's
#              Certificate of Origin sign-off CONTRIBUTING.md asks for. A merge is not
#              checked: it is made by whoever merges, not by a contributor.
#
#   make commit-fixup                     the commits on HEAD on no remote-tracking branch
#   make commit-fixup BASE=<commit>       the commits on HEAD that are not on <commit>
#   make commit-fixup ALL=1               every commit on HEAD
#   make commit-fixup CHECKS=sign-off     only the checks named, space-separated
#   make commit-fixup FIX=1 [KEY=<id>]    rewrite them, signing with user.signingkey or <id>
#
# It exits 1 when a commit fails. CI runs it on every pull request with BASE the pull
# request's base commit and CHECKS=sign-off.
#
# Fixing rebases from the parent of the oldest failing commit. On each commit from there to
# HEAD, oldest first, it removes the credit lines, adds the author's sign-off, then signs.
# Every commit after the oldest failing one is rewritten too, and its hash changes. Each
# keeps its author and author date. It refuses when the working tree has uncommitted changes,
# when a commit it would rewrite is on a remote-tracking branch unless ALL=1, and when a
# commit to sign off has an author other than the committer: only the author can sign off.
#
# "Unsigned" is git's `%G?` of N. A signature this machine cannot check, E, counts as signed:
# the key is not in the keyring, but the commit carries a signature.
set -euo pipefail

credits='^Co-Authored-By: Claude|^Claude-Session: |Generated with \[Claude Code\]'
checks="${CHECKS:-credits signature sign-off}"
key="${KEY:-}"

checking() { [[ " $checks " == *" $1 "* ]]; }
lower() { tr '[:upper:]' '[:lower:]'; }
is_merge() { git rev-parse --verify --quiet "$1^2" >/dev/null; }

# Whether commit $1 has a Signed-off-by: with its author's email, compared without regard to
# case, as git compares it.
signed_off() {
    local author
    author="$(git log -1 --format=%ae "$1" | lower)"
    git log -1 --format='%(trailers:key=Signed-off-by,valueonly,separator=%x0a)' "$1" \
        | lower | grep -qF "<$author>"
}

# The checks commit $1 fails, comma-separated, or nothing.
failures() {
    local failed=()
    if checking credits && git log -1 --format=%B "$1" | grep -Eiq "$credits"; then
        failed+=(credits)
    fi
    if checking signature && [[ "$(git log -1 --format=%G? "$1")" == N ]]; then
        failed+=(signature)
    fi
    if checking sign-off && ! is_merge "$1" && ! signed_off "$1"; then
        failed+=(sign-off)
    fi
    local IFS=,
    echo "${failed[*]}"
}

# Run by the rebase on each commit: rewrite HEAD's message, then sign it.
if [[ "${1:-}" == --amend ]]; then
    message="$(git log -1 --format=%B)"
    if checking credits; then
        message="$({ grep -Eiv "$credits" <<<"$message" || true; } | git stripspace)"
    fi
    if checking sign-off && ! is_merge HEAD && ! signed_off HEAD; then
        message="$(git interpret-trailers \
            --trailer "Signed-off-by: $(git log -1 --format='%an <%ae>')" <<<"$message")"
    fi
    sign=()
    checking signature && sign=("--gpg-sign${key:+=$key}")
    if [[ ${#sign[@]} -gt 0 || "$message" != "$(git log -1 --format=%B | git stripspace)" ]]; then
        git commit --quiet --amend --no-verify --allow-empty "${sign[@]}" -m "$message"
    fi
    exit 0
fi

for check in $checks; do
    case "$check" in
        credits | signature | sign-off) ;;
        *) echo "FAIL: CHECKS names $check. The checks are credits, signature and sign-off."; exit 1 ;;
    esac
done

branch="$(git branch --show-current)"
if [[ -n "${BASE:-}" ]]; then
    if ! git rev-parse --verify --quiet "$BASE^{commit}" >/dev/null; then
        echo "FAIL: $BASE is not a commit here. Fetch it, or name another with BASE=<commit>."
        exit 1
    fi
    scope=("$BASE..HEAD")
    described="after $BASE"
elif [[ "${ALL:-}" == 1 ]]; then
    scope=(HEAD)
    described="on $branch"
else
    scope=(HEAD --not --remotes)
    described="on $branch and on no remote"
fi

# The commits in scope that fail a check, newest first: "<hash> <date> <failures> <subject>".
failing() {
    local commit failed
    while IFS= read -r commit; do
        failed="$(failures "$commit")"
        [[ -z "$failed" ]] || git log -1 --format="%H %ad $failed %s" --date=short "$commit"
    done < <(git rev-list "${scope[@]}")
}

show() { cut -c1-12,41- <<<"$1" | sed 's/^/  /'; }

list="$(failing)"
if [[ -z "$list" ]]; then
    echo "Every commit $described passes: $checks."
    exit 0
fi
echo "FAIL: $(wc -l <<<"$list") commit(s) $described fail a check ($checks):"
show "$list"

if [[ "${FIX:-}" != 1 ]]; then
    echo
    echo "Fix them with: make commit-fixup FIX=1${BASE:+ BASE=$BASE}${ALL:+ ALL=$ALL}${CHECKS:+ CHECKS=\"$CHECKS\"}"
    exit 1
fi

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "FAIL: the working tree has uncommitted changes. Commit or stash them first."
    exit 1
fi
if ! git var GIT_COMMITTER_IDENT >/dev/null 2>&1; then
    echo "FAIL: git has no committer identity. Set user.name and user.email first."
    exit 1
fi

oldest="$(tail -1 <<<"$list" | cut -d' ' -f1)"
if git rev-parse --verify --quiet "$oldest^" >/dev/null; then
    onto=("$oldest^")
    rewritten=("$oldest^..HEAD")
else
    onto=(--root)
    rewritten=(HEAD)
fi

pushed=$(($(git rev-list --count "${rewritten[@]}") - $(git rev-list --count "${rewritten[@]}" --not --remotes)))
if [[ $pushed -gt 0 && "${ALL:-}" != 1 ]]; then
    echo "FAIL: $pushed commit(s) from ${oldest:0:12} to HEAD are on a remote-tracking branch."
    echo "Rewriting them needs ALL=1, and pushing then needs git push --force-with-lease."
    exit 1
fi

if checking sign-off; then
    me="$(git var GIT_COMMITTER_IDENT | sed -E 's/.*<([^>]*)>.*/\1/' | lower)"
    others=()
    while IFS= read -r commit; do
        if ! is_merge "$commit" && ! signed_off "$commit" \
            && [[ "$(git log -1 --format=%ae "$commit" | lower)" != "$me" ]]; then
            others+=("$(git log -1 --format='%h %an <%ae>: %s' "$commit")")
        fi
    done < <(git rev-list "${rewritten[@]}")
    if [[ ${#others[@]} -gt 0 ]]; then
        echo "FAIL: only the author can sign off these, and the committer here is <$me>:"
        printf '  %s\n' "${others[@]}"
        exit 1
    fi
fi

head_before="$(git rev-parse HEAD)"
echo
echo "Rewriting from ${oldest:0:12}. To undo: git reset --hard $head_before"
# Run from a copy outside the repository: an older commit's tree does not hold this script.
amend="$(mktemp)"
trap 'rm -f "$amend"' EXIT
cp "${BASH_SOURCE[0]}" "$amend"
if ! git rebase --quiet --force-rebase --rebase-merges --exec "bash $amend --amend" "${onto[@]}"; then
    git rebase --abort
    echo "FAIL: the rebase stopped, and was aborted; HEAD is $head_before again."
    exit 1
fi

left="$(failing)"
if [[ -n "$left" ]]; then
    echo "FAIL: still failing:"
    show "$left"
    exit 1
fi
echo "Done. Every commit $described passes: $checks."
if [[ $pushed -gt 0 ]]; then
    echo "Pushed commits were rewritten: pushing needs git push --force-with-lease."
fi
