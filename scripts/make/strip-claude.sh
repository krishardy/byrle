#!/usr/bin/env bash
# List the commits on the current branch whose message credits Claude, and with STRIP=1
# rewrite them without those lines: `Co-Authored-By: Claude ...`, `Claude-Session: ...` and
# `Generated with [Claude Code]`.
#
#   make strip-claude                 list those not yet pushed
#   make strip-claude STRIP=1         rewrite them, then sign with make unsigned SIGN=1
#   make strip-claude STRIP=1 ALL=1   rewrite pushed ones too; pushing then needs --force
#
# Rewriting rebases from the parent of the oldest such commit, so every commit after it is
# rewritten too. Their hashes change and their signatures are dropped. Each keeps its author
# and author date. It refuses when the working tree has uncommitted changes.
set -euo pipefail

credits='^Co-Authored-By: Claude|^Claude-Session: |Generated with \[Claude Code\]'

# Run by the rebase on each commit: amend HEAD's message without the credit lines.
if [[ "${1:-}" == --amend ]]; then
    message="$(git log -1 --format=%B | grep -Eiv "$credits" | git stripspace)"
    if [[ "$message" != "$(git log -1 --format=%B | git stripspace)" ]]; then
        git commit --quiet --amend --no-verify --allow-empty --no-gpg-sign -m "$message"
    fi
    exit 0
fi

branch="$(git branch --show-current)"
# Without ALL=1, only commits on no remote-tracking branch.
scope=(HEAD)
[[ "${ALL:-}" == 1 ]] || scope+=(--not --remotes)

# The commits in scope that credit Claude, newest first: "<hash> <date> <subject>".
crediting() {
    git log -E -i --grep="$credits" --format='%H %ad %s' --date=short "${scope[@]}"
}

every="$(git rev-list -E -i --grep="$credits" --count HEAD)"
unpushed="$(git rev-list -E -i --grep="$credits" --count HEAD --not --remotes)"
pushed=$((every - unpushed))
list="$(crediting)"
if [[ -z "$list" ]]; then
    echo "No commit in scope on $branch credits Claude."
else
    echo "$(wc -l <<<"$list") commit(s) on $branch credit Claude:"
    cut -c1-12,41- <<<"$list" | sed 's/^/  /'
fi
if [[ "${ALL:-}" != 1 && "$pushed" -gt 0 ]]; then
    echo "$pushed pushed commit(s) credit Claude too; ALL=1 includes them."
fi
[[ -n "$list" ]] || exit 0

if [[ "${STRIP:-}" != 1 ]]; then
    echo
    echo "Rewrite them with: make strip-claude STRIP=1${ALL:+ ALL=1}"
    exit 0
fi

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "FAIL: the working tree has uncommitted changes. Commit or stash them first."
    exit 1
fi
oldest="$(tail -1 <<<"$list" | cut -d' ' -f1)"
if ! git var GIT_COMMITTER_IDENT >/dev/null 2>&1; then
    echo "FAIL: git has no committer identity. Set user.name and user.email first."
    exit 1
fi

head_before="$(git rev-parse HEAD)"
if git rev-parse --verify --quiet "$oldest^" >/dev/null; then
    onto=("$oldest^")
else
    onto=(--root)
fi
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

left="$(crediting)"
if [[ -n "$left" ]]; then
    echo "FAIL: still credit Claude:"
    cut -c1-12,41- <<<"$left" | sed 's/^/  /'
    exit 1
fi
echo "Done. Sign the rewritten commits with: make unsigned SIGN=1"
if [[ "${ALL:-}" == 1 ]]; then
    echo "Pushed commits were rewritten: pushing needs git push --force-with-lease."
fi
