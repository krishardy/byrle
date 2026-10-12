#!/usr/bin/env bash
# List the commits on the current branch that carry no signature, and with SIGN=1 sign them.
#
#   make unsigned                     list them
#   make unsigned SIGN=1              sign them with user.signingkey
#   make unsigned SIGN=1 KEY=<id>     sign them with key <id>
#
# Signing rebases from the parent of the oldest unsigned commit, so every commit after it
# is rewritten and signed too, including ones already signed. Their hashes change. It
# refuses when the working tree has uncommitted changes, and when a commit it would rewrite
# is on a remote-tracking branch, since rewriting a pushed commit needs a force push.
#
# "Unsigned" is git's `%G?` of N. A signature this machine cannot check, E, counts as
# signed: the key is not in the keyring, but the commit carries a signature.
set -euo pipefail

sign="${SIGN:-}"
key="${KEY:-}"

# The unsigned commits, newest first: "<hash> <date> <subject>".
unsigned() {
    git log --format='%G? %H %ad %s' --date=short | awk '$1 == "N" { $1 = ""; print substr($0, 2) }'
}

list="$(unsigned)"
if [[ -z "$list" ]]; then
    echo "Every commit on $(git branch --show-current) is signed."
    exit 0
fi
count="$(wc -l <<<"$list")"
echo "$count unsigned commit(s) on $(git branch --show-current):"
cut -c1-12,41- <<<"$list" | sed 's/^/  /'

if [[ "$sign" != 1 ]]; then
    echo
    echo "Sign them with: make unsigned SIGN=1 [KEY=<id>]"
    exit 0
fi

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "FAIL: the working tree has uncommitted changes. Commit or stash them first."
    exit 1
fi

oldest="$(tail -1 <<<"$list" | cut -d' ' -f1)"
remotes="$(git for-each-ref --contains "$oldest" --format='%(refname:short)' refs/remotes)"
if [[ -n "$remotes" ]]; then
    echo "FAIL: ${oldest:0:12} is on $remotes. Signing it would rewrite pushed history."
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
git rebase --force-rebase --rebase-merges "--gpg-sign${key:+=$key}" "${onto[@]}"

left="$(unsigned)"
if [[ -n "$left" ]]; then
    echo "FAIL: still unsigned:"
    cut -c1-12,41- <<<"$left" | sed 's/^/  /'
    exit 1
fi
echo "Signed. Every commit on $(git branch --show-current) carries a signature."
