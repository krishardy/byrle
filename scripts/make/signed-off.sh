#!/usr/bin/env bash
# Refuse when a commit after BASE carries no `Signed-off-by:` naming its author's email, the
# Developer's Certificate of Origin sign-off CONTRIBUTING.md asks for. CI runs it on every
# pull request, with BASE the pull request's base commit.
#
#   make signed-off                  the commits on HEAD that are not on origin/main
#   make signed-off BASE=<commit>    the commits on HEAD that are not on <commit>
#
# Merge commits are not checked: a merge is made by whoever merges, not by a contributor.
# The email is compared without regard to case, as git compares it.
set -euo pipefail

base="${BASE:-origin/main}"

if ! git rev-parse --verify --quiet "$base^{commit}" >/dev/null; then
    echo "FAIL: $base is not a commit here. Fetch it, or name another with BASE=<commit>."
    exit 1
fi

missing=()
while IFS= read -r commit; do
    author="$(git log -1 --format='%ae' "$commit" | tr '[:upper:]' '[:lower:]')"
    signed="$(git log -1 --format='%(trailers:key=Signed-off-by,valueonly,separator=%x0a)' "$commit" \
        | tr '[:upper:]' '[:lower:]')"
    if ! grep -qF "<$author>" <<<"$signed"; then
        missing+=("$(git log -1 --format='%h %an <%ae>: %s' "$commit")")
    fi
done < <(git rev-list --no-merges "$base..HEAD")

if [[ ${#missing[@]} -eq 0 ]]; then
    echo "Every commit after $base is signed off by its author."
    exit 0
fi
echo "FAIL: ${#missing[@]} commit(s) after $base carry no Signed-off-by: with the author's email:"
printf '  %s\n' "${missing[@]}"
echo
echo "Sign them off: git rebase --signoff $base, then push again. See CONTRIBUTING.md."
exit 1
