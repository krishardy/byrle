# Each commit in a pull request has a signature GitHub verified

- **Number:** 0139
- **Status:** Implemented 2026-11-14, for TODO.md ad-hoc #55: `scripts/make/pr-signatures.py`,
  `make pr-signatures`, the `signatures` job in `.github/workflows/ci.yml`.
- **Related:** [ci-gates](0044-ci-gates.md)

## Decision

CI's `signatures` job runs on pull requests only. It runs `make pr-signatures PR=<number>`,
which reads `GET /repos/{repo}/pulls/{number}/commits` and fails when a commit's
`commit.verification.verified` is `false`. It prints each failing commit with GitHub's
`reason`, such as `unsigned`, `unknown_key` or `bad_email`.

GitHub sets `verified` when a GPG, SSH or S/MIME signature checks against a key the author
registered on their GitHub account, and the key's account has the committer's email. A merge
or a squash made on github.com is signed by GitHub's own key and is verified.

The job sends `GITHUB_TOKEN` with `contents: read` and `pull-requests: read`. A token is not
needed for a public repository, but without one the API allows 60 requests an hour from an
address, which a shared runner can exhaust.

The API lists at most 250 commits of a pull request. The script compares the count it listed
with the pull request's `commits` and fails when it listed fewer.

## Alternatives considered

| Option | Why not |
|---|---|
| `make commit-fixup CHECKS=signature`, as `signed-off` runs | It reads git's `%G?` and counts `E`, a signature with no key to check it, as signed. The runner has no contributor's key, so every signature would be `E`. It checks that a signature is present, not that it is valid |
| A keyring of contributors' keys in the repository, checked with `git verify-commit` | Each new contributor's key would be added by a pull request before their first pull request passes. GitHub already holds each account's keys |
| The branch protection rule "Require signed commits" | It refuses a push to the protected branch, not a pull request, and is a repository setting no file in the repository records. It can be turned on as well |

## Evidence, 2026-11-14

| Command | Result |
|---|---|
| `make pr-signatures PR=3` | `Every commit in krishardy/byrle#3 has a signature GitHub verified: 2.` |
| `make pr-signatures PR=2` | 66 of 66 verified |
| `REPO=python/cpython make pr-signatures PR=1` | exit 1, 3 commits listed as `unsigned` |
| `PR=2`, with 10 commits a page | 66 of 66 over 7 pages |

Mutation-tested. With the loop stopping after its first page of 10, `PR=2` printed
`FAIL: krishardy/byrle#2 has 66 commits and the API listed 10.` and exited 1. With the
`verified` test removed, `python/cpython#1` passed.

The workflow job is not run until it is pushed.
