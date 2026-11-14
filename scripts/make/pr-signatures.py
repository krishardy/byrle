#!/usr/bin/env python3
"""Check that each commit in a pull request has a signature GitHub verified.

    make pr-signatures PR=<number> [REPO=<owner>/<name>]

GitHub verifies a GPG, SSH or S/MIME signature against the keys the commit's author has
registered with their GitHub account. It reports `verified` and a `reason` for each commit:
`valid`, or why not, such as `unsigned`, `unknown_key` or `bad_email`. This script reads that
answer from the API. It does not check a signature itself: the runner has no contributor's
public key. See docs/engineering_decisions/0139-pr-commit-signatures.md.

REPO defaults to $GITHUB_REPOSITORY, then to the `origin` remote. $GITHUB_TOKEN is sent when
set. Without one the API allows 60 requests an hour from one address.

It exits 1 when a commit is not verified, and when the API lists fewer commits than the pull
request has: the API lists at most 250.
"""

import json
import os
import re
import subprocess
import sys
import urllib.request

API = "https://api.github.com"
PER_PAGE = 100


def repository():
    if os.environ.get("REPO"):
        return os.environ["REPO"]
    if os.environ.get("GITHUB_REPOSITORY"):
        return os.environ["GITHUB_REPOSITORY"]
    url = subprocess.run(["git", "remote", "get-url", "origin"], capture_output=True,
                         text=True, check=True).stdout.strip()
    found = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", url)
    if not found:
        sys.exit(f"FAIL: origin is {url}, not a GitHub repository. Name one with REPO=<owner>/<name>.")
    return found.group(1)


def get(path):
    request = urllib.request.Request(API + path, headers={
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "byrle-pr-signatures",
    })
    if os.environ.get("GITHUB_TOKEN"):
        request.add_header("Authorization", f"Bearer {os.environ['GITHUB_TOKEN']}")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main():
    number = os.environ.get("PR", "")
    if not number.isdigit():
        sys.exit("usage: make pr-signatures PR=<number> [REPO=<owner>/<name>]")
    repo = repository()
    expected = get(f"/repos/{repo}/pulls/{number}")["commits"]

    commits = []
    page = 1
    while True:
        listed = get(f"/repos/{repo}/pulls/{number}/commits?per_page={PER_PAGE}&page={page}")
        commits += listed
        if len(listed) < PER_PAGE:
            break
        page += 1

    if len(commits) < expected:
        print(f"FAIL: {repo}#{number} has {expected} commits and the API listed {len(commits)}.")
        return 1
    failing = [c for c in commits if not c["commit"]["verification"]["verified"]]
    if failing:
        print(f"FAIL: {len(failing)} of {len(commits)} commit(s) in {repo}#{number} "
              "have no signature GitHub verified:")
        for c in failing:
            subject = c["commit"]["message"].splitlines()[0]
            print(f"  {c['sha'][:12]} {c['commit']['verification']['reason']} {subject}")
        print("Sign each with a key registered on your GitHub account: see CONTRIBUTING.md.")
        return 1
    print(f"Every commit in {repo}#{number} has a signature GitHub verified: {len(commits)}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
