#!/usr/bin/env python3
"""Fail on trufflehog findings that .trufflehog-allow does not list verbatim.

Usage: trufflehog_allowed.py ALLOWLIST JSON...

Each JSON file is trufflehog's `--json` output, one finding per line. A finding is allowed
only when its `Raw` value equals an allowlist line, whole. Prints each other finding and
each allowlist line that matched nothing. Exits 1 when a finding is not allowed.
"""

import json
import sys


def allowlist(path):
    with open(path, encoding="utf-8") as f:
        lines = (line.rstrip("\n") for line in f)
        return {line for line in lines if line and not line.startswith("#")}


def findings(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("{"):
                yield json.loads(line)


def where(finding):
    data = finding.get("SourceMetadata", {}).get("Data", {})
    if "Git" in data:
        git = data["Git"]
        return f"{git.get('commit', '?')[:12]} {git.get('file', '?')}:{git.get('line', '?')}"
    fs = data.get("Filesystem", {})
    return f"{fs.get('file', '?')}:{fs.get('line', '?')}"


def main(argv):
    allowed = allowlist(argv[1])
    used, refused, count = set(), [], 0
    for path in argv[2:]:
        for finding in findings(path):
            count += 1
            raw = finding.get("Raw", "")
            if raw in allowed:
                used.add(raw)
            else:
                refused.append(finding)
    print(f"findings: {count}, allowed by {argv[1]}: {count - len(refused)}")
    for finding in refused:
        verified = "verified" if finding.get("Verified") else "unverified"
        print(f"  {finding.get('DetectorName')} ({verified})  {where(finding)}  {finding.get('Raw')}")
    stale = sorted(allowed - used)
    if stale:
        print(f"allowlist lines matching nothing: {len(stale)}")
        for line in stale:
            print(f"  {line}")
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
