"""What `make semgrep` was told to leave alone.

Reads the output of a scan run with `--json --verbose --sarif-output=<file>`: the JSON file
named first on the command line, then the SARIF file. Prints three lists:

- each finding a `nosemgrep` comment suppresses: file, line, rule, and the line's text
- `nosemgrep` comments in tracked files that suppress nothing
- each path the engine did not scan, with its reason, from the JSON

Suppressed findings come from the SARIF, where both semgrep and opengrep keep each one with
`suppressions`. semgrep 1.185.0's JSON omits them, and with `--disable-nosem` it does not
mark them `is_ignored`. A comment suppresses a finding on its own line or on the line after
it.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

# A comment marker, then `nosem` or `nosemgrep`. A mention in prose, in backticks, does not
# match.
COMMENT = re.compile(r"(?://|#|/\*|--|<!--)\s*nosem(?:grep)?\b")


def comments() -> list[tuple[str, int, str]]:
    """Every suppression comment in a tracked file, as path, line number and line text."""
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], check=True, capture_output=True
    ).stdout.decode()
    found = []
    for name in filter(None, tracked.split("\0")):
        try:
            text = Path(name).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if COMMENT.search(line):
                found.append((name, number, line.strip()))
    return found


def main() -> None:
    with open(sys.argv[1], encoding="utf-8") as f:
        scan = json.load(f)
    with open(sys.argv[2], encoding="utf-8") as f:
        sarif = json.load(f)

    ignored = sorted(
        (
            (
                r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                r["locations"][0]["physicalLocation"]["region"]["startLine"],
                r["ruleId"],
                r["locations"][0]["physicalLocation"]["region"]["snippet"]["text"],
            )
            for run in sarif["runs"]
            for r in run["results"]
            if r.get("suppressions")
        ),
    )
    print(f"suppressed by nosemgrep: {len(ignored)}")
    for path, line, rule, text in ignored:
        print(f"  {path}:{line}  {rule}")
        print(f"      {text.strip().splitlines()[0]}")

    live = {(path, line) for path, line, _, _ in ignored}
    stale = [
        (path, number, text)
        for path, number, text in comments()
        if (path, number) not in live and (path, number + 1) not in live
    ]
    print(f"\nnosemgrep comments suppressing nothing: {len(stale)}")
    for path, number, text in stale:
        print(f"  {path}:{number}  {text}")

    skipped = sorted(scan["paths"].get("skipped", []), key=lambda s: s["path"])
    print(f"\nnot scanned: {len(skipped)}")
    for s in skipped:
        print(f"  {s['path']}  {s['reason']}")


if __name__ == "__main__":
    main()
