"""What `make semgrep` was told to leave alone.

Reads the JSON of a scan run with `--disable-nosem --json --verbose`, from the file named on
the command line, and prints three lists:

- each finding a `nosemgrep` comment suppresses: file, line, rule, and the line's text
- `nosemgrep` comments in tracked files that suppress nothing
- each path semgrep did not scan, with semgrep's reason

semgrep reports a suppressed finding only when suppressions are off, where it marks the
finding `is_ignored`. A comment suppresses a finding on its own line or on the line after it.
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

    ignored = sorted(
        (r for r in scan["results"] if r["extra"].get("is_ignored")),
        key=lambda r: (r["path"], r["start"]["line"]),
    )
    print(f"suppressed by nosemgrep: {len(ignored)}")
    for r in ignored:
        first = r["extra"]["lines"].strip().splitlines()[0]
        print(f"  {r['path']}:{r['start']['line']}  {r['check_id']}")
        print(f"      {first}")

    live = {(r["path"], r["start"]["line"]) for r in ignored}
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
