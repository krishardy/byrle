#!/usr/bin/env python3
"""Checks docs/engineering_decisions: each file is `<number>-<name>.md` with that number as
its `**Number:**`, numbers are not reused, index.md lists every file once under its number
with what supersedes it, and every link in docs/ to a decision names a file that exists.

Usage: decisions.py
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DECISIONS = REPO / "docs/engineering_decisions"
FILE = re.compile(r"^(\d{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.md$")
ROW = re.compile(r"^\| (\d{4}) \| \[[^\]]+\]\(([^)]+)\) \| [^|]* \| ([^|]*) \|$", re.M)
LINK = re.compile(r"\]\(([^)#\s]+\.md)(?:#[^)]*)?\)")


def problems():
    found = []
    files = sorted(p for p in DECISIONS.glob("*.md") if p.name != "index.md")
    numbers = {}
    for path in files:
        match = FILE.match(path.name)
        if not match:
            found.append(f"{path.name}: not <number>-<name>.md")
            continue
        number = match.group(1)
        if number in numbers:
            found.append(f"{path.name}: number {number} is also {numbers[number]}")
        numbers[number] = path.name
        text = path.read_text()
        meta = re.search(r"^- \*\*Number:\*\* (\d{4})$", text, re.M)
        if not meta or meta.group(1) != number:
            found.append(f"{path.name}: its metadata has no `- **Number:** {number}`")
    index = (DECISIONS / "index.md").read_text()
    listed = {}
    for number, target, superseded in ROW.findall(index):
        if listed.get(target):
            found.append(f"index.md: {target} is listed twice")
        listed[target] = (number, superseded.strip())
    for path in files:
        row = listed.pop(path.name, None)
        if row is None:
            found.append(f"index.md: {path.name} is not listed")
            continue
        if not path.name.startswith(row[0] + "-"):
            found.append(f"index.md: {path.name} is listed as {row[0]}")
        by = re.search(r"^- \*\*Superseded by:\*\* .*\]\((\d{4})-", path.read_text(), re.M)
        if bool(by) != bool(row[1]) or (by and f"[{by.group(1)}]" not in row[1]):
            found.append(f"index.md: {path.name}'s superseded column is not its metadata's")
    found += [f"index.md: {target} is listed but is no file" for target in listed]
    for doc in (REPO / "docs").rglob("*.md"):
        for target in LINK.findall(doc.read_text()):
            if target.startswith(("http:", "https:")):
                continue
            resolved = (doc.parent / target).resolve()
            if resolved.parent == DECISIONS and not resolved.exists():
                found.append(f"{doc.relative_to(REPO)}: links {target}, which is no file")
    return found


def main():
    found = problems()
    for problem in found:
        print(problem)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
