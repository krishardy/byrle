#!/usr/bin/env python3
"""Repeated code blocks and repeated string literals, for docs/duplication-catalogue.md.

Two scans over tracked files, standard library only:

- blocks: runs of 8 or more lines that recur in Rust, shell and Python under src/, tests/,
  examples/ and scripts/. Lines are compared with whitespace collapsed, and blank lines,
  comment lines and lines of only brackets are skipped, so formatting does not hide a copy.
  Each block is labelled `prod`, `test` or `mixed`: Rust after `#[cfg(test)]` is test.
- strings: string literals of 16 or more characters that appear more than once in Rust,
  split into those that touch production code and those only in tests.

It reports; it changes nothing and always exits 0. Which findings to act on is a judgement
the catalogue records.
"""

import collections
import re
import subprocess
from pathlib import Path

WINDOW = 8
MIN_LITERAL = 16
TRIVIAL = re.compile(r"^[\s{}\[\]();,]*$")
COMMENT = re.compile(r"^(//|#(?!\[)|/\*|\*)")
LITERAL = re.compile(r'"((?:[^"\\]|\\.){%d,})"' % MIN_LITERAL)


def tracked(*suffixes: str) -> list[str]:
    names = subprocess.run(
        ["git", "ls-files", "src", "tests", "examples", "scripts"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [n for n in names if n.endswith(suffixes) and "/fixtures/" not in n]


def lines(path: str):
    """Each line with its number and whether it is inside Rust test code."""
    in_test = path.startswith("tests/")
    for number, raw in enumerate(Path(path).read_text(errors="replace").splitlines(), 1):
        if path.endswith(".rs") and raw.strip().startswith("#[cfg(test)]"):
            in_test = True
        yield number, raw, in_test


def blocks() -> None:
    units = []
    for path in tracked(".rs", ".sh", ".py"):
        rows = [
            (number, re.sub(r"\s+", " ", raw.strip()), in_test)
            for number, raw, in_test in lines(path)
            if raw.strip() and not TRIVIAL.match(raw) and not COMMENT.match(raw.strip())
        ]
        units.append((path, rows))

    at = {}
    starts = collections.defaultdict(list)
    for u, (_, rows) in enumerate(units):
        for i in range(len(rows) - WINDOW + 1):
            key = tuple(r[1] for r in rows[i : i + WINDOW])
            at[(u, i)] = key
            starts[key].append((u, i))

    found = collections.defaultdict(set)
    for occurrences in starts.values():
        for a, (ua, ia) in enumerate(occurrences):
            for ub, ib in occurrences[a + 1 :]:
                if ua == ub and abs(ia - ib) < WINDOW:
                    continue
                previous = at.get((ua, ia - 1))
                if previous is not None and previous == at.get((ub, ib - 1)):
                    continue
                length = WINDOW
                while True:
                    next_a = at.get((ua, ia + length - WINDOW + 1))
                    if next_a is None or next_a != at.get((ub, ib + length - WINDOW + 1)):
                        break
                    length += 1
                rows_a = units[ua][1]
                text = tuple(r[1] for r in rows_a[ia : ia + length])
                for u, i in ((ua, ia), (ub, ib)):
                    rows = units[u][1]
                    found[text].add((units[u][0], rows[i][0], rows[i + length - 1][0], rows[i][2]))

    ranked = sorted(found.items(), key=lambda kv: -len(kv[0]) * (len(kv[1]) - 1))
    kinds = collections.Counter()
    shown = set()
    report = []
    for text, places in ranked:
        places = sorted(places)
        signature = tuple((p[0], p[1]) for p in places)
        if signature in shown:
            continue
        shown.add(signature)
        tests = [p[3] for p in places]
        kind = "test" if all(tests) else "prod" if not any(tests) else "mixed"
        kinds[kind] += 1
        report.append(f"\n{len(text)} lines x{len(places)} [{kind}]")
        report.extend(f"  {path}:{first}-{last}" for path, first, last, _ in places)
        report.extend(f"    | {line[:100]}" for line in text[:3])
    print(f"# Blocks of {WINDOW}+ lines: {sum(kinds.values())} ({dict(sorted(kinds.items()))})")
    print("\n".join(report))


def strings() -> None:
    seen = collections.defaultdict(list)
    for path in tracked(".rs"):
        for number, raw, in_test in lines(path):
            if raw.strip().startswith("//"):
                continue
            for match in LITERAL.finditer(raw):
                seen[match.group(1)].append((path, number, in_test))
    repeated = {text: places for text, places in seen.items() if len(places) > 1}
    production = {t: p for t, p in repeated.items() if any(not x[2] for x in p)}
    test_only = {t: p for t, p in repeated.items() if all(x[2] for x in p)}

    print(
        f"\n# String literals of {MIN_LITERAL}+ characters: {len(production)} touching "
        f"production code, {len(test_only)} test-only "
        f"({sum(len(p) for p in test_only.values())} occurrences)"
    )
    print("\n## Touching production code")
    for text, places in sorted(production.items(), key=lambda kv: -len(kv[1])):
        where = ", ".join(f"{p}:{n}{' (test)' if t else ''}" for p, n, t in places[:6])
        print(f"{len(places):3}  {text[:80]!r}\n     {where}")
    print("\n## Test-only, 25 most repeated")
    for text, places in sorted(test_only.items(), key=lambda kv: -len(kv[1]))[:25]:
        files = ", ".join(sorted({p for p, _, _ in places}))
        print(f"{len(places):3}  {text[:70]!r}  in {files}")


if __name__ == "__main__":
    blocks()
    strings()
