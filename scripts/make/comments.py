#!/usr/bin/env python3
"""Check that source comments are only the three kinds TODO item 23 keeps.

- `//!` module documentation: at most 4 lines per file.
- `///` on a function: at most 2 lines, plus 1 per parameter other than `self`, plus 1
  for a return value, plus 1 more when it returns a `Result`.
- `///` on anything else (a type, field, variant, constant, `impl`, trait or module):
  1 line. An environment variable is a constant, so it gets 1 line too.
- No `//` comments, except `// nosemgrep:` directives, which semgrep reads.

Blank `///` lines count. Files listed in `comments-baseline.txt` are not yet held to this;
a listed file that passes is an error too, so the list only shrinks.
See docs/engineering_decisions/source-comments.md.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASELINE = ROOT / "scripts/make/comments-baseline.txt"
MODULE_LIMIT = 4
ITEM_LIMIT = 1
FN_DESCRIPTION = 2

ITEM = re.compile(
    r"^(pub(\([^)]*\))?\s+)?((const|async|unsafe|extern\s+\"[^\"]*\")\s+)*"
    r"(fn|struct|enum|const|static|type|trait|impl|mod|macro_rules!|union)\b"
)


def signature(lines, start):
    """The text of the item starting at `start`, up to its body or its `;`."""
    text = []
    depth = 0
    for line in lines[start:]:
        code = line.split("//")[0]
        for ch in code:
            if ch in "(<[":
                depth += 1
            elif ch in ")>]":
                depth -= 1
            elif ch in "{;" and depth <= 0:
                text.append(code[: code.index(ch)])
                return " ".join(text)
        text.append(code)
    return " ".join(text)


def fn_limit(sig):
    """The lines a function's doc may take, from its signature."""
    open_at = sig.find("(")
    depth, close_at = 0, len(sig)
    for i in range(open_at, len(sig)):
        if sig[i] in "(<[":
            depth += 1
        elif sig[i] in ")>]":
            depth -= 1
            if depth == 0:
                close_at = i
                break
    params = [p.strip() for p in split_top(sig[open_at + 1 : close_at]) if p.strip()]
    params = [p for p in params if not re.fullmatch(r"&?(mut\s+)?('\w+\s+)?(mut\s+)?self(\s*:.*)?", p)]
    rest = sig[close_at + 1 :]
    returns = rest.split("where")[0]
    limit = FN_DESCRIPTION + len(params)
    if "->" in returns and not re.search(r"->\s*\(\s*\)", returns):
        limit += 1
        if "Result" in returns:
            limit += 1
    return limit


def split_top(text):
    """`text` split at commas that are not inside brackets."""
    parts, depth, current = [], 0, ""
    for ch in text:
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += ch
    parts.append(current)
    return parts


def line_comments(text):
    """The 1-based line of each `//` comment in `text` that is not `///` or `//!`, with
    its text. Strings, raw strings and character literals are skipped."""
    found = []
    i, line, n = 0, 1, len(text)
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end == -1 else end
            comment = text[i:end]
            if not (comment.startswith("///") or comment.startswith("//!")):
                found.append((line, comment))
            i = end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            found.append((line, text[i:end].split("\n")[0]))
            line += text.count("\n", i, end)
            i = end
        elif ch == "r" and re.match(r'r#*"', text[i:]) and not re.match(r"\w", text[i - 1 : i] or " "):
            hashes = re.match(r'r(#*)"', text[i:]).group(1)
            close = '"' + hashes
            end = text.find(close, i + 2 + len(hashes))
            end = n if end == -1 else end + len(close)
            line += text.count("\n", i, end)
            i = end
        elif ch == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            line += text.count("\n", i, j)
            i = j + 1
        elif ch == "'":
            literal = re.match(r"'(\\.[^']*|[^'\\])'", text[i:])
            i += len(literal.group(0)) if literal else 1
        else:
            i += 1
    return found


def problems(path):
    """Each line of `path` that breaks a rule, as `line: reason`."""
    lines = path.read_text().split("\n")
    found = []
    module = sum(1 for line in lines if line.strip().startswith("//!"))
    if module > MODULE_LIMIT:
        found.append(f"1: {module} lines of //! module documentation, over {MODULE_LIMIT}")
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped.startswith("///"):
            start = i
            while i < len(lines) and lines[i].strip().startswith("///"):
                i += 1
            item = i
            while item < len(lines) and (
                lines[item].strip().startswith("#[") or lines[item].strip() == ""
            ):
                item += 1
            target = lines[item].strip() if item < len(lines) else ""
            match = ITEM.match(target)
            kind = match.group(5) if match else "field or variant"
            limit = fn_limit(signature(lines, item)) if kind == "fn" else ITEM_LIMIT
            if i - start > limit:
                found.append(f"{start + 1}: {i - start} lines of /// on a {kind}, over {limit}")
            continue
        i += 1
    for line, comment in line_comments("\n".join(lines)):
        if not comment.startswith("// nosemgrep:"):
            found.append(f"{line}: a // comment")
    return found


def main():
    files = sorted(
        p
        for pattern in ("src/**/*.rs", "tests/*.rs")
        for p in ROOT.glob(pattern)
    )
    baseline = set()
    if BASELINE.exists():
        baseline = {
            line.strip()
            for line in BASELINE.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        }
    failed = False
    for path in files:
        name = str(path.relative_to(ROOT))
        found = problems(path)
        if name in baseline:
            if not found:
                print(f"{name}: passes, so remove it from {BASELINE.name}")
                failed = True
            continue
        for problem in found:
            print(f"{name}:{problem}")
            failed = True
    stale = baseline - {str(p.relative_to(ROOT)) for p in files}
    for name in sorted(stale):
        print(f"{name}: in {BASELINE.name} but not a source file")
        failed = True
    if "--baseline" in sys.argv:
        failing = [str(p.relative_to(ROOT)) for p in files if problems(p)]
        BASELINE.write_text(
            "# Files not yet held to scripts/make/comments.py. Only ever shrinks.\n"
            + "".join(f"{name}\n" for name in failing)
        )
        return 0
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
