#!/usr/bin/env python3
"""Check that only src/service.rs and src/tls.rs build or hold a `reqwest::Client`.

Every other request goes through a `service::Service`, which sends only the headers its
service declares. See docs/engineering_decisions/0133-a-client-for-each-service.md.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
ALLOWED = {"src/service.rs", "src/tls.rs"}
TESTS = re.compile(r"#\[cfg\(test\)\]\s*\n(#\[cfg_attr[^\n]*\n)?\s*(pub(\([^)]*\))?\s+)?mod tests")
RAW = re.compile(r"reqwest::(Client\b|ClientBuilder\b|get\()")


def main():
    found = []
    for path in sorted((ROOT / "src").rglob("*.rs")):
        name = path.relative_to(ROOT).as_posix()
        if name in ALLOWED or name.endswith("/testing.rs"):
            continue
        text = path.read_text()
        tests = TESTS.search(text)
        code = text[: tests.start()] if tests else text
        for number, line in enumerate(code.splitlines(), 1):
            if RAW.search(line):
                found.append(f"{name}:{number}: {line.strip()}")
    for line in found:
        print(f"    {line}: a raw reqwest client; ask through a service::Service")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
