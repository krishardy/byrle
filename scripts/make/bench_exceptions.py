#!/usr/bin/env python3
"""The policy `make bench` measures with: the defaults, and an exception for each version
the audit log at argv[1] shows refused, loosening each check that refused it. Written to
argv[2]. Prints each exception's version and checks.

A latency measurement needs every install to finish; the exceptions keep every check
running, where `allow` in the settings could skip one.
"""

import datetime
import json
import sys

# The `set` each check is loosened with. `max_cvss` lists the version's advisories instead.
LOOSENED = {
    "cooldown_days": ("cooldown_days", 0),
    "install_scripts": ("install_scripts", "allow"),
    "kev": ("kev", "allow"),
    "yanked": ("yanked", "allow"),
    "deprecated": ("deprecated", "allow"),
    "provenance": ("provenance", "allow"),
}


def refused(audit):
    """(ecosystem, name, version) -> (checks, advisory ids), for each pinned refusal."""
    found = {}
    with open(audit, encoding="utf-8") as lines:
        for line in lines:
            event = json.loads(line)
            if event.get("action") not in ("block", "quarantine") or not event.get("version"):
                continue
            key = (event["ecosystem"], event["name"], event["version"])
            checks, ids = found.setdefault(key, (set(), set()))
            checks.update(event.get("checks", []))
            facts = (event.get("inputs") or {}).get("facts") or {}
            ids.update(a["id"] for a in facts.get("advisories", []))
    return found


def main():
    audit, policy = sys.argv[1], sys.argv[2]
    expires = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
    lines = ["version: 1", "packages:"]
    for (ecosystem, name, version), (checks, ids) in sorted(refused(audit).items()):
        loosened = {LOOSENED[c][0]: LOOSENED[c][1] for c in checks if c in LOOSENED}
        if "max_cvss" in checks:
            loosened["vuln_advisory_ids"] = sorted(ids)
        unloosened = sorted(c for c in checks if c not in LOOSENED and c != "max_cvss")
        if unloosened:
            sys.exit(f"{ecosystem} {name} {version}: no exception loosens {unloosened}")
        print(f"    {ecosystem} {name} {version}: {', '.join(sorted(checks))}")
        lines += [
            f"  - match: {{ ecosystem: {ecosystem}, name: {json.dumps(name)}, "
            f"version: {json.dumps(version)} }}",
            f"    set: {json.dumps(loosened)}",
            "    reason: refused under the defaults; make bench measures latency, not policy",
            f"    expires: {expires}",
        ]
    if len(lines) == 2:
        lines.pop()
    with open(policy, "w", encoding="utf-8") as out:
        out.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
