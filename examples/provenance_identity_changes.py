#!/usr/bin/env python3
"""How many versions the provenance identity check refuses, under the rule byrle uses and
two looser ones, and whether each change keeps the repository's owner.

For every package in the dependency sets of `tier1_false_positives.py`, resolved into
lockfiles by npm and uv, each version's attestation is read in publish order: npm's from
the registry's attestations endpoint, PyPI's from its integrity API. The identity is the
repository and workflow file, read without verifying the attestation.

The versions before one are those `analysis::attestation::provenance` compares it with: the
one published just before, every one published in the 7 days before it, and the most
recent attested one. Under each rule an attested version is refused when:

- R0, byrle's: any attested version before it names another identity
- R1: no attested version before it names its identity
- R2: no attested version of the package published before it, ever, names its identity
- R3: no attested version published at least 7 days before it names its identity; with
  none that old, R0 over the attested versions in the 7 days before it

Prints a table of versions refused under each, and each version R0 refuses.

Usage: provenance_identity_changes.py
"""

import base64
import concurrent.futures
import datetime
import json
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from tier1_false_positives import NPM_SETS, PYPI_SETS, lockfile


def get(url):
    """The JSON at `url`, or None for a 404. A timeout, a connection failure or a 5xx is
    asked again, three times in all."""
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=60) as answer:
                return json.load(answer)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            if error.code < 500 or attempt == 2:
                raise
        except (TimeoutError, urllib.error.URLError, ConnectionError):
            if attempt == 2:
                raise
        time.sleep(2)
    return None


def npm_names(lock):
    packages = json.loads(Path(lock).read_text())["packages"]
    return {path.rsplit("node_modules/", 1)[1] for path in packages if path}


def pypi_names(lock):
    out = subprocess.run(["uv", "export", "--no-hashes", "--no-header", "--no-emit-project"],
                         cwd=Path(lock).parent, capture_output=True, text=True, check=True)
    return {line.split("==")[0].strip() for line in out.stdout.splitlines()
            if "==" in line and not line.startswith(" ")}


def npm_identity(name, version):
    quoted = urllib.parse.quote(f"{name}@{version}", safe="@")
    found = get(f"https://registry.npmjs.org/-/npm/v1/attestations/{quoted}")
    for attestation in (found or {}).get("attestations", []):
        if not attestation["predicateType"].startswith("https://slsa.dev/provenance/"):
            continue
        payload = attestation["bundle"]["dsseEnvelope"]["payload"]
        predicate = json.loads(base64.b64decode(payload))["predicate"]
        if "buildDefinition" in predicate:  # SLSA v1
            workflow = predicate["buildDefinition"]["externalParameters"]["workflow"]
            repository, path = workflow["repository"], workflow["path"]
        else:  # SLSA v0.2
            source = predicate["invocation"]["configSource"]
            repository, path = source["uri"].split("@", 1)[0], source["entryPoint"]
        repository = repository.removeprefix("git+").removeprefix("https://github.com/")
        return f"{repository}/{path}"
    return None


def npm_versions(name):
    """(version, identity) for each version published since npm provenance began."""
    document = get(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}")
    times = sorted((t, v) for v, t in document.get("time", {}).items()
                   if v not in ("created", "modified") and t >= "2023-04-01")
    with concurrent.futures.ThreadPoolExecutor(16) as pool:
        identities = pool.map(lambda tv: npm_identity(name, tv[1]), times)
        return [(t, v, identity) for (t, v), identity in zip(times, identities)]


def pypi_identity(name, version, filename):
    found = get(f"https://pypi.org/integrity/{name}/{version}/{filename}/provenance")
    for bundle in (found or {}).get("attestation_bundles", []):
        publisher = bundle.get("publisher", {})
        if publisher.get("kind") == "GitHub":
            return f"{publisher['repository']}/.github/workflows/{publisher['workflow']}"
    return None


def pypi_versions(name):
    """(version, identity) for each version since PEP 740, read from its sdist or first file."""
    document = get(f"https://pypi.org/pypi/{name}/json")
    releases = []
    for version, files in document["releases"].items():
        if not files or files[0]["upload_time_iso_8601"] < "2024-10-01":
            continue
        chosen = next((f for f in files if f["packagetype"] == "sdist"), files[0])
        releases.append((chosen["upload_time_iso_8601"], version, chosen["filename"]))
    releases.sort()
    with concurrent.futures.ThreadPoolExecutor(16) as pool:
        identities = pool.map(lambda r: pypi_identity(name, r[1], r[2]), releases)
        return [(t, v, identity) for (t, v, _), identity in zip(releases, identities)]


def owner(identity):
    return identity.split("/", 1)[0]


WINDOW = datetime.timedelta(days=7)


def when(stamp):
    return datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def refusals(history):
    """(version, identity, R0's differing identity or None, R1, R2 and R3 refuse) for each
    attested version with an attested version before it, `history` in publish order."""
    found = []
    for i, (stamp, version, identity) in enumerate(history):
        if identity is None:
            continue
        earlier = history[:i]
        attested = [h for h in earlier if h[2]]
        if not attested:
            continue
        compared = {earlier[-1]} | {h for h in earlier if when(stamp) - when(h[0]) <= WINDOW}
        compared.add(attested[-1])
        named = {h[2] for h in compared if h[2]}
        differing = next((n for n in sorted(named) if n != identity), None)
        old = {h[2] for h in attested if when(stamp) - when(h[0]) >= WINDOW}
        recent = {h[2] for h in attested if when(stamp) - when(h[0]) < WINDOW}
        by_r3 = identity not in old if old else bool(recent - {identity})
        found.append((version, identity, differing, bool(named) and identity not in named,
                      identity not in {h[2] for h in attested}, by_r3))
    return found


def main():
    names = {"npm": set(), "pypi": set()}
    with tempfile.TemporaryDirectory() as work:
        for packages in NPM_SETS:
            names["npm"] |= npm_names(lockfile(work, "npm", packages))
        for packages in PYPI_SETS:
            names["pypi"] |= pypi_names(lockfile(work, "pypi", packages))
    read = {"npm": npm_versions, "pypi": pypi_versions}
    print("| Ecosystem | Packages attested | Attested versions compared | R0 refuses "
          "| of them, same owner | R1 refuses | R2 refuses | R3 refuses "
          "| Packages R0 refuses in |")
    print("|---|---|---|---|---|---|---|---|---|")
    listed = []
    for ecosystem in ("npm", "pypi"):
        packages = compared = r0 = same = r1 = r2 = r3 = 0
        refused_in = set()
        for name in sorted(names[ecosystem]):
            found = refusals(read[ecosystem](name))
            packages += bool(found)
            compared += len(found)
            for version, identity, differing, by_r1, by_r2, by_r3 in found:
                r1 += by_r1
                r2 += by_r2
                r3 += by_r3
                if by_r3:
                    listed.append(f"R3 {ecosystem} {name} {version}: {identity}")
                if differing:
                    r0 += 1
                    same += owner(differing) == owner(identity)
                    refused_in.add(name)
                    listed.append(f"{ecosystem} {name} {version}: {identity}, and before it "
                                  f"{differing}{'  R1' if by_r1 else ''}{'  R2' if by_r2 else ''}")
        print(f"| {ecosystem} | {packages} | {compared} | {r0} | {same} | {r1} | {r2} | {r3} "
              f"| {len(refused_in)} |")
    print()
    print("\n".join(listed))


if __name__ == "__main__":
    main()
