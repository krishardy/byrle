#!/usr/bin/env python3
"""How many crates.io versions carry `trustpub_data`, and how many versions byrle's
dropped-provenance and identity rules would refuse if they read it.

The 500 most-downloaded crates are read from the crates.io API, each crate's newest 100
versions in one request, one request a second as https://crates.io/data-access asks. The
answers are kept in the cache directory, so a second run makes no request it made before.

A version is attested when `trustpub_data` is set. Its identity is the provider and
repository: crates.io records no workflow file. Read in publish order, a version is a drop
when it is not attested and an earlier version is, and a change when it is attested and
the attested version before it names another identity.

Prints adoption by month since trusted publishing opened, each drop and change with who
published it, and how many attested crates set `trustpub_only`.

Usage: cargo_trustpub.py CACHE_DIR
"""

import collections
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

API = "https://crates.io/api/v1"
USER_AGENT = "byrle-research (https://github.com/krishardy/byrle)"
OPENED = "2025-07"


def get(url):
    """The JSON at `url`, a second after the request before it. A timeout, a connection
    failure or a 5xx is asked again, four times in all."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(4):
        time.sleep(1)
        try:
            with urllib.request.urlopen(request, timeout=60) as answer:
                return json.load(answer)
        except urllib.error.HTTPError as error:
            if error.code < 500 or attempt == 3:
                raise
        except (TimeoutError, urllib.error.URLError, ConnectionError):
            if attempt == 3:
                raise
        time.sleep(10 * (attempt + 1))
    return None


def cached(path, url):
    if not path.exists():
        path.write_text(json.dumps(get(url)))
    return json.loads(path.read_text())


def top_crates(cache):
    path = cache / "top.json"
    if not path.exists():
        names = []
        for page in range(1, 6):
            found = get(f"{API}/crates?sort=downloads&per_page=100&page={page}")
            names += [crate["name"] for crate in found["crates"]]
        path.write_text(json.dumps(names))
    return json.loads(path.read_text())


def identity(version):
    data = version.get("trustpub_data")
    return data and (data["provider"], data.get("repository") or data.get("project_path"))


def publisher(version):
    return (version.get("published_by") or {}).get("login", "trusted publishing")


def main(cache):
    cache.mkdir(parents=True, exist_ok=True)
    by_month, attested_by_month = collections.Counter(), collections.Counter()
    drops, changes, attested_crates = [], [], []
    for name in top_crates(cache):
        found = cached(cache / f"{name}.json",
                       f"{API}/crates/{name}/versions?per_page=100&sort=date")
        before = None
        for version in sorted(found["versions"], key=lambda v: v["created_at"]):
            month = version["created_at"][:7]
            if month >= OPENED:
                by_month[month] += 1
                attested_by_month[month] += bool(identity(version))
            if identity(version):
                if before and before != identity(version):
                    changes.append((name, version["num"], before, identity(version)))
                before = identity(version)
            elif before:
                drops.append((name, version["num"], version["created_at"][:10],
                               publisher(version)))
        if before:
            attested_crates.append(name)

    print("| Month | Versions | With `trustpub_data` |\n|---|---|---|")
    for month in sorted(by_month):
        print(f"| {month} | {by_month[month]} | {attested_by_month[month]} |")
    print(f"\n{len(attested_crates)} crates attested; drops {len(drops)}:")
    for drop in drops:
        print("  ", *drop)
    print(f"changes {len(changes)}:")
    for change in changes:
        print("  ", *change)
    only = [name for name in attested_crates
            if cached(cache / f"crate-{name}.json", f"{API}/crates/{name}")["crate"]
            .get("trustpub_only")]
    print(f"trustpub_only: {len(only)} of {len(attested_crates)}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
