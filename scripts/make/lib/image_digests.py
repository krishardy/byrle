#!/usr/bin/env python3
"""Check each image pinned by digest in the files named: whether its tag still points at it.

    image_digests.py <file>...

A reference is `<registry>/<repository>:<tag>@sha256:<digest>`, anywhere in a line. The
digest asked for is the tag's index (its manifest list), the one digest that covers every
architecture.

A line `image: <reference>` or `<NAME>_IMAGE=<reference>` with no digest is reported as not
pinned. One with a `$` in it names a variable and is not read.

One line per reference: `current`, or `moved` with the tag's digest now. Exits 0 when all
are current and pinned, 1 when one moved or is not pinned, 2 when a registry could not be
asked.
"""

import json
import re
import sys
import urllib.request

REFERENCE = re.compile(
    r"\b([a-z0-9.-]+\.[a-z]{2,})/([a-z0-9._/-]+):([A-Za-z0-9._-]+)@(sha256:[0-9a-f]{64})")
UNPINNED = re.compile(r"^\s*(?:image:\s*|[A-Z_]+_IMAGE=)([^\s#$@]+)\s*(?:#.*)?$", re.M)
ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
# Where each registry's API is, and where it hands out an anonymous pull token.
REGISTRIES = {
    "docker.io": ("https://registry-1.docker.io",
                  "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull"),
    "ghcr.io": ("https://ghcr.io", "https://ghcr.io/token?scope=repository:{}:pull"),
}


def tag_digest(registry, repository, tag):
    api, token_url = REGISTRIES[registry]
    with urllib.request.urlopen(token_url.format(repository), timeout=30) as response:
        token = json.load(response)["token"]
    request = urllib.request.Request(
        f"{api}/v2/{repository}/manifests/{tag}", method="HEAD",
        headers={"Accept": ACCEPT, "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.headers["Docker-Content-Digest"]


def main(paths):
    status = 0
    for path in paths:
        with open(path) as f:
            text = f.read()
        for name in UNPINNED.findall(text):
            print(f"{name}: not pinned by digest ({path})")
            status = max(status, 1)
        for registry, repository, tag, pinned in sorted(set(REFERENCE.findall(text))):
            name = f"{registry}/{repository}:{tag}"
            if registry not in REGISTRIES:
                print(f"{name}: {registry} is not a registry this reads ({path})")
                status = 2
                continue
            try:
                now = tag_digest(registry, repository, tag)
            except OSError as error:
                print(f"{name}: could not be read: {error}")
                status = 2
                continue
            if now == pinned:
                print(f"{name}: {pinned[:19]} is current ({path})")
            else:
                print(f"{name}: moved to {now}; {path} pins {pinned[:19]}")
                status = max(status, 1)
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
