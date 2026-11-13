#!/usr/bin/env python3
"""OSV bundles for `make smoke-console`: npm.zip and pypi.zip in the directory argv[1].

Each holds one MAL record for a package nobody installs, so a refresh loads a snapshot.
With argv[2] "yes", npm.zip holds MAL-2099-2 for is-number 7.0.0 as well. With "empty",
npm.zip holds no entries.
"""

import json
import sys
import zipfile
from pathlib import Path


def record(ident, ecosystem, name, versions):
    return {
        "schema_version": "1.7.3",
        "id": ident,
        "modified": "2099-01-01T00:00:00Z",
        "summary": f"A test record for make smoke-console: {name}",
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": name},
                "versions": versions,
            }
        ],
    }


def write(path, records):
    with zipfile.ZipFile(path, "w") as bundle:
        for entry in records:
            bundle.writestr(f"{entry['id']}.json", json.dumps(entry))


def main():
    directory = Path(sys.argv[1])
    npm = [record("MAL-2099-1", "npm", "byrle-smoke-nobody", ["0.0.1"])]
    if sys.argv[2] == "yes":
        npm.append(record("MAL-2099-2", "npm", "is-number", ["7.0.0"]))
    elif sys.argv[2] == "empty":
        npm = []
    write(directory / "npm.zip", npm)
    write(directory / "pypi.zip", [record("MAL-2099-3", "PyPI", "byrle-smoke-nobody", ["0.0.1"])])


if __name__ == "__main__":
    main()
