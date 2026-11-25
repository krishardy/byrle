# GuardDog runs in its own container

- **Number:** 0146
- **Status:** Implemented 2026-11-25. `container/Containerfile.guarddog`,
  `container/guarddog-requirements.txt`, `container/guarddog-byrle.sh`,
  `scripts/make/guarddog-image.sh` (`make guarddog-image`).
- **Amends:** [detectors](0092-detectors.md), whose `BYRLE_DETECTORS` example runs
  GuardDog installed on the host.

## Decision

```
make guarddog-image
export BYRLE_DETECTORS='guarddog=/path/to/byrle/container/guarddog-byrle.sh {ecosystem} scan {name} --version={version} --output-format=json'
```

`guarddog-byrle.sh` takes GuardDog's arguments and runs `localhost/byrle-guarddog:3.2.0`
(`BYRLE_GUARDDOG_IMAGE` names another) with `podman run`:

| Flag | Why |
|---|---|
| no bind mount | GuardDog runs code it downloads by name, so it reads no file of the host's |
| `--volume byrle-guarddog-cache:/var/cache/guarddog` | its lists of popular packages, below |
| `--read-only`, `--tmpfs /tmp` of 1 GiB | a run writes only to /tmp, which goes with the container |
| `--cap-drop=all`, `--security-opt=no-new-privileges` | GuardDog needs no capability |
| `--pids-limit=256`, `--memory=2g` | a package cannot exhaust the host |
| `--env` for `SOCKS` and the forward proxies only | byrle passes a detector nothing else, and the container gets no other variable |
| podman's default network | GuardDog downloads the package itself |
| `--pull=never` | the image is the one `make guarddog-image` built |

The image is `python:3.13-slim-trixie` with the 34 packages of
`guarddog-requirements.txt`, from `uv pip compile --generate-hashes`, installed with
`--require-hashes`. It runs as uid 10001.

## What it took

| Problem, 2026-11-25 | Fix |
|---|---|
| `pipx install guarddog==3.2.0` on Python 3.14 built pygit2 1.18.2 from source, which needs libgit2's `git2.h` | Python 3.13, for which pygit2 publishes wheels |
| On the Arch host, every scan's `download-package` failed: `OpenSSL error: failed to load certificates: ... Permission denied`. GuardDog's Landlock sandbox grants the directory of Python's CA file, `/etc/ssl`, and `/etc/ssl/cert.pem` is a symlink into `/etc/ca-certificates/extracted` | `SSL_CERT_FILE` and `SSL_CERT_DIR` name Debian's bundle, a regular file |
| `guarddog --version` failed with `PermissionError` writing `top_npm_packages.json` into its own install: GuardDog rewrites a list once it is 30 days old | `GUARDDOG_TOP_PACKAGES_CACHE_LOCATION=/var/cache/guarddog`, seeded with the lists GuardDog ships. The named volume keeps each refresh: after one scan, `top_npm_packages.json` was dated 2026-11-25 |
| trivy found 5 HIGH in pip's vendored urllib3 2.7.0, msgpack and setuptools | pip is removed after the install |

With only `PATH` and `HOME` set, as byrle runs a detector, `guarddog-byrle.sh --version`
printed `3.2.0`. `npm scan express --version=5.3.0` took 12.4 s and reported
`capability-network-outbound`, as GuardDog on the host did, with no errors. GuardDog's own
sandbox works inside the container.

trivy reports 53 HIGH in the Debian packages of the base image, none with a fix, on
2026-11-25.

## Costs

- A podman container per scan. The 12.4 s for express was mostly GuardDog's download and
  scan, not the container start.
- byrle runs up to `BYRLE_MAX_CONCURRENT_ANALYSES` detectors at once. Two runs that refresh
  the same list together write the same file in the volume.
