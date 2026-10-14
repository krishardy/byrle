# Releases and their provenance

- **Status:** Implemented 2026-10-14: `.github/workflows/release.yml`. No release has been
  published yet.
- **Related:** [provenance-check](provenance-check.md), [ci-gates](ci-gates.md)

## Decision

Chosen by the user 2026-10-14:

| Question | Answer |
|---|---|
| What a release publishes | Linux x86_64 and aarch64 binaries as GitHub release assets, and an image on `ghcr.io/krishardy/byrle` |
| How provenance is made | `actions/attest-build-provenance`: SLSA v1 build provenance, signed through Sigstore, as npm and PyPI packages that byrle checks carry |
| What starts a release | pushing a `v*` tag, which must be `v` and the version in `Cargo.toml` |

## What the workflow does

| Job | Runner | Does |
|---|---|---|
| `binaries` | `ubuntu-latest`, `ubuntu-24.04-arm` | `make release-check`, `make release-binary`, attests each tarball, uploads it |
| `release` | `ubuntu-latest` | creates the GitHub release with each tarball and its `.sha256` |
| `image` | `ubuntu-latest` | `make release-image-context`, builds `Containerfile.release` for `linux/amd64` and `linux/arm64`, pushes it tagged with the version, attests it by digest |

The image holds the binaries the `binaries` job attested, unpacked from their tarballs, so
it is not a second, unattested build. It is distroless `cc-debian13:nonroot`, with no
shell; the development `Containerfile` builds from source on the `debug` variant.

Each job has only the permissions it uses, and the workflow's default is none. Each action
is pinned by commit, with its release in a comment: a tag can be moved to other code.

A binary is built on Ubuntu 24.04 and needs glibc 2.39 or later, so it does not run on
Debian 12. A static musl build would.

## Verifying

```
gh attestation verify byrle-0.1.0-x86_64-unknown-linux-gnu.tar.gz --repo krishardy/byrle
gh attestation verify oci://ghcr.io/krishardy/byrle:0.1.0 --repo krishardy/byrle
```

Each names the workflow, `.github/workflows/release.yml`, and the commit it built.

## Checked before the first release

| Check | Result |
|---|---|
| actionlint 1.7.12 on `release.yml` and `ci.yml` | clean, after a colon in an unquoted `run:` line broke the YAML |
| `make release-check TAG=v0.1.0`, and `TAG=v9.9.9` | passes, and refuses |
| `make release-binary`, then `make release-image-context` | `byrle-0.1.0-x86_64-unknown-linux-gnu.tar.gz` with the binary, `LICENSE` and `README.md`; unpacked, `byrle --version` says `byrle 0.1.0` |

The workflow itself runs only on GitHub. The first tag pushed is its first run.
