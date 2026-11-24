# A release verifies only as `release.yml`'s run for its tag, and no third-party action runs while one is made

- **Number:** 0141
- **Status:** Implemented 2026-11-24 for steps 1 and 3 below. Steps 2 and 4 are not done.
- **Where:** `.github/workflows/release.yml`, `.github/workflows/ci.yml`,
  `scripts/make/release-image.sh`, `README.md`, `docs/runbook.md`
- **Related:** [release-provenance](0108-release-provenance.md),
  [deployment-targets](0140-deployment-targets.md)

## The path

Every deployment target pins a release that its operator checked with `gh attestation verify`.
Before this decision the documented command was `--repo krishardy/byrle` alone. That accepts
an attestation signed by any workflow file in the repository, run from any branch or tag.

| Way in | What it took |
|---|---|
| A pushed `v*` tag | write access: `release.yml` builds, attests and publishes on any tag |
| A pushed branch whose workflow asks for `id-token: write` | write access: its attestation passed `--repo` |
| `docker/setup-buildx-action`, `docker/login-action`, `docker/build-push-action` | a compromised release of any of them: they ran in the `image` job, which holds `packages: write` and `id-token: write` |
| A stolen token or session for the owner's account | any of the above |
| GitHub | it runs the runners and issues the OIDC identity |

## Decision

Asked for by the user 2026-11-24.

| Step | Change | Closes |
|---|---|---|
| 1 | Verify with `--signer-workflow krishardy/byrle/.github/workflows/release.yml --source-ref refs/tags/v<version> --deny-self-hosted-runners`, in `README.md`, `docs/runbook.md` and the release notes. The deployment docs point at the runbook rather than repeat it | an attestation from another workflow, another ref, or a self-hosted runner |
| 3 | `make release-image` builds and pushes the image with the runner's docker CLI and buildx, and BuildKit from `moby/buildkit:v0.35.1` pinned by digest. The three `docker/*` actions are gone, so only `actions/*` run in `release.yml`. `ci.yml` sets `permissions: contents: read` for every job that names none | a third-party action holding the release's tokens; a CI job's token taking the repository's default permissions |

v0.1.0's tarball attestation, read from `/repos/krishardy/byrle/attestations/sha256:ca99560d...`
on 2026-11-24, names `.github/workflows/release.yml@refs/tags/v0.1.0` and a `github-hosted`
runner, so the step 1 command accepts it. `gh` is not installed where this was written, so the
command itself was not run.

## Not done

| Step | What | Who |
|---|---|---|
| 2 | A tag ruleset on `v*` that lets only the owner create one; a `release` environment with the owner as required reviewer, named by the `release` and `image` jobs; Actions allowed only `actions/*`, `Swatinem/rust-cache` and the ones named here; default workflow permissions read-only | the owner, in the repository's settings |
| 4 | Each tag rebuilt by the owner with `make release-binary`, compared byte for byte with the release, and the SHA-256 sums published only when they match, signed with the owner's key. A run that GitHub or an action subverted then matches no pin | needs the build to be reproducible, which has not been measured |

`make release-image` has not run: there is no Docker here. It runs first on the next tag.
