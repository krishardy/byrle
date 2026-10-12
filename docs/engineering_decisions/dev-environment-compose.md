# The development environment runs in podman-compose

- **Status:** Implemented 2026-10-12. `compose.yaml`, `Containerfile`, `.dockerignore`,
  `scripts/make/run-dev.sh`.

## Decision

`make run-dev` builds byrle into an image and starts it with Postgres 18, from
`compose.yaml`, using `podman-compose`. It replaces `run-dev` running `cargo run` on the
host and the `start-dev-db`, `stop-dev-db` and `rm-dev-db` targets.

| Service | Image | Published on |
|---|---|---|
| `db` | `docker.io/library/postgres:18-alpine`, volume at `/var/lib/postgresql` | `127.0.0.1:5433` |
| `byrle` | built from `Containerfile`, `byrle daemon` | `127.0.0.1:8080` |

The role, password and database are `DEV_DB_USER`, `DEV_DB_PASSWORD` and `DEV_DB_NAME`
in the Makefile. `run-dev.sh` takes them as arguments and exports them for `compose.yaml`.
`byrle` starts once `db` answers `pg_isready` over TCP, because the daemon applies
migrations at startup.

`podman exec -it byrle-dev sh` opens a shell next to the daemon, where `byrle account`,
`byrle refresh` and the other commands use the same `BYRLE_DATABASE_URL`.

## Why podman-compose and not `podman compose`

`podman compose` runs whichever provider `compose_providers` in `containers.conf` names,
and docker-compose first when it is installed. On 2026-10-12 with docker-compose 5.1.4:

| Provider | What happened |
|---|---|
| docker-compose, `DOCKER_HOST` set | the containers ran in the rootless Docker daemon `DOCKER_HOST` named, not in podman |
| docker-compose, `DOCKER_HOST` unset | failed until `podman.socket` was started |
| docker-compose, socket running | sent the whole directory to the build, past 84 MB of the 82 GB `target/` before it was stopped; `.dockerignore` was applied after the upload |
| podman-compose 1.6.0 | runs `podman build`, which reads the directory and leaves out what `.dockerignore` lists |

`run-dev.sh` calls `podman-compose` directly, so the build does not depend on
`containers.conf`.

## The image

A debug build, from `rust:1-slim-trixie`, with `SQLX_OFFLINE=true` reading `.sqlx/`. The
cargo registry and `target/` are cache mounts, so a rebuild compiles only what changed.
The runtime image is `gcr.io/distroless/cc-debian13:debug-nonroot`: Debian 13 as the
build stage is, glibc, the CA bundle rustls reads for the upstream registries, a `nonroot`
user and a busybox shell. Its entrypoint is `/busybox/sh`, so `Containerfile` sets it to
`byrle`.

`BYRLE_LISTEN` is `0.0.0.0:8080` inside the container, as `127.0.0.1` there cannot be
reached through the published port. `BYRLE_PROXY_URL` is `http://127.0.0.1:8080`, the
address the host's package managers use and lockfiles record.

byrle runs as `nonroot`, uid 65532; `trivy config` reports root as DS-0002. It listens on
8080 and writes its spool to `/tmp`.

### Runtime images compared

trivy on each base image alone, 2026-10-12, with no `--ignore-unfixed`. "Runs byrle" is
`byrle --version` from the binary built here, which needs `GLIBC_2.39`.

| Image | OS | Size | HIGH | MEDIUM | Shell | CA bundle | Non-root user | Runs byrle |
|---|---|---|---|---|---|---|---|---|
| `debian:trixie-slim` | Debian 13.7 | 81 MB | 43, none fixed | 58 | yes | after `apt-get` | after `useradd` | yes |
| `ubuntu:24.04` | Ubuntu 24.04 | 80 MB | 1, fixed | 9 | yes | no | no | not tried |
| `gcr.io/distroless/cc-debian13:debug` | Debian 13.7 | 30 MB | 0 | 23 | busybox | yes | `nonroot` | yes |
| `cgr.dev/chainguard/wolfi-base` | Wolfi | 18 MB | 0 | 0 | yes | yes | `nonroot` | yes |
| `ubi10/ubi-micro` | RHEL 10.2 | 24 MB | 0 | 0 | yes | no | no | yes |
| `ubi10/ubi-minimal` | RHEL 10.2 | 87 MB | 0 | 0 | yes | yes | no | yes |
| `alpine` | Alpine 3.24.2 | 8 MB | 0 | 1 | yes | no | no | needs a musl build |

Wolfi had no findings, but Chainguard's free images are published as `latest` only, so
the version cannot be pinned.

## podman-compose 1.6.0 behaviour the files work around

| Behaviour | Workaround |
|---|---|
| `up --build` leaves a running container on its old image | `run-dev.sh` passes `--force-recreate` |
| `exec` sets the service's `environment` again, interpolated from the current shell, where `DEV_DB_*` are usually unset, so `BYRLE_DATABASE_URL` lost its credentials | the shell is `podman exec -it byrle-dev sh`, which keeps the container's environment |
| every command reads the whole file, so `${DEV_DB_USER:?}` failed `logs` and `down` | plain `${DEV_DB_USER}`; `run-dev.sh` refuses empty values |
| byrle handles SIGHUP only, and as PID 1 ignored SIGTERM, so `down` waited 10 s | `init: true` |

## Scanning

`make trivy`, part of `make sast`, runs `trivy config` on the repository and `trivy image`
on an image built from `Containerfile`, and fails on a HIGH or CRITICAL finding, fixed
package or not. `trivy config` does not read `compose.yaml`.
