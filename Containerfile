# byrle for the development environment in compose.yaml, started by `make run-dev`.
#
# A debug build, as `cargo run` makes. `.sqlx/` holds the query cache, so the build needs
# no database. The runtime image keeps a shell, so `podman exec -it byrle-dev sh` can run
# byrle's other commands next to the daemon.

FROM docker.io/library/rust:1-slim-trixie AS build
WORKDIR /src
COPY . .
ENV SQLX_OFFLINE=true
# The registry and target directory are cache mounts, kept between builds, so a rebuild
# compiles only what changed. The binary is copied out because the cache is not in the
# image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked && cp target/debug/byrle /usr/local/bin/byrle

# Debian 13, as the build stage is, with glibc, the CA bundle rustls reads for the upstream
# registries, a `nonroot` user and a busybox shell, and no package manager. On 2026-10-12
# trivy found no HIGH vulnerabilities in it. debian:trixie-slim had 43, none with a fixed
# package.
FROM gcr.io/distroless/cc-debian13:debug-nonroot
COPY --from=build /usr/local/bin/byrle /usr/local/bin/byrle
# Not root. It listens on 8080 and writes its spool to /tmp, which need no privilege. The
# base image sets this already; trivy's DS-0002 asks for it here.
USER nonroot
# The base image's entrypoint is /busybox/sh.
ENTRYPOINT ["byrle"]
CMD ["daemon"]
