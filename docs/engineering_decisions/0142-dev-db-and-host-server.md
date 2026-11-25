# The development Postgres runs in podman-compose, and byrle on the host

- **Number:** 0142
- **Status:** Implemented 2026-11-25. `scripts/make/start-dev-db.sh`,
  `scripts/make/start-dev-server.sh`, `scripts/make/reset-dev-db.sh`,
  `scripts/make/lib/dev-db.sh`, `container/compose.yaml`.
- **Supersedes:** [0101-dev-environment-compose](0101-dev-environment-compose.md)

## Decision

| Target | What it runs | Returns |
|---|---|---|
| `start-dev-db` | `podman-compose up -d db`, from `container/compose.yaml` | once the db container reports healthy |
| `start-dev-server` | `start-dev-db`, then `cargo run -- daemon` on the host | when byrle exits |
| `reset-dev-db` | `podman-compose down -v`, then `start-dev-db` | once the empty db container reports healthy |

They replace `make run`, which ran `cargo run -- daemon` with no database, and `make
run-dev`, which built byrle into an image and ran it beside Postgres. `compose.yaml` has
only the `db` service. `container/Containerfile` stays, for `make trivy`.

`start-dev-server` sets `BYRLE_DATABASE_URL` to the published port, `BYRLE_LISTEN` to
`127.0.0.1:8080` and `BYRLE_POLICY` to `dev/policy.yaml`. A host build skips the image
build that `run-dev` ran on each change. It fails while another process holds port 8080,
and names that process.

`DEV_DB_PORT`, default 5433, joins `DEV_DB_USER`, `DEV_DB_PASSWORD` and `DEV_DB_NAME` in
`DEV_DB_ARGS`. `compose.yaml` publishes `${DEV_DB_PORT:-5433}`, because `logs` and `down`
read the file in a shell where it is unset.

The compose project is still `byrle-dev`, so the volume `run-dev` made is the one
`start-dev-db` uses.

`reset-dev-db` refuses while something listens on `127.0.0.1:8080`, because a daemon there
would keep its connections to the deleted database. After it, every artifact answers 503
until `byrle refresh` runs again.

0101's reasons for `podman-compose` over `podman compose` still apply.

## podman-compose 1.6.0 `up -d --wait db`

On 2026-11-25 it did not return after 5 minutes, with the db container healthy.
`dev_db_wait` reads `.State.Health.Status` from `podman inspect` instead, finding the
container by its `com.docker.compose.project` and `com.docker.compose.service` labels.
