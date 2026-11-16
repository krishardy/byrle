# Deployment scripts in `deployment/`, one directory per target, compose first

- **Number:** 0140
- **Status:** Started 2026-11-15, for TODO.md ad-hoc #56: `deployment/compose/`,
  `deployment/ansible/` and `deployment/terraform-aws/` are written and not yet run.
- **Where:** `deployment/`, `scripts/make/smoke-compose.sh`, `scripts/make/ansible-check.sh`,
  `scripts/make/terraform-check.sh`
- **Related:** [tls-front-nginx](0100-tls-front-nginx.md),
  [release-provenance](0108-release-provenance.md)

## Decision

Deployment scripts are kept in this repository, under `deployment/`, one directory per target:

| Target | Directory |
|---|---|
| Docker Compose or Podman Compose, on one host | `compose/` |
| Directly on a host, with Ansible | `ansible/` |
| AWS, with Terraform | `terraform-aws/` |

This replaces TODO.md ad-hoc #39, which put Terraform in a separate repository,
`byrle-deploy`. Decided by the user 2026-11-15.

## `compose/`

| Choice | Why |
|---|---|
| Each image pinned by its tag's index digest, with the tag beside it | A tag can be repointed: `postgres:18-alpine` and `nginx:1.30-alpine` move on each patch release. The release image is attested by digest, so a digest runs what `gh attestation verify` checked. The index digest covers amd64 and arm64. Decided by the user 2026-11-16 |
| `make check-deps` reports each pinned image whose tag has moved, and each `image:` or `*_IMAGE=` line with no digest | `scripts/make/lib/image_digests.py` asks the registry for the tag's index digest. It fails `make check-deps` only with `CHECK_DEPS_STRICT=1`, as outdated crates do. Mutation-tested: with one character of postgres's digest changed, it printed `moved to sha256:b6972e1115a4...` and exited 1 |
| The release image, `ghcr.io/krishardy/byrle:<version>`, named by `BYRLE_IMAGE` | It is the attested build ([release-provenance](0108-release-provenance.md)). `container/compose.yaml` builds from source, for development |
| nginx from `nginx:1.30-alpine`, with `docs/fronting-tls.md`'s server block as a template | nginx is the supported front ([tls-front-nginx](0100-tls-front-nginx.md)). The image's `envsubst` step fills in `BYRLE_RP_KEY` and replaces only variables that are set, so `$http_host` and `$remote_addr` stay |
| Only nginx publishes a port | byrle and Postgres serve plain connections and are reached on the compose network |
| The certificate and key mounted as two files | certbot's `live/<name>/` has symlinks into `../../archive/`, which do not resolve inside a mount of the directory |
| One volume, `state`, at `/home/nonroot`, holding the spool and both logs | The image runs as 65532 and has no shell to `chown` a directory. A named volume takes the owner of the directory it is mounted on, and `/home/nonroot` is 65532's. byrle creates the spool directory itself |
| `refresh` as a service under a profile, run by a systemd timer on the host | byrle has no schedule of its own and the image has no shell or cron. A scheduler container would need the engine's socket |
| Settings in `.env`, passed whole to `byrle` with `env_file` | Any setting `byrle --help` lists can be added there without editing `compose.yaml`. The compose file sets the ones that depend on its own layout, which override `.env` |

`make smoke-compose` copies the directory to a temporary one, writes a `.env` with a local
CA's certificate for localhost, brings it up and checks health, a refresh, readiness, and a
pip install with a token made through `exec`. It removes the containers and volumes on exit.

## `ansible/`

| Choice | Why |
|---|---|
| One role, `byrle`, with task files for Postgres, byrle and nginx | Its settings are in one `defaults/main.yml`. Separate roles would each need `byrle_listen` and `byrle_rp_key` |
| `ansible.builtin` modules only, with `psql` and `createuser` for the role and database | `community.postgresql` needs a collection and psycopg2 on the host. galaxy.ansible.com answered this machine with 403 |
| The release tarball, checked against a SHA-256 per architecture in the defaults | A pin, as the images are. The sums were read from the release's `.sha256` files on 2026-11-16 |
| Postgres 18 from apt.postgresql.org | The version the compose target and the runbook use. Debian 13 ships 17 |
| Peer authentication over `/var/run/postgresql`, `postgres:///byrle?host=/var/run/postgresql&user=byrle` | No database password to keep. sqlx 0.8.6 reads a `host` beginning `/` as the socket's directory. Run on 2026-11-16 against Postgres 18: `byrle account create` connected and migrated; the same URL as another OS user failed with `Peer authentication failed for user "byrle"` |
| A `byrle` system user, `StateDirectory` and `LogsDirectory`, and `ProtectSystem=strict` | systemd creates `/var/lib/byrle` and `/var/log/byrle` owned by it. Nothing else is writable |
| `byrle-admin`, a wrapper on `systemd-run` | Account and token commands need the service's user, for peer authentication, and its environment file |
| The refresh timer's `OnActiveSec=1min` | The first refresh runs after install without the playbook waiting the minute it takes |
| The distribution's nginx | Security updates come with the host's. The server block is the one `make smoke-tls-front` runs |

`make ansible-check` installs ansible-core 2.22.0 and ansible-lint 26.11.0, pinned in
`scripts/make/lib/ansible.sh`, and runs `--syntax-check` and ansible-lint's `production`
profile. `make check-deps` reports a newer release of either.

## `terraform-aws/`

| Choice | Why |
|---|---|
| ECS Fargate, with the release image | The attested build, as compose runs it. No host to patch |
| An Application Load Balancer with an ACM certificate, and nginx in the task behind it | The load balancer cannot add `X-Byrle-RP-Key`. nginx adds it, with `set_real_ip_from` the VPC and `real_ip_header X-Forwarded-For` taking the client's address from the last entry, which the load balancer appended. Run on 2026-11-16 with nginx 1.28 and a header-echoing upstream: a request sent `X-Forwarded-For: 6.6.6.6, 203.0.113.9` reached it as `203.0.113.9`, with the key |
| A `config` container, in the nginx image, that writes the policy and nginx's server block to the task's volumes and exits | The release image has no shell, and Fargate mounts no files from the host. The nginx image is already pulled for the task, so no third image is pinned |
| RDS for Postgres, with `sslmode=require` | RDS for Postgres 15 and later refuses unencrypted connections. `verify-full` needs the RDS certificate authority in the image, which it does not have |
| The database password and `BYRLE_RP_KEY` from `ephemeral "random_password"`, through write-only arguments, into Secrets Manager | They are in neither the plan nor the state. The tasks read the password as `PGPASSWORD`: sqlx 0.8.6 and 0.9 read it when the URL has none (`sqlx-postgres/src/options/parse.rs`, `new_without_pgpass`). An RDS-managed password was not used: RDS rotates it every 7 days, and a task reads its secrets only when it starts |
| The audit and account event logs on EFS, through an access point owned by 65532 | They outlive the task. The image has no shell to `chown` with |
| The spool on the task's storage, 30 GiB | It holds downloads only while they are analysed |
| One task, replaced only after the old one stops | Two would append to the same logs on EFS. An apply that changes the task leaves installs unanswered for about a minute |
| Tasks in public subnets with public addresses, admitting only the load balancer | Their requests to the registries would go through a NAT gateway otherwise, charged by the gigabyte |
| `refresh` as its own task definition, started by EventBridge Scheduler | The proxy's task definition has nginx, which never exits |
| Provider versions pinned exactly in `versions.tf`, and no lock file committed | Terraform records `registry.terraform.io` in the lock, OpenTofu `registry.opentofu.org`. An operator keeps the lock their own `init` writes |

`make terraform-check` downloads OpenTofu 1.13.9 from its GitHub release, checks it against
the SHA-256 in `scripts/make/lib/terraform.sh`, and runs `tofu fmt -check` and `tofu
validate`. OpenTofu, because HashiCorp's download and registry hosts answered this machine's
egress proxy with 403. `make check-deps` reports a newer OpenTofu, AWS provider or random
provider, and checks `ecs.tf`'s nginx digest.

## Not verified here

The machine this was written on has no Docker or Podman. What was checked: the YAML parses,
and `podman-compose config` (1.6, with `podman` stubbed) fills in `.env` as intended. `make
smoke-compose` has not run.

`deployment/ansible/` has not run against a host. Its templates were rendered on this
machine and read.

`env.example` names the release image by tag alone. ghcr.io answered this machine's egress
proxy with 403, so its digest was not read, and `make check-deps` reports it as not pinned.

`deployment/terraform-aws/` has not been planned or applied: there is no AWS account here.
`make terraform-check` ran with the providers from OpenTofu's GitHub releases in a local
mirror, since registry.opentofu.org also answered 403. Not known: whether ECS Exec runs
`byrle` in the distroless image, and whether RDS offers Postgres 18 in a given region.
`config.sh` ran on this machine with its paths moved and a stand-in for `envsubst`, and
`nginx -t` passed on what it wrote.
