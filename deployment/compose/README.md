# byrle with Docker Compose or Podman Compose

byrle's release image, Postgres 18 and nginx on TLS, on one host. [runbook](../../docs/runbook.md)
says what to run in what order once it is up. `make smoke-compose` brings this directory up
with a local CA's certificate and checks it.

| Service | Image | Reached at |
|---|---|---|
| `nginx` | `nginx:1.30-alpine`, by digest | the host's `BYRLE_HTTPS_PORT`, 443 by default |
| `byrle` | `BYRLE_IMAGE`, `ghcr.io/krishardy/byrle:0.1.0` | `byrle:8080` on the compose network |
| `db` | `postgres:18-alpine`, by digest | `db:5432` on the compose network |
| `refresh` | `BYRLE_IMAGE` | run by `systemd/byrle-refresh.timer`, not by `up` |

| Volume | Holds |
|---|---|
| `db` | Postgres: intel, accounts, tokens, analyses and decisions |
| `state` | byrle's `/home/nonroot`: the spool, up to 8 GiB, and `audit.jsonl` and `account-events.jsonl` with their rotated files |

## 1. Install

Copy this directory to the host, as `/opt/byrle` for the timer below. Then:

```
cd /opt/byrle
cp env.example .env
chmod 600 .env
```

Fill in `.env`. Each line is passed to the `byrle` container, so any setting `byrle
--help` lists can be added there.

| Setting | Set to |
|---|---|
| `BYRLE_IMAGE` | the release by digest, `ghcr.io/krishardy/byrle:<version>@sha256:<digest>`, after verifying it as [runbook](../../docs/runbook.md#1-install-and-verify) says |
| `BYRLE_PROXY_URL` | nginx's address as installing machines reach it, with its port if not 443 |
| `BYRLE_TLS_CERT`, `BYRLE_TLS_KEY` | the certificate chain and key on the host |
| `POSTGRES_PASSWORD`, `BYRLE_RP_KEY` | `openssl rand -hex 32` each |
| `BYRLE_MODE` | `observe` for the first week |

With rootless Podman, nginx reads the key as the user running Podman. certbot writes
`privkey.pem` readable by root alone.

## 2. Start

```
docker compose up -d
docker compose --profile refresh run --rm refresh
curl https://byrle.example.com/-/byrle/ready
```

byrle applies its migrations at startup. `/-/byrle/ready` answers 200 once intel is
loaded. Until then, an artifact answers 503.

With Podman, `podman compose` or `podman-compose` takes the same arguments.

## 3. Refresh on a schedule

```
cp systemd/byrle-refresh.service systemd/byrle-refresh.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now byrle-refresh.timer
```

The timer runs `refresh` every 6 hours. The service's `WorkingDirectory` is `/opt/byrle`,
and its `ExecStart` is `docker compose`: edit both for another directory or for Podman.
`refresh` exits 1 when a stream did not load and its last load stays, and systemd reports
that as a failure: `journalctl -u byrle-refresh` has the stream.

## 4. Accounts and tokens

The image has no shell. Run byrle in the running container:

```
docker compose exec byrle byrle account create alice
docker compose exec byrle byrle token create alice laptop
```

## 5. Change it

| Change | Then |
|---|---|
| `policy/policy.yaml` | `docker compose kill -s HUP byrle` |
| `.env`, such as removing `BYRLE_MODE` to enforce | `docker compose up -d` |
| a renewed certificate | `docker compose up -d --force-recreate nginx` |
| a new release | verify it, set `BYRLE_IMAGE` to its digest, `docker compose up -d` |
| a new Postgres or nginx | set the digest in `compose.yaml`, `docker compose up -d`. `make check-deps` reports a tag that moved |
| remove everything, Postgres too | `docker compose down -v` |
