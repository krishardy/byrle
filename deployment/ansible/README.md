# byrle directly on a host, with Ansible

`site.yml` installs byrle on each host in the `byrle` group. [runbook](../../docs/runbook.md)
says what to run in what order once it is up. `make ansible-check` syntax-checks and lints
it. Nothing here has run against a host yet.

The hosts are Debian or Ubuntu, on x86_64 or aarch64. Only `ansible.builtin` modules are
used, so no collection is installed.

| Piece | From | Where |
|---|---|---|
| byrle | the release tarball, checked against `byrle_release_sha256` | `/opt/byrle/<release>/byrle`, linked from `/usr/local/bin/byrle` |
| `byrle.service` | `templates/byrle.service.j2` | runs `byrle daemon` as the `byrle` system user, at `byrle_listen` |
| `byrle-refresh.timer` | `templates/byrle-refresh.timer.j2` | runs `byrle refresh` on `byrle_refresh_on_calendar`, and 1 to 16 minutes after the timer starts |
| Postgres 18 | apt.postgresql.org | the `byrle` role and database, reached over `/var/run/postgresql` by peer authentication: no password |
| nginx | the distribution's package | `/etc/nginx/conf.d/byrle.conf`, on `byrle_https_port` |
| settings | `templates/byrle.env.j2` | `/etc/byrle/byrle.env`, readable by root and the `byrle` group |
| policy | `files/policy.yaml`, or `byrle_policy_src` | `/etc/byrle/policy.yaml` |
| spool | | `/var/lib/byrle/spool`, up to 8 GiB |
| audit and account event logs | | `/var/log/byrle/` |

## 1. Configure

```
cp inventory.example.yml inventory.yml
ansible-vault create group_vars/byrle/vault.yml    # vault_byrle_rp_key: <openssl rand -hex 32>
```

| Setting | Default | Set to |
|---|---|---|
| `byrle_proxy_url` | none, required | nginx's address as installing machines reach it. Lockfiles record it |
| `byrle_tls_cert`, `byrle_tls_key` | none, required with nginx | the certificate chain and key on the host |
| `byrle_rp_key` | none, required | at least 32 bytes, from the vault |
| `byrle_mode` | `observe` | `""` to enforce |
| `byrle_github_token` | `""` | a token, for GitHub's Advisory Database |
| `byrle_environment` | `{}` | any other setting `byrle --help` lists, as `NAME: value` |
| `byrle_version`, `byrle_release_sha256` | 0.1.0 | a new release, after verifying it as [runbook](../../docs/runbook.md#1-install-and-verify) says |
| `byrle_postgres_local` | `true` | `false`, with `byrle_database_url`, for another Postgres |
| `byrle_nginx` | `true` | `false` to put another front at `byrle_listen` |

The certificate is not issued here. With certbot, a deploy hook of `systemctl reload nginx`
picks up a renewal.

## 2. Install

```
ansible-playbook site.yml --ask-vault-pass
```

Running it again changes only what differs. A changed policy reloads byrle. A changed
setting, unit or release restarts it.

## 3. Accounts and tokens

`byrle-admin` runs byrle as the service does, as the `byrle` user with
`/etc/byrle/byrle.env`:

```
sudo byrle-admin account create alice
sudo byrle-admin token create alice laptop
```

## 4. Watch it

| What | How |
|---|---|
| byrle's log | `journalctl -u byrle` |
| the last refresh | `systemctl status byrle-refresh`, `journalctl -u byrle-refresh` |
| ready | `curl https://<name>/-/byrle/ready` answers 200 once intel is loaded |
