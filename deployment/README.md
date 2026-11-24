# Deploying byrle

One directory per target. Each runs the release image or binary with Postgres, behind TLS.
Each puts nginx in front, as [fronting-tls](../docs/fronting-tls.md)
sets out. [runbook](../docs/runbook.md) applies to each once it is up.

| Target | Directory | State |
|---|---|---|
| Docker Compose or Podman Compose, on one host | [compose/](compose/README.md) | Started. `make smoke-compose` checks it; not yet run |
| Directly on a host, with Ansible | [ansible/](ansible/README.md) | Started. `make ansible-check` passes; not yet run against a host |
| AWS, with OpenTofu | [opentofu-aws/](opentofu-aws/README.md) | Started. `make opentofu-check` passes; not yet applied to an AWS account |

`container/compose.yaml` is the development Postgres, started by `make start-dev-db`. It
is not a deployment.
