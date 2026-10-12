#!/usr/bin/env bash
# Build byrle and start it with its Postgres in podman, from compose.yaml. Returns once
# both are up, and prints how to open a shell in the byrle container.
#
# Usage: run-dev.sh USER PASSWORD DATABASE
#
# podman-compose rather than `podman compose`, which runs docker-compose when it is
# installed. docker-compose sends the whole directory to the build, target/ included, and
# .dockerignore is applied only after that. podman-compose runs `podman build`, which
# reads the directory and leaves out what .dockerignore lists.
set -euo pipefail

if [[ $# -ne 3 || -z "$1" || -z "$2" || -z "$3" ]]; then
    echo "FAIL: usage: $(basename "$0") USER PASSWORD DATABASE"
    exit 1
fi
export DEV_DB_USER="$1" DEV_DB_PASSWORD="$2" DEV_DB_NAME="$3"

if ! command -v podman-compose >/dev/null 2>&1; then
    echo "FAIL: podman-compose is not on PATH."
    exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# --force-recreate: podman-compose 1.6.0 leaves a running container on its old image after
# --build makes a new one, so a rebuilt byrle would not run.
podman-compose -f "$repo_root/compose.yaml" up -d --build --force-recreate --wait

cat <<EOF

byrle is listening on http://127.0.0.1:8080, Postgres on 127.0.0.1:5433.
From $repo_root:

  shell:   podman exec -it byrle-dev sh
  logs:    podman-compose logs -f byrle
  stop:    podman-compose down
  delete:  podman-compose down -v    (the database too)
EOF
