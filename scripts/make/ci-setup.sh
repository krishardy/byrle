#!/usr/bin/env bash
# Install the tools CI job $1 needs, as .github/workflows/ci.yml runs it, so a job's setup
# can be run anywhere. The versions are pinned in scripts/make/lib/, which make dev-setup
# uses too.
#
#   make ci-setup JOB=lint     Rust with clippy and rustfmt, and the pinned shellcheck
#   make ci-setup JOB=test     Rust
#   make ci-setup JOB=sqlx     Rust, and sqlx-cli
#
# The pinned shellcheck goes in $RUNNER_TEMP/bin on a runner and ~/.local/bin elsewhere.
# On a runner that directory is added to $GITHUB_PATH, ahead of the image's own copy.
set -euo pipefail

lib="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib"
# shellcheck source=scripts/make/lib/rust.sh
. "$lib/rust.sh"
# shellcheck source=scripts/make/lib/sqlx-cli.sh
. "$lib/sqlx-cli.sh"

case "${1:-}" in
    lint)
        byrle_install_rust clippy rustfmt
        bin="${RUNNER_TEMP:-$HOME/.local}/bin"
        SHELLCHECK_DEST="$bin" "$lib/../install-shellcheck.sh"
        if [[ -n "${GITHUB_PATH:-}" ]]; then
            echo "$bin" >>"$GITHUB_PATH"
        fi
        ;;
    test)
        byrle_install_rust
        ;;
    sqlx)
        byrle_install_rust
        byrle_install_sqlx_cli
        ;;
    *)
        echo "usage: make ci-setup JOB=lint|test|sqlx"
        exit 2
        ;;
esac
