#!/usr/bin/env bash
# Install sqlx-cli, pinned to the sqlx minor the build uses.
#
# Sourced, not executed. `byrle_install_sqlx_cli` installs it when it is missing or of
# another minor, and returns with nothing installed when the right one is already there.
#
# Both `scripts/make/dev-setup.sh` and the CI workflow call this, so the pin is written
# once. It has to track the `sqlx` version in Cargo.toml: `make sqlx-prepare` writes the
# offline cache that the build then reads, and a CLI of another minor writes a cache the
# build does not accept.

# Pinned to the sqlx minor in Cargo.toml. An installed CLI of another minor is replaced
# rather than kept.
byrle_sqlx_minor="0.8"

byrle_install_sqlx_cli() {
    echo "==> sqlx-cli $byrle_sqlx_minor (offline query cache, used by 'make sqlx-prepare')"
    if cargo sqlx --version 2>/dev/null | grep -q " $byrle_sqlx_minor\."; then
        echo "    already installed"
        return 0
    fi
    # Postgres only, matching the one backend. The default features build every driver.
    cargo install sqlx-cli --version "^$byrle_sqlx_minor" --locked --force \
        --no-default-features --features rustls,postgres
}
