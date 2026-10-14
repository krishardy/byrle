#!/usr/bin/env bash
# The Rust toolchain CI builds with. Sourced, not executed.
#
# `stable` rather than a pinned version: the repo has no `rust-toolchain.toml` and no
# `rust-version` in Cargo.toml, so a contributor runs whatever stable rustup gives them,
# and CI checking an older toolchain would pass on lints they cannot see.

byrle_rust_toolchain="stable"

# Install the toolchain, minimal, with the components named in $@, and make it the default.
byrle_install_rust() {
    local components=()
    if [[ $# -gt 0 ]]; then
        components=(--component "$(IFS=,; echo "$*")")
    fi
    echo "==> Rust $byrle_rust_toolchain${*:+ with $*}"
    rustup toolchain install "$byrle_rust_toolchain" --profile minimal "${components[@]}"
    rustup default "$byrle_rust_toolchain"
}
