#!/usr/bin/env bash
# The nightly toolchain `make coverage` runs on.
#
# Sourced, not executed. On nightly, cargo-llvm-cov sets `--cfg coverage_nightly`, and each
# `#[cfg(test)]` item carries `#[cfg_attr(coverage_nightly, coverage(off))]`, so the floor
# counts library code and not the tests. `coverage(off)` is not stable on 1.98. See
# docs/engineering_decisions/coverage-counts-library-code-only.md.
#
# Pinned, so a nightly that stops building this crate is chosen by editing this line rather
# than met on the next run. Builds, tests, lint and release stay on stable.
byrle_coverage_toolchain="nightly-2026-09-28"
# The cargo-llvm-cov that reads this nightly's target directory. Its cargo keeps a test
# binary under `debug/build/<package>/<hash>/out`, and 0.8.4 looked only in `debug/deps`:
# "failed to collect object files" on 2026-10-12. 0.9.1 reads it.
byrle_llvm_cov_version="0.9.1"

# Whether the installed cargo-llvm-cov is $byrle_llvm_cov_version.
byrle_llvm_cov_pinned() {
    [[ "$(cargo llvm-cov --version 2>/dev/null)" == "cargo-llvm-cov $byrle_llvm_cov_version" ]]
}

byrle_install_coverage_toolchain() {
    echo "==> $byrle_coverage_toolchain (the toolchain 'make coverage' runs on)"
    if rustup run "$byrle_coverage_toolchain" rustc --version >/dev/null 2>&1; then
        echo "    already installed"
        return 0
    fi
    # cargo-llvm-cov reads the instrumentation this toolchain's rustc emits, so its
    # llvm-tools component comes with it.
    rustup toolchain install "$byrle_coverage_toolchain" --profile minimal \
        --component llvm-tools-preview 2>&1 | sed 's/^/    /'
}
