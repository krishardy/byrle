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
waharoa_coverage_toolchain="nightly-2026-09-28"

waharoa_install_coverage_toolchain() {
    echo "==> $waharoa_coverage_toolchain (the toolchain 'make coverage' runs on)"
    if rustup run "$waharoa_coverage_toolchain" rustc --version >/dev/null 2>&1; then
        echo "    already installed"
        return 0
    fi
    # cargo-llvm-cov reads the instrumentation this toolchain's rustc emits, so its
    # llvm-tools component comes with it.
    rustup toolchain install "$waharoa_coverage_toolchain" --profile minimal \
        --component llvm-tools-preview 2>&1 | sed 's/^/    /'
}
