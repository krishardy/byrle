#!/usr/bin/env bash
# The OpenTofu release `make terraform-check` runs, and the SHA-256 of its tarball per
# platform, from the release's tofu_<version>_SHA256SUMS. Sourced, not executed.
#
# OpenTofu, not Terraform: its releases are on GitHub, and HashiCorp's download and registry
# hosts refuse the machine this was written on. deployment/terraform-aws runs on both.
# shellcheck disable=SC2034  # read by the scripts that source this

tofu_version="1.13.9"
declare -A tofu_sha256=(
    [linux_amd64]="b34b327cc1ef07178207b6f2cd1f5276537d3e5b7be316500f6dac50d4c0a857"
    [linux_arm64]="5dc196dde75b667e4806d358310ec96742774cd0993c54c1237efee5644b69b8"
    [darwin_arm64]="496f4c3064b5c3bff79174b3dae4faaf65a66774eb8e2bf074f895412c5f124f"
)
