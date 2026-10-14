#!/usr/bin/env bash
# The shellcheck release `make install-shellcheck` installs, with each Linux tarball's
# sha256 as the release lists it. Sourced, not executed.
# shellcheck disable=SC2034  # read by the scripts that source this

shellcheck_version="v0.11.0"
shellcheck_sha256_x86_64="b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6"
shellcheck_sha256_aarch64="68a8133197a50beb8803f8d42f9908d1af1c5540d4bb05fdfca8c1fa47decefc"
