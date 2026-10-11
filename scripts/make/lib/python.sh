#!/usr/bin/env bash
# pip and uv pointed at one index and nothing else, for the targets that run them.
#
# Sourced, not executed. Each function prints an install command, one argument per line,
# so a caller can run it directly or under `timeout`:
#
#   mapfile -t cmd < <(byrle_pip_command "$venv" "$index" requests); "${cmd[@]}"
#
# PIP_CONFIG_FILE=/dev/null because a configured `extra-index-url` is queried alongside
# the proxy and serves its own file URLs. Measured: with the operator's own pip.conf in
# place, an install through the proxy fetched every file from the other index and the
# proxy saw no `/packages/` request at all. UV_NO_CONFIG=1 for the same reason.
#
# No cache, because pip and uv install from their caches without asking any index, which
# would skip enforcement entirely. That bypass is real (plan section 7); here it would just
# invalidate the run.
#
# --disable-pip-version-check because the check asks the index for `/simple/pip/`, a
# request that is not the install's.

byrle_pip_command() {
    local venv="$1" index="$2"; shift 2
    printf '%s\n' env PIP_CONFIG_FILE=/dev/null "$venv/bin/pip" install \
        --index-url "$index" --trusted-host 127.0.0.1 \
        --no-cache-dir --disable-pip-version-check "$@"
}

byrle_uv_command() {
    local venv="$1" index="$2"; shift 2
    printf '%s\n' env "VIRTUAL_ENV=$venv" UV_NO_CONFIG=1 uv pip install \
        --index-url "$index" --allow-insecure-host 127.0.0.1 --no-cache "$@"
}
