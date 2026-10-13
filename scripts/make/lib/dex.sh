#!/usr/bin/env bash
# Dex, the OIDC provider `make smoke-console` logs in through. See
# docs/engineering_decisions/console-login.md.
#
# Sourced, not executed. `start_dex CONFIG PORT` starts it, `stop_dex` stops it. It runs in a
# docker container when docker answers, and otherwise as a binary built from Dex's tag with
# Go, kept under the user's cache directory, since Dex publishes no binaries.

dex_version="v2.46.0"
dex_image="ghcr.io/dexidp/dex:${dex_version}"
dex_container=""
dex_pid=""

# The path of a Dex binary at $dex_version, built with Go the first time. Empty without Go.
dex_binary() {
    local dir="${XDG_CACHE_HOME:-$HOME/.cache}/byrle/dex-$dex_version"
    if [[ -x "$dir/dex" ]]; then
        printf '%s' "$dir/dex"
        return
    fi
    command -v go >/dev/null || return 0
    local src
    src="$(mktemp -d)"
    mkdir -p "$dir"
    if git clone -q --depth 1 --branch "$dex_version" https://github.com/dexidp/dex.git "$src" \
        && (cd "$src" && go build -o "$dir/dex" ./cmd/dex); then
        printf '%s' "$dir/dex"
    fi
    rm -rf "$src"
}

stop_dex() {
    if [[ -n "$dex_container" ]]; then
        docker rm -f "$dex_container" >/dev/null 2>&1 || true
    fi
    if [[ -n "$dex_pid" ]]; then
        kill "$dex_pid" 2>/dev/null || true
        wait "$dex_pid" 2>/dev/null || true
    fi
}

# Start Dex with the config at $1, serving on 127.0.0.1:$2, and wait for its discovery.
start_dex() {
    local config="$1" port="$2"
    if docker info >/dev/null 2>&1; then
        dex_container="byrle-smoke-dex-$$"
        docker run -d --name "$dex_container" --network host \
            -v "$config:/etc/dex/config.yaml:ro" "$dex_image" \
            dex serve /etc/dex/config.yaml >/dev/null
    else
        local binary
        binary="$(dex_binary)"
        if [[ -z "$binary" ]]; then
            echo "neither docker nor Go is available to run Dex $dex_version."
            return 1
        fi
        "$binary" serve "$config" >"$config.log" 2>&1 &
        dex_pid=$!
    fi
    for _ in $(seq 1 60); do
        curl -s -o /dev/null "http://127.0.0.1:$port/dex/.well-known/openid-configuration" && return 0
        sleep 0.5
    done
    echo "Dex did not answer on port $port within 30s"
    return 1
}
