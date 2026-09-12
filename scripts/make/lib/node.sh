#!/usr/bin/env bash
# Put nvm's latest stable node on PATH, for the targets that run package managers.
#
# Sourced, not executed. Every caller that shells out to npm, pnpm, yarn or bun sources
# this first, so they all agree on which node they are testing against.
#
# Without it the node in play is whatever the shell's profile happened to resolve, which
# on a machine with both nvm and asdf is not stable between invocations: this repository
# saw node 16 and node 24 from the same PATH on the same machine minutes apart. That
# decides real behaviour, not just versions. yarn 2+ needs node 18 or later because
# corepack calls URL.canParse, so on node 16 it is skipped entirely.
#
# "Latest stable" is nvm's own answer, `nvm version node`, rather than the highest
# directory name, so the definition stays nvm's rather than becoming ours.
#
# Does nothing when nvm is not installed, which leaves the PATH as it was.

# Locate nvm without requiring NVM_DIR to be exported into a non-interactive shell.
waharoa_nvm_dir() {
    local candidate
    for candidate in "${NVM_DIR:-}" "$HOME/.nvm" "$HOME/.config/nvm"; do
        if [[ -n "$candidate" && -f "$candidate/nvm.sh" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

# Prepend the latest stable node's bin directory to PATH, and describe the choice in
# WAHAROA_NODE. Leaves both untouched when there is no nvm.
#
# It sets a variable rather than printing, because a caller capturing the output with
# `$(...)` would run this in a subshell and the new PATH would die with it.
waharoa_use_latest_node() {
    local dir version bin
    dir="$(waharoa_nvm_dir)" || return 0

    # nvm.sh is written for interactive shells and reads unset variables, so `set -u` has
    # to come off while it loads. The subshell keeps that from leaking.
    version="$(
        set +u
        # shellcheck disable=SC1091
        . "$dir/nvm.sh" >/dev/null 2>&1 || exit 0
        nvm version node 2>/dev/null
    )"
    [[ "$version" == v* ]] || return 0

    bin="$dir/versions/node/$version/bin"
    [[ -d "$bin" ]] || return 0

    PATH="$bin:$PATH"
    export PATH
    # Exported because the callers that source this read it, and shellcheck cannot see
    # across the source boundary.
    export WAHAROA_NODE="node $version, the latest stable nvm has installed"
}
