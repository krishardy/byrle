#!/usr/bin/env bash
# Fails a smoke whose clients asked a path the proxy does not recognise. Each one is a
# path an adapter's classify_path should list, so a client update that asks a new one fails
# the smoke before it is refused for a user. See
# docs/engineering_decisions/0119-unrecognised-paths-refused.md.
#
# Sourced, not executed.

# Exits 1, printing each line, when a proxy log in "$@" logged an unrecognised path.
recognised() {
    local lines
    lines="$(sed -E 's/\x1b\[[0-9;]*m//g' "$@" 2>/dev/null | grep 'unrecognised path' || true)"
    if [[ -n "$lines" ]]; then
        echo "FAIL: a client asked a path the proxy does not recognise:"
        echo "$lines"
        exit 1
    fi
}
