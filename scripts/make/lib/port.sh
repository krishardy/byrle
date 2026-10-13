#!/usr/bin/env bash
# Whether a local TCP port is already listened on, and by which process. Reads /proc, so it
# needs none of ss, lsof or netstat.
#
# Sourced, not executed.

# Succeeds when something listens on 127.0.0.1:$1, printing each listener's pid and command.
port_taken() {
    local port="$1" hex inodes inode fd
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null || return 1
    printf -v hex '%04X' "$port"
    # Field 2 is the local address as ADDR:PORT in hex, field 4 the state, 0A for LISTEN.
    inodes="$(awk -v p=":$hex" '$4 == "0A" && substr($2, length($2) - 4) == p { print $10 }' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null)"
    for inode in $inodes; do
        for fd in /proc/[0-9]*/fd/*; do
            if [[ "$(readlink "$fd" 2>/dev/null)" == "socket:[$inode]" ]]; then
                fd="${fd#/proc/}"
                printf '%s %s\n' "${fd%%/*}" "$(tr '\0' ' ' <"/proc/${fd%%/*}/cmdline")"
            fi
        done
    done
    return 0
}

# Fail, naming the listener, for each of the ports given that is already taken.
require_free_ports() {
    local port held
    for port in "$@"; do
        if held="$(port_taken "$port")"; then
            echo "port $port is already in use${held:+, by:}"
            [[ -n "$held" ]] && printf '%s\n' "$held"
            return 1
        fi
    done
}
