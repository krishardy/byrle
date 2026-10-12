# Proxy tokens for the smoke scripts. See docs/admin-plan.md §4.1.
#
# Sourced, not executed. Needs `repo_root` and `fail` from the caller.

# Create account $2 in the store at $1, and print a new token for it. Called in `$(...)`,
# so a failure is reported on stderr.
issue_token() {
    local url="$1" account="$2"
    BYRLE_DATABASE_URL="$url" cargo run --quiet --manifest-path "$repo_root/Cargo.toml" \
        -- account create "$account" >/dev/null || { fail "byrle account create $account failed"; } >&2
    BYRLE_DATABASE_URL="$url" cargo run --quiet --manifest-path "$repo_root/Cargo.toml" \
        -- token create "$account" smoke 2>/dev/null || { fail "byrle token create failed"; } >&2
}

# Assert that $1, asked for without a token, answers 401 asking for Basic credentials.
assert_unauthorized() {
    local headers status
    headers="$(curl -s -o /dev/null -D - "$1")"
    status="$(printf '%s' "$headers" | head -1 | cut -d' ' -f2)"
    [[ "$status" == "401" ]] || fail "$1 without a token answered $status, not 401"
    printf '%s' "$headers" | grep -qi '^www-authenticate: Basic realm="byrle"' \
        || fail "the 401 for $1 does not ask for Basic credentials"
}

# Assert that file $2 does not contain token $1.
assert_token_absent() {
    if grep -qF "$1" "$2"; then
        fail "$2 contains the proxy token"
    fi
}
