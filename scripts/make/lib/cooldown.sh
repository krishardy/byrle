#!/usr/bin/env bash
# A cooldown for the smoke scripts that covers a version published at a given time.
#
# Sourced, not executed.

# The cooldown_days that refuses a version published at ISO 8601 time $1: one more than
# the UTC calendar days since, as policy::facts dates a version.
cooldown_covering() {
    python3 -I -c '
import sys, datetime
published = datetime.datetime.fromisoformat(sys.argv[1]).astimezone(datetime.UTC).date()
print((datetime.datetime.now(datetime.UTC).date() - published).days + 1)' "$1"
}
