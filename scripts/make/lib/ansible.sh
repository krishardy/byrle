#!/usr/bin/env bash
# The ansible-core and ansible-lint releases `make ansible-check` installs into
# target/ansible-venv. Sourced, not executed.
# shellcheck disable=SC2034  # read by the scripts that source this

ansible_core_version="2.22.0"
ansible_lint_version="26.11.0"
