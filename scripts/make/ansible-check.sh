#!/usr/bin/env bash
# Check deployment/ansible: `ansible-playbook --syntax-check` and `ansible-lint` at its
# production profile, with the pinned versions in scripts/make/lib/ansible.sh. They are
# installed into target/ansible-venv, and again when a pin changes.
#
# Nothing is run against a host. The inventory is inventory.example.yml.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/make/lib/ansible.sh
. "$repo_root/scripts/make/lib/ansible.sh"
venv="$repo_root/target/ansible-venv"
pins="ansible-core==$ansible_core_version ansible-lint==$ansible_lint_version"

if [[ "$(cat "$venv/pins" 2>/dev/null || true)" != "$pins" ]]; then
    rm -rf "$venv"
    python3 -m venv "$venv"
    # shellcheck disable=SC2086  # $pins is two arguments
    "$venv/bin/pip" install --quiet $pins
    echo "$pins" >"$venv/pins"
fi

cd "$repo_root/deployment/ansible"
export ANSIBLE_HOME="$venv/home" PATH="$venv/bin:$PATH"
ansible-playbook -i inventory.example.yml --syntax-check site.yml
ansible-lint --offline --profile production site.yml
