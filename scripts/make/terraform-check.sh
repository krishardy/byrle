#!/usr/bin/env bash
# Check deployment/terraform-aws: `tofu fmt -check` and `tofu validate`, with the OpenTofu
# release pinned in scripts/make/lib/terraform.sh. It is downloaded into target/tofu and
# checked against the pinned SHA-256.
#
# Nothing is planned or applied: no AWS account is used. `tofu init` fetches the providers
# versions.tf pins, into target/tofu/data. The .terraform.lock.hcl it writes is ignored by git:
# an operator keeps the one their own `init` writes.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/make/lib/terraform.sh
. "$repo_root/scripts/make/lib/terraform.sh"

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) platform=linux_amd64 ;;
    Linux-aarch64) platform=linux_arm64 ;;
    Darwin-arm64) platform=darwin_arm64 ;;
    *) echo "no pinned OpenTofu for $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

dir="$repo_root/target/tofu/$tofu_version"
tofu="$dir/tofu"
if [[ ! -x "$tofu" ]]; then
    tarball="tofu_${tofu_version}_${platform}.tar.gz"
    mkdir -p "$dir"
    curl -sSfL --max-time 300 -o "$dir/$tarball" \
        "https://github.com/opentofu/opentofu/releases/download/v$tofu_version/$tarball"
    echo "${tofu_sha256[$platform]}  $dir/$tarball" | sha256sum -c --quiet -
    tar -xzf "$dir/$tarball" -C "$dir" tofu
    rm "$dir/$tarball"
fi

cd "$repo_root/deployment/terraform-aws"
export TF_DATA_DIR="$repo_root/target/tofu/data" TF_IN_AUTOMATION=1
"$tofu" fmt -check -diff
"$tofu" init -backend=false -input=false
"$tofu" validate
