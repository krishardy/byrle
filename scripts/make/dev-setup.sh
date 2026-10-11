#!/usr/bin/env bash
# Install the development dependencies this project's targets expect.
#
# Deliberately additive and re-runnable: it installs what is missing and leaves
# anything already present alone.
set -euo pipefail

need() { command -v "$1" >/dev/null 2>&1; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/make/lib/node.sh
. "$repo_root/scripts/make/lib/node.sh"
byrle_use_latest_node

echo "==> rustup components"
rustup component add clippy rustfmt 2>&1 | sed 's/^/    /'

echo "==> cargo-binstall (installs the cargo tools below)"
if cargo binstall -V >/dev/null 2>&1; then
    echo "    found $(cargo binstall -V)"
else
    # Built from source. Upstream's other route is `curl ... | bash`, which this file does
    # not run, for the reason the trufflehog entry below gives.
    cargo install cargo-binstall --locked
fi

# Fetches a prebuilt binary where one is published, and builds from source where not.
binstall() { cargo binstall --no-confirm --locked --disable-telemetry "$@"; }

echo "==> cargo-audit (dependency advisories; used when re-running the config spike)"
if cargo audit --version >/dev/null 2>&1; then
    echo "    already installed"
else
    binstall cargo-audit
fi

echo "==> cargo-outdated (dependency freshness, used by 'make check-deps')"
if cargo outdated --version >/dev/null 2>&1; then
    echo "    already installed"
else
    binstall cargo-outdated
fi

# shellcheck source=scripts/make/lib/sqlx-cli.sh
. "$repo_root/scripts/make/lib/sqlx-cli.sh"
byrle_install_sqlx_cli

echo "==> cargo-llvm-cov (unit test coverage, used by 'make coverage')"
if cargo llvm-cov --version >/dev/null 2>&1; then
    echo "    already installed"
else
    # It reads the instrumentation rustc emits, so the matching llvm-tools component
    # has to be there as well.
    rustup component add llvm-tools-preview 2>&1 | sed 's/^/    /'
    binstall cargo-llvm-cov
fi

# shellcheck source=scripts/make/lib/coverage-toolchain.sh
. "$repo_root/scripts/make/lib/coverage-toolchain.sh"
byrle_install_coverage_toolchain

echo "==> cargo-mutants (mutation testing, used by 'make mutants')"
if cargo mutants --version >/dev/null 2>&1; then
    echo "    already installed"
else
    binstall cargo-mutants
fi

echo "==> trufflehog (credential scanning, used by 'make sast')"
if need trufflehog; then
    echo "    found $(trufflehog --version 2>&1 | head -1)"
elif need brew; then
    brew install trufflehog
elif need go; then
    # Not `go install ...@latest`: trufflehog's go.mod has replace directives, which Go
    # applies only to the main module, and refuses that install with "The go.mod file
    # for the module providing named packages contains one or more replace directives".
    # Built from a clone of the latest tag instead, where it is the main module.
    src="$(mktemp -d)"
    trap 'rm -rf "$src"' EXIT
    version=""
    if ! { version="$(go list -m -f '{{.Version}}' github.com/trufflesecurity/trufflehog/v3@latest)" \
        && git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$version" \
            https://github.com/trufflesecurity/trufflehog.git "$src" \
        && (cd "$src" && go install .); }; then
        echo "    NOT INSTALLED: building trufflehog ${version:-@latest} failed. 'make sast' cannot scan."
    fi
    rm -rf "$src"
    trap - EXIT
else
    # Upstream offers `curl ... install.sh | sh`. Not run automatically here: piping a
    # remote script into a shell is the pattern this project exists to distrust, and it
    # wants /usr/local/bin, so it is the operator's call rather than ours.
    echo "    NOT INSTALLED. Install with brew or go, or review and run:"
    echo "    https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh"
fi

echo "==> shellcheck (shell linting, used by 'make lint')"
if need shellcheck; then
    echo "    found $(shellcheck --version 2>/dev/null | awk '/^version:/ {print $2}')"
elif need pipx; then
    # The shellcheck-py package ships the real binary in a platform wheel, so this
    # needs no root and works the same on Linux and macOS.
    pipx install shellcheck-py
elif need pip3; then
    pip3 install --user shellcheck-py
elif need pacman; then
    echo "    install with: sudo pacman -S shellcheck"
elif need apt-get; then
    echo "    install with: sudo apt-get install shellcheck"
elif need brew; then
    brew install shellcheck
else
    echo "    NOT INSTALLED and no installer found. 'make lint' cannot check shell."
fi

echo "==> semgrep (static analysis, used by 'make sast')"
if need semgrep; then
    echo "    found $(semgrep --version 2>/dev/null)"
    # `make semgrep` requires a login, because the registry serves fewer rules to an
    # anonymous client: 57 against 103 measured on this repository. Reported here so it
    # is part of setting a machine up rather than a surprise on the first scan.
    settings="${SEMGREP_SETTINGS_FILE:-}"
    if [[ -z "$settings" ]]; then
        if [[ -n "${XDG_CONFIG_HOME:-}" && -d "${XDG_CONFIG_HOME}" ]]; then
            settings="$XDG_CONFIG_HOME/.semgrep/settings.yml"
        else
            settings="$HOME/.semgrep/settings.yml"
        fi
    fi
    token=""
    if [[ -n "${SEMGREP_APP_TOKEN:-}" ]]; then
        token="env"
    elif [[ -f "$settings" ]]; then
        value="$(sed -nE 's/^[[:space:]]*api_token:[[:space:]]*//p' "$settings" | head -1 \
            | tr -d '"'"'"'[:space:]')"
        [[ -n "$value" && "$value" != "null" && "$value" != "~" ]] && token="$settings"
    fi
    if [[ -n "$token" ]]; then
        echo "    logged in ($token)"
    else
        echo "    NOT LOGGED IN. Run 'semgrep login': the registry serves roughly half"
        echo "    the rules to an anonymous client, and 'make semgrep' requires it."
    fi
elif need pipx; then
    pipx install semgrep
elif need pip3; then
    # --user keeps it out of the system site-packages; pipx is still preferable.
    pip3 install --user semgrep
else
    echo "    NOT INSTALLED and no pipx or pip3 found. 'make sast' cannot run."
    echo "    See https://semgrep.dev/docs/getting-started/"
fi

# Pinned: kani 0.68.0 panics compiling this crate, at kani-compiler/src/intrinsics.rs:243.
# See docs/engineering_decisions/sqlx-0-8-and-rsa-advisory.md.
kani_version="0.67.0"
echo "==> kani $kani_version (formal verification, used by 'make verify')"
if [[ "$(cargo kani --version 2>/dev/null)" == "cargo-kani $kani_version" ]]; then
    echo "    already installed"
else
    binstall kani-verifier --version "$kani_version"
    # kani needs a second step to fetch its solver backend.
    cargo kani setup
fi

echo "==> node"
if [[ -n "${BYRLE_NODE:-}" ]]; then
    echo "    $BYRLE_NODE"
    echo "    Every target that runs a package manager uses it, so they all test against"
    echo "    the same one."
elif need node; then
    echo "    found $(node --version), and no nvm, so that is what the targets use"
else
    echo "    NOT FOUND. 'make smoke-npm' cannot run without it."
fi

echo "==> npm (required by 'make smoke-npm')"
if need npm; then
    echo "    found $(npm --version)"
else
    echo "    NOT FOUND. Install Node.js; 'make smoke-npm' cannot run without it."
fi

# The other package managers, all optional. `make smoke-clients` and `make inspect` cover
# whichever are present and skip the rest. They are worth having: every one of them
# except npm fetches dist.tarball from the host the packument names, which is the whole
# reason the proxy rewrites artifact URLs.
echo "==> pnpm (optional, used by 'make smoke-clients')"
if need pnpm; then echo "    found $(pnpm --version)"; else echo "    not installed"; fi

echo "==> yarn 1 (optional, used by 'make smoke-clients')"
if need yarn; then echo "    found $(yarn --version)"; else echo "    not installed"; fi

echo "==> yarn 2+ (optional, used by 'make smoke-clients')"
if ! need corepack; then
    # Node shipped corepack from 16.9 until it was unbundled in 25, so on a current node
    # it has to be installed. It is how a project selects yarn 2+ without replacing the
    # yarn on PATH.
    # Node shipped corepack from 16.9 until it was unbundled in 25, so a current node
    # needs it installed.
    if ! need npm; then
        echo "    NOT INSTALLED, and no npm to install it with."
    elif npm install -g corepack >/dev/null 2>&1; then
        echo "    installed $(corepack --version 2>/dev/null)"
    else
        # The usual cause is the configured registry, not corepack. Retrying against
        # npmjs says which of the two is broken instead of leaving it ambiguous.
        echo "    install from $(npm config get registry 2>/dev/null) failed"
        if npm install -g corepack --registry https://registry.npmjs.org/ >/dev/null 2>&1; then
            echo "    installed $(corepack --version 2>/dev/null) from registry.npmjs.org instead."
            echo "    Your configured registry rejected the request, which will affect every"
            echo "    other install too. Check its credentials."
        else
            echo "    and so did registry.npmjs.org. 'make smoke-clients' skips yarn 2+"
            echo "    until 'npm install -g corepack' works."
        fi
    fi
elif ! need node; then
    echo "    node not found, so corepack cannot run."
else
    node_major="$(node --version | sed -E 's/^v([0-9]+).*/\1/')"
    if [[ "$node_major" -lt 18 ]]; then
        echo "    corepack found, but node is v$node_major. yarn 2+ needs 18 or later,"
        echo "    and corepack itself calls URL.canParse, which 16 does not have."
        echo "    'make smoke-clients' skips yarn 2+ on this node."
    else
        echo "    corepack $(corepack --version), node v$node_major: available."
        echo "    Nothing to install: a project selects it with a packageManager field,"
        echo "    and 'make smoke-clients' sets that up in a temporary project."
    fi
fi

echo "==> bun (optional, used by 'make smoke-clients')"
if need bun; then
    echo "    found $(bun --version)"
elif need pacman; then
    echo "    install with: sudo pacman -S bun"
elif need brew; then
    brew install oven-sh/bun/bun
elif need npm; then
    npm install -g bun
else
    # Upstream offers `curl ... | bash`. Not run automatically, for the same reason the
    # trufflehog entry above gives: piping a remote script into a shell is the pattern
    # this project exists to distrust.
    echo "    NOT INSTALLED and no package manager found. Install from your distribution,"
    echo "    or review https://bun.sh/install before running it."
fi

# The Python side. `make smoke-python` runs pip, which comes with a venv, and uv, which
# does not. Without uv the run still passes and silently checks one client instead of two,
# which is the failure this file already avoids for shellcheck.
echo "==> python3 (used by 'make smoke-python')"
if need python3; then
    echo "    found $(python3 --version 2>&1 | awk '{print $2}')"
else
    echo "    NOT FOUND. 'make smoke-python' cannot run without it."
fi

echo "==> uv (optional, used by 'make smoke-python')"
if need uv; then
    echo "    found $(uv --version 2>/dev/null | awk '{print $2}')"
elif need pipx; then
    pipx install uv >/dev/null 2>&1 \
        && echo "    installed $(uv --version 2>/dev/null | awk '{print $2}')" \
        || echo "    pipx install uv failed; 'make smoke-python' skips the uv check"
elif need pacman; then
    echo "    install with: sudo pacman -S uv"
elif need brew; then
    brew install uv
else
    # Upstream offers `curl ... | sh`, which this file does not run for the reason the
    # bun entry above gives.
    echo "    NOT INSTALLED and no package manager found. Install from your distribution,"
    echo "    or review https://docs.astral.sh/uv/getting-started/installation/ first."
fi

echo
echo "dev setup complete."
