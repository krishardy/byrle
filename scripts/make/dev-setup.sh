#!/usr/bin/env bash
# Install the development dependencies this project's targets expect.
#
# Deliberately additive and re-runnable: it installs what is missing and leaves
# anything already present alone.
set -euo pipefail

need() { command -v "$1" >/dev/null 2>&1; }

echo "==> rustup components"
rustup component add clippy rustfmt 2>&1 | sed 's/^/    /'

echo "==> cargo-audit (dependency advisories; used when re-running the config spike)"
if cargo audit --version >/dev/null 2>&1; then
    echo "    already installed"
else
    cargo install cargo-audit --locked
fi

echo "==> cargo-outdated (dependency freshness, used by 'make check-deps')"
if cargo outdated --version >/dev/null 2>&1; then
    echo "    already installed"
else
    cargo install cargo-outdated --locked
fi

echo "==> cargo-llvm-cov (unit test coverage, used by 'make coverage')"
if cargo llvm-cov --version >/dev/null 2>&1; then
    echo "    already installed"
else
    # It reads the instrumentation rustc emits, so the matching llvm-tools component
    # has to be there as well.
    rustup component add llvm-tools-preview 2>&1 | sed 's/^/    /'
    cargo install cargo-llvm-cov --locked
fi

echo "==> trufflehog (credential scanning, used by 'make sast')"
if need trufflehog; then
    echo "    found $(trufflehog --version 2>&1 | head -1)"
elif need brew; then
    brew install trufflehog
elif need go; then
    go install github.com/trufflesecurity/trufflehog/v3@latest
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

echo "==> kani (formal verification, used by 'make verify')"
if cargo kani --version >/dev/null 2>&1; then
    echo "    already installed"
else
    cargo install --locked kani-verifier
    # kani needs a second step to fetch its solver backend.
    cargo kani setup
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
    echo "    corepack not found. It ships with Node 16.9 and later, and is how a"
    echo "    project selects yarn 2+ without replacing the yarn on PATH."
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

echo
echo "dev setup complete."
