#!/usr/bin/env bash
# End-to-end check of the proxy against real Python dependency managers.
#
# The npm counterpart is `smoke-npm.sh`; this is the PyPI half of the same question, and
# it exists for the same reason: Stage 3's exit criterion is stated in terms of real
# client behavior, so it has to be checked with a real client.
#
# Asserts, in order:
#   1. a plain pip install completes through the proxy
#   2. every installed distribution, transitive ones included, was fetched through us
#   3. every one of them was normalized to a PURL, at the version on disk
#   4. every file's digest was known before the fetch and verified on the way past
#   5. one version's wheel and sdist get different answers under `install_scripts: block`
#   6. uv, which has its own resolver, installs and verifies the same way
#   7. `install_scripts: block` refuses docopt 0.6.2, sdist only, and `allow` installs it
#   8. test-eicar 0.1.0, which holds the EICAR test string, is served and verified
# The packages in 7 and 8 are in docs/engineering_decisions/live-test-packages.md. No PyPI
# project still exists that a MAL record covers, so `known_malware` is not run here.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/make/lib/python.sh
. "$repo_root/scripts/make/lib/python.sh"

port="${WAHAROA_PORT:-8734}"
index="http://127.0.0.1:${port}/simple/"
workdir="$(mktemp -d)"
log="$workdir/proxy.log"
clean_log="$workdir/clean.log"
proxy_pid=""

cleanup() {
    [[ -n "$proxy_pid" ]] && kill "$proxy_pid" 2>/dev/null || true
    rm -rf "$workdir"
}
trap cleanup EXIT

command -v python3 >/dev/null || { echo "python3 is required for this check"; exit 1; }

if ss -ltn 2>/dev/null | grep -q ":${port} "; then
    echo "port ${port} is already in use; set WAHAROA_PORT to something free"
    exit 1
fi

fail() { echo "FAIL: $*"; echo "--- proxy log ---"; cat "$log"; exit 1; }

# A rewritten index is the whole point: pip and uv both use each file's `url` as written,
# so without a public base the files are fetched from files.pythonhosted.org and nothing
# about them is observed.
start_proxy() {
    WAHAROA_SPOOL_DIR="$workdir/spool" WAHAROA_LISTEN="127.0.0.1:${port}" \
    WAHAROA_PUBLIC_URL="http://127.0.0.1:${port}" \
    WAHAROA_POLICY="${1:-}" \
        cargo run --quiet --manifest-path "$repo_root/Cargo.toml" -- daemon >"$log" 2>&1 &
    proxy_pid=$!
    for _ in $(seq 1 60); do
        grep -q "waharoa listening" "$log" && return 0
        kill -0 "$proxy_pid" 2>/dev/null || fail "proxy exited during startup"
        sleep 1
    done
    fail "proxy did not start within 60s"
}

stop_proxy() {
    [[ -n "$proxy_pid" ]] && kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
    proxy_pid=""
}

clean() { sed -E 's/\x1b\[[0-9;]*m//g' "$log" >"$clean_log"; }
count() { grep -c "$1" "$clean_log" || true; }

# scripts/make/lib/python.sh says why each flag is there.
pip_install() {
    local dir="$1"; shift
    local cmd
    mapfile -t cmd < <(waharoa_pip_command "$dir/venv" "$index" --quiet "$@")
    "${cmd[@]}"
}

make_venv() {
    local dir="$1"
    mkdir -p "$dir"
    python3 -m venv "$dir/venv" >/dev/null 2>&1 || fail "could not create a venv in $dir"
}

# What is installed, as purls. `pip` and `setuptools` come with the venv and were never
# fetched, so they are not part of the question.
installed_purls() {
    "$1/venv/bin/python" - <<'PY'
import importlib.metadata as md, re
builtin = {"pip", "setuptools", "wheel", "uv"}
for dist in md.distributions():
    name = dist.metadata["Name"]
    if name is None:
        continue
    normalised = re.sub(r"[-_.]+", "-", name).lower()
    if normalised in builtin:
        continue
    print(f"pkg:pypi/{normalised}@{dist.version}")
PY
}

echo "==> 1/8  install completes through the proxy"
start_proxy ""
make_venv "$workdir/basic"
pip_install "$workdir/basic" requests || fail "pip install requests failed"
installed_purls "$workdir/basic" | grep -q '^pkg:pypi/requests@' \
    || fail "requests was not installed"
echo "    ok"

echo "==> 2/8  every distribution, transitive included, came through the proxy"
clean
on_disk="$(installed_purls "$workdir/basic" | sed 's|^pkg:pypi/||; s|@.*||' | sort -u)"
# The index page the resolver read, which is the normalised project name in the path.
# `|| true` on every one of these: under `set -e` a grep that matches nothing exits 1
# and kills the script with no diagnosis, which is the case each check exists to report.
indexed="$(grep -oE 'simple index normalized url.path=/simple/[^/ ]+' "$clean_log" \
    | sed -E 's|.*/simple/||' | sort -u || true)"
missed="$(comm -23 <(echo "$on_disk") <(echo "$indexed") || true)"
[[ -z "$missed" ]] || fail "these projects never had an index read: $(echo "$missed" | tr '\n' ' ')"
echo "    ok ($(echo "$on_disk" | wc -l) projects, all intercepted)"

echo "==> 3/8  every installed distribution was normalized to a PURL at the version on disk"
expected_purls="$(installed_purls "$workdir/basic" | sort -u)"
[[ -n "$expected_purls" ]] || fail "could not read any installed versions"
observed_purls="$(grep -oE 'waharoa.package.claimed_purl=[^ ]+' "$clean_log" | cut -d= -f2- | sort -u || true)"
unnormalized="$(comm -23 <(echo "$expected_purls") <(echo "$observed_purls") || true)"
[[ -z "$unnormalized" ]] \
    || fail "installed but never normalized to a purl: $(echo "$unnormalized" | tr '\n' ' ')"

# A skipped version is a shape the normalizer cannot read.
if grep -oE 'simple index normalized.*skipped=[0-9]+' "$clean_log" | grep -qv 'skipped=0'; then
    fail "an index had versions the normalizer could not read:
$(grep -E 'simple index normalized.*skipped=[0-9]+' "$clean_log" | grep -v 'skipped=0')"
fi
indexes="$(count 'simple index normalized')"
echo "    ok ($(echo "$expected_purls" | wc -l) purls, $indexes indexes, 0 versions skipped)"

# A file nothing has analysed is deferred with a 503 until its analysis has finished, and
# served on the client's retry. Every request logs `artifact requested`; only the served
# one is a file fetched.
DEFERRED='deferred: the artifact has not been analysed'
served() {
    echo "$(( $(count 'artifact requested') - $(count "$DEFERRED") ))"
}

echo "==> 4/8  every file digest was known before the fetch and verified"
deferred="$(count "$DEFERRED")"
known="$(( $(count 'digest known') - deferred ))"
verified="$(count 'artifact digest verified')"
files="$(served)"
[[ "$files" -gt 0 ]] || fail "no files were fetched through the proxy"
[[ "$known" -eq "$files" ]] \
    || fail "$files files fetched but only $known had a digest from their index"
[[ "$verified" -eq "$files" ]] \
    || fail "$files files fetched but only $verified were verified"
if grep -q 'MISMATCH' "$clean_log"; then
    fail "a file did not match the digest its index published:
$(grep 'MISMATCH' "$clean_log")"
fi
if grep -q 'not served' "$clean_log"; then
    fail "a file could not be assessed:
$(grep 'not served' "$clean_log")"
fi
# A rewritten index is what makes the above possible. Nothing may be left pointing away.
if grep -qE 'simple index rewritten.*waharoa.package.left_alone_files=[1-9]' "$clean_log"; then
    fail "an index kept files on an origin the proxy does not front:
$(grep -E 'simple index rewritten.*waharoa.package.left_alone_files=[1-9]' "$clean_log")"
fi
echo "    ok ($files files, all with a known digest, all verified, none left offsite, $deferred deferred for analysis)"
stop_proxy

echo "==> 5/8  one version's wheel and sdist get different answers"
# A PyPI version is several files. `idna` 3.20 ships a wheel and an sdist; installing the
# wheel runs nothing and installing the sdist runs setup.py, so a policy that blocks
# install scripts has to answer them differently. The version-level record says false,
# because a resolver that can take the wheel will.
#
# Pinned, because the assertions below name the files. Without the pin this check read
# `idna-3.19.tar.gz` and pip installed 3.20 the day it was published.
idna="3.20"
cat >"$workdir/scripts.yaml" <<'YAML'
version: 1
cooldown_days: 0
install_scripts: block
YAML
start_proxy "$workdir/scripts.yaml"

make_venv "$workdir/sdist"
set +e
pip_install "$workdir/sdist" --no-binary :all: "idna==$idna" >"$workdir/sdist.out" 2>&1
sdist_status=$?
set -e
[[ "$sdist_status" -ne 0 ]] || fail "the sdist installed although install scripts are blocked"
grep -q '403' "$workdir/sdist.out" \
    || fail "the sdist install failed for some reason other than a refusal:
$(cat "$workdir/sdist.out")"

make_venv "$workdir/wheel"
pip_install "$workdir/wheel" "idna==$idna" \
    || fail "the wheel of the same version was refused too"

clean
grep -qE "refused by policy.*idna-$idna\.tar\.gz" "$clean_log" \
    || fail "the refusal does not name the sdist it refused"
grep -qE "refused by policy.*idna-$idna-py3-none-any\.whl" "$clean_log" \
    && fail "the wheel was refused; only the sdist runs the package's own code"
grep -qE "proxied.*idna-$idna-py3-none-any\.whl http.response.status_code=200" "$clean_log" \
    || fail "the wheel was not served"
if grep -qE "proxied.*idna-$idna\.tar\.gz http.response.status_code=200" "$clean_log"; then
    fail "the refused sdist was fetched upstream; the refusal came too late"
fi
echo "    ok (sdist refused 403, wheel of the same version served, sdist never fetched)"
stop_proxy

echo "==> 6/8  uv, with its own resolver, installs and verifies the same way"
if ! command -v uv >/dev/null; then
    echo "    skipped (uv is not installed)"
else
    start_proxy ""
    mkdir -p "$workdir/uv"
    uv venv -q "$workdir/uv/venv" >/dev/null 2>&1 || fail "uv could not create a venv"
    mapfile -t uv_cmd < <(waharoa_uv_command "$workdir/uv/venv" "$index" --quiet requests)
    "${uv_cmd[@]}" || fail "uv pip install requests failed"

    clean
    uv_files="$(served)"
    uv_verified="$(count 'artifact digest verified')"
    [[ "$uv_files" -gt 0 ]] || fail "uv fetched no files through the proxy"
    [[ "$uv_verified" -eq "$uv_files" ]] \
        || fail "uv fetched $uv_files files but only $uv_verified were verified"
    grep -q 'user_agent.original=uv/' "$clean_log" || fail "uv did not identify itself to the proxy"
    echo "    ok ($uv_files files, all verified, client=$(grep -oE 'user_agent.original=uv/[^ ]+' "$clean_log" | head -1 | cut -d= -f2))"
    stop_proxy
fi

echo "==> 7/8  install_scripts refuses a version offering only an sdist, and allow installs it"
docopt_file="/packages/a2/55/8f8cab2afd404cf578136ef2cc5dfb50baa1761b68c9da1fb1e4eed343c9/docopt-0.6.2.tar.gz"
printf 'version: 1\ncooldown_days: 0\ninstall_scripts: %s\n' block >"$workdir/block.yaml"
printf 'version: 1\ncooldown_days: 0\ninstall_scripts: %s\n' allow >"$workdir/allow.yaml"
start_proxy "$workdir/block.yaml"
status=$(curl -s -o "$workdir/docopt.json" -w '%{http_code}' \
    -H 'Accept: application/vnd.pypi.simple.v1+json' "${index}docopt/")
[[ "$status" == "200" ]] || fail "the docopt index answered $status; it has to be a 200"
if python3 -c "import json,sys; sys.exit(0 if any(f['filename'] == 'docopt-0.6.2.tar.gz' for f in json.load(open(sys.argv[1]))['files']) else 1)" \
    "$workdir/docopt.json"; then
    fail "docopt 0.6.2 is still offered, so pip can still pick it"
fi
status=$(curl -s -o "$workdir/docopt.out" -w '%{http_code}' "http://127.0.0.1:${port}${docopt_file}")
[[ "$status" == "403" ]] || fail "a pinned fetch of docopt-0.6.2.tar.gz answered $status"
grep -q install_scripts "$workdir/docopt.out" || fail "the refusal of docopt does not name install_scripts"
clean
if grep -qE "proxied.*docopt-0\.6\.2\.tar\.gz http.response.status_code=200" "$clean_log"; then
    fail "the refused sdist was fetched upstream"
fi
stop_proxy
start_proxy "$workdir/allow.yaml"
make_venv "$workdir/docopt"
pip_install "$workdir/docopt" "docopt==0.6.2" || fail "docopt 0.6.2 was not installed under allow"
installed_purls "$workdir/docopt" | grep -q '^pkg:pypi/docopt@0.6.2$' || fail "docopt was not installed"
echo "    ok (block: filtered and 403; allow: built and installed)"
stop_proxy

echo "==> 8/8  a package holding the EICAR test string is served and verified"
start_proxy ""
make_venv "$workdir/eicar"
pip_install "$workdir/eicar" "test-eicar==0.1.0" || fail "pip install test-eicar failed"
grep -rq 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' "$workdir/eicar/venv/lib" \
    || fail "the installed test-eicar does not hold the EICAR string"
clean
grep -q 'artifact digest verified.*pkg:pypi/test-eicar@0.1.0' "$clean_log" \
    || fail "the test-eicar wheel was not verified"
echo "    ok (installed, digest verified)"
stop_proxy

echo
echo "PASS: the proxy serves PyPI as Stage 3 requires."
