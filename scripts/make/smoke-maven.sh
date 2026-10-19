#!/usr/bin/env bash
# End-to-end check of the proxy against real mvn and Gradle, behind nginx on TLS. See
# docs/maven-plan.md, step 8.
#
# Asserts, in order:
#   1. mvn resolves commons-lang3 through the proxy, run again after a first fetch the
#      proxy answers 503, and its jar is verified
#   2. a denial of commons-lang3's newest version: a range resolves an older one, it is
#      left out of maven-metadata.xml, and its jar answers 403
#   3. a cooldown covering commons-lang3's newest version resolves an older one
#   4. ./gradlew, with an init script, resolves a plugin from the portal and
#      commons-lang3 from Central through the proxy, the plugin's dropped signature
#      weighed under the threshold, and refused naming provenance once weighed at it;
#      doctor finds the init script and the wrapper's jar and distribution checked
#   5. install_scripts refuses lombok, an annotation processor, and Gradle compiles with
#      it under allow
#   6. with Postgres, after a refresh: commons-text 1.9, which osv/maven scores over
#      max_cvss, answers 403 naming it, and 1.10.0 is served
#   7. with tokens required, a request without one is 401; mvn sends one from <server>,
#      Gradle from credentials { }, and ./mvnw from MVNW_USERNAME and MVNW_PASSWORD
# Steps 1 to 5 run with no Postgres, and so with BYRLE_REQUIRE_TOKEN=0. Each mvn run has
# its own local repository, and Gradle a user home of its own, so this user's settings are
# not read. Gradle is run with --refresh-dependencies, so its cache answers nothing.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/make/lib/recognised.sh
. "$repo_root/scripts/make/lib/recognised.sh"
# shellcheck source=scripts/make/lib/postgres.sh
. "$repo_root/scripts/make/lib/postgres.sh"
# shellcheck source=scripts/make/lib/token.sh
. "$repo_root/scripts/make/lib/token.sh"
# shellcheck source=scripts/make/lib/tls_front.sh
. "$repo_root/scripts/make/lib/tls_front.sh"
# shellcheck source=scripts/make/lib/port.sh
. "$repo_root/scripts/make/lib/port.sh"
# shellcheck source=scripts/make/lib/cooldown.sh
. "$repo_root/scripts/make/lib/cooldown.sh"
# shellcheck source=scripts/make/lib/gradle.sh
. "$repo_root/scripts/make/lib/gradle.sh"

port="${BYRLE_PORT:-8740}"
front_port="${BYRLE_FRONT_PORT:-8741}"
base="http://127.0.0.1:${port}"
front="https://localhost:${front_port}"
workdir="$(mktemp -d)"
log="$workdir/proxy.log"
proxy_pid=""
front_pid=""
database_url=""
require_token=0
account=""
token=""
rp_key="$(openssl rand -hex 32)"
central="https://repo.maven.apache.org/maven2"
lang3="org/apache/commons/commons-lang3"

cleanup() {
    if [[ -n "$proxy_pid" ]]; then kill "$proxy_pid" 2>/dev/null || true; fi
    if [[ -n "$front_pid" ]]; then kill "$front_pid" 2>/dev/null || true; fi
    rm -rf "$workdir"
}
trap cleanup EXIT

for needed in java keytool mvn gradle nginx openssl; do
    if ! command -v "$needed" >/dev/null 2>&1; then
        echo "FAIL: $needed is not on PATH. Run 'make dev-setup'."
        exit 1
    fi
done
for taken in "$port" "$front_port"; do
    if port_taken "$taken" >/dev/null; then
        echo "port ${taken} is already in use; set BYRLE_PORT and BYRLE_FRONT_PORT to free ones"
        exit 1
    fi
done

# On stderr, as a failure inside `$(...)` is otherwise captured.
fail() { { echo "FAIL: $*"; echo "--- proxy log ---"; cat "$log"; } >&2; exit 1; }

make_certificates "$workdir"
mkdir -p "$workdir/nginx"
nginx_conf "$front_port" "$workdir/nginx" "$workdir" "$port" "$rp_key" >"$workdir/nginx/nginx.conf"
nginx -p "$workdir/nginx" -c "$workdir/nginx/nginx.conf" -g 'daemon off;' \
    >"$workdir/nginx/front.log" 2>&1 &
front_pid=$!

# Java trusts the JDK's CAs and the test CA from this store, and reaches the proxy directly.
java_home="$(java -XshowSettings:properties -version 2>&1 | sed -n 's/^ *java.home = //p')"
cp "$java_home/lib/security/cacerts" "$workdir/trust.p12"
chmod u+w "$workdir/trust.p12"
keytool -importcert -noprompt -alias byrle-test -file "$workdir/ca.pem" \
    -keystore "$workdir/trust.p12" -storepass changeit >/dev/null 2>&1
trust="-Djavax.net.ssl.trustStore=$workdir/trust.p12 -Djavax.net.ssl.trustStorePassword=changeit"
trust+=" -Dhttp.nonProxyHosts=localhost|127.0.0.1"
# ./gradlew downloads its distribution from services.gradle.org itself, through the
# forward proxy the environment names, when it names one.
forward="${HTTPS_PROXY:-${https_proxy:-}}"
jvm_proxy=""
if [[ -n "$forward" ]]; then
    hostport="${forward#*://}"
    hostport="${hostport%%/*}"
    jvm_proxy="-Dhttps.proxyHost=${hostport%:*} -Dhttps.proxyPort=${hostport##*:}"
fi
export NO_PROXY="localhost,127.0.0.1${NO_PROXY:+,$NO_PROXY}"

start_proxy() {
    BYRLE_SPOOL_DIR="$workdir/spool" BYRLE_LISTEN="127.0.0.1:${port}" BYRLE_RP_KEY="$rp_key" \
    BYRLE_PROXY_URL="$front" BYRLE_POLICY="${1:-}" \
    BYRLE_DATABASE_URL="$database_url" BYRLE_REQUIRE_TOKEN="$require_token" \
        cargo run --quiet --manifest-path "$repo_root/Cargo.toml" -- daemon >"$log" 2>&1 &
    proxy_pid=$!
    for _ in $(seq 1 60); do
        grep -q "byrle listening" "$log" && return 0
        kill -0 "$proxy_pid" 2>/dev/null || fail "proxy exited during startup"
        sleep 1
    done
    fail "proxy did not start within 60s"
}

stop_proxy() {
    if [[ -n "$proxy_pid" ]]; then kill "$proxy_pid" 2>/dev/null || true; fi
    wait "$proxy_pid" 2>/dev/null || true
    proxy_pid=""
    recognised "$log"
}

clean_log() { sed -E 's/\x1b\[[0-9;]*m//g' "$log"; }

# Whether the proxy log has a line matching $1. Not `clean_log | grep -q`: under pipefail
# that fails when grep stops at its match while sed is still writing.
logged() { grep -q -- "$1" < <(clean_log); }

# A Maven project in $1 depending on commons-lang3 at version or range $2, with mvn's
# settings beside it: every repository mirrored to the proxy, with a <server> when a
# token is set.
pom() {
    local dir="$1" version="$2" server=""
    rm -rf "$dir"
    mkdir -p "$dir"
    printf '<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>example.test</groupId><artifactId>probe</artifactId><version>0.1.0</version>
<dependencies><dependency><groupId>org.apache.commons</groupId>
<artifactId>commons-lang3</artifactId><version>%s</version></dependency></dependencies>
</project>\n' "$version" >"$dir/pom.xml"
    if [[ -n "$token" ]]; then
        server="<servers><server><id>byrle</id><username>$account</username><password>$token</password></server></servers>"
    fi
    printf '<settings><mirrors><mirror><id>byrle</id><mirrorOf>*</mirrorOf><url>%s/maven</url></mirror></mirrors>%s</settings>\n' \
        "$front" "$server" >"$dir/settings.xml"
}

# mvn $2... in project $1, with its own settings and local repository.
mvn_in() {
    local dir="$1"
    shift
    (cd "$dir" && MAVEN_OPTS="$trust" MAVEN_ARGS="" timeout 900 mvn -B -s "$dir/settings.xml" \
        -Dmaven.repo.local="$dir/repo" "$@")
}

# mvn_in $1 $2..., run again with -U while it fails on a 503 from the proxy, as mvn records
# a failed fetch and does not ask again without it. Prints how many runs it took.
mvn_retried() {
    local dir="$1" runs
    shift
    for runs in $(seq 1 20); do
        if mvn_in "$dir" -U "$@" >"$workdir/mvn.out" 2>&1; then
            echo "$runs"
            return 0
        fi
        grep -q "503" "$workdir/mvn.out" || fail "mvn $* failed: $(grep ERROR "$workdir/mvn.out" | head -5)"
        sleep 2
    done
    fail "mvn $* still answered 503 after $runs runs"
}

# The commons-lang3 version mvn resolves in project $1.
resolved() {
    mvn_retried "$1" dependency:resolve >/dev/null
    grep -o 'org.apache.commons:commons-lang3:jar:[^:]*' "$workdir/mvn.out" | head -1 | cut -d: -f4
}

# One Gradle user home for every project, so ./gradlew downloads its distribution once.
gradle_home="$workdir/gradle-home"
mkdir -p "$gradle_home/init.d"
for property in $trust $jvm_proxy; do
    printf 'systemProp.%s\n' "${property#-D}"
done >"$gradle_home/gradle.properties"

# A Gradle project in $1 using the portal's versions plugin and commons-lang3, with
# lombok as an annotation processor when $2 is `lombok`, and a wrapper of the installed
# Gradle with its distribution's sha256 pinned. The user home's init script replaces
# every repository with the proxy's, with credentials when a token is set.
gradle_project() {
    local dir="$1" lombok="${2:-}" processor="" credentials=""
    rm -rf "$dir" "$gradle_home/init.d/byrle.gradle"
    mkdir -p "$dir/src/main/java/probe"
    printf "rootProject.name = 'probe'\n" >"$dir/settings.gradle"
    # Before the build script, whose plugin the wrapper task would otherwise resolve.
    (cd "$dir" && GRADLE_USER_HOME="$gradle_home" gradle --no-daemon -q wrapper \
        --gradle-version "$gradle_version" >"$workdir/wrapper.out" 2>&1) \
        || fail "gradle wrapper failed: $(tail -5 "$workdir/wrapper.out")"
    printf 'distributionSha256Sum=%s\n' "$gradle_sha256" \
        >>"$dir/gradle/wrapper/gradle-wrapper.properties"
    if [[ "$lombok" == lombok ]]; then
        processor="compileOnly 'org.projectlombok:lombok:1.18.42'
    annotationProcessor 'org.projectlombok:lombok:1.18.42'"
        printf 'package probe;\n@lombok.Value public class Point { int x; }\n' \
            >"$dir/src/main/java/probe/Point.java"
    fi
    printf "plugins {
    id 'java'
    id 'com.github.ben-manes.versions' version '0.52.0'
}
repositories { mavenCentral() }
dependencies {
    implementation 'org.apache.commons:commons-lang3:3.17.0'
    %s
}
tasks.register('resolve') {
    def cp = configurations.runtimeClasspath
    doLast { cp.files.each { println it.name } }
}
" "$processor" >"$dir/build.gradle"
    if [[ -n "$token" ]]; then
        credentials="credentials { username = '$account'; password = '$token' }"
    fi
    printf "def central = '%s/maven/'
def portal = '%s/gradle-plugins/'
def only = { RepositoryHandler repos, String mirror ->
    repos.all { ArtifactRepository repo ->
        if (!(repo instanceof MavenArtifactRepository) || !repo.url.toString().startsWith(mirror)) {
            repos.remove(repo)
        }
    }
    repos.maven { url = mirror; %s }
}
beforeSettings { settings ->
    settings.pluginManagement.repositories { only(delegate, portal) }
}
allprojects {
    buildscript { only(repositories, portal) }
    only(repositories, central)
}
" "$front" "$front" "$credentials" >"$gradle_home/init.d/byrle.gradle"
}

# ./gradlew $2... in project $1, run again while it fails on a 503 from the proxy.
gradlew_retried() {
    local dir="$1" runs
    shift
    for runs in $(seq 1 20); do
        if (cd "$dir" && GRADLE_USER_HOME="$gradle_home" timeout 900 ./gradlew --no-daemon \
            --refresh-dependencies "$@" >"$workdir/gradle.out" 2>&1); then
            echo "$runs"
            return 0
        fi
        grep -q "503" "$workdir/gradle.out" \
            || fail "./gradlew $* failed: $(grep -v '^\s*at ' "$workdir/gradle.out" | head -8)"
        sleep 2
    done
    fail "./gradlew $* still answered 503 after $runs runs"
}

# The status the proxy answers for path $1, once it stops deferring it with 503.
fetched() {
    local status
    for _ in $(seq 1 120); do
        status="$(curl -s --noproxy '*' --cacert "$workdir/ca.pem" -o "$workdir/fetched.out" \
            -w '%{http_code}' ${token:+-u "$account:$token"} "$front$1")"
        [[ "$status" == "503" ]] || break
        sleep 1
    done
    echo "$status"
}

# commons-lang3's newest release on Central, and when its .pom was last modified.
newest="$(curl -sf "$central/$lang3/maven-metadata.xml" \
    | sed -n 's:.*<release>\(.*\)</release>.*:\1:p')"
[[ -n "$newest" ]] || fail "Central's maven-metadata.xml for commons-lang3 names no release"
published="$(curl -sfI "$central/$lang3/$newest/commons-lang3-$newest.pom" | python3 -I -c '
import sys, email.utils
for line in sys.stdin:
    name, _, value = line.partition(":")
    if name.lower() == "last-modified":
        print(email.utils.parsedate_to_datetime(value.strip()).isoformat())')"
[[ -n "$published" ]] || fail "Central sent no Last-Modified for commons-lang3 $newest"
lang3_age="$(cooldown_covering "$published")"
# gradle-versions-plugin 0.52.0 is unsigned after a signed 0.11.1. No earlier version is in
# its line, 0.52, so it weighs provenance_dropped alone, half the threshold.
plugin="com/github/ben-manes/gradle-versions-plugin/0.52.0/gradle-versions-plugin-0.52.0.jar"
printf 'version: 1\ncooldown_days: 0\n' >"$workdir/default.yaml"
printf 'version: 1\ncooldown_days: 0\nsignal_weights: { provenance_dropped: 100 }\n' \
    >"$workdir/dropped.yaml"
printf 'version: 1\ncooldown_days: 0\ninstall_scripts: allow\n' >"$workdir/allow.yaml"

echo "==> 1/7  mvn resolves through the proxy on TLS, each 503 run again, the jar verified"
start_proxy "$workdir/default.yaml"
pom "$workdir/build" 3.17.0
runs="$(mvn_retried "$workdir/build" dependency:resolve)"
[[ -f "$workdir/build/repo/$lang3/3.17.0/commons-lang3-3.17.0.jar" ]] \
    || fail "commons-lang3 3.17.0's jar is not in the local repository"
logged "artifact digest verified.*pkg:maven/org.apache.commons/commons-lang3@3.17.0" \
    || fail "commons-lang3 3.17.0's jar was not verified through the proxy"
jars="$(grep -c "artifact digest verified" < <(clean_log))"
echo "    ok ($jars files verified, in $runs runs of mvn)"
stop_proxy

echo "==> 2/7  a denied version is not resolved, and its jar is 403"
printf 'version: 1\ncooldown_days: 0\ndenials:\n  - purl: pkg:maven/org.apache.commons/commons-lang3@%s\n    reason: smoke-maven\n' \
    "$newest" >"$workdir/deny.yaml"
start_proxy "$workdir/deny.yaml"
pom "$workdir/deny" "[3.0,)"
denied_to="$(resolved "$workdir/deny")"
[[ -n "$denied_to" && "$denied_to" != "$newest" ]] \
    || fail "commons-lang3 resolved to $denied_to under a denial of $newest"
[[ "$(fetched "/maven/$lang3/maven-metadata.xml")" == "200" ]] || fail "the metadata was not served"
if grep -q "<version>$newest</version>" "$workdir/fetched.out"; then
    fail "maven-metadata.xml still lists the denied $newest"
fi
[[ "$(fetched "/maven/$lang3/$newest/commons-lang3-$newest.jar")" == "403" ]] \
    || fail "the jar of commons-lang3 $newest was not refused"
echo "    ok (the range resolved $denied_to; $newest left out of the metadata, its jar 403)"
stop_proxy

echo "==> 3/7  a cooldown covering commons-lang3's newest version resolves an older one"
printf 'version: 1\ncooldown_days: %s\n' "$lang3_age" >"$workdir/cooldown.yaml"
start_proxy "$workdir/cooldown.yaml"
pom "$workdir/cooldown" "[3.0,)"
cooled_to="$(resolved "$workdir/cooldown")"
[[ -n "$cooled_to" && "$cooled_to" != "$newest" ]] \
    || fail "commons-lang3 resolved to $cooled_to under cooldown_days: $lang3_age"
echo "    ok (cooldown_days: $lang3_age; resolved $cooled_to, not $newest)"
stop_proxy

echo "==> 4/7  ./gradlew resolves a portal plugin and Central's jars through the init script"
start_proxy "$workdir/dropped.yaml"
[[ "$(fetched "/gradle-plugins/$plugin")" == "403" ]] \
    || fail "gradle-versions-plugin 0.52.0 was not refused with provenance_dropped at 100"
grep -q "provenance" "$workdir/fetched.out" \
    || fail "the refusal of gradle-versions-plugin 0.52.0 does not name provenance"
stop_proxy
start_proxy "$workdir/default.yaml"
gradle_project "$workdir/gradle"
runs="$(gradlew_retried "$workdir/gradle" -q resolve)"
grep -qx "commons-lang3-3.17.0.jar" "$workdir/gradle.out" \
    || fail "./gradlew resolve printed $(head -5 "$workdir/gradle.out")"
logged "artifact digest verified.*pkg:maven/com.github.ben-manes/gradle-versions-plugin@0.52.0" \
    || fail "the portal's gradle-versions-plugin 0.52.0 was not verified through the proxy"
(cd "$workdir/gradle" && GRADLE_USER_HOME="$gradle_home" BYRLE_PROXY_URL="$front" \
    cargo run --quiet --manifest-path "$repo_root/Cargo.toml" -- doctor >"$workdir/doctor.out" 2>&1) || true
for line in "ok  gradle registry: $front/maven/" "ok  gradle extra indexes: none" \
    "ok  gradle wrapper jar: Gradle $gradle_version's" "ok  gradle distribution: distributionSha256Sum is"; do
    grep -qF "$line" "$workdir/doctor.out" || fail "doctor did not report \"$line\":
$(grep gradle "$workdir/doctor.out")"
done
echo "    ok (the plugin 403 naming provenance at 100, then resolved by default in $runs runs;"
echo "       doctor read the init script and the wrapper)"
stop_proxy

echo "==> 5/7  install_scripts refuses lombok, an annotation processor, and allow compiles it"
start_proxy "$workdir/default.yaml"
[[ "$(fetched /maven/org/projectlombok/lombok/1.18.42/lombok-1.18.42.jar)" == "403" ]] \
    || fail "lombok 1.18.42 was not refused"
grep -q "install_scripts" "$workdir/fetched.out" || fail "the refusal of lombok does not name install_scripts"
gradle_project "$workdir/blocked" lombok
if (cd "$workdir/blocked" && GRADLE_USER_HOME="$gradle_home" timeout 900 ./gradlew \
    --no-daemon -q compileJava >"$workdir/gradle.out" 2>&1); then
    fail "Gradle compiled with lombok under install_scripts: block"
fi
stop_proxy
start_proxy "$workdir/allow.yaml"
gradle_project "$workdir/allowed" lombok
gradlew_retried "$workdir/allowed" -q compileJava >/dev/null
[[ -f "$workdir/allowed/build/classes/java/main/probe/Point.class" ]] || fail "Point was not compiled"
echo "    ok (lombok 403 naming install_scripts; compiled under allow)"
stop_proxy

echo "==> 6/7  an osv/maven advisory over max_cvss is refused, and the fix is served"
if ! choose_postgres >/dev/null; then
    echo "    skipped (neither docker nor initdb and pg_ctl are available)"
    echo "==> 7/7  skipped (no Postgres to keep the accounts and tokens in)"
    recognised "$log"
    echo "PASS: the proxy serves Maven, without the steps that need Postgres."
    exit 0
fi
pg_port="${BYRLE_PG_PORT:-55440}"
start_postgres "byrle-smoke-maven-pg-$$" "$pg_port" || fail "postgres did not start"
trap 'stop_postgres; cleanup' EXIT
database_url="$(postgres_url "$pg_port")"
# Exit 1 is an optional stream that did not load, such as GitHub's without a token.
set +e
BYRLE_DATABASE_URL="$database_url" cargo run --quiet --manifest-path "$repo_root/Cargo.toml" \
    -- refresh >"$workdir/refresh.out" 2>&1
refresh_status=$?
set -e
[[ "$refresh_status" -le 1 ]] || fail "byrle refresh exited $refresh_status:
$(tail -20 "$workdir/refresh.out")"
start_proxy "$workdir/default.yaml"
ready=$(curl -s -o /dev/null -w '%{http_code}' "$base/-/byrle/ready")
[[ "$ready" == "200" ]] || fail "the proxy is not ready after the refresh ($ready)"
text="org/apache/commons/commons-text"
[[ "$(fetched "/maven/$text/1.9/commons-text-1.9.jar")" == "403" ]] \
    || fail "the jar of commons-text 1.9 was not refused"
grep -q "max_cvss" "$workdir/fetched.out" || fail "the refusal of commons-text 1.9 does not name max_cvss"
[[ "$(fetched "/maven/$text/1.10.0/commons-text-1.10.0.jar")" == "200" ]] \
    || fail "commons-text 1.10.0 was not served"
echo "    ok (1.9 is 403 naming max_cvss; 1.10.0 served)"
stop_proxy

echo "==> 7/7  a token is required, and mvn, Gradle and ./mvnw send it"
# maven-dependency-plugin 3.11.0 depends on commons-beanutils 1.9.4, over the default
# max_cvss once advisories are loaded.
printf 'version: 1\ncooldown_days: 0\nmax_cvss: 10\n' >"$workdir/token.yaml"
account=smoke-maven
issued="$(issue_token "$database_url" "$account")"
require_token=1
start_proxy "$workdir/token.yaml"
assert_unauthorized "$base/maven/$lang3/maven-metadata.xml"
pom "$workdir/no-token" 3.17.0
if mvn_in "$workdir/no-token" dependency:resolve >"$workdir/mvn.out" 2>&1; then
    fail "mvn resolved without a token"
fi
token="$issued"
pom "$workdir/token" 3.17.0
mvn_retried "$workdir/token" dependency:resolve >/dev/null
gradle_project "$workdir/gradle-token"
gradlew_retried "$workdir/gradle-token" -q resolve >/dev/null
mvn_retried "$workdir/token" -N wrapper:wrapper >/dev/null
grep -q "^distributionUrl=$front/maven/org/apache/maven/apache-maven/" \
    "$workdir/token/.mvn/wrapper/maven-wrapper.properties" \
    || fail "mvn wrote $(grep distributionUrl "$workdir/token/.mvn/wrapper/maven-wrapper.properties")"
for _ in $(seq 1 20); do
    if (cd "$workdir/token" && MVNW_USERNAME="$account" MVNW_PASSWORD="$token" \
        MAVEN_USER_HOME="$workdir/token/mvnw-home" JAVA_TOOL_OPTIONS="$trust" \
        timeout 600 ./mvnw -v >"$workdir/mvnw.out" 2>&1); then
        break
    fi
    sleep 2
done
grep -q "^Apache Maven " "$workdir/mvnw.out" || fail "./mvnw printed $(tail -5 "$workdir/mvnw.out")"
logged "artifact digest verified.*pkg:maven/org.apache.maven/apache-maven@" \
    || fail "./mvnw's distribution was not verified through the proxy"
assert_token_absent "$token" "$log"
echo "    ok (401 without a token; mvn, Gradle and ./mvnw sent one)"
stop_proxy

recognised "$log"

echo "PASS: the proxy serves Maven as Stage 6 requires."
