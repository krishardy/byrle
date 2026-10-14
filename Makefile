.PHONY: help dev-setup build lint semgrep trufflehog trivy sast test test-integration coverage mutants mutants-status verify sqlx-prepare check-deps update-deps run smoke-npm smoke-python smoke-clients smoke-proxy smoke-tls-front smoke-console bench memory retry-matrix offsite-urls inspect spike-config duplicates unsigned run-dev

help:
	@echo "byrle targets:"
	@echo "  dev-setup      install development dependencies"
	@echo "  build          build the byrle binary (release profile)"
	@echo "  lint           rustfmt, clippy and shellcheck, warnings as errors"
	@echo "  semgrep        pattern-based static analysis"
	@echo "  trufflehog     credential scanning (working tree and git history)"
	@echo "  trivy          Containerfile misconfigurations and dev image vulnerabilities"
	@echo "  sast           semgrep + trufflehog + trivy"
	@echo "  test           unit tests"
	@echo "  test-integration  tests needing a real Postgres, in a container or local cluster"
	@echo "  sqlx-prepare   regenerate .sqlx/, the offline query cache"
	@echo "  coverage       unit test coverage, failing under the CLAUDE.md floor"
	@echo "  mutants        mutation testing of the Rust changed since BASE (default HEAD)"
	@echo "  mutants-status how far the current or last mutants run is, and what it missed"
	@echo "  verify         formal verification (kani)"
	@echo "  check-deps     vulnerable and out-of-date dependencies"
	@echo "  update-deps    update Cargo.lock within the manifest's constraints"
	@echo "  run            run the proxy in the foreground"
	@echo "  run-dev        build byrle and start it with Postgres in podman-compose"
	@echo "  smoke-npm      what the proxy does, checked with npm"
	@echo "  smoke-python   what the proxy does for PyPI, checked with pip and uv"
	@echo "  smoke-clients  whether npm's other four clients route artifacts through it"
	@echo "  smoke-proxy    whether upstream traffic honours HTTP_PROXY, HTTPS_PROXY and NO_PROXY"
	@echo "  smoke-tls-front  the proxy behind nginx on TLS, checked with npm and pip"
	@echo "  smoke-console    the Stage 4.9 exit test: installs, the console API, alerts, Dex login"
	@echo "  bench          install times through the proxy against direct, for npm and uv"
	@echo "  memory         the proxy's peak, median and idle RSS under install and document loads"
	@echo "  retry-matrix   what each client does when the proxy defers a request"
	@echo "  offsite-urls   which packument URLs each client fetches as written"
	@echo "  inspect        show one request per client, for looking at by eye"
	@echo "  spike-config   re-run the config-format spike (plan §5, decision #11)"
	@echo "  duplicates     repeated code blocks and string literals (docs/duplication-catalogue.md)"
	@echo "  unsigned       list unsigned commits; SIGN=1 [KEY=<id>] signs them by rebasing"

# The repository path as trufflehog sees it, which is the real path for a native
# binary. Override it if trufflehog runs in a container, where the repository is
# visible at the mount point rather than at its host path:
#   make trufflehog TRUFFLEHOG_REPO_ROOT=/pwd
TRUFFLEHOG_REPO_ROOT ?= $(CURDIR)

# The development database's role, password and database, for run-dev. Postgres reads
# them only when it creates its volume; see compose.yaml.
DEV_DB_USER ?= byrle
DEV_DB_PASSWORD ?= byrle
DEV_DB_NAME ?= byrle
DEV_DB_ARGS = $(DEV_DB_USER) $(DEV_DB_PASSWORD) $(DEV_DB_NAME)

# Recipes stay one-line wrappers; the logic lives in scripts/make/<target>.sh
dev-setup:
	@scripts/make/dev-setup.sh

build:
	@scripts/make/build.sh

lint:
	@scripts/make/lint.sh

semgrep:
	@scripts/make/semgrep.sh

trufflehog:
	@TRUFFLEHOG_REPO_ROOT='$(TRUFFLEHOG_REPO_ROOT)' scripts/make/trufflehog.sh

# Prerequisites, so each scanner is runnable on its own. Make stops at the first
# failing prerequisite; use `make -k sast` to run both regardless.
trivy:
	@scripts/make/trivy.sh

sast: semgrep trufflehog trivy

test:
	@cargo test

test-integration:
	@scripts/make/test-integration.sh

sqlx-prepare:
	@scripts/make/sqlx-prepare.sh $(ARGS)

coverage:
	@scripts/make/coverage.sh

mutants:
	@scripts/make/mutants.sh $(BASE)

mutants-status:
	@scripts/make/mutants-status.py

verify:
	@scripts/make/verify.sh

check-deps:
	@scripts/make/check-deps.sh

update-deps:
	@scripts/make/update-deps.sh

run:
	@scripts/make/run.sh

run-dev:
	@scripts/make/run-dev.sh $(DEV_DB_ARGS)

smoke-npm:
	@scripts/make/smoke-npm.sh

smoke-python:
	@scripts/make/smoke-python.sh

smoke-clients:
	@scripts/make/smoke-clients.sh

smoke-proxy:
	@scripts/make/smoke-proxy.sh

smoke-tls-front:
	@scripts/make/smoke-tls-front.sh

smoke-console:
	@scripts/make/smoke-console.sh

bench:
	@scripts/make/bench.sh

memory:
	@scripts/make/memory.sh

retry-matrix:
	@scripts/make/retry-matrix.sh

offsite-urls:
	@scripts/make/offsite-urls.sh

inspect:
	@scripts/make/inspect.sh

spike-config:
	@scripts/make/spike-config.sh

duplicates:
	@scripts/make/duplicates.py

unsigned:
	@SIGN="$(SIGN)" KEY="$(KEY)" scripts/make/unsigned.sh
