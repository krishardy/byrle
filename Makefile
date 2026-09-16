.PHONY: help dev-setup lint semgrep trufflehog sast test test-integration coverage mutants verify sqlx-prepare check-deps update-deps run smoke-npm smoke-python smoke-clients retry-matrix offsite-urls inspect spike-config duplicates

help:
	@echo "waharoa targets:"
	@echo "  dev-setup      install development dependencies"
	@echo "  lint           rustfmt, clippy and shellcheck, warnings as errors"
	@echo "  semgrep        pattern-based static analysis"
	@echo "  trufflehog     credential scanning (working tree and git history)"
	@echo "  sast           semgrep + trufflehog"
	@echo "  test           unit tests"
	@echo "  test-integration  tests needing a real Postgres, in a container"
	@echo "  sqlx-prepare   regenerate .sqlx/, the offline query cache"
	@echo "  coverage       unit test coverage, failing under the CLAUDE.md floor"
	@echo "  mutants        mutation testing of the Rust changed since BASE (default HEAD)"
	@echo "  verify         formal verification (kani)"
	@echo "  check-deps     vulnerable and out-of-date dependencies"
	@echo "  update-deps    update Cargo.lock within the manifest's constraints"
	@echo "  run            run the proxy in the foreground"
	@echo "  smoke-npm      end-to-end check of the proxy against a real npm client"
	@echo "  smoke-python   the same against pip and uv"
	@echo "  smoke-clients  where npm, pnpm and yarn diverge through the proxy"
	@echo "  retry-matrix   what each client does when the proxy defers a request"
	@echo "  offsite-urls   which packument URLs each client fetches as written"
	@echo "  inspect        show one request per client, for looking at by eye"
	@echo "  spike-config   re-run the config-format spike (plan §5, decision #11)"
	@echo "  duplicates     repeated code blocks and string literals (docs/duplication-catalogue.md)"

# The repository path as trufflehog sees it, which is the real path for a native
# binary. Override it if trufflehog runs in a container, where the repository is
# visible at the mount point rather than at its host path:
#   make trufflehog TRUFFLEHOG_REPO_ROOT=/pwd
TRUFFLEHOG_REPO_ROOT ?= $(CURDIR)

# Recipes stay one-line wrappers; the logic lives in scripts/make/<target>.sh
dev-setup:
	@scripts/make/dev-setup.sh

lint:
	@scripts/make/lint.sh

semgrep:
	@scripts/make/semgrep.sh

trufflehog:
	@TRUFFLEHOG_REPO_ROOT='$(TRUFFLEHOG_REPO_ROOT)' scripts/make/trufflehog.sh

# Prerequisites, so each scanner is runnable on its own. Make stops at the first
# failing prerequisite; use `make -k sast` to run both regardless.
sast: semgrep trufflehog

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

verify:
	@scripts/make/verify.sh

check-deps:
	@scripts/make/check-deps.sh

update-deps:
	@scripts/make/update-deps.sh

run:
	@scripts/make/run.sh

smoke-npm:
	@scripts/make/smoke-npm.sh

smoke-python:
	@scripts/make/smoke-python.sh

smoke-clients:
	@scripts/make/smoke-clients.sh

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
