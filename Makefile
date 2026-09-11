.PHONY: help dev-setup lint semgrep trufflehog sast test verify check-deps run smoke-npm spike-config

help:
	@echo "waharoa targets:"
	@echo "  dev-setup      install development dependencies"
	@echo "  lint           clippy and shellcheck, warnings as errors"
	@echo "  semgrep        pattern-based static analysis"
	@echo "  trufflehog     credential scanning (working tree and git history)"
	@echo "  sast           semgrep + trufflehog"
	@echo "  test           unit tests"
	@echo "  verify         formal verification (kani)"
	@echo "  check-deps     vulnerable and out-of-date dependencies"
	@echo "  run            run the proxy in the foreground"
	@echo "  smoke-npm      end-to-end check of the proxy against a real npm client"
	@echo "  spike-config   re-run the config-format spike (plan §5, decision #11)"

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

verify:
	@scripts/make/verify.sh

check-deps:
	@scripts/make/check-deps.sh

run:
	@scripts/make/run.sh

smoke-npm:
	@scripts/make/smoke-npm.sh

spike-config:
	@scripts/make/spike-config.sh
