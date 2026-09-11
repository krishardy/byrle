.PHONY: help dev-setup lint sast test verify check-deps run smoke-npm spike-config

help:
	@echo "waharoa targets:"
	@echo "  dev-setup      install development dependencies"
	@echo "  lint           clippy across all targets, warnings as errors"
	@echo "  sast           static analysis (semgrep)"
	@echo "  test           unit tests"
	@echo "  verify         formal verification (kani)"
	@echo "  check-deps     vulnerable and out-of-date dependencies"
	@echo "  run            run the proxy in the foreground"
	@echo "  smoke-npm      end-to-end check of the proxy against a real npm client"
	@echo "  spike-config   re-run the config-format spike (plan §5, decision #11)"

# Recipes stay one-line wrappers; the logic lives in scripts/make/<target>.sh
dev-setup:
	@scripts/make/dev-setup.sh

lint:
	@scripts/make/lint.sh

sast:
	@scripts/make/sast.sh

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
