.PHONY: help run smoke-npm spike-config

help:
	@echo "waharoa targets:"
	@echo "  run            run the proxy in the foreground (see scripts/make/run.sh)"
	@echo "  smoke-npm      end-to-end check of the proxy against a real npm client"
	@echo "  spike-config   re-run the config-format spike (plan §5, decision #11)"

# Recipes stay one-line wrappers; the logic lives in scripts/make/<target>.sh
run:
	@scripts/make/run.sh

smoke-npm:
	@scripts/make/smoke-npm.sh

spike-config:
	@scripts/make/spike-config.sh
