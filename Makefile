.PHONY: help spike-config

help:
	@echo "waharoa targets:"
	@echo "  spike-config   re-run the config-format spike (plan §5, decision #11)"

# Recipes stay one-line wrappers; the logic lives in scripts/make/<target>.sh
spike-config:
	@scripts/make/spike-config.sh
