# Safe development entry points. No downloads, exposed services or cleanup shortcuts.
PY ?= python3

.PHONY: help plan test lint
help:
	@printf '%s\n' 'make plan CONFIG=... : installation plan only' 'make test : prepared offline hardening suite (requires OS sandbox)' 'make lint : local lint, no downloads'

plan:
	@test -n "$(CONFIG)" || (echo 'CONFIG is required'; exit 2)
	$(PY) -m runtime.install --plan --config "$(CONFIG)"

test:
	$(PY) -m pytest tests/hardening -q -p no:cacheprovider

lint:
	$(PY) -m ruff check runtime app tests/hardening
