UV ?= uv

.PHONY: sync lint format typecheck test

sync:
	$(UV) sync

lint:
	$(UV) run ruff check cartha_cli tests

format:
	$(UV) run ruff format cartha_cli tests

typecheck:
	$(UV) run mypy cartha_cli

test: lint typecheck
	$(UV) run pytest
