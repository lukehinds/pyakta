SHELL := /bin/bash
.PHONY: install-dev clean

PROJECT_DIR := pyakta

install-dev:
	@echo "Installing development dependencies using uv..."
	uv pip install .[dev]
	@echo "Development dependencies installed."

test:
	@echo "Running tests..."
	uv run pytest
	@echo "Tests completed."

lint:
	@echo "Running lint..."
	uv run ruff check .
	@echo "Lint completed."

format:
	@echo "Running format..."
	uv run ruff format .
	@echo "Format completed."

build:
	@echo "Building..."
	uv run build
	@echo "Build completed."

bandit:
	@echo "Running bandit..."
	uv run bandit -r $(PROJECT_DIR)
	@echo "Bandit completed."


