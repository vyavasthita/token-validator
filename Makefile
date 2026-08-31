NAME := token-validator
VERSION = $(shell cat VERSION 2>/dev/null || echo "0.0.0-DEV")

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "$(NAME) - JWT Token Validation Library"
	@echo ""
	@echo "Targets:"
	@echo "  deps        Install all dependencies (including test extras)"
	@echo "  lint        Run ruff linter"
	@echo "  fmt         Format code with ruff"
	@echo "  fmt-check   Check code formatting"
	@echo "  test        Run unit tests with coverage"
	@echo "  build       Build wheel package"
	@echo "  clean       Remove build artifacts"

.PHONY: deps
deps:
	poetry install --extras test

.PHONY: lint
lint: deps
	poetry run ruff check src tests

.PHONY: fmt
fmt: deps
	poetry run ruff format src tests

.PHONY: fmt-check
fmt-check: deps
	poetry run ruff format --check src tests

.PHONY: test
test: deps
	mkdir -p tests/reports
	poetry run pytest -v --tb=short --junit-xml tests/reports/unit_tests.xml \
		--cov=src --cov-report=term-missing --cov-report=xml:tests/reports/coverage.xml \
		--cov-report=html:tests/reports/html tests/

.PHONY: build
build: deps
	poetry build -f wheel -o build/

.PHONY: clean
clean:
	rm -rf build/ dist/ tests/reports/
	rm -rf .pytest_cache/ .coverage htmlcov/
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +
