.PHONY: install dev test lint format typecheck clean build publish

# Development
install:
	pip install -e .

dev:
	pip install -e ".[dev]"

# Testing
test:
	pytest -v

test-cov:
	pytest --cov=capiscio_mcp --cov-report=html --cov-report=term-missing --cov-fail-under=80

test-watch:
	pytest-watch

# Code quality
lint:
	ruff check capiscio_mcp tests

lint-fix:
	ruff check --fix capiscio_mcp tests

format:
	black capiscio_mcp tests

format-check:
	black --check capiscio_mcp tests

typecheck:
	mypy capiscio_mcp

# All checks
check: lint format-check typecheck test

# Building
clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +

build: clean
	python -m build

# Publishing
publish-test: build
	twine upload --repository testpypi dist/*

publish: build
	twine upload dist/*

# Proto generation (when capiscio-core has mcp.proto)
proto:
	python -m grpc_tools.protoc \
		-I../capiscio-core/proto \
		--python_out=capiscio_mcp/_proto \
		--grpc_python_out=capiscio_mcp/_proto \
		../capiscio-core/proto/capiscio/v1/mcp.proto
