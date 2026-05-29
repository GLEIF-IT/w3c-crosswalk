# Shell selection and configuration
SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

# Python, UV, and Twine binary selection
PYTHON := ./.venv/bin/python
UV := uv
TWINE := uvx --from twine twine

# vc-isomer package and module info
PACKAGE := vc-isomer
MODULE := vc_isomer
CLI := isomer
LOCAL_PROJECT ?= w3c-crosswalk

# Docker/containerization config
CONTAINER_ENGINE ?= docker
DOCKER_TAG ?= local
COMPOSE ?= $(CONTAINER_ENGINE) compose
LOCAL_COMPOSE := docker/compose.local.yml
LOCAL_COMPOSE_CMD = $(COMPOSE) --env-file "$(ENV_FILE)" -p "$(LOCAL_PROJECT)" -f "$(LOCAL_COMPOSE)"
VERIFIER_BUILD_COMPOSE := docker/compose.build.yml
VERIFIER_BUILD_SERVICES := isomer-python isomer-node isomer-go isomer-dashboard

# External app configuration
GO_CACHE ?= /tmp/isomer-go-cache

# Local stack deployment configuration
LOCAL_STACK_TMP := .tmp/local-stack
ENV_FILE ?= .env

# Packaging Config
DIST_DIR := dist
PYPI_UPLOAD_URL := https://upload.pypi.org/legacy/
PYPI_CHECK_URL := https://pypi.org/simple/$(PACKAGE)/
TEST_PYPI_UPLOAD_URL := https://test.pypi.org/legacy/
TEST_PYPI_CHECK_URL := https://test.pypi.org/simple/$(PACKAGE)/

.PHONY: help sync clean test-cli test-fast test-integration test smoke external-node-sync external-node-check external-go-check dashboard-sync dashboard-check test-external-w3c-node test-external-w3c-go test-external-w3c-all docker-verifiers-build docker-verifiers-smoke local-up local-seed local-project local-test local-down local-reset build dist-check check-clean prepublish publish-test publish

help:
	@printf '%s\n' \
		'Publishing pipeline for $(PACKAGE)' \
		'' \
		'Local checks:' \
		'  make sync              Sync the uv environment' \
		'  make test-cli          Run CLI contract tests' \
		'  make test-fast         Run fast contract/runtime tests' \
		'  make test-integration  Run the focused live integration test' \
		'  make test              Run all tests used before publishing' \
		'  make smoke             Check import/package/CLI wiring' \
		'  make external-node-sync  Install/build the Node W3C verifier sidecar' \
		'  make external-node-check Check the Node W3C verifier sidecar' \
		'  make external-go-check   Check the Go W3C verifier sidecar' \
		'  make dashboard-sync      Install the verifier dashboard app' \
		'  make dashboard-check     Check the verifier dashboard app' \
		'  make test-external-w3c-all Run live e2e through Node and Go sidecars' \
		'  make docker-verifiers-build Build local Python/Node/Go verifier images' \
		'  make docker-verifiers-smoke Smoke-test verifier container health checks' \
		'  make local-up          Start the portable wallet + verifier compose stack' \
		'  make local-seed        Run the SignifyPy VRD projection-chain seeder' \
		'  make local-project     Project the seeded VRD credential through all verifiers' \
		'  make local-test        Run stack acceptance checks' \
		'  make local-down        Stop the portable local stack and preserve volumes' \
		'  make local-reset       Destroy local stack volumes and generated seed artifacts' \
		'  make build             Build sdist and wheel into dist/' \
		'  make dist-check        Build and validate artifacts with twine check' \
		'' \
		'Publishing:' \
		'  make publish-test      Upload dist/* to TestPyPI' \
		'  make publish           Upload dist/* to PyPI' \
		'' \
		'Credentials:' \
		'  TEST_PYPI_TOKEN=... make publish-test' \
		'  PYPI_TOKEN=... make publish' \
		'  UV_PUBLISH_TOKEN=... also works for either upload target' \
		'' \
		'Set ALLOW_DIRTY=1 to bypass the clean-worktree guard.'

sync:
	$(UV) sync

clean:
	rm -rf $(DIST_DIR) build *.egg-info src/*.egg-info

test-cli:
	$(PYTHON) -m pytest tests/test_cli.py -q

test-fast:
	$(PYTHON) -m pytest \
		tests/test_cesr_fixtures.py \
		tests/test_profile.py \
		tests/test_jwt.py \
		tests/test_status.py \
		tests/test_verifier.py \
		tests/test_service.py \
		tests/test_longrunning.py \
		tests/test_runtime_http.py \
		tests/test_verifier_runtime.py \
		tests/test_isomer_runtime.py -q

test-integration:
	$(PYTHON) -m pytest tests/integration/test_single_sig_vrd_isomer.py -q --tb=short

test: test-cli test-fast test-integration

smoke:
	$(PYTHON) -m py_compile $$(find src/$(MODULE) -name '*.py' -print)
	$(PYTHON) -c "import $(MODULE)"
	@if $(PYTHON) -c "import isomer" >/dev/null 2>&1; then \
		echo 'unexpected importable compatibility package: isomer'; \
		exit 1; \
	fi
	$(PYTHON) -m $(MODULE).cli --help >/dev/null
	./.venv/bin/$(CLI) --help >/dev/null
	$(PYTHON) -c "from importlib.metadata import version; print('$(PACKAGE)', version('$(PACKAGE)'))"
	@if $(PYTHON) -c "from importlib.metadata import version; version('isomer')" >/dev/null 2>&1; then \
		echo 'unexpected installed distribution metadata: isomer'; \
		exit 1; \
	fi

external-node-sync:
	$(MAKE) -C apps/isomer-node sync

external-node-check:
	$(MAKE) -C apps/isomer-node check test

external-go-check:
	$(MAKE) -C apps/isomer-go GO_CACHE="$(GO_CACHE)" check

dashboard-sync:
	$(MAKE) -C apps/isomer-dashboard sync

dashboard-check:
	$(MAKE) -C apps/isomer-dashboard check test

test-external-w3c-node: external-node-sync external-node-check
	ISOMER_EXTERNAL_VERIFIERS=node $(PYTHON) -m pytest tests/integration/test_single_sig_vrd_isomer.py -q --tb=short

test-external-w3c-go: external-go-check
	ISOMER_EXTERNAL_VERIFIERS=go $(PYTHON) -m pytest tests/integration/test_single_sig_vrd_isomer.py -q --tb=short

test-external-w3c-all: external-node-sync external-node-check external-go-check
	ISOMER_EXTERNAL_VERIFIERS=node,go $(PYTHON) -m pytest tests/integration/test_single_sig_vrd_isomer.py -q --tb=short

docker-verifiers-build:
	ISOMER_PYTHON_IMAGE="w3c-crosswalk/isomer-python:$(DOCKER_TAG)" \
	ISOMER_NODE_IMAGE="w3c-crosswalk/isomer-node:$(DOCKER_TAG)" \
	ISOMER_GO_IMAGE="w3c-crosswalk/isomer-go:$(DOCKER_TAG)" \
	ISOMER_DASHBOARD_IMAGE="w3c-crosswalk/isomer-dashboard:$(DOCKER_TAG)" \
	$(COMPOSE) -f docker/compose.verifiers.yml -f "$(VERIFIER_BUILD_COMPOSE)" build $(VERIFIER_BUILD_SERVICES)

docker-verifiers-smoke: docker-verifiers-build
	python scripts/docker/smoke-verifier-containers.py --engine "$(CONTAINER_ENGINE)" --tag "$(DOCKER_TAG)"

local-up:
	@test -f "$(ENV_FILE)" || cp .env.example "$(ENV_FILE)"
	$(LOCAL_COMPOSE_CMD) up -d

local-seed:
	@test -f "$(ENV_FILE)" || cp .env.example "$(ENV_FILE)"
	@mkdir -p "$(LOCAL_STACK_TMP)"
	$(LOCAL_COMPOSE_CMD) run --rm signifypy-seed

local-project:
	@test -f "$(ENV_FILE)" || cp .env.example "$(ENV_FILE)"
	@mkdir -p "$(LOCAL_STACK_TMP)"
	@test -f "$(LOCAL_STACK_TMP)/w3c-vrd-chain-manifest.json" || { echo 'missing $(LOCAL_STACK_TMP)/w3c-vrd-chain-manifest.json; run make local-seed first' >&2; exit 1; }
	$(LOCAL_COMPOSE_CMD) run --rm signifypy-project

local-test:
	@test -f "$(ENV_FILE)" || cp .env.example "$(ENV_FILE)"
	@mkdir -p "$(LOCAL_STACK_TMP)"
	$(LOCAL_COMPOSE_CMD) --profile seed config >/dev/null
	$(MAKE) local-project

local-down:
	@test -f "$(ENV_FILE)" || cp .env.example "$(ENV_FILE)"
	$(LOCAL_COMPOSE_CMD) down --remove-orphans

local-reset:
	@test -f "$(ENV_FILE)" || cp .env.example "$(ENV_FILE)"
	$(LOCAL_COMPOSE_CMD) down --remove-orphans --volumes
	rm -rf "$(LOCAL_STACK_TMP)"
	mkdir -p "$(LOCAL_STACK_TMP)"

build: clean
	$(UV) build

dist-check: build
	$(TWINE) check $(DIST_DIR)/*

check-clean:
	@if [ "$${ALLOW_DIRTY:-0}" != "1" ]; then \
		if [ -n "$$(git status --porcelain)" ]; then \
			echo 'refusing to publish from a dirty worktree; commit/stash first or set ALLOW_DIRTY=1'; \
			git status --short; \
			exit 1; \
		fi \
	fi

prepublish: check-clean test smoke dist-check

publish-test: prepublish
	@if [ -z "$${TEST_PYPI_TOKEN:-}$${UV_PUBLISH_TOKEN:-}$${UV_PUBLISH_USERNAME:-}$${UV_PUBLISH_PASSWORD:-}" ]; then \
		echo 'missing TestPyPI credentials; set TEST_PYPI_TOKEN or uv publish credentials'; \
		exit 1; \
	fi
	@if [ -n "$${TEST_PYPI_TOKEN:-}" ]; then \
		UV_PUBLISH_TOKEN="$$TEST_PYPI_TOKEN" $(UV) publish --publish-url "$(TEST_PYPI_UPLOAD_URL)" --check-url "$(TEST_PYPI_CHECK_URL)" $(DIST_DIR)/*; \
	else \
		$(UV) publish --publish-url "$(TEST_PYPI_UPLOAD_URL)" --check-url "$(TEST_PYPI_CHECK_URL)" $(DIST_DIR)/*; \
	fi

publish: prepublish
	@if [ -z "$${PYPI_TOKEN:-}$${UV_PUBLISH_TOKEN:-}$${UV_PUBLISH_USERNAME:-}$${UV_PUBLISH_PASSWORD:-}" ]; then \
		echo 'missing PyPI credentials; set PYPI_TOKEN or uv publish credentials'; \
		exit 1; \
	fi
	@if [ -n "$${PYPI_TOKEN:-}" ]; then \
		UV_PUBLISH_TOKEN="$$PYPI_TOKEN" $(UV) publish --publish-url "$(PYPI_UPLOAD_URL)" --check-url "$(PYPI_CHECK_URL)" $(DIST_DIR)/*; \
	else \
		$(UV) publish --publish-url "$(PYPI_UPLOAD_URL)" --check-url "$(PYPI_CHECK_URL)" $(DIST_DIR)/*; \
	fi
