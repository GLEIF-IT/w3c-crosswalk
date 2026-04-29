SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

PACKAGE := vc-isomer
MODULE := vc_isomer
CLI := isomer
DIST_DIR := dist
PYTHON := ./.venv/bin/python
UV := uv
TWINE := uvx --from twine twine
DID_JWT_VC_ROOT := ../did-jwt-vc
WEBS_DID_RESOLVER_ROOT := packages/webs-did-resolver
VC_GO_ROOT := ../vc-go
GO_CACHE ?= /tmp/isomer-go-cache
DOCKER_TAG ?= local

PYPI_UPLOAD_URL := https://upload.pypi.org/legacy/
PYPI_CHECK_URL := https://pypi.org/simple/$(PACKAGE)/
TEST_PYPI_UPLOAD_URL := https://test.pypi.org/legacy/
TEST_PYPI_CHECK_URL := https://test.pypi.org/simple/$(PACKAGE)/

.PHONY: help sync clean test-cli test-fast test-integration test smoke external-node-sync external-node-check external-go-check dashboard-sync dashboard-check test-external-w3c-node test-external-w3c-go test-external-w3c-all docker-verifiers-build docker-verifiers-smoke docker-verifiers-test build dist-check check-clean prepublish publish-test publish

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
		'  make docker-verifiers-test  Run KERIA Docker verifier acceptance' \
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
	@test -f "$(DID_JWT_VC_ROOT)/package.json" || { echo 'missing sibling did-jwt-vc clone at $(DID_JWT_VC_ROOT)'; exit 1; }
	yarn --cwd "$(DID_JWT_VC_ROOT)" install --frozen-lockfile
	yarn --cwd "$(DID_JWT_VC_ROOT)" build
	npm --prefix "$(WEBS_DID_RESOLVER_ROOT)" install
	npm --prefix "$(WEBS_DID_RESOLVER_ROOT)" run build
	npm --prefix apps/isomer-node install

external-node-check:
	npm --prefix apps/isomer-node run check
	npm --prefix apps/isomer-node test

external-go-check:
	@test -f "$(VC_GO_ROOT)/go.mod" || { echo 'missing sibling vc-go clone at $(VC_GO_ROOT)'; exit 1; }
	cd apps/isomer-go && env GOCACHE="$(GO_CACHE)" go test ./...

dashboard-sync:
	npm --prefix apps/isomer-dashboard install

dashboard-check:
	npm --prefix apps/isomer-dashboard run check
	npm --prefix apps/isomer-dashboard test

test-external-w3c-node: external-node-sync external-node-check
	ISOMER_EXTERNAL_VERIFIERS=node $(PYTHON) -m pytest tests/integration/test_single_sig_vrd_isomer.py -q --tb=short

test-external-w3c-go: external-go-check
	ISOMER_EXTERNAL_VERIFIERS=go $(PYTHON) -m pytest tests/integration/test_single_sig_vrd_isomer.py -q --tb=short

test-external-w3c-all: external-node-sync external-node-check external-go-check
	ISOMER_EXTERNAL_VERIFIERS=node,go $(PYTHON) -m pytest tests/integration/test_single_sig_vrd_isomer.py -q --tb=short

docker-verifiers-build:
	TAG="$(DOCKER_TAG)" docker buildx bake --file docker-bake.hcl

docker-verifiers-smoke: docker-verifiers-build
	python scripts/docker/smoke-verifier-containers.py --tag "$(DOCKER_TAG)"

docker-verifiers-test: docker-verifiers-build
	cd ../keria && KERIA_DOCKER_W3C_ACCEPTANCE=1 .venv/bin/pytest tests/integration/test_w3c_projection_docker_verifiers.py -q

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
