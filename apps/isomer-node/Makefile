SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

APP_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(APP_DIR)/../..)
WEBS_DID_RESOLVER_ROOT := $(REPO_ROOT)/packages/webs-did-resolver

CONTAINER_ENGINE ?= docker
DOCKER_TAG ?= local
IMAGE ?= w3c-crosswalk/isomer-node:$(DOCKER_TAG)

ISOMER_HOST ?= 127.0.0.1
ISOMER_PORT ?= 8789
ISOMER_RESOLVER_URL ?= http://127.0.0.1:7678/1.0/identifiers
ISOMER_RESOURCE_ROOT ?= $(REPO_ROOT)

.PHONY: help sync check test serve image

help:
	@printf '%s\n' \
		'isomer-node app targets:' \
		'  make sync   Install dependencies and build pinned local packages' \
		'  make check  Run TypeScript checks' \
		'  make test   Run Node tests' \
		'  make serve  Run the verifier sidecar locally' \
		'  make image  Build the verifier container image'

sync:
	npm --prefix "$(WEBS_DID_RESOLVER_ROOT)" install
	npm --prefix "$(WEBS_DID_RESOLVER_ROOT)" run build
	npm install
	npm run build:pinned-deps

check:
	npm run check

test:
	npm test

serve:
	npm run serve -- \
		--host "$(ISOMER_HOST)" \
		--port "$(ISOMER_PORT)" \
		--resolver-url "$(ISOMER_RESOLVER_URL)" \
		--resource-root "$(ISOMER_RESOURCE_ROOT)"

image:
	$(CONTAINER_ENGINE) build -f "$(APP_DIR)/Dockerfile" -t "$(IMAGE)" "$(REPO_ROOT)"
