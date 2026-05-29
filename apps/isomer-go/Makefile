SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

APP_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(APP_DIR)/../..)

CONTAINER_ENGINE ?= docker
DOCKER_TAG ?= local
IMAGE ?= w3c-crosswalk/isomer-go:$(DOCKER_TAG)
GO_CACHE ?= /tmp/isomer-go-cache

ISOMER_HOST ?= 127.0.0.1
ISOMER_PORT ?= 8790
ISOMER_RESOLVER_URL ?= http://127.0.0.1:7678/1.0/identifiers
ISOMER_RESOURCE_ROOT ?= $(REPO_ROOT)

.PHONY: help sync check test serve image

help:
	@printf '%s\n' \
		'isomer-go app targets:' \
		'  make sync   Download Go modules' \
		'  make check  Run Go tests' \
		'  make test   Alias for check' \
		'  make serve  Run the verifier sidecar locally' \
		'  make image  Build the verifier container image'

sync:
	env GOCACHE="$(GO_CACHE)" go mod download

check:
	env GOCACHE="$(GO_CACHE)" go test ./...

test: check

serve:
	env GOCACHE="$(GO_CACHE)" go run ./cmd/isomer-go \
		--host "$(ISOMER_HOST)" \
		--port "$(ISOMER_PORT)" \
		--resolver-url "$(ISOMER_RESOLVER_URL)" \
		--resource-root "$(ISOMER_RESOURCE_ROOT)"

image:
	$(CONTAINER_ENGINE) build -f "$(APP_DIR)/Dockerfile" -t "$(IMAGE)" "$(REPO_ROOT)"
