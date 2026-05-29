SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

APP_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(APP_DIR)/../..)

CONTAINER_ENGINE ?= docker
DOCKER_TAG ?= local
IMAGE ?= w3c-crosswalk/isomer-dashboard:$(DOCKER_TAG)

ISOMER_DASHBOARD_HOST ?= 127.0.0.1
ISOMER_DASHBOARD_PORT ?= 8791

.PHONY: help sync check test serve image

help:
	@printf '%s\n' \
		'isomer-dashboard app targets:' \
		'  make sync   Install dependencies' \
		'  make check  Run TypeScript checks' \
		'  make test   Run dashboard tests' \
		'  make serve  Run the dashboard locally' \
		'  make image  Build the dashboard container image'

sync:
	npm install

check:
	npm run check

test:
	npm test

serve:
	ISOMER_DASHBOARD_HOST="$(ISOMER_DASHBOARD_HOST)" \
	ISOMER_DASHBOARD_PORT="$(ISOMER_DASHBOARD_PORT)" \
	npm run serve

image:
	$(CONTAINER_ENGINE) build -f "$(APP_DIR)/Dockerfile" -t "$(IMAGE)" "$(REPO_ROOT)"
