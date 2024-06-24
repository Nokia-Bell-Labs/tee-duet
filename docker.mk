# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

SHELL := /bin/bash
SELF_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
VERSION ?= $(shell git -C $(SELF_DIR) describe --always --tags --dirty)

define build_image
	@#echo "Dockerfile $(1)"
	@#echo "container $(2)"
	@#echo "Current dependencies $^"
	docker -D -l debug build \
		-f $(1) \
		-t $(2) . || exit $$!;
endef

