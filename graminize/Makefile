# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

SHELL := /bin/bash
include functions.mk
include ../docker.mk

SIGNING_KEY ?= "keys/signer-key.pem"
GRAMINE_IMAGE ?= duet/gramine
APP_USER ?= duet

GRAMINE_TEMPLATE ?= entrypoint.manifest.template
MANIFEST_FILE ?= entrypoint.manifest

MODULE_NAME=$(MODULE)
BASE_IMAGE ?= duet/$(MODULE_NAME)

######################################################################

DOCKER_BUILD_TEMPLATE := Dockerfile.build.template

DOCKER_PREFIX := Dockerfile
SUFFIX_GRAMINIZED := graminized
SUFFIX_SIGNED := signed
DOCKER_GRAMINIZED := $(DOCKER_PREFIX)_$(MODULE_NAME)_$(SUFFIX_GRAMINIZED)
DOCKER_SIGNED := $(DOCKER_PREFIX)_$(MODULE_NAME)_$(SUFFIX_SIGNED)
IMAGE_GRAMINIZED := $(BASE_IMAGE)-$(SUFFIX_GRAMINIZED)
IMAGE_SIGNED := $(IMAGE_GRAMINIZED)
MANIFEST_PREFIX := $(MANIFEST_FILE)
MANIFEST := $(MANIFEST_PREFIX)_$(MODULE_NAME)

DOCKER_ENV_FILE = "gramine.env"

# Need to get arch from inside the container
ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
PYTHON_PATH ?= $(realpath $(shell sh -c "command -v python3"))
ifeq ($(DEBUG),1)
LOG_LEVEL = debug
else
LOG_LEVEL = error
endif
RA_TYPE ?= dcap
RA_CLIENT_SPID ?=
RA_CLIENT_LINKABLE ?= 0

ifeq ($(MODULE_NAME),admin)
LOADER_ARGS := "-B,-m,home.duet.AdminEnclave.admin"
endif

############################################################
# Create the gramine image if needed
gramine-image: Dockerfile.gramine
	@echo "Building gramine image <$(GRAMINE_IMAGE)>"
	$(call build_image,Dockerfile.gramine,$(GRAMINE_IMAGE))
#	@docker build --rm \
#		--build-arg http_proxy=${http_proxy} \
#		--build-arg https_proxy=${https_proxy} \
#		-f Dockerfile.gramine . \
#		-t $(GRAMINE_IMAGE)


############################################################
# Create the .env file with the parameters for the manifest

env-docker: $(DOCKER_ENV_FILE)

######################################################################
# Create Dockerfile from template

$(DOCKER_ENV_FILE):
	@$(call create_env_file,$(DOCKER_ENV_FILE),"/home/duet")

dockerfile:
	@$(call create_dockerfile,$(MODULE_NAME),$(MODULE))


######################################################################
# Create a container image from generated Dockerfile

signed-image: dockerfile $(DOCKER_ENV_FILE) signing-key entrypoint.manifest.template
	@echo "Building docker image <$(IMAGE_GRAMINIZED)>"
	$(call build_image,$(DOCKER_GRAMINIZED),$(IMAGE_GRAMINIZED))
#	docker build --rm \
#		--no-cache \
#		--build-arg http_proxy=${http_proxy} \
#		--build-arg https_proxy=${https_proxy} \
#		-f $(DOCKER_GRAMINIZED) . \
#		-t $(IMAGE_GRAMINIZED)

# Create a RSA signing key if needed
signing-key: $(SIGNING_KEY)

$(SIGNING_KEY):
	@echo "Generating new signing key <$(SIGNING_KEY)>"
	@if [ ! -f "$(SIGNING_KEY)" ]; then \
		mkdir -p keys; \
		openssl genpkey -outform PEM -algorithm RSA \
			-pkeyopt rsa_keygen_bits:3072 \
			-pkeyopt rsa_keygen_pubexp:3 \
			--out $(SIGNING_KEY); \
	fi

######################################################################
clean:
	rm -f $(DOCKER_PREFIX)_*_$(SUFFIX_GRAMINIZED)
	rm -f *.manifest *.sig *.sgx
	rm -f *.env .env
