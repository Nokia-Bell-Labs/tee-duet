# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

SHELL := /bin/bash
# Create the env file with the manifest parameters
# $(1) - environment, either 'baremetal.env' or 'docker.env'
# $(2) - directory of the main python script
define create_env_file
	@echo "Generating <$(1)>"
	@echo "GRAMINE_TEMPLATE=$(GRAMINE_TEMPLATE)" > $(1)
	@echo "MANIFEST_FILE=$(MANIFEST_FILE)" >> $(1)
	@echo "SGX_RSA_KEY_PATH=$(SIGNING_KEY)" >> $(1)
	@echo "# Arguments for generating the gramine manifest from the template" >> $(1)
	@echo "work_dir"=$(2) >> $(1)
	@echo "log_level=$(LOG_LEVEL)" >> $(1)
	@echo "ra_type=$(RA_TYPE)" >> $(1)
	@echo "ra_client_spid=$(RA_CLIENT_SPID)" >> $(1)
	@echo "ra_client_linkable=$(RA_CLIENT_LINKABLE)" >> $(1)
	@echo "loader_args"=$(LOADER_ARGS) >> $(1)
endef

# Create a tailored Dockerfile from template Dockerfile.build 
# $(1) - base image w/o "duet/"
# $(2) - python app module 
define create_dockerfile
	@echo "Generating <$(DOCKER_PREFIX)_$(1)_$(SUFFIX_GRAMINIZED)>"
	@sed 's/{{gramine_image}}/$(shell echo "$(GRAMINE_IMAGE)" | sed -e 's/[\/&]/\\&/g')/g; \
			s/{{base_image}}/duet\/$(1)/g; \
			s/{{app_module}}/$(2)/g; \
			s/{{app_user}}/$(APP_USER)/g' \
			$(DOCKER_BUILD_TEMPLATE) > $(DOCKER_PREFIX)_$(1)_$(SUFFIX_GRAMINIZED)
endef
