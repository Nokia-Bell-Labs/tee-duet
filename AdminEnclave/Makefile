# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Makefile
SHELL := /bin/bash
include ../docker.mk

default: image

ADMIN_SOURCE = $(shell find .)
image: \
	Dockerfile \
	$(ADMIN_SOURCE)
	$(call build_image,Dockerfile,duet/admin)

graminize: \
	Dockerfile \
	$(ADMIN_SOURCE) \
	image
	make -C ../graminize MODULE=admin signed-image
	rm -f sealed_data/private_key
	rm -f sealed_data/fernet_key

sealed_data_dir:
	@$(shell mkdir -p "$(shell pwd)/sealed_data")
	@$(shell chmod 770 "$(shell pwd)/sealed_data")

run-sgx: sealed_data_dir
	docker run -d --rm \
		--name duetadmin-enclave \
		--device=/dev/sgx_enclave:/dev/sgx_enclave \
		-v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
		-v $(shell pwd)/sealed_data:/home/duet/AdminEnclave/sealed --user 1000:1000 \
		-v $(shell pwd)/service_owner_pub_keys:/home/duet/AdminEnclave/service_owner_pub_keys --user 1000:1000 \
		--hostname duetadmin \
		-p 6037:6037 \
		duet/admin-graminized

clean:
	rm -f *.tar.gz
	rm -rf sealed_data/*
