#!/bin/bash

# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# The entrypoint for all graminized containers

set -e

#gramine-sgx /gramine/app_files/entrypoint
gramine-sgx entrypoint