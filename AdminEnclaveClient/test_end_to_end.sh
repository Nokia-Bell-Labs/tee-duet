#!/bin/bash

# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

start_output=$(python3 duet_admin_client.py --action start-cvm --cvm-type snp)
echo "${start_output}"

CVM_ID=$(echo "${start_output}" | grep "started cvm_id" | awk '{print $NF}')
echo "cvm_id: $CVM_ID"
echo "========================================"

sleep 3

python3 duet_admin_client.py --cvm-id $CVM_ID --action run-commands --command "python3 --version"

sleep 3

python3 duet_admin_client.py --cvm-id $CVM_ID --action mark-cvm --cvm-mode in-service

sleep 3

python3 duet_admin_client.py --cvm-id $CVM_ID --action run-commands --command "python3 --version"

sleep 3

python3 duet_admin_client.py --cvm-id $CVM_ID --action get-cvm-state-long

sleep 3

python3 duet_admin_client.py --cvm-id $CVM_ID --action stop-cvm
