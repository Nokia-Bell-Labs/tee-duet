#!/bin/bash

# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

set -x

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --yes build-essential libcurl4-openssl-dev libjsoncpp-dev libboost-all-dev cmake nlohmann-json3-dev jq unzip

wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb
sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2_amd64.deb

wget https://github.com/Azure/confidential-computing-cvm-guest-attestation/archive/refs/heads/tdx-preview.zip

unzip tdx-preview.zip

cd ~/confidential-computing-cvm-guest-attestation-tdx-preview/tdx-attestation-app

sudo dpkg -i package/azguestattestation1_1.0.3_amd64.deb

cmake .
make

sudo ./TdxAttest -c maa_config.json | tail -2 > attestation_token.txt

cat attestation_token.txt | cut -d "." -f 1 | base64 -d 2>/dev/null | jq .
cat attestation_token.txt | cut -d "." -f 2 | base64 -d 2>/dev/null | jq .
