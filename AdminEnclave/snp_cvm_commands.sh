#!/bin/bash

# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

set -x

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --yes build-essential libcurl4-openssl-dev libjsoncpp-dev libboost-all-dev cmake nlohmann-json3-dev jq unzip

wget https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/azguestattestation1_1.0.5_amd64.deb

sudo dpkg -i azguestattestation1_1.0.5_amd64.deb

wget https://github.com/Azure/confidential-computing-cvm-guest-attestation/archive/refs/heads/main.zip

unzip main.zip

cd ~/confidential-computing-cvm-guest-attestation-main/cvm-attestation-sample-app
cmake .
make 
sudo ./AttestationClient -o token > attestation_token.txt

cat attestation_token.txt | cut -d "." -f 1 | base64 -d 2>/dev/null | jq .
cat attestation_token.txt | cut -d "." -f 2 | base64 -d 2>/dev/null | jq .
