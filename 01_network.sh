#!/bin/bash

# Load the configuration file
CONFIG_FILE="$(dirname "${BASH_SOURCE[0]}")/00_config"
echo "*** Loading config file ${CONFIG_FILE} ***"
source ${CONFIG_FILE}

az group create \
    --name ${resourceGroupName} \
    --location ${location}

az network vnet create \
    --name ${vnet} \
    --resource-group ${resourceGroupName} \
    --address-prefix 10.0.0.0/16 \
    --subnet-name ${subnet} \
    --subnet-prefixes 10.0.16.0/20

az network vnet subnet update \
  --name ${subnet} \
  --vnet-name ${vnet} \
  --resource-group ${resourceGroupName} \
  --service-endpoints Microsoft.ContainerRegistry Microsoft.AzureCosmosDB

