#!/bin/bash

# Load the configuration file
CONFIG_FILE="$(dirname "${BASH_SOURCE[0]}")/00_config"
echo "*** Loading config file ${CONFIG_FILE} ***"
source ${CONFIG_FILE}

echo "*** Creating NSG <${vmnsg}> ***"
az network nsg create \
	--resource-group ${resourceGroupName} \
	--location ${location} \
	--name ${vmnsg}

echo "*** Creating NSG rule in <${vmnsg}> to allow inbound SSH traffic ***"
az network nsg rule create \
		--resource-group ${resourceGroupName} \
		--nsg-name ${vmnsg} \
		--name Allow-SSH \
		--access Allow \
		--protocol Tcp \
		--direction Inbound \
		--priority 300 \
		--source-address-prefix ${allowedIPs} \
		--source-port-range "*" \
		--destination-address-prefix "*" \
		--destination-port-range 22

echo "*** Associating <${vmnsg}> with the subnet <${subnet}> ***"
az network vnet subnet update \
		--vnet-name ${vnet} \
		--name ${subnet} \
		--network-security-group ${vmnsg}

echo "*** Creating public IP address <${vmPublicIp}> ***"
az network public-ip create \
		--name ${vmPublicIp} \
		--allocation-method Static

echo "***Creating NIC <${vmnic}> for subnet <${subnet}> ***"
az network nic create \
		--vnet-name ${vnet} \
		--subnet ${subnet} \
		--name ${vmnic} \
		--public-ip-address ${vmPublicIp}

az vm create \
		--resource-group ${resourceGroupName} \
		--name ${vmName} \
		--size ${vmSize} \
		--nics ${vmnic} \
		--admin-username ${vmUser} \
		--ssh-key-values ${sshKeyFile} \
		--authentication-type ssh \
		--image ${vmImage} \
		--os-disk-size-gb 128 \
		--storage-sku StandardSSD_LRS \
		--public-ip-sku Standard \
		--enable-secure-boot true \
		--encryption-at-host

az vm create \
		--resource-group ${resourceGroupName} \
		--name ${vmName} \
		--size ${vmSize} \
		--nics ${vmnic} \
		--admin-username ${vmUser} \
		--ssh-key-values ${sshKeyFile} \
		--authentication-type ssh \
		--image ${vmImage} \
		--os-disk-size-gb 128 \
		--storage-sku StandardSSD_LRS \
		--public-ip-sku Standard \
		--enable-secure-boot true \
		--encryption-at-host