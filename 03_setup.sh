#!/bin/bash

# Load the configuration file
CONFIG_FILE="$(dirname "${BASH_SOURCE[0]}")/00_config"
echo "*** Loading config file ${CONFIG_FILE} ***"
source ${CONFIG_FILE}

vmIpAddress=$(get_ip ${vmName})
echo "*** Public IP for VM <${vmName}>: $vmIpAddress ***"

az vm identity assign --resource-group NITSbx-NPR-EUW-SSRSBOX-rg --name duet-vm --identities test-man2

# copy dependencies installation script and run it
scp -i ${sshKeyFilePrivate} install_vm_dependencies.sh ${vmUser}@${vmIpAddress}:install_vm_dependencies.sh

sleep 1

ssh -i ${sshKeyFilePrivate} ${vmUser}@${vmIpAddress} -t 'pwd; chmod +x ~/install_vm_dependencies.sh; ./install_vm_dependencies.sh'

