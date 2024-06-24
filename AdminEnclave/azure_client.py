# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

from azure.identity import ManagedIdentityCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient

from .cvm import ConfidentialVM

class AzureClient():
    def __init__(self, config, logger):
        self._config = config
        self._logger = logger

        # Acquire a credential object.
        #credential = DefaultAzureCredential(managed_identity_client_id=managed_identity_client_id)
        self._credential = ManagedIdentityCredential(client_id=self._config["managed_identity_client_id"])
        self._network_client = NetworkManagementClient(self._credential, self._config["subscription_id"])
        self._compute_client = ComputeManagementClient(self._credential, self._config["subscription_id"])

    def setup_subnet(self):
        # Step 3: Provision the subnet and wait for completion
        resource_group_name = self._config["resource_group_name"]
        vnet_name = self._config["vnet_name"]
        subnet_name = self._config["subnet_name"]
        
        poller = self._network_client.subnets.begin_create_or_update(
            resource_group_name,
            vnet_name,
            subnet_name,
            {
                "address_prefix": "10.0.0.0/24"
            },
        )

        subnet_result = poller.result()
        self._logger.info(f"Provisioned virtual subnet {subnet_result.name} with address prefix {subnet_result.address_prefix}")

        return subnet_result

    def setup_ip(self):
        # Step 4: Provision an IP address and wait for completion
        resource_group_name = self._config["resource_group_name"]
        ip_name = self._config["ip_name"]
        location = self._config["location"]
        
        poller = self._network_client.public_ip_addresses.begin_create_or_update(
            resource_group_name,
            ip_name,
            {
                "location": location,
                "sku": {"name": "Standard"},
                "public_ip_allocation_method": "Static",
                "public_ip_address_version": "IPV4",
            },
        )

        ip_address_result = poller.result()
        self._logger.info(f"Provisioned public IP address {ip_address_result.name} with address {ip_address_result.ip_address}")
        
        return ip_address_result

    def setup_nsg(self):
        resource_group_name = self._config["resource_group_name"]
        nsg_name = self._config["nsg_name"]
        location = self._config["location"]

        poller = self._network_client.network_security_groups.begin_create_or_update(
            resource_group_name, 
            nsg_name, 
            {
                "location": location,
            },
        )
        
        nsg_result = poller.result()
        self._logger.info(f"Provisioned network security group {nsg_result.name}")
        
        return nsg_result

    def setup_nic(self, subnet_id, ip_id, nsg_id):
        # Step 5: Provision the network interface client
        resource_group_name = self._config["resource_group_name"]
        nic_name = self._config["nic_name"]
        location = self._config["location"]
        ip_config_name = self._config["ip_config_name"]

        poller = self._network_client.network_interfaces.begin_create_or_update(
            resource_group_name,
            nic_name,
            {
                "location": location,
                "ip_configurations": [
                    {
                        "name": ip_config_name,
                        "subnet": {"id": subnet_id},
                        "public_ip_address": {"id": ip_id},
                    }
                ],
                "network_security_group": {
                    "id": nsg_id
                }
            }
        )

        nic_result = poller.result()
        self._logger.info(f"Provisioned network interface client {nic_result.name}")

        return nic_result

    def setup_nsg_rule(self):
        resource_group_name = self._config["resource_group_name"]
        nsg_name = self._config["nsg_name"]
        
        poller = self._network_client.security_rules.begin_create_or_update(
            resource_group_name,
            nsg_name,
            security_rule_name="allow-ssh",
            security_rule_parameters={
                "properties": {
                    "access": "Allow",
                    "destinationAddressPrefix": "10.0.0.0/24",
                    "destinationPortRange": "22",
                    "direction": "Inbound",
                    "priority": 300,
                    "protocol": "*",
                    "sourceAddressPrefix": "Internet",
                    "sourcePortRange": "*",
                }
            },
        )
        
        nsg_rule_result = poller.result()
        
        return nsg_rule_result

    def provision_cvm(self, serialized_public_key, nic_id):
        # Step 6: Provision the virtual machine
        resource_group_name = self._config["resource_group_name"]
        location = self._config["location"]
        vm_size = self._config["vm_size"]
        vm_name = self._config["vm_name"]
        username = self._config["username"]
        vm_image_tokens = self._config["vm_image_tokens"]
  
        parameters={
            "location": location,
            "properties": {
                "hardwareProfile": {
                    "vmSize": vm_size
                    },
                "networkProfile": {
                    "networkInterfaces": [
                        {
                            "id": nic_id,
                            "properties": {"primary": True},
                        }
                    ]
                },
                "osProfile": {
                    "adminUsername": username,
                        "computerName": vm_name,
                        "linuxConfiguration": {
                            "disablePasswordAuthentication": True,
                            "ssh": {
                                "publicKeys": [
                                    {
                                        "keyData": serialized_public_key,
                                        "path": "/home/" + username + "/.ssh/authorized_keys",
                                    }
                                ]
                            },
                        },
                    }
                },
                "securityProfile": {
                    "encryptionAtHost": True,
                    "securityType": "ConfidentialVM",
                    "uefiSettings": {
                        "secureBootEnabled": True, 
                        "vTpmEnabled": True
                        },
                },
                "storageProfile": {
                    "imageReference": {
                        "publisher": vm_image_tokens[0],
                        "offer": vm_image_tokens[1],
                        "sku": vm_image_tokens[2],
                        "version": vm_image_tokens[3],
                    },
                    "osDisk": {
                        "createOption": "FromImage",
                        "diskSizeGB": 128,
                        "caching": "ReadWrite",
                        "deleteOption": "Delete",
                        "managedDisk": {
                            "securityProfile": {
                                "securityEncryptionType": "DiskWithVMGuestState",
                            },
                            "storageAccountType": "StandardSSD_LRS",
                        },
                    },
                },
            }
        poller = self._compute_client.virtual_machines.begin_create_or_update(
            resource_group_name,
            vm_name,
            parameters
        )

        vm_result = poller.result()

        self._logger.info(f"Provisioned virtual machine {vm_result.name} with username {username}")
        return vm_result

    def provision_resources(self, serialized_public_key):
        subnet_result = self.setup_subnet()
        ip_address_result = self.setup_ip()

        subnet_id = subnet_result.id
        ip_id = ip_address_result.id
        ip_address = ip_address_result.ip_address

        nsg_result = self.setup_nsg()
        nsg_id = nsg_result.id

        nic_result = self.setup_nic(subnet_id, ip_id, nsg_id)
        nic_id = nic_result.id

        nsg_rule_result = self.setup_nsg_rule()
        
        vm_result = self.provision_cvm(serialized_public_key, nic_id)
        
        cvm = ConfidentialVM(self._config["username"], ip_address, serialized_public_key, self._logger)
        
        return cvm

    def delete_resources(self):
        resource_group_name = self._config["resource_group_name"]
        vm_name = self._config["vm_name"]
        nic_name = self._config["nic_name"]
        ip_name = self._config["ip_name"]
        nsg_name = self._config["nsg_name"]

        self._logger.info(f"Deleting the VM: {vm_name}")
        self._compute_client.virtual_machines.begin_delete(resource_group_name, vm_name).result()

        self._logger.info(f"Deleting NIC: {nic_name}")
        self._network_client.network_interfaces.begin_delete(resource_group_name, nic_name).wait()

        self._logger.info(f"Deleting the IP: {ip_name}")
        self._network_client.public_ip_addresses.begin_delete(resource_group_name, ip_name)

        self._logger.info(f"Deleting the NSG: {nsg_name}")
        self._network_client.network_security_groups.begin_delete(resource_group_name, nsg_name).wait()
