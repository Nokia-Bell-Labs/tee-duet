# duet: Combining a Trustworthy Controller with a Confidential Computing Environment

This repository contains the code that is published as part of the artifact evaluation for the paper titled:

duet: Combining a Trustworthy Controller with a Confidential Computing Environment

The paper appears at the Proceedings of the [7th Workshop on System Software for Trusted Execution (SysTEX 2024)](https://systex24.github.io) happening July 8, 2024 in co-location with [EuroS&P'24](https://eurosp2024.ieee-security.org/) July 8-12, 2024, Vienna, Austria.

In this project, we combine two Trusted Execution Environments (TEEs) to work together; hence, the repo name *tee-duet*.

## Repo structure

- `AdminEnclave/` contains the source code for the controller as well as the build scripts to create a container image and building a graminized version that can use the SGX hardware.

- `AdminEnclaveClient/` contains a proof-of-concept client that interacts with the controller, the script to generate a public/private keypair for the service owner and an end-to-end example script.

- `graminize/` contains the necessary files to build the graminized container image for the controller.

- `install_vm_dependencies.sh` is the script that sets up the SGX VM with the necessary software (e.g., SGX libraries, docker, python packages).

- `docker.mk` defines a function for building container images.

## Pre-requisites

1. Create an SGX-capable VM in Azure: Ubuntu 22.04 LTS, Standard_DC2s_v3 (e.g., with name duet-vm) with username (e.g., `duet`)

2. The resource hosting the controller needs to have a role for creation of resources (i.e., Contributor).
In the below examples, the managed identity (i.e., test-man2) has Contributor role.

You can assign the role to the VM with Azure CLI (installable with `sudo apt install azure-cli` on your local machine) or over the web portal.

```
az vm identity assign --resource-group <your-resource-group-name> --name duet-vm --identities test-man2
```

You can check whether the VM has been correctly assigned the identity via:
```
az vm identity show --resource-group <your-resource-group-name> --name duet-vm
```

3. Then copy the repo to the VM and ssh into it.

4. The following script configures dependencies and installs necessary packages.

```
chmod +x install_vm_dependencies.sh
./install_vm_dependencies.sh
```
Note the above script adds the user `duet` to docker group. If you have a different username, please modify the script to match it.

## Setup

Some operations in the controller are privileged operations. They are only supposed to be invoked by the service owner. To authenticate the service owner, we use the service owner's public key and verify the signature on the operations requested by the client.

The service owner public key needs to be available to the controller. We supply a folder with the public key at the initialization time of the controller. Note that this is a rudimentary approach; one can also create a new interface in the controller, in which a service owner registers its public key. We leave this as future work.

To generate the public key and store it, do the following:

```
cd AdminEnclaveClient
python3 generate_private_key.py
```

This will produce `AdminEnclaveClient/service_owner_private_key` and `AdminEnclave/service_owner_pub_keys/service_owner_private_key.pub`.

## Running with SGX

1. Build the gramine image that will help creating duet's controller in a graminized container.

```
make -C graminize gramine-image
```

2. Copy `AdminEnclave/azure_config.env.template` as `AdminEnclave/azure_config.env` and modify its contents to enter your Azure related information.

Note that any changes to this file will require re-building the controller docker image and the sub-sequent graminized version.

3. Then build the controller.

```
make -C AdminEnclave graminize
```

4. Afterwards, one can instantiate the controller as

```
make -C AdminEnclave run-sgx
```

5. Then, you can run the demo test script. It will request a new CVM, run some commands on it, mark it `in-service`, try to run more commands (which will fail), get the CVM's state via controller logs, and finally stop the CVM.

First make sure that the requirements are installed:

```
cd AdminEnclaveClient
python3 -m pip install -r requirements.txt
```

Then you can run the example end-to-end test script using the interface as a service owner.

```
./test_end_to_end.sh
```

You can also utilize the client independently. For usage and examples, please check the contents of the `test_end_to_end.sh` script.

## Troubleshooting

Currently, there is not much fault tolerance and error propagation. Please refer to the following steps for debugging any issues.

1. Sometimes, the managed identity is removed from the Azure VM. It is not clear why this happens. 
As a result, the controller fails performing some provisioning operations for the CVM and throws an error.
Please retry the commands from the client side.

2. When there is an error at the client, the reason usually is an error not propagated from the server. 
To see what went wrong, one can use `docker logs duetadmin-enclave`.

## Run direct mode

Alternatively, one can also run the controller without the SGX. This is useful for debugging/developing the controller code.
First, install the dependencies:

```
pip3 install -r AdminEnclave/requirements.txt
```

Then run the controller:

```
python3 -m AdminEnclave.admin -t direct
```

The client will work normally; however, it will print a warning message that the quote was not valid.

## Controller details for Azure

1. The controller provisions Azure resources to set up the CVM.

Currently, one can launch an AMD SEV-SNP or an Intel TDX machine.

```
python3 duet_admin_client.py --action start-cvm --cvm-type snp
python3 duet_admin_client.py --action start-cvm --cvm-type tdx
```

2. For an SEV-SNP, the controller provisions a Standard_DC2ads_v5 machine with 2 vCPUs.
For an Intel TDX, the controller provisions a Standard_DC2eds_v5 machine with 2 vCPUs.

Therefore, quotas in the resource group should be increased if necessary.

3. As a basis for the CVM, the standard Ubuntu 22.04 image designated for confidential computing is used (canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest).

4. The controller launches the CVM with the following security profile (see `AzureClient:provision_cvm() function in AdminEnclave/azure_client.py`):

```
"securityProfile": {
                    "encryptionAtHost": True,
                    "securityType": "ConfidentialVM",
                    "uefiSettings": {
                        "secureBootEnabled": True, 
                        "vTpmEnabled": True
                        },
                },
```

For these reasons, the Azure environment needs to be configured to allow these requests.

5. The controller creates a separate virtual network and a default subnet in that virtual network for the CVM being launched.

6. Note that not all locations may have CVM-capable machines.
We tested the launch of the controller and the CVMs in location `westeurope`, in which both types of VMs were available.
It is also suggested to use the same location for the controller and the CVM (i.e., as defined in `AdminEnclave/azure_config.env`).