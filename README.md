# duet: Combining a Trustworthy Controller with a Confidential Computing Environment

This repository contains the code that is published as part of the artifact evaluation for the paper titled:

duet: Combining a Trustworthy Controller with a Confidential Computing Environment

The paper appears at the Proceedings of the [7th Workshop on System Software for Trusted Execution (SysTEX 2024)](https://systex24.github.io) happening July 8, 2024 in co-location with [EuroS&P'24](https://eurosp2024.ieee-security.org/) July 8-12, 2024, Vienna, Austria.

In this project, we combine two Trusted Execution Environments (TEEs) to work together; hence, the repo name *tee-duet*.

## Pre-requisites

1. Create an SGX-capable VM in Azure: Ubuntu 22.04 LTS, Standard_DC2s_v3 (e.g., with name duet-vm) with username (e.g., `duet`)

2. The resource hosting the controller needs to have a role for creation of resources (i.e., Contributor).
In the below examples, the managed identity (i.e., test-man2) has Contributor role.

You can assign the role to the VM with Azure CLI (installable with `sudo apt install azure-cli` on your local machine) or over the web portal.

```
az vm identity assign --resource-group NITSbx-NPR-EUW-SSRSBOX-rg --name duet-vm --identities test-man2
```

You can check whether the VM has been correctly assigned the identity via:
```
az vm identity show --resource-group NITSbx-NPR-EUW-SSRSBOX-rg --name duet-vm
```

3. Then copy the repo to the VM and ssh into it.

4. Copy `AdminEnclave/azure_config.env.template` as `AdminEnclave/azure_config.env` and modify its contents to enter your Azure related information.

5. The following script configures dependencies and installs necessary packages.

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

2. Then build the controller.

```
make -C AdminEnclave graminize
```

3. Afterwards, one can instantiate the controller as

```
make -C AdminEnclave run-sgx
```

4. Then, you can run the demo test script. It will request a new CVM, run some commands on it, mark it `in-service`, try to run more commands (which will fail), get the CVM's state via controller logs, and finally stop the CVM.

```
cd AdminEnclaveClient
./test_end_to_end.sh
```

You can also utilize the client independently. For usage and examples, please check the contents of the `test_end_to_end.sh` script.

Note that sometimes, the managed identity is removed from the Azure VM. It is not clear why this happens. 
As a result, the controller fails performing some provisioning operations for the CVM and throws an error (i.e., no fault tolerance yet).
Please retry the command from the client side.

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

