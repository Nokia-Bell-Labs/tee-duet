# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

from argparse import ArgumentParser
import json
import logging
from logging.config import dictConfig
import os
import random
import sys
import signal
import time

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

from dotenv import load_dotenv

from flask import Flask, request, jsonify

from .azure_client import AzureClient
from .utils.encoding import stringify, bytes_to_base64_str, decode_base64
from .utils.crypto import generate_rsa_keypair, generate_ephemeral_rsa_key_for_cvm,\
                        decrypt_data_with_private_key, decrypt_data_with_private_key_pem,\
                        encrypt_data_with_public_key, encrypt_data_with_public_key_pem,\
                        verify_signature_with_public_key, verify_signature_with_public_key_pem,\
                        sign_data_with_private_key, sign_data_with_private_key_pem

dictConfig({
    "version": 1,
    "formatters": {"default": {
        "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
    }},
    "handlers": {"wsgi": {
        "class": "logging.StreamHandler",
        "formatter": "default"
    }},
    "root": {
        "level": "INFO",
        "handlers": ["wsgi"]
    }
})

app = Flask(__name__)
entrypoint = "/"

DUET_ADMIN = None

CVMs = {}

def _extend_config(config, cvm_type):
    config["vm_image"] = os.getenv("VM_IMAGE", "canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest")
    config["username"] = "duet"

    config["vm_image_tokens"] = config["vm_image"].split(":")

    config["cvm_type"] = cvm_type
    if cvm_type == "snp":
        config["vm_size"] = "Standard_DC2ads_v5"
    elif cvm_type == "tdx":
        config["vm_size"] = "Standard_DC2eds_v5"

    config["vm_name"] = config["prefix"] + "-cvm-" + cvm_type + "-" + str(random.randint(1000, 3000))

    vm_name = config["vm_name"]
    config["nsg_name"] = vm_name + "-nsg"
    config["nic_name"] = vm_name + "-nic"
    config["ip_name"] = vm_name + "-ip"
    config["ip_config_name"] = vm_name + "-ip-config"

    return config

def _load_configuration_env(env_filename="/home/duet/AdminEnclave/azure_config.env"):
    load_dotenv(dotenv_path=env_filename)

    config = {}
    config["subscription_id"] = os.getenv("SUBSCRIPTION_ID")
    config["managed_identity_client_id"] = os.getenv("MANAGED_IDENTITY_CLIENT_ID")

    config["location"] = os.getenv("LOCATION")
    config["resource_group_name"] = os.getenv("RESOURCE_GROUP_NAME")
    config["vnet_name"] = os.getenv("VNET_NAME")
    config["subnet_name"] = os.getenv("SUBNET_NAME")

    config["prefix"] = os.getenv("PREFIX")
    if any([config[p] is None for p in config]):
        app.logger.info("[ERROR]: empty environment variable(s)")
        app.logger.info(json.dumps(config, indent=4))
        return None

    return config

class DuetAdmin():
    def __init__(self, environment, logger):
        self._logger = logger
        self._private_key = None
        self._public_key = None
        self._serialized_public_key = None
        self._environment = environment
        self._service_owner_public_key_pem = None

        if self._environment == "direct":
            self._init_key_pair()
            with open("AdminEnclave/service_owner_pub_keys/service_owner_private_key.pub", "rb") as f:
                self._service_owner_public_key_pem = f.read()

    def _init_key_pair(self):
        # Generate a new RSA key pair
        self._public_key, self._private_key = generate_rsa_keypair(4096)

        self._serialized_public_key = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self._logger.info("Generated new RSA key pair.")

    def get_public_key(self):
        return self._serialized_public_key

    # Function to decrypt using RSA private key
    def _decrypt_data(self, encrypted_data: bytes) -> bytes:
        return decrypt_data_with_private_key(encrypted_data, self._private_key)

    def _sign_data(self, data: bytes) -> bytes:
        return sign_data_with_private_key(data, self._private_key)

    def _verify_signature_for_privileged_operation(self, request_data):
        params = request_data["params"]
        signature = decode_base64(request_data["signature"])

        return verify_signature_with_public_key_pem(signature, bytes(json.dumps(params, sort_keys=True), "utf-8"), self._service_owner_public_key_pem)

    def start_cvm(self, request_data):
        result = {}
        result["success"] = False
        
        verified = self._verify_signature_for_privileged_operation(request_data)

        if verified:
            cvm_type = request_data["params"]["cvm_type"]
            assert cvm_type in ["snp", "tdx"]

            if self._environment == "sgx":
                config = _load_configuration_env()
            elif self._environment == "direct":
                config = _load_configuration_env("AdminEnclave/azure_config.env")

            config = _extend_config(config, cvm_type)
            # 1. create an azure client
            azure_client = AzureClient(config, app.logger)

            # 2. create an ephemeral RSA keypair to be used for login
            serialized_public_key, serialized_private_key = generate_ephemeral_rsa_key_for_cvm()
            #app.logger.info(serialized_public_key)
            #app.logger.info(serialized_private_key)
            
            # don't need to write them to a file
            # can be used for debugging
            #with open("ephemeral_private_key", "w") as f:
            #    f.write(serialized_private_key)
            #os.chmod("ephemeral_private_key", 0o600)
            #with open("ephemeral_private_key.pub", "w") as f:
            #    f.write(serialized_public_key)

            # 3. use the azure client to provision resources
            cvm = azure_client.provision_resources(serialized_public_key)

            cvm.set_private_key(serialized_private_key)
            
            cvm.set_config(config)

            # give time to azure to update firewall rules etc.
            time.sleep(30)

            # initial installation
            cvm.connect()

            filepath = "AdminEnclave/"
            if self._environment == "sgx":
                filepath = "/home/duet/" + filepath

            commands_filename = cvm.get_cvm_type() + "_cvm_commands.sh"

            cvm.copy_file(filepath, commands_filename)

            output = []
            initial_commands = ["chmod +x " + commands_filename, "./" + commands_filename]
            for command in initial_commands:
                command_output = cvm.execute_command(command)
                output.extend(command_output)
                time.sleep(3)

            cvm.disconnect()

            state = cvm.get_current_state()
            
            global CVMs
            cvm_id = cvm.get_cvm_id()
            CVMs[cvm_id] = cvm

            self._logger.info(f"cvm_id: {cvm_id}")
            
            result["success"] = True
            result["state"] = state
        else:
            result["error"] = "start-cvm: Starting a new CVM is a privileged operation for the service owner."

        signature = self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))

        return result, signature

    def run_commands(self, request_data):
        result = {}
        result["success"] = False

        verified = self._verify_signature_for_privileged_operation(request_data)

        if verified:
            cvm_id = request_data["params"]["cvm_id"]
            commands = request_data["params"]["commands"]

            global CVMs
            if cvm_id in CVMs:
                cvm = CVMs[cvm_id]
                if cvm.get_cvm_mode() == "in-update":
                    # 4. connect to the CVM and install packages
                    # 5. execute a command and obtain result
                    cvm.connect()
                    
                    output = []
                    for command in commands:
                        output.extend(cvm.execute_command(command))
                        time.sleep(3)

                    cvm.disconnect()
                    
                    result["success"] = True
                    result["output"] = output
                else:
                    result["error"] = "run-commands: Running commands not allowed while CVM is in service."
            else:
                result["error"] = "run-commands: No such CVM."
        else:
            result["error"] = "run-commands: Running commands on a CVM is a privileged operation for the service owner."

        signature = self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))

        return result, signature

    def get_cvm_state(self, cvm_id, should_be_long):
        result = {}
        result["success"] = False

        global CVMs
        if cvm_id in CVMs:
            state = CVMs[cvm_id].get_current_state(should_be_long)

            result["success"] = True
            result["state"] = state
        else:
            result["error"] = "get-cvm-state: No such CVM."

        signature = self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))
        
        return result, signature

    def mark_cvm(self, request_data):
        result = {}
        result["success"] = False
        
        verified = self._verify_signature_for_privileged_operation(request_data)

        if verified:
            cvm_id = request_data["params"]["cvm_id"]
            cvm_mode = request_data["params"]["cvm_mode"]
            assert cvm_mode in ["in-update", "in-service"]

            global CVMs
            if cvm_id in CVMs:
                if cvm_mode == "in-update":
                    # TODO: clear out CVM's confidential data and keys
                    pass
                CVMs[cvm_id].set_cvm_mode(cvm_mode)
                mode = {}
                mode["cvm_id"] = cvm_id
                mode["cvm_mode"] = CVMs[cvm_id].get_cvm_mode()
                
                result["success"] = True
                result["mode"] = mode
            else:
                result["error"] = "mark-cvm: No such CVM."
        else:
            result["error"] = "mark-cvm: Changing the mode of a CVM is a privileged operation for the service owner."
        
        signature = self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))
        
        return result, signature

    def stop_cvm(self, request_data):
        result = {}
        result["success"] = False
        
        verified = self._verify_signature_for_privileged_operation(request_data)

        if verified:
            cvm_id = request_data["params"]["cvm_id"]

            global CVMs
            if cvm_id in CVMs:
                cvm = CVMs[cvm_id]
                config = cvm.get_config()
                azure_client = AzureClient(config, app.logger)
                azure_client.delete_resources()
                
                result["success"] = True
                result["status"] = True
            else:
                result["error"] = "stop-cvm: No such CVM."
        else:
            result["error"] = "stop-cvm: Stopping a CVM is a privileged operation for the service owner."

        signature = self._sign_data(bytes(json.dumps(result, sort_keys=True), "utf-8"))

        return result, signature

class DuetAdminEnclave(DuetAdmin):
    def __init__(self, environment, logger):
        super().__init__(environment, logger)

        with open("/home/duet/AdminEnclave/service_owner_pub_keys/service_owner_private_key.pub", "rb") as f:
            self._service_owner_public_key_pem = f.read()

        self._init_key_pair()

        self._write_enclave_report_data()

        # Initialize the enclave
        # The path to the tmps in-memory file
        self.tmp_path = "/tmp"
        sys.path.append(self.tmp_path)

    def _init_key_pair(self):
        sealed_key = "/home/duet/AdminEnclave/sealed/private_key"
        if os.path.isfile(sealed_key):
            with open(sealed_key, "rb") as f:
                private_key_pem = f.read()
            private_key  = serialization.load_pem_private_key(
                private_key_pem,
                password=None
            )
            self._private_key = private_key
            self._public_key = self._private_key.public_key()
            self._serialized_public_key = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self._logger.info(f"Loaded RSA key from sealed file `{sealed_key}`")

        else:
            super()._init_key_pair()
            # Seal serialized private key to a file
            while True:
                try:
                    with open(sealed_key, "wb") as f:
                        private_key_pem = self._private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        )
                        f.write(private_key_pem)
                        self._logger.info(f"Stored sealed RSA key in file `{sealed_key}`")
                        break
                except Exception as exc:
                    self._logger.error(exc)
                    time.sleep(1)

    def _write_enclave_report_data(self):
        # Write the secure hash of the public key into the user_report_data
        hash_object = hashes.Hash(hashes.SHA256())
        hash_object.update(self._serialized_public_key)
        try:
            with open("/dev/attestation/user_report_data", "wb") as f:
                f.write(hash_object.finalize())
        except Exception as exc:
            raise exc

    def get_quote(self) -> bytes:
        with open ("/dev/attestation/attestation_type") as f:
            self.attestation_type = f.read()
        try:
            with open("/dev/attestation/quote", "rb") as f:
                quote = f.read()
        except Exception as e:
            message = ("Cannot find `/dev/attestation/quote`; "
                       "are you running with remote attestation enabled?")
            raise type(e)(message).with_traceback(e.__traceback__)
        return quote

    
class DuetAdminFactory:
    @staticmethod
    def create_duet_admin(environment="direct"):
        duet_admin = None
        if environment == "direct":
            duet_admin = DuetAdmin(environment, logger=app.logger)
        elif environment == "sgx":
            duet_admin = DuetAdminEnclave(environment, logger=app.logger)
        else:
            app.logger.error(f"create_duet_admin {environment}: Unknown environment type.")
        return duet_admin

def get_enclave_quote_and_key():
    quote = b""
    if isinstance(DUET_ADMIN, DuetAdminEnclave):
        quote = DUET_ADMIN.get_quote()
    public_key = DUET_ADMIN.get_public_key()
    return quote, public_key

@app.route(f"{entrypoint}/quote", methods=["GET"])
def handle_quote_and_key_request():
    quote, key = get_enclave_quote_and_key()
    response = {}
    response["quote"] = stringify(quote)
    response["public_key"] = stringify(key)
    return jsonify(response), 200

@app.route(f"{entrypoint}/start_cvm", methods=["POST"])
def handle_request_start_cvm():
    request_data = request.get_json()

    global DUET_ADMIN
    result, signature = DUET_ADMIN.start_cvm(request_data)
    
    response = {}
    response["result"] = result
    response["signature"] = bytes_to_base64_str(signature)
    return jsonify(response), 200

@app.route(f"{entrypoint}/run_commands", methods=["POST"])
def handle_request_run_commands():
    request_data = request.get_json()

    global DUET_ADMIN
    result, signature = DUET_ADMIN.run_commands(request_data)
    
    response = {}
    response["result"] = result
    response["signature"] = bytes_to_base64_str(signature)
    return jsonify(response), 200

@app.route(f"{entrypoint}/get_cvm_state", methods=["POST"])
def handle_request_get_cvm_state():
    request_data = request.get_json()
    cvm_id = request_data["params"]["cvm_id"]
    should_be_long = request_data["params"]["should_be_long"]
    
    global DUET_ADMIN
    result, signature = DUET_ADMIN.get_cvm_state(cvm_id, should_be_long)
    
    response = {}
    response["result"] = result
    response["signature"] = bytes_to_base64_str(signature)
    return jsonify(response), 200

@app.route(f"{entrypoint}/mark_cvm", methods=["POST"])
def handle_request_mark_cvm():
    request_data = request.get_json()
    
    global DUET_ADMIN
    result, signature = DUET_ADMIN.mark_cvm(request_data)
    
    response = {}
    response["result"] = result
    response["signature"] = bytes_to_base64_str(signature)
    return jsonify(response), 200

@app.route(f"{entrypoint}/stop_cvm", methods=["POST"])
def handle_request_stop_cvm():
    request_data = request.get_json()

    global DUET_ADMIN
    result, signature = DUET_ADMIN.stop_cvm(request_data)

    response = {}
    response["result"] = result
    response["signature"] = bytes_to_base64_str(signature)
    return jsonify(response), 200

def parse_args():
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", default=6037, help="Server port")
    parser.add_argument("-t", "--type", choices=["direct", "sgx"], default="sgx", help="TEE type for duet/admin")
    parser.add_argument("--service-owner-public-key-file", default="service-owner-public-key.pub")
    args = parser.parse_args()
    return args

# Register a signal handler for SIGINT
def handle_sigint(signal, frame):
    app.logger.info("SIGINT received. Stopping DuetAdmin...")
    sys.exit()

def main():
    app.logger.setLevel(logging.INFO)

    logger = logging.getLogger("azure")
    logger.setLevel(logging.WARNING)
    
    logger = logging.getLogger("azure.core.pipeline.policies.http_logging_policy")
    logger.setLevel(logging.ERROR)

    # Attach the signal handler to SIGINT
    signal.signal(signal.SIGINT, handle_sigint)

    args = parse_args()
    port = args.port

    app.logger.info(f"Starting duet/admin in `{args.type}` mode...")

    global DUET_ADMIN
    DUET_ADMIN = DuetAdminFactory.create_duet_admin(args.type)

    app.run(port=port, host="0.0.0.0", threaded=True, load_dotenv=False)

if __name__ == "__main__":
    main()

    '''
    # TESTING
    cvm = ConfidentialVM("duet", "13.95.141.84")
    with open("ephemeral_private_key", "r") as f:
        pkey = f.read()
    cvm.set_private_key(pkey)
    cvm.connect()
    for command in ["df -h", "python3 --version"]:
        cvm.execute_command(command)
        time.sleep(3)

    cvm.disconnect()
    '''
