# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

from argparse import ArgumentParser
import base64
from email.policy import default
from enum import Enum
import json
import logging
import sys

from azure.identity import DefaultAzureCredential
from azure.security.attestation import AttestationClient

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

import requests

# Convert bytes object to serializble string representation
def bytes_to_base64_str(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

# Decode base64-encoded data
def decode_base64(input_str :str) -> bytes:
    v = input_str.encode("utf-8")
    if len(v) % 4 != 0:
        decoded_value = input_str
    else:
        try:
            decoded_value = base64.b64decode(v)
        except Exception as exc:
            decoded_value = input_str

    return decoded_value

ATTESTATION_SERVICE_URL="https://sharedneu.neu.attest.azure.net"

def _verify_quote(quote, enclave_key):
    # Check the quote via remote attestation
    # use the internal checks to validate the token's properties
    # if the quote is not valid, there will be an exception
    try:
        attest_client = AttestationClient(
            endpoint=ATTESTATION_SERVICE_URL,
            credential=DefaultAzureCredential(),
            validate_token=True,
            validate_signature=True,
            validate_issuer=True,
            issuer=ATTESTATION_SERVICE_URL,
            validate_expiration=True,
            #validation_callback=validate_token
            )

        response, token = attest_client.attest_sgx_enclave(quote, runtime_data=enclave_key)

    except Exception as exc:
        #print(exc)
        return False

    return True

def _verify_public_key_hash(key_hash_recvd, enclave_key):
    if not isinstance(enclave_key, bytes):
        enclave_key = bytes(enclave_key, "utf-8")

    key_hash_calc = hashes.Hash(hashes.SHA256())
    key_hash_calc.update(enclave_key)
    calculated_hash_digest = key_hash_calc.finalize().hex()

    if calculated_hash_digest == key_hash_recvd:
        return True

    return False

def _verify_expected_mrenclave(mrenclave_received, mrenclave_expected):
    if mrenclave_received == mrenclave_expected:
        return True

    return False

def verify_remote_enclave(remote_quote, remote_public_key, expected_mrenclave):
    if not isinstance(remote_quote, bytes):
        remote_quote = bytes(remote_quote, "utf-8")

    if not isinstance(remote_public_key, bytes):
        remote_public_key = bytes(remote_public_key, "utf-8")

    remote_quote = base64.b64decode(remote_quote)

    if not _verify_quote(remote_quote, remote_public_key):
        return False

    if not _verify_public_key_hash(remote_quote[368:400].hex(), remote_public_key):
        return False

    # TODO: check attributes, mrenclave, mrsigner, isvprodid, isvsvn
    #if not _verify_expected_mrenclave(remote_quote[112:144].hex(), expected_mrenclave):
    #    return False

    return True

# Generate an ephemeral RSA keypair for controller's messages for us
def generate_client_ephemeral_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, public_key_pem

class DuetAdminClient():
    def __init__(self, base_url, service_owner_private_key_file=None):
        self._base_url = base_url

        if service_owner_private_key_file:
            with open(service_owner_private_key_file, "rb") as f:
                serialized_private_key = f.read()
                self._service_owner_private_key = load_pem_private_key(serialized_private_key, None, default_backend())
                self._service_owner_public_key = self._service_owner_private_key.public_key()

        self._controller_public_key = None
        self._controller_quote_verified = False

        self._client_private_key, self._client_public_key = generate_client_ephemeral_rsa_keypair()
        self._verify_controller()

    def _sign_data(self, data: bytes) -> bytes:
        signature = self._service_owner_private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def _encrypt_data_for_controller(self, data):
        return data
        # TODO: encrypt the data sent to the controller
        if not isinstance(data, bytes):
            data = bytes(data, "utf-8")
        
        cipher = self._controller_public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return cipher

    def _prepare_data_for_controller(self, params, is_privileged=False):
        data = {}
        data["params"] = params

        if is_privileged:
            signature = self._sign_data(bytes(json.dumps(params, sort_keys=True), "utf-8"))
            data["signature"] = bytes_to_base64_str(signature)

        encrypted_data = self._encrypt_data_for_controller(data)

        return encrypted_data

    def _make_request_to_controller(self, url: str, params: dict, is_privileged: bool) -> tuple[dict, int]:
        encrypted_data = self._prepare_data_for_controller(params, is_privileged)

        try:
            response = requests.post(url, json=encrypted_data)
            response_code = response.status_code
            response_data = response.json()
            return response_data, response_code
        except requests.exceptions.RequestException as exc:
            print("Request encountered an exception:", exc)
            raise

    def _verify_controller(self):
        response_data, responce_code = self.get_controller_quote()

        quote = response_data["quote"]
        public_key = bytes(response_data["public_key"], "utf-8")

        self._controller_quote_verified = verify_remote_enclave(quote, public_key, "")
        print(f"Valid SGX controller: {self._controller_quote_verified}")
        if not self._controller_quote_verified:
            print(f"[WARNING]: Unverified SGX controller.")

        self._controller_public_key = load_pem_public_key(public_key)
    
    def _verify_controller_signature(self, signature, data):
        if not isinstance(signature, bytes):
            signature = bytes(signature, "utf-8")

        if not isinstance(data, bytes):
            data = bytes(data, "utf-8")
    
        try:
            self._controller_public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256())
            return True
        except Exception as exc:
            raise

    # non-privileged operation to establish trust in the controller
    def get_controller_quote(self):
        url = self._base_url + "/quote"
        try:
            response = requests.get(url)
            response_code = response.status_code
            response_data = response.json()
            return response_data, response_code
        except requests.exceptions.RequestException as exc:
            print("Request encountered an exception:", exc)
            raise
    
    # privileged operation to set up a new CVM
    # request must be signed with service owner's private key, so that the controller can check
    def start_cvm(self, cvm_type):
        url = self._base_url + "/start_cvm"
        params = {"cvm_type": cvm_type}
        response_data, response_code = self._make_request_to_controller(url, params, is_privileged=True)
        
        result = response_data["result"]
        signature = response_data["signature"]
        verified = self._verify_controller_signature(decode_base64(signature), bytes(json.dumps(result, sort_keys=True), "utf-8"))
        if not verified:
            return None

        return result

    # non-privileged operation
    def get_cvm_state(self, cvm_id, should_be_long=False):
        url = self._base_url + "/get_cvm_state"
        params = {"cvm_id": cvm_id, "should_be_long": should_be_long}

        response_data, response_code = self._make_request_to_controller(url, params, is_privileged=False)

        result = response_data["result"]
        signature = response_data["signature"]
        verified = self._verify_controller_signature(decode_base64(signature), bytes(json.dumps(result, sort_keys=True), "utf-8"))
        if not verified:
            return None
        else:
            state = result["state"]
            if should_be_long:
                list_name = "command_outputs"
                param_name = "output"
            else:
                list_name = "command_output_hashes"
                param_name = "output_hash"

            for entry in state[list_name]:
                command = entry["command"]
                print("command: " + command)
                print("-" * 20)
                output = entry[param_name]

                for line in output:
                    print(line, end="")
                
                print("=" * 20)
        
        return result

    def run_commands(self, cvm_id, commands):
        url = self._base_url + "/run_commands"
        params = {"cvm_id": cvm_id, "commands": commands}

        response_data, response_code = self._make_request_to_controller(url, params, is_privileged=True)

        result = response_data["result"]
        signature = response_data["signature"]
        verified = self._verify_controller_signature(decode_base64(signature), bytes(json.dumps(result, sort_keys=True), "utf-8"))
        if not verified:
            return None

        return result

    def mark_cvm(self, cvm_id, cvm_mode):
        url = self._base_url + "/mark_cvm"
        params = {"cvm_id": cvm_id, "cvm_mode": cvm_mode}

        response_data, response_code = self._make_request_to_controller(url, params, is_privileged=True)

        result = response_data["result"]
        signature = response_data["signature"]
        verified = self._verify_controller_signature(decode_base64(signature), bytes(json.dumps(result, sort_keys=True), "utf-8"))
        if not verified:
            return None

        return result

    def stop_cvm(self, cvm_id):
        url = self._base_url + "/stop_cvm"
        params = {"cvm_id": cvm_id}

        response_data, response_code = self._make_request_to_controller(url, params, is_privileged=True)

        result = response_data["result"]
        signature = response_data["signature"]
        verified = self._verify_controller_signature(decode_base64(signature), bytes(json.dumps(result, sort_keys=True), "utf-8"))
        if not verified:
            return None

        return result

def parse_args():
    parser = ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:6037", help="Controller URL")
    parser.add_argument("--service-owner-private-key-file", default="service_owner_private_key", help="Service owner private key to sign privileged commands")
    parser.add_argument("--action", required=True, choices=["start-cvm", "stop-cvm", "run-commands", "get-cvm-state", "get-cvm-state-long", "mark-cvm"])
    parser.add_argument("--cvm-type", metavar='CVM_TYPE', choices=["snp", "tdx"])
    parser.add_argument("--cvm-id", metavar='CVM_ID', help="Stop a CVM (privileged)")
    parser.add_argument("--cvm-mode", metavar='CVM_MODE', choices=["in-update", "in-service"])
    parser.add_argument("--command", metavar='COMMAND', nargs='+', action="append", help="Run commands on a CVM (privileged)")
    args = parser.parse_args()
    return args

def check_valid_args(args):
    if args.action in ["start-cvm", "stop-cvm", "run-commands", "mark-cvm"]:
        if not args.service_owner_private_key_file:
            print("Missing argument: SERVICE_OWNER_PRIVATE_KEY_FILE")
            return False

        if args.action == "start-cvm":
            if not args.cvm_type:
                print("Missing argument: CVM_TYPE")
                return False
        else: #if args.action in ["stop-cvm", "run-commands", "mark-cvm"]:
            if not args.cvm_id:
                print("Missing argument: CVM_ID")
                return False

            if args.action == "run-commands":
                if not args.command:
                    print("Missing argument: COMMAND")
                    return False
            elif args.action == "mark-cvm":
                if not args.cvm_mode:
                    print("Missing argument: CVM_MODE")
                    return False
    else:
        if args.action in ["get-cvm-state", "get-cvm-state-long"]:
            if not args.cvm_id:
                print("Missing argument: CVM_ID")
                return False
    return True

def print_args(args):
    print("-"*10 + "Arguments" + "-"*10)
    for key, value in vars(args).items():
        print(str(key) + ": " + str(value))
    print("-"*29)

def main():
    args = parse_args()
    # demo(args)

    if not check_valid_args(args):
        print("Invalid args.")
        return 1

    print("="*10 + "Start of command: " + args.action + "="*10)
    print_args(args)
    sys.stdout.flush()

    client = DuetAdminClient(args.url, args.service_owner_private_key_file)

    if args.action == "start-cvm":
        result = client.start_cvm(args.cvm_type)
        if result["success"]:
            print("started cvm_id: " + result["state"]["cvm_id"])
    elif args.action == "stop-cvm":
        result = client.stop_cvm(args.cvm_id)
        if result["success"]:
            print(result["status"])
    elif args.action == "run-commands":
        commands = []
        for c in args.command:
            commands.append(''.join(c))
        result = client.run_commands(args.cvm_id, commands)
        if result["success"]:
            print(result["output"])
    elif args.action == "mark-cvm":
        result = client.mark_cvm(args.cvm_id, args.cvm_mode)
        if result["success"]:
            print(result["mode"])
    elif args.action == "get-cvm-state":
        result = client.get_cvm_state(args.cvm_id, False)
    elif args.action == "get-cvm-state-long":
        result = client.get_cvm_state(args.cvm_id, True)
    
    if not result["success"]:
        print("ERROR: " + result["error"])

    print("="*11 + "End of command: " + args.action + "="*11)
    print()

if __name__ == "__main__":
    main()