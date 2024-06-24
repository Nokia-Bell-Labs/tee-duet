# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import io
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization

import paramiko

class ConfidentialVM():
    def __init__(self, username, ip, serialized_public_key, logger):
        self._logger = logger
        self._username = username
        self._ip_address = ip
        self._serialized_public_key = serialized_public_key
        
        hash_object = hashes.Hash(hashes.SHA256())
        hash_object.update(bytes(self._serialized_public_key, "utf-8"))
        self._cvm_id = hash_object.finalize().hex()
        self._logger.info(f"cvm_id: {self._cvm_id}")

        self._command_outputs = []
        self._command_output_hashes = []
        
        self._config = None
        
        self._ssh_client = None
        self._private_key = None
        self._sftp_client = None
        
        self._service_owner_public_key = None
        self._mode = "in-update"

    def get_cvm_type(self):
        return self._config["cvm_type"]

    def set_config(self, config):
        self._config = config
    
    def get_config(self):
        return self._config

    def get_cvm_id(self):
        return self._cvm_id

    def set_cvm_mode(self, cvm_mode):
        self._mode = cvm_mode

    def get_cvm_mode(self):
        return self._mode

    def get_current_state(self, should_be_long=False):
        state = {}
        state["cvm_id"] = self._cvm_id
        if should_be_long:
            state["command_outputs"] = self._command_outputs
        else:
            state["command_output_hashes"] = self._command_output_hashes
        
        return state

    def set_private_key(self, pkey):
        pkeyfile = io.StringIO(pkey)
        self._private_key = paramiko.RSAKey.from_private_key(pkeyfile)
        #self._private_key = paramiko.RSAKey.from_private_key_file("ephemeral_private_key")

    def execute_command(self, command):
        if not self._ssh_client:
            self.connect()
        _stdin, _stdout, _stderr = self._ssh_client.exec_command(command, get_pty=True)
        output = []
        for line in iter(_stdout.readline, ""):
            output.append(line)
            #print(line, end="")
            #sys.stdout.flush()
            self._logger.info(line.strip("\n"))
        
        entry = {}
        entry["command"] = command
        entry["output"] = output
        self._command_outputs.append(entry)

        entry2 = {}
        entry2["command"] = command
        # hash the output and store that
        hash_object = hashes.Hash(hashes.SHA256())
        hash_object.update(bytes(str(output), "utf-8"))
        output_hash = hash_object.finalize().hex()
        entry2["output_hash"] = output_hash
        self._command_output_hashes.append(entry2)

        return output

    def _get_ssh_client(self):
        if not self._ssh_client:
            self._ssh_client = paramiko.SSHClient()
            policy = paramiko.AutoAddPolicy()
            self._ssh_client.set_missing_host_key_policy(policy)

        return self._ssh_client

    def _get_sftp_client(self):
        if not self._sftp_client:
            self._ssh_client = self._get_ssh_client()
            self._sftp_client = self._ssh_client.open_sftp()
        
        return self._sftp_client
        
    def connect(self):
        self._ssh_client = self._get_ssh_client()
        self._ssh_client.connect(self._ip_address, username=self._username, pkey=self._private_key)

    def copy_file(self, filepath, filename):
        self._sftp_client = self._get_sftp_client()
        self._sftp_client.put(filepath + filename, "/home/" + self._username + "/" + filename)

    def disconnect(self):
        self._ssh_client.close()