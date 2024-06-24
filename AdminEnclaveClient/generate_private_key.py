# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import os
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

# Generate a new RSA key pair
def generate_keypair(key_size, filename):

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    with open(filename, "wb") as f:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        f.write(private_key_pem)

    public_key = private_key.public_key()
    with open("../AdminEnclave/service_owner_pub_keys/" + filename + ".pub", "wb") as f:
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        f.write(public_key_pem)

os.makedirs("../AdminEnclave/service_owner_pub_keys", exist_ok=True)
generate_keypair(4096, "service_owner_private_key")
