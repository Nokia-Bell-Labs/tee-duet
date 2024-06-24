# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

def _convert_to_bytes_if_necessary(data):
    if not isinstance(data, bytes):
        data = bytes(data, "utf-8")
    return data

def generate_rsa_keypair(key_size):
    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
    public_key = private_key.public_key()
    
    return public_key, private_key

def generate_ephemeral_rsa_key_for_cvm():
    public_key, private_key = generate_rsa_keypair(key_size=4096)

    serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode()
    
    serialized_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

    return serialized_public_key, serialized_private_key

def _decrypt_data_with_private_key(encrypted_data, private_key):
    data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    return data

def _sign_data_with_private_key(data, private_key):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def sign_data_with_private_key(data, private_key):
    data = _convert_to_bytes_if_necessary(data)
    assert isinstance(private_key, rsa.RSAPrivateKey)
    
    return _sign_data_with_private_key(data, private_key)
    
def sign_data_with_private_key_pem(data, private_key_pem):
    data = _convert_to_bytes_if_necessary(data)
    private_key_pem = _convert_to_bytes_if_necessary(private_key_pem)
    
    private_key = load_pem_private_key(private_key_pem)
    
    return _sign_data_with_private_key(data, private_key)

def decrypt_data_with_private_key(encrypted_data, private_key):
    encrypted_data = _convert_to_bytes_if_necessary(encrypted_data)
    assert isinstance(private_key, rsa.RSAPrivateKey)

    return _decrypt_data_with_private_key(encrypted_data, private_key)

def decrypt_data_with_private_key_pem(encrypted_data, private_key_pem):
    encrypted_data = _convert_to_bytes_if_necessary(encrypted_data)
    private_key_pem = _convert_to_bytes_if_necessary(private_key_pem)
    
    private_key = load_pem_private_key(private_key_pem)

    return _decrypt_data_with_private_key(encrypted_data, private_key)

def _encrypt_data_with_public_key(data, public_key):
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_data

def encrypt_data_with_public_key(data, public_key):
    data = _convert_to_bytes_if_necessary(data)
    assert isinstance(public_key, rsa.RSAPublicKey)

    return _encrypt_data_with_public_key(data, public_key)

def encrypt_data_with_public_key_pem(data, public_key_pem):
    data = _convert_to_bytes_if_necessary(data)
    public_key_pem = _convert_to_bytes_if_necessary(public_key_pem)

    public_key = load_pem_public_key(public_key_pem)

    return _encrypt_data_with_public_key(data, public_key)

def _verify_signature_with_public_key(signature, data, public_key):
    verified = False
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        verified = True
    except Exception as exc:
        pass

    return verified
    
def verify_signature_with_public_key(signature, data, public_key):
    data = _convert_to_bytes_if_necessary(data)
    signature = _convert_to_bytes_if_necessary(signature)
    assert isinstance(public_key, rsa.RSAPublicKey)

    return _verify_signature_with_public_key(signature, data, public_key)

def verify_signature_with_public_key_pem(signature, data, public_key_pem):
    data = _convert_to_bytes_if_necessary(data)
    signature = _convert_to_bytes_if_necessary(signature)
    public_key_pem = _convert_to_bytes_if_necessary(public_key_pem)
    
    public_key = load_pem_public_key(public_key_pem)

    return _verify_signature_with_public_key(signature, data, public_key)
