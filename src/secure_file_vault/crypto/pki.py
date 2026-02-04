#!/usr/bin/env python3
"""PKI functions for RSA encryption"""

import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

def generate_rsa_keypair(save_dir: str, bits: int = 4096):
    """Generate RSA keys"""
    key = RSA.generate(bits)
    priv_p = os.path.join(save_dir, "private_key.pem")
    pub_p = os.path.join(save_dir, "public_key.pem")
    with open(priv_p, "wb") as f:
        f.write(key.export_key("PEM"))
    with open(pub_p, "wb") as f:
        f.write(key.publickey().export_key("PEM"))
    return priv_p, pub_p

def load_rsa_key(path: str, private=True):
    with open(path, "rb") as f:
        key = RSA.import_key(f.read())
    if private and not key.has_private():
        raise ValueError("Expected an RSA PRIVATE key file (.pem) here.")
    if not private and key.has_private():
        raise ValueError("Expected an RSA PUBLIC key file (.pem) here, not a private key.")
    return key

def sign_hash_with_rsa(hash_bytes, priv_key):
    h = SHA256.new(hash_bytes)
    return pkcs1_15.new(priv_key).sign(h)

def verify_hash_with_rsa(hash_bytes, pub_key, sig):
    h = SHA256.new(hash_bytes)
    try:
        pkcs1_15.new(pub_key).verify(h, sig)
        return True
    except (ValueError, TypeError):
        return False

