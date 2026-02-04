#!/usr/bin/env python3
"""Symmetric encryption functions"""

import secrets
from Crypto.Hash import SHA256

KEY_LEN = 32

def generate_key() -> bytes:
    """Generate a secure 256-bit key"""
    return secrets.token_bytes(KEY_LEN)

def save_key(key: bytes, path: str):
    """Save key to file in hex format"""
    with open(path, 'w') as f:
        f.write(key.hex())

def load_key(path: str) -> bytes:
    """Load key from hex file"""
    with open(path, 'r') as f:
        return bytes.fromhex(f.read().strip())

def sha256_bytes(data: bytes) -> bytes:
    """Calculate SHA256 hash of bytes"""
    h = SHA256.new()
    h.update(data)
    return h.digest()
