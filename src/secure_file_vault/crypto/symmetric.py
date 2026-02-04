"""
Symmetric encryption functions using AES-256-GCM
"""

import secrets
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

KEY_LEN = 32
GCM_TAG_LEN = 16

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
    """Compute SHA-256 hash of data"""
    h = SHA256.new()
    h.update(data)
    return h.digest()

def encrypt_aes_gcm(key: bytes, plaintext: bytes, associated_data: bytes = None):
    """
    Encrypt data using AES-256-GCM
    
    Args:
        key: 32-byte encryption key
        plaintext: Data to encrypt
        associated_data: Optional associated data for authentication
    
    Returns:
        tuple: (nonce, ciphertext, tag)
    """
    cipher = AES.new(key, AES.MODE_GCM)
    
    if associated_data:
        cipher.update(associated_data)
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ciphertext, tag

def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, 
                   associated_data: bytes = None) -> bytes:
    """
    Decrypt data using AES-256-GCM
    
    Args:
        key: 32-byte decryption key
        nonce: Nonce used for encryption
        ciphertext: Encrypted data
        tag: Authentication tag
        associated_data: Optional associated data used during encryption
    
    Returns:
        bytes: Decrypted plaintext
    
    Raises:
        ValueError: If authentication fails
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    if associated_data:
        cipher.update(associated_data)
    
    return cipher.decrypt_and_verify(ciphertext, tag)
# Performance considerations: Large file handling
# Security: Always wipe keys from memory after use

