"""
Public Key Infrastructure (PKI) functions
RSA key generation, signing, and verification
"""

import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from .symmetric import sha256_bytes

def generate_rsa_keypair(save_dir: str, bits: int = 4096):
    """
    Generate RSA keypair and save to files
    
    Args:
        save_dir: Directory to save keys
        bits: Key size in bits (default 4096)
    
    Returns:
        tuple: (private_key_path, public_key_path)
    """
    key = RSA.generate(bits)
    priv_p = os.path.join(save_dir, "private_key.pem")
    pub_p  = os.path.join(save_dir, "public_key.pem")
    
    with open(priv_p, "wb") as f:
        f.write(key.export_key("PEM"))
    
    with open(pub_p, "wb") as f:
        f.write(key.publickey().export_key("PEM"))
    
    return priv_p, pub_p

def load_rsa_key(path: str, private: bool = True) -> RSA.RsaKey:
    """
    Load RSA key from PEM file
    
    Args:
        path: Path to PEM file
        private: Whether to expect a private key
    
    Returns:
        RSA.RsaKey: Loaded key
    
    Raises:
        ValueError: If key type doesn't match expectation
    """
    with open(path, "rb") as f:
        key = RSA.import_key(f.read())
    
    if private and not key.has_private():
        raise ValueError("Expected an RSA PRIVATE key file (.pem) here.")
    
    if not private and key.has_private():
        raise ValueError("Expected an RSA PUBLIC key file (.pem) here, not a private key.")
    
    return key

def sign_hash_with_rsa(hash_bytes: bytes, priv_key: RSA.RsaKey) -> bytes:
    """
    Sign a hash with RSA private key
    
    Args:
        hash_bytes: Hash to sign
        priv_key: RSA private key
    
    Returns:
        bytes: RSA signature
    """
    h = SHA256.new(hash_bytes)
    return pkcs1_15.new(priv_key).sign(h)

def verify_hash_with_rsa(hash_bytes: bytes, pub_key: RSA.RsaKey, sig: bytes) -> bool:
    """
    Verify RSA signature
    
    Args:
        hash_bytes: Original hash
        pub_key: RSA public key
        sig: Signature to verify
    
    Returns:
        bool: True if signature is valid
    """
    h = SHA256.new(hash_bytes)
    try:
        pkcs1_15.new(pub_key).verify(h, sig)
        return True
    except (ValueError, TypeError):
        return False
    