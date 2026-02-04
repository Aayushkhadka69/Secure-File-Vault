#!/usr/bin/env python3
"""Vault operations for encryption/decryption"""

import os
import json
import datetime
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from .symmetric import sha256_bytes
from .pki import sign_hash_with_rsa, verify_hash_with_rsa, load_rsa_key

GCM_TAG_LEN = 16

def encrypt_aes_gcm(key, plaintext):
    """Encrypt using AES-GCM"""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ciphertext, tag

def decrypt_aes_gcm(key, nonce, ciphertext, tag):
    """Decrypt using AES-GCM"""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def encrypt_produce_files(input_path, key, out_dir, status_cb=None, rsa_priv_path=None):
    """Encrypt file and produce output files"""
    if status_cb:
        status_cb("Encryption started")
    
    # Read input file
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    # Encrypt
    nonce, ciphertext, tag = encrypt_aes_gcm(key, plaintext)
    
    # Create output filename
    base = os.path.basename(input_path)
    name = os.path.splitext(base)[0]
    os.makedirs(out_dir, exist_ok=True)
    
    vault_p = os.path.join(out_dir, f"{name}.vault")
    
    # Write encrypted data
    with open(vault_p, 'wb') as f:
        f.write(ciphertext + tag)
    
    # Create metadata
    meta = {
        "original_name": base,
        "iv_hex": nonce.hex(),
        "tag_len": len(tag),
        "encryption_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    meta_p = os.path.join(out_dir, f"{name}.meta.json")
    with open(meta_p, 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2)
    
    return vault_p, meta_p

def decrypt_using_files(vault_path, key, meta_path, out_dir, status_cb=None, rsa_pub_path=None):
    """Decrypt file using vault files"""
    if status_cb:
        status_cb("Decryption started")
    
    # Read metadata
    with open(meta_path, 'r', encoding='utf-8') as f:
        meta = json.load(f)
    
    # Read encrypted data
    with open(vault_path, 'rb') as f:
        data = f.read()
    
    if len(data) < GCM_TAG_LEN:
        raise ValueError("Vault file too short")
    
    ciphertext, tag = data[:-GCM_TAG_LEN], data[-GCM_TAG_LEN:]
    nonce = bytes.fromhex(meta["iv_hex"])
    
    # Decrypt
    plaintext = decrypt_aes_gcm(key, nonce, ciphertext, tag)
    
    # Save decrypted file
    name = meta.get("original_name", "restored_file")
    out_p = os.path.join(out_dir, name)
    
    # Avoid overwriting
    base, ext = os.path.splitext(out_p)
    i = 1
    final = out_p
    while os.path.exists(final):
        final = f"{base}_restored{i}{ext}"
        i += 1
    
    with open(final, 'wb') as f:
        f.write(plaintext)
    
    return final
def verify_signature_standalone(hash_path, sig_path, pub_key_path, status_cb=None):
    """Standalone signature verification without decrypting."""
    if status_cb:
        status_cb("Reading files...")
    
    if not os.path.exists(hash_path):
        return False, None, "Hash file not found."
    if not os.path.exists(sig_path):
        return False, None, "Signature file not found."
    if not os.path.exists(pub_key_path):
        return False, None, "Public key file not found."
    
    try:
        with open(hash_path, "r", encoding="utf-8") as f:
            hash_hex = f.read().strip()
        hash_bytes = bytes.fromhex(hash_hex)
        
        with open(sig_path, "r", encoding="utf-8") as f:
            sig_hex = f.read().strip()
        sig_bytes = bytes.fromhex(sig_hex)
        
        if status_cb:
            status_cb("Loading public key...")
        pub_key = load_rsa_key(pub_key_path, private=False)
        
        if status_cb:
            status_cb("Verifying signature...")
        is_valid = verify_hash_with_rsa(hash_bytes, pub_key, sig_bytes)
        
        if status_cb:
            status_cb("Verification complete.")
        return is_valid, hash_hex, None
    except Exception as e:
        return False, None, str(e)

