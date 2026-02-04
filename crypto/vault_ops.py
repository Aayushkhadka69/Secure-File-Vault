"""
Vault file operations - encryption, decryption, and verification
"""

import os
import json
import datetime
from .symmetric import (
    sha256_bytes, encrypt_aes_gcm, decrypt_aes_gcm, 
    GCM_TAG_LEN
)
from .pki import (
    load_rsa_key, sign_hash_with_rsa, 
    verify_hash_with_rsa
)

def encrypt_produce_files(
    input_path: str,
    key: bytes,
    out_dir: str,
    rsa_priv_path: str,
    status_cb=None,
    current_user: str = None
):
    """
    Encrypt file and produce vault files with PKI signature
    
    Args:
        input_path: Path to file to encrypt
        key: 32-byte encryption key
        out_dir: Output directory for vault files
        rsa_priv_path: Path to RSA private key for signing
        status_cb: Optional callback for status updates
        current_user: Current username for metadata
    
    Returns:
        tuple: (vault_path, hash_path, meta_path, sig_path, hash_hex)
    
    Raises:
        ValueError: If RSA private key is not provided
    """
    if not rsa_priv_path or not os.path.exists(rsa_priv_path):
        raise ValueError("RSA private key is required for encryption (PKI mandatory).")

    if status_cb:
        status_cb("Reading input...")
    
    with open(input_path, "rb") as f:
        plaintext = f.read()

    if status_cb:
        status_cb("Computing SHA-256...")
    hsh = sha256_bytes(plaintext)

    if status_cb:
        status_cb("Encrypting (AES-256-GCM)...")
    
    # Encrypt with associated data (the hash)
    iv, ciphertext, tag = encrypt_aes_gcm(key, plaintext, hsh)

    # PKI sign (mandatory)
    if status_cb:
        status_cb("Signing hash (RSA)...")
    priv = load_rsa_key(rsa_priv_path, private=True)
    sig = sign_hash_with_rsa(hsh, priv)

    # Prepare output files
    base = os.path.basename(input_path)
    name = os.path.splitext(base)[0]
    os.makedirs(out_dir, exist_ok=True)

    vault_p = os.path.join(out_dir, f"{name}.vault")
    hash_p  = os.path.join(out_dir, f"{name}.hash")
    meta_p  = os.path.join(out_dir, f"{name}.meta.json")
    sig_p   = os.path.join(out_dir, f"{name}.sig")

    # Write vault file (ciphertext + tag)
    with open(vault_p, "wb") as f:
        f.write(ciphertext + tag)
    
    # Write hash file
    with open(hash_p, "w", encoding="utf-8") as f:
        f.write(hsh.hex())
    
    # Write signature file
    with open(sig_p, "w", encoding="utf-8") as f:
        f.write(sig.hex())

    # Write metadata
    meta = {
        "original_name": base,
        "size_bytes": len(plaintext),
        "sha256_hex": hsh.hex(),
        "iv_hex": iv.hex(),
        "tag_len": len(tag),
        "encryption_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "encrypted_by": current_user,
        "pki_used": True,
        "rsa_sig_file": os.path.basename(sig_p),
        "key_required": True,
    }
    
    with open(meta_p, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    if status_cb:
        status_cb("Encryption complete (PKI).")
    
    return vault_p, hash_p, meta_p, sig_p, hsh.hex()

def decrypt_using_files(
    vault_path: str,
    key: bytes,
    meta_path: str,
    out_dir: str,
    rsa_pub_path: str,
    status_cb=None
):
    """
    Decrypt vault file with PKI signature verification
    
    Args:
        vault_path: Path to .vault file
        key: 32-byte decryption key
        meta_path: Path to .meta.json file
        out_dir: Output directory for restored file
        rsa_pub_path: Path to RSA public key for verification
        status_cb: Optional callback for status updates
    
    Returns:
        tuple: (restored_path, hash_hex, signature_verified)
    
    Raises:
        ValueError: If signature verification fails or decryption fails
    """
    if not rsa_pub_path or not os.path.exists(rsa_pub_path):
        raise ValueError("RSA public key is required for decryption (PKI mandatory).")

    if status_cb:
        status_cb("Reading files...")
    
    # Load metadata
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    
    stored_hash = bytes.fromhex(meta["sha256_hex"])

    # VERIFY SIGNATURE FIRST
    rsa_sig_file = meta.get("rsa_sig_file")
    if not rsa_sig_file:
        raise ValueError("Metadata missing RSA signature info (PKI mandatory).")

    folder = os.path.dirname(vault_path) or "."
    sig_path = os.path.join(folder, rsa_sig_file)
    
    if not os.path.exists(sig_path):
        raise ValueError(".sig file missing; cannot verify PKI signature.")

    if status_cb:
        status_cb("Verifying RSA signature FIRST (before decryption)...")
    
    with open(sig_path, "r", encoding="utf-8") as f:
        sig = bytes.fromhex(f.read().strip())
    
    pub = load_rsa_key(rsa_pub_path, private=False)
    
    if not verify_hash_with_rsa(stored_hash, pub, sig):
        raise ValueError(
            "RSA signature verification FAILED. File may be tampered. "
            "Decryption BLOCKED for security."
        )

    if status_cb:
        status_cb("Signature verified. Proceeding with decryption...")
    
    # Read vault file
    with open(vault_path, "rb") as f:
        data = f.read()
    
    if len(data) < GCM_TAG_LEN:
        raise ValueError("Vault file too short")
    
    ct, tag = data[:-GCM_TAG_LEN], data[-GCM_TAG_LEN:]
    iv = bytes.fromhex(meta["iv_hex"])

    if status_cb:
        status_cb("Decrypting (AES-256-GCM)...")
    
    try:
        pt = decrypt_aes_gcm(key, iv, ct, tag, stored_hash)
    except Exception as e:
        raise ValueError(f"Decryption/authentication failed: {str(e)}")

    if status_cb:
        status_cb("Verifying SHA-256...")
    
    if sha256_bytes(pt) != stored_hash:
        raise ValueError("Integrity check failed")

    # Save restored file with unique name
    name = meta.get("original_name", "restored_file")
    out_p = os.path.join(out_dir, name)
    base, ext = os.path.splitext(out_p)
    
    i = 1
    final = out_p
    while os.path.exists(final):
        final = f"{base}_restored{i}{ext}"
        i += 1
    
    with open(final, "wb") as f:
        f.write(pt)

    if status_cb:
        status_cb("Decryption complete (PKI signature VERIFIED).")
    
    return final, stored_hash.hex(), True

def verify_signature_standalone(
    hash_path: str, 
    sig_path: str, 
    pub_key_path: str, 
    status_cb=None
):
    """
    Standalone signature verification without decrypting
    
    Args:
        hash_path: Path to .hash file
        sig_path: Path to .sig file
        pub_key_path: Path to RSA public key
        status_cb: Optional callback for status updates
    
    Returns:
        tuple: (is_valid, hash_hex, error_message)
    """
    if status_cb:
        status_cb("Reading files...")
    
    # Check file existence
    if not os.path.exists(hash_path):
        return False, None, "Hash file not found."
    
    if not os.path.exists(sig_path):
        return False, None, "Signature file not found."
    
    if not os.path.exists(pub_key_path):
        return False, None, "Public key file not found."
    
    try:
        # Read hash file
        with open(hash_path, "r", encoding="utf-8") as f:
            hash_hex = f.read().strip()
        hash_bytes = bytes.fromhex(hash_hex)
        
        # Read signature file
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
        return False, None, str(e)#   M e m o r y   m a n a g e m e n t :   P r o c e s s   l a r g e   f i l e s   i n   c h u n k s  
 