"""
Tests for cryptographic functions
"""

import unittest
import tempfile
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from crypto.symmetric import generate_key, save_key, load_key, encrypt_aes_gcm, decrypt_aes_gcm
from crypto.pki import generate_rsa_keypair, load_rsa_key, sign_hash_with_rsa, verify_hash_with_rsa

class TestCryptoSymmetric(unittest.TestCase):
    def test_key_generation(self):
        key = generate_key()
        self.assertEqual(len(key), 32)
    
    def test_key_save_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key = generate_key()
            key_path = os.path.join(tmpdir, "test.key")
            
            save_key(key, key_path)
            loaded_key = load_key(key_path)
            
            self.assertEqual(key, loaded_key)
    
    def test_aes_gcm_encryption_decryption(self):
        key = generate_key()
        plaintext = b"This is a test message for encryption"
        
        nonce, ciphertext, tag = encrypt_aes_gcm(key, plaintext)
        decrypted = decrypt_aes_gcm(key, nonce, ciphertext, tag)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_aes_gcm_with_associated_data(self):
        key = generate_key()
        plaintext = b"Test data"
        associated_data = b"Additional authentication data"
        
        nonce, ciphertext, tag = encrypt_aes_gcm(key, plaintext, associated_data)
        decrypted = decrypt_aes_gcm(key, nonce, ciphertext, tag, associated_data)
        
        self.assertEqual(plaintext, decrypted)

class TestCryptoPKI(unittest.TestCase):
    def test_rsa_keypair_generation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            priv_path, pub_path = generate_rsa_keypair(tmpdir, bits=2048)
            
            self.assertTrue(os.path.exists(priv_path))
            self.assertTrue(os.path.exists(pub_path))
            
            priv_key = load_rsa_key(priv_path, private=True)
            pub_key = load_rsa_key(pub_path, private=False)
            
            self.assertTrue(priv_key.has_private())
            self.assertFalse(pub_key.has_private())
    
    def test_signature_verification(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            priv_path, pub_path = generate_rsa_keypair(tmpdir, bits=2048)
            
            priv_key = load_rsa_key(priv_path, private=True)
            pub_key = load_rsa_key(pub_path, private=False)
            
            # Test data
            test_data = b"Data to be signed"
            from crypto.symmetric import sha256_bytes
            data_hash = sha256_bytes(test_data)
            
            # Sign
            signature = sign_hash_with_rsa(data_hash, priv_key)
            
            # Verify
            is_valid = verify_hash_with_rsa(data_hash, pub_key, signature)
            self.assertTrue(is_valid)
            
            # Test with wrong data
            wrong_data = b"Wrong data"
            wrong_hash = sha256_bytes(wrong_data)
            is_valid_wrong = verify_hash_with_rsa(wrong_hash, pub_key, signature)
            self.assertFalse(is_valid_wrong)

if __name__ == "__main__":
    unittest.main()