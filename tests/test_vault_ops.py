"""
Tests for vault operations
"""

import unittest
import tempfile
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from crypto.symmetric import generate_key
from crypto.pki import generate_rsa_keypair
from crypto.vault_ops import encrypt_produce_files, decrypt_using_files, verify_signature_standalone

class TestVaultOperations(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        
        with open(self.test_file, "w") as f:
            f.write("This is test content for encryption.\n" * 10)
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_encrypt_decrypt_cycle(self):
        # Generate keys
        key = generate_key()
        priv_path, pub_path = generate_rsa_keypair(self.temp_dir, bits=2048)
        
        # Encrypt
        vault_path, hash_path, meta_path, sig_path, file_hash = encrypt_produce_files(
            self.test_file,
            key,
            self.temp_dir,
            priv_path,
            current_user="test_user"
        )
        
        # Check files were created
        for path in [vault_path, hash_path, meta_path, sig_path]:
            self.assertTrue(os.path.exists(path))
        
        # Decrypt
        restored_path, verified_hash, sig_valid = decrypt_using_files(
            vault_path,
            key,
            meta_path,
            self.temp_dir,
            pub_path
        )
        
        # Verify
        self.assertTrue(os.path.exists(restored_path))
        self.assertEqual(file_hash, verified_hash)
        self.assertTrue(sig_valid)
        
        # Compare content
        with open(self.test_file, "r") as f:
            original = f.read()
        with open(restored_path, "r") as f:
            restored = f.read()
        
        self.assertEqual(original, restored)
    
    def test_signature_verification_standalone(self):
        # Generate keys
        key = generate_key()
        priv_path, pub_path = generate_rsa_keypair(self.temp_dir, bits=2048)
        
        # Encrypt to get files
        _, hash_path, _, sig_path, _ = encrypt_produce_files(
            self.test_file,
            key,
            self.temp_dir,
            priv_path,
            current_user="test_user"
        )
        
        # Verify signature standalone
        is_valid, hash_hex, error_msg = verify_signature_standalone(
            hash_path,
            sig_path,
            pub_path
        )
        
        self.assertTrue(is_valid)
        self.assertIsNotNone(hash_hex)
        self.assertIsNone(error_msg)

if __name__ == "__main__":
    unittest.main()