#!/usr/bin/env python3
"""Test that all modules can be imported"""

import sys
import os

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_auth_import():
    """Test authentication module imports"""
    try:
        from secure_file_vault.auth import user_manager
        print("✓ Authentication module imports work")
        return True
    except ImportError as e:
        print(f"✗ Auth import error: {e}")
        return False

def test_crypto_import():
    """Test crypto module imports"""
    try:
        from secure_file_vault.crypto import symmetric, pki, vault_ops
        print("✓ Crypto module imports work")
        return True
    except ImportError as e:
        print(f"✗ Crypto import error: {e}")
        return False

def test_main_exists():
    """Test that main.py exists and can be imported"""
    try:
        from secure_file_vault import main
        print("✓ Main module imports work")
        return True
    except ImportError as e:
        print(f"✗ Main import error: {e}")
        return False

if __name__ == "__main__":
    print("Running import tests...")
    print("-" * 40)
    
    results = []
    results.append(test_auth_import())
    results.append(test_crypto_import())
    results.append(test_main_exists())
    
    print("-" * 40)
    if all(results):
        print("✅ All import tests passed!")
    else:
        print("❌ Some import tests failed")
        sys.exit(1)
        