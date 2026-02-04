#!/usr/bin/env python3
"""
Test imports for Secure File Vault
FINAL VERSION - All paths corrected
"""

import os
import sys

# CORRECT PATH: Go from tests/ -> project root -> src
project_root = os.path.join(os.path.dirname(__file__), '..')
src_path = os.path.join(project_root, 'src')
sys.path.insert(0, src_path)

print(f"📁 Test directory: {os.path.dirname(__file__)}")
print(f"📁 Project root: {project_root}")
print(f"📁 Source path: {src_path}")


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
    """Test that main module can be imported"""
    try:
        from secure_file_vault import main
        print("✓ Main module imports work")
        
        # Optional: Check if it has a main() function
        if hasattr(main, 'main'):
            print("✓ Main module has main() function")
        return True
    except ImportError as e:
        print(f"✗ Main import error: {e}")
        return False


def run_all_tests():
    """Run all import tests"""
    print("\n" + "=" * 50)
    print("RUNNING IMPORT TESTS")
    print("=" * 50)
    
    results = []
    results.append(test_auth_import())
    results.append(test_crypto_import())
    results.append(test_main_exists())
    
    print("\n" + "=" * 50)
    print("TEST RESULTS")
    print("=" * 50)
    
    if all(results):
        print("✅ ALL TESTS PASSED!")
        return True
    else:
        print("❌ SOME TESTS FAILED")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

