#!/usr/bin/env python3
"""
Test imports for Secure File Vault
"""

import os
import sys

# Add the parent directory to sys.path to allow imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

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

def run_all_tests():
    """Run all import tests"""
    print("=" * 50)
    print("Running import tests...")
    print("=" * 50)
    
    results = []
    
    results.append(("Authentication", test_auth_import()))
    results.append(("Crypto", test_crypto_import()))
    results.append(("Main", test_main_exists()))
    
    print("\n" + "=" * 50)
    print("Test Results Summary:")
    print("=" * 50)
    
    passed = 0
    for name, result in results:
        status = "PASSED" if result else "FAILED"
        if result:
            passed += 1
        print(f"{name:20} {status}")
    
    print(f"\nTotal: {passed}/{len(results)} tests passed")
    
    return all(result for _, result in results)

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)


def test_gui_import():
    """Test GUI module imports"""
    try:
        from secure_file_vault.gui import main_window
        print("✓ GUI module imports work")
        return True
    except ImportError as e:
        print(f"✗ GUI import error: {e}")
        return False

def test_utils_import():
    """Test utilities module imports"""
    try:
        from secure_file_vault.utils import file_utils, config
        print("✓ Utils module imports work")
        return True
    except ImportError as e:
        print(f"✗ Utils import error: {e}")
        return False
