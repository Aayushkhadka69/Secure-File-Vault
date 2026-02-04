#!/usr/bin/env python3
"""
Test imports for Secure File Vault
Clean version without VS Code warnings
"""

import os
import sys

# Setup path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


def run_import_test(module_path, import_name):
    """Helper to test imports without triggering VS Code warnings."""
    try:
        # Use __import__ instead of 'from x import y' to avoid VS Code warnings
        module = __import__(module_path, fromlist=[import_name])
        return True, None
    except ImportError as e:
        return False, str(e)


def test_auth_import():
    """Test authentication module imports."""
    success, error = run_import_test('secure_file_vault.auth', 'user_manager')
    if success:
        print("✓ Authentication module imports work")
        return True
    else:
        print(f"✗ Auth import error: {error}")
        return False


def test_crypto_import():
    """Test crypto module imports."""
    modules = ['symmetric', 'pki', 'vault_ops']
    all_success = True
    errors = []
    
    for module in modules:
        success, error = run_import_test('secure_file_vault.crypto', module)
        if not success:
            all_success = False
            errors.append(f"{module}: {error}")
    
    if all_success:
        print("✓ Crypto module imports work")
        return True
    else:
        print(f"✗ Crypto import errors: {', '.join(errors)}")
        return False


def test_main_import():
    """Test main module import."""
    try:
        # Import using different method to avoid warnings
        import importlib
        importlib.import_module('secure_file_vault.main')
        print("✓ Main module imports work")
        return True
    except ImportError as e:
        print(f"✗ Main import error: {e}")
        return False


def main():
    """Run all tests."""
    print("\n" + "=" * 50)
    print("Running Import Tests")
    print("=" * 50)
    
    results = [
        ("Authentication", test_auth_import()),
        ("Cryptography", test_crypto_import()),
        ("Main Module", test_main_import()),
    ]
    
    print("\n" + "=" * 50)
    print("Results:")
    print("=" * 50)
    
    passed = sum(1 for _, result in results if result)
    
    for name, result in results:
        status = "PASSED" if result else "FAILED"
        print(f"{name:20} {status}")
    
    print(f"\nTotal: {passed}/{len(results)} tests passed")
    
    return all(result for _, result in results)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
