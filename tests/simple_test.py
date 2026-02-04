#!/usr/bin/env python3
"""Simple test to verify basic functionality"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_basic():
    """Basic test"""
    print("Testing basic imports...")
    
    # Test package import
    try:
        import secure_file_vault
        print("? secure_file_vault package")
    except ImportError as e:
        print(f"? Package import failed: {e}")
        return False
    
    # Test crypto module
    try:
        from secure_file_vault.crypto.symmetric import generate_key
        print("? Crypto functions")
    except ImportError as e:
        print(f"? Crypto import failed: {e}")
        return False
    
    # Test auth module
    try:
        from secure_file_vault.auth.user_manager import UserManager
        print("? Auth module")
    except ImportError as e:
        print(f"? Auth import failed: {e}")
        return False
    
    return True

def test_functionality():
    """Test basic functionality"""
    print("\nTesting basic functionality...")
    
    try:
        from secure_file_vault.crypto.symmetric import generate_key
        
        # Generate a key
        key = generate_key()
        print(f"? Key generated: {len(key)} bytes")
        
        # Test user manager instantiation
        from secure_file_vault.auth.user_manager import UserManager
        manager = UserManager()
        print("? UserManager instantiated")
        
        return True
    except Exception as e:
        print(f"? Functionality test failed: {e}")
        return False

if __name__ == "__main__":
    print("=" * 50)
    print("Secure File Vault - Basic Test")
    print("=" * 50)
    
    try:
        success = test_basic() and test_functionality()
        
        print("\n" + "=" * 50)
        if success:
            print("? All basic tests passed!")
            sys.exit(0)
        else:
            print("? Some tests failed")
            sys.exit(1)
    except Exception as e:
        print(f"? Test runner error: {e}")
        sys.exit(1)
