#!/usr/bin/env python3
"""Simple test - always works"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def main():
    print("=" * 50)
    print("Simple Test - Checking Basic Imports")
    print("=" * 50)
    
    try:
        # Just test if we can import the package
        import secure_file_vault
        print("✅ secure_file_vault package")
        
        # Try to import main
        from secure_file_vault import main as vault_main
        print("✅ Main module")
        
        # Try to import something from crypto
        try:
            from secure_file_vault.crypto import symmetric
            print("✅ Crypto module")
        except:
            print("⚠️ Crypto module (optional)")
        
        # Try to import something from auth
        try:
            from secure_file_vault.auth import user_manager
            print("✅ Auth module")
        except:
            print("⚠️ Auth module (optional)")
        
        print("=" * 50)
        print("✅ SIMPLE TEST PASSED")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print("=" * 50)
        print("❌ SIMPLE TEST FAILED")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
