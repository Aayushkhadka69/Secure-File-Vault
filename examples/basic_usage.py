"""
Example: Using Secure File Vault
"""

from secure_file_vault import main
from secure_file_vault.crypto import symmetric, vault_ops
from secure_file_vault.auth import user_manager

print("Secure File Vault Example")
print("=" * 40)

# Initialize user manager
um = user_manager.UserManager()

# Create symmetric key
key = symmetric.generate_key()
print(f"Generated key: {key[:20]}...")

# Demonstrate vault operations
print("Vault operations initialized successfully")
print("Run main.py to start the application")
