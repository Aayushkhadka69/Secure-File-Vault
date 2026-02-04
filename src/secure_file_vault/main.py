#!/usr/bin/env python3
"""
Secure File Vault - Main Entry Point
Military-grade encryption system with user authentication and PKI
"""

import sys
import os

# Add current directory to path for module imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auth.auth_window import AuthWindow

def main():
    """Main entry point for the Secure File Vault application"""
    print("Starting Secure File Vault...")
    print("If window doesn't appear, check for error messages below.")
    print("For first-time use: Click REGISTER button to create account.")
    print("Username must be at least 4 characters.")
    print("Password must be at least 8 characters.")
    
    try:
        auth = AuthWindow()
    except Exception as e:
        print(f"Error starting application: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
    
