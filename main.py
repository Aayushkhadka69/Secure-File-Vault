#!/usr/bin/env python3
"""
SECURE FILE VAULT - LAUNCHER
Run this to start the application
"""
import sys
import os

# Fix imports - point to your actual code
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, "src", "secure_file_vault")
sys.path.insert(0, src_path)

try:
    # Import from your actual main.py in src folder
    from main import main as start_vault
    print("=" * 60)
    print("SECURE FILE VAULT v2.0 - MILITARY-GRADE ENCRYPTION")
    print("=" * 60)
    start_vault()
except ImportError as e:
    print(f"[ERROR] Missing module: {e}")
    print("Install required packages: pip install pycryptodome")
    input("Press Enter to exit...")
except Exception as e:
    print(f"[ERROR] Failed to start: {e}")
    import traceback
    traceback.print_exc()
    input("Press Enter to exit...")
