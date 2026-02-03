"""
Utility functions for Secure File Vault
"""

import os
import subprocess
import sys

def open_path(path):
    """
    Open a path in the system's default file explorer
    
    Args:
        path: Path to open (file or directory)
    """
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)
        elif sys.platform.startswith("darwin"):
            subprocess.run(["open", path], check=False)
        else:
            subprocess.run(["xdg-open", path], check=False)
    except Exception as e:
        print(f"Error opening path: {e}")

def ensure_directory_exists(directory_path):
    """
    Ensure a directory exists, create it if it doesn't
    
    Args:
        directory_path: Path to directory
    """
    os.makedirs(directory_path, exist_ok=True)
    return directory_path

def format_file_size(size_bytes):
    """
    Format file size in human-readable format
    
    Args:
        size_bytes: Size in bytes
    
    Returns:
        str: Formatted size string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

def get_file_hash_hex(file_path):
    """
    Calculate SHA-256 hash of a file and return as hex string
    
    Args:
        file_path: Path to file
    
    Returns:
        str: SHA-256 hash in hexadecimal
    """
    import hashlib
    
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def validate_file_path(file_path):
    """
    Validate that a file path exists and is accessible
    
    Args:
        file_path: Path to validate
    
    Returns:
        tuple: (is_valid, error_message)
    """
    if not file_path:
        return False, "File path is empty"
    
    if not os.path.exists(file_path):
        return False, "File does not exist"
    
    if not os.path.isfile(file_path):
        return False, "Path is not a file"
    
    try:
        with open(file_path, 'rb') as f:
            f.read(1)
        return True, "File is accessible"
    except IOError as e:
        return False, f"Cannot read file: {str(e)}"

def secure_delete_file(file_path, passes=3):
    """
    Securely delete a file by overwriting it multiple times
    
    Warning: This is a basic implementation and may not be secure
    on all file systems. Use with caution.
    
    Args:
        file_path: Path to file to delete
        passes: Number of overwrite passes
    
    Returns:
        bool: True if successful
    """
    try:
        file_size = os.path.getsize(file_path)
        
        with open(file_path, 'rb+') as f:
            for _ in range(passes):
                f.seek(0)
                # Write random data
                import random
                random_data = bytearray(random.getrandbits(8) for _ in range(file_size))
                f.write(random_data)
                f.flush()
        
        os.remove(file_path)
        return True
    except Exception as e:
        print(f"Secure delete failed: {e}")
        # Fall back to normal delete
        try:
            os.remove(file_path)
            return True
        except:
            return False