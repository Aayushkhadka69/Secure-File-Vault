"""
User authentication and management module
Handles user registration, login, and encrypted user database
"""

import os
import json
import datetime
import secrets
import hashlib
import base64
import getpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

USER_DATA_FILE = os.path.join(os.getcwd(), "users.enc")

class UserManager:
    """Manages user authentication, registration, and encrypted user database"""
    
    def __init__(self):
        self.master_key = self._derive_master_key()
        self.current_user = None
        
    def _derive_master_key(self):
        """Derive a master key from system info for encrypting user data"""
        system_info = f"{os.name}{os.getenv('COMPUTERNAME', 'unknown')}{getpass.getuser()}"
        return hashlib.sha512(system_info.encode()).digest()[:32]
    
    def encrypt_user_data(self, data):
        """Encrypt user data using AES-GCM"""
        iv = get_random_bytes(16)
        cipher = AES.new(self.master_key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return base64.b64encode(iv + tag + ciphertext).decode()
    
    def decrypt_user_data(self, encrypted_data):
        """Decrypt user data using AES-GCM"""
        try:
            data = base64.b64decode(encrypted_data)
            iv, tag, ciphertext = data[:16], data[16:32], data[32:]
            cipher = AES.new(self.master_key, AES.MODE_GCM, nonce=iv)
            return cipher.decrypt_and_verify(ciphertext, tag).decode()
        except Exception:
            return None
    
    def hash_password(self, password, salt=None):
        """Hash password with PBKDF2-HMAC-SHA512"""
        if salt is None:
            salt = secrets.token_bytes(32)
        return hashlib.pbkdf2_hmac('sha512', password.encode(), salt, 100000), salt
    
    def register_user(self, username, password):
        """Register a new user with validation"""
        users = self.load_users()
        
        if username in users:
            return False, "Username already exists"
        
        if len(username) < 4:
            return False, "Username must be at least 4 characters"
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        
        password_hash, salt = self.hash_password(password)
        users[username] = {
            'password_hash': password_hash.hex(),
            'salt': salt.hex(),
            'created': datetime.datetime.now().isoformat(),
            'last_login': None
        }
        
        self.save_users(users)
        return True, "Registration successful"
    
    def authenticate_user(self, username, password):
        """Authenticate user credentials"""
        users = self.load_users()
        
        if username not in users:
            return False, "Authentication failed: Invalid username or password"
        
        user_data = users[username]
        stored_hash = bytes.fromhex(user_data['password_hash'])
        salt = bytes.fromhex(user_data['salt'])
        
        input_hash, _ = self.hash_password(password, salt)
        
        if secrets.compare_digest(input_hash, stored_hash):
            user_data['last_login'] = datetime.datetime.now().isoformat()
            users[username] = user_data
            self.save_users(users)
            self.current_user = username
            return True, "Authentication successful"
        
        return False, "Authentication failed: Invalid username or password"
    
    def load_users(self):
        """Load encrypted user database from file"""
        if not os.path.exists(USER_DATA_FILE):
            return {}
        
        try:
            with open(USER_DATA_FILE, 'r') as f:
                encrypted_data = f.read().strip()
                if not encrypted_data:
                    return {}
                
                decrypted_json = self.decrypt_user_data(encrypted_data)
                if decrypted_json:
                    return json.loads(decrypted_json)
        except Exception:
            pass
        
        return {}
    
    def save_users(self, users):
        """Save encrypted user database to file"""
        try:
            json_data = json.dumps(users, indent=2)
            encrypted_data = self.encrypt_user_data(json_data)
            with open(USER_DATA_FILE, 'w') as f:
                f.write(encrypted_data)
            return True
        except Exception:
            return False
