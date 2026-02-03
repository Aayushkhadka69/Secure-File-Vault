# 🔐 Secure File Vault v2.0

**Military-Grade File Encryption System with PKI Authentication**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![GitHub Issues](https://img.shields.io/github/issues/Aayushkhadka69/secure-file-vault)](https://github.com/Aayushkhadka69/secure-file-vault/issues)
[![GitHub Stars](https://img.shields.io/github/stars/Aayushkhadka69/secure-file-vault)](https://github.com/Aayushkhadka69/secure-file-vault/stargazers)

A professional, military-grade file encryption tool featuring AES-256-GCM encryption with RSA-4096 PKI signatures, designed for maximum security and data integrity.

## ✨ Features

### 🔒 Security Features
- **AES-256-GCM Encryption**: Authenticated encryption with associated data
- **RSA-4096 PKI**: Mandatory digital signatures for all operations
- **Military-Grade Key Derivation**: PBKDF2-HMAC-SHA512 with 32-byte salt
- **Tamper Detection**: Blocks decryption if files are modified
- **Secure User Authentication**: Encrypted credential storage with system-derived master key

### 💻 Technical Features
- **Modular Architecture**: Clean separation of concerns (auth, crypto, gui, utils)
- **Cross-Platform**: Windows, macOS, and Linux support
- **GUI Interface**: Military-themed terminal-style interface
- **Key Management**: Secure key generation, storage, and memory wiping
- **File Integrity**: SHA-256 verification with RSA signatures

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Docker (optional, for containerized deployment)

### Option 1: Using Docker (Recommended)
```bash
# Clone the repository
git clone https://github.com/Aayushkhadka69/secure-file-vault.git
cd secure-file-vault

# Build and run with Docker
docker build -t secure-file-vault .
docker run -it --rm -v $(pwd)/secure_vault:/app/secure_vault secure-file-vault