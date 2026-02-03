# Contributing to Secure File Vault

Thank you for your interest in contributing to Secure File Vault! This document provides guidelines for contributing.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## How Can I Contribute?

### Reporting Bugs
1. Check if the bug has already been reported in the Issues section
2. If not, create a new issue with:
   - Clear description of the bug
   - Steps to reproduce
   - Expected vs actual behavior
   - Screenshots if applicable

### Suggesting Features
1. Check if the feature has already been suggested
2. Create a new issue with:
   - Clear description of the feature
   - Why it would be useful
   - Any implementation ideas

### Pull Requests
1. Fork the repository
2. Create a new branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Add tests if applicable
5. Update documentation
6. Commit changes: `git commit -m 'Add some feature'`
7. Push to your fork: `git push origin feature/your-feature-name`
8. Open a Pull Request

## Development Setup

### Prerequisites
- Python 3.8+
- Git
- Docker (optional)

### Setup
```bash
# Clone the repository
git clone https://github.com/Aayushkhadka69/secure-file-vault.git
cd secure-file-vault

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (macOS/Linux)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies