#!/usr/bin/env python3
"""Setup script for Secure File Vault"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="secure-file-vault",
    version="2.0.0",
    author="Aayush Khadka",
    author_email="aayushkhadka084@gmail.com",
    description="Military-grade secure file encryption vault with GUI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Aayushkhadka69/Secure-File-Vault",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
        "Topic :: Desktop Environment :: File Managers",
    ],
    python_requires=">=3.8",
    install_requires=[
        "pycryptodome>=3.20.0",
    ],
    entry_points={
        "console_scripts": [
            "secure-vault=secure_file_vault.main:main",
        ],
    },
    include_package_data=True,
)
