from setuptools import setup, find_packages
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as f:
    requirements = f.read().splitlines()

setup(
    name="secure-file-vault",
    version="2.0.0",
    author="Aayush Khadka",
    author_email="aayushkhadka084@gmail.com",
    description="Military-grade file encryption system with PKI authentication",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Aayushkhadka69/secure-file-vault",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "secure-vault=main:main",
        ],
    },
    include_package_data=True,
    keywords="encryption security cryptography vault pki aes rsa",
)
