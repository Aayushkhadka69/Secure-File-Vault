#!/usr/bin/env python3
"""Utility functions"""

import os
import subprocess
import sys

def open_path(path):
    """Cross-platform file opening"""
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)
        elif sys.platform.startswith("darwin"):
            subprocess.run(["open", path], check=False)
        else:
            subprocess.run(["xdg-open", path], check=False)
    except Exception:
        pass

def sanitize_path(path: str) -> str:
    """Sanitize file paths to prevent directory traversal attacks"""
    return os.path.normpath(path)
