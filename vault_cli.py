#!/usr/bin/env python3
"""
Secure Digital Document Vault - main program (interactive menu).

Usage (from the repository root):
    python vault_cli.py                  # data stored in ./vault_home
    python vault_cli.py --home my_data   # another data folder

For a quick scripted demonstration of the cryptography, run examples/demo.py instead.
"""
import os
import sys

# The source code lives in src/. Adding it here lets the menu run even if the
# project was not installed with "pip install -r requirements.txt".
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from vault.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
