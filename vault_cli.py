#!/usr/bin/env python3
"""
Secure Digital Document Vault - main program (interactive menu).

Usage (from the repository root):
    python vault_cli.py                  # data stored in ./vault_home
    python vault_cli.py --home my_data   # another data folder

For a quick scripted demonstration of the cryptography, run demo.py instead.
"""
import sys

from vault.cli import main

if __name__ == "__main__":
    sys.exit(main())
