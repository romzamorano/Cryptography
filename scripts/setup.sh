#!/usr/bin/env sh
# Secure Digital Document Vault - setup for Linux / macOS
# Creates a virtual environment, installs the dependencies and the project,
# and runs the test suite.  Usage (from the repository root):  sh scripts/setup.sh
set -e
cd "$(dirname "$0")/.."
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m unittest discover -s tests
echo
echo "Ready. Activate the environment with:  . .venv/bin/activate"
echo "Then run the program with:            python vault_cli.py"
