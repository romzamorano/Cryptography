#!/usr/bin/env sh
# Runs every test (unit + integration) from the repository root, even without installing the project.
cd "$(dirname "$0")/.."
PYTHONPATH="src${PYTHONPATH:+:$PYTHONPATH}" python3 -m unittest discover -s tests -v
