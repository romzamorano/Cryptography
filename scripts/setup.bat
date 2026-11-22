@echo off
REM Secure Digital Document Vault - setup for Windows
REM Creates a virtual environment, installs the dependencies and the project,
REM and runs the test suite.  Usage (from the repository root):  scripts\setup.bat
cd /d "%~dp0.."
py -m venv .venv || python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m unittest discover -s tests
echo.
echo Ready. Activate the environment with:  .venv\Scripts\activate
echo Then run the program with:            python vault_cli.py
