@echo off
REM Runs every test (unit + integration) from the repository root, even without installing the project.
cd /d "%~dp0.."
set "PYTHONPATH=src;%PYTHONPATH%"
python -m unittest discover -s tests -v
