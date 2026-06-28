@echo off
title CyberShield - Cybersecurity Platform
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    py -m venv .venv
    call .venv\Scripts\activate.bat
    pip install -r requirements.txt
) else (
    call .venv\Scripts\activate.bat
)

echo.
echo  CyberShield - AI-Powered Threat Detection
echo  Website: http://127.0.0.1:5001
echo  Admin:   admin / admin123
echo.
py app.py
pause
