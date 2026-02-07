@echo off
cd /d "%~dp0"
title AI Network Traffic Analyzer Setup
color 0A

:: Check for Admin Privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [SUCCESS] Running with Admin Privileges.
) else (
    echo [ERROR] This tool requires Admin privileges to capture network traffic.
    echo Please right-click this file and select "Run as Administrator".
    pause
    exit
)

:: Check for Python
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    pause
    exit
)

echo.
echo [1/3] Installing/Updating Dependencies...
pip install flask flask-socketio scapy eventlet
echo.

echo [2/3] Initializing Database...
:: The app handles DB creation on first run.
echo.

echo [3/3] Starting AI Network Traffic Analyzer...
echo    - Open your browser to: http://127.0.0.1:5000
echo    - Press CTRL+C to stop.
echo.

python app.py
pause