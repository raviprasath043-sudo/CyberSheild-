@echo off

title CyberShield Production Server

echo ====================================
echo       CyberShield Security System
echo ====================================
echo.
echo Starting production server...
echo.

call venv\Scripts\activate

python run_server.py

pause
