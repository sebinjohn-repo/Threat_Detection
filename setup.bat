@echo off
TITLE CyberGuard AI - Setup & Installation
echo ==================================================================
echo 🛡️  CyberGuard AI: Installing Dependencies...
echo ==================================================================
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not added to PATH!
    echo Please install Python 3.9+ from https://www.python.org/
    pause
    exit /b 1
)

echo [1/2] Upgrading pip...
python -m pip install --upgrade pip

echo [2/2] Installing required packages (Flask, Flask-CORS, httpx)...
python -m pip install flask flask-cors httpx

echo.
echo ==================================================================
echo ✅ CyberGuard AI setup complete!
echo Next step: Run "start.bat" to launch the application.
echo ==================================================================
echo.
pause
