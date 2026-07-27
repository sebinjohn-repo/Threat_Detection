@echo off
TITLE CyberGuard AI - Platform Launcher
echo ==================================================================
echo 🛡️  CyberGuard AI Platform Launcher
echo ==================================================================
echo.

set /p USER_API_KEY="Enter TCS GENAI_API_KEY (or press ENTER for Offline Mock Mode): "

if not "%USER_API_KEY%"=="" (
    set GENAI_API_KEY=%USER_API_KEY%
    echo [INFO] API Key set for TCS Gateway.
) else (
    echo [INFO] Running in Offline Crash-Proof Fallback Mode.
)

echo.
echo Launching CyberGuard AI...
echo Backend API & Frontend UI will be available at http://localhost:5000
echo.

python run_app.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Application exited with errors.
    pause
)
