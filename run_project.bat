@echo off
setlocal EnableExtensions

cd /d "%~dp0"

echo =========================================
echo   Zero Trust IoT - Project Launcher
echo =========================================
echo.

set "PYTHON_EXE=%CD%\.venv\Scripts\python.exe"

if not exist "%PYTHON_EXE%" (
    echo [INFO] Virtual environment not found at .venv
    echo [INFO] Creating virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        echo Install Python 3 and re-run this file.
        pause
        exit /b 1
    )
)

echo [INFO] Installing/updating dependencies...
call "%PYTHON_EXE%" -m pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Dependency installation failed.
    pause
    exit /b 1
)

echo.
echo [INFO] Starting Security Engine...
start "ZeroTrust - Security Engine" cmd /k "cd /d "%CD%" && "%PYTHON_EXE%" scripts\run_security_engine.py"

timeout /t 2 /nobreak >nul

echo [INFO] Starting Dashboard...
start "ZeroTrust - Dashboard" cmd /k "cd /d "%CD%" && "%PYTHON_EXE%" scripts\run_dashboard.py"

timeout /t 2 /nobreak >nul

choice /C YN /N /M "Bridge ESP32 Serial to dashboard? (Y/N): "
if errorlevel 2 goto AFTER_BRIDGE
set /p ESP32_PORT=Enter ESP32 COM port (example COM5): 
if not "%ESP32_PORT%"=="" start "ZeroTrust - ESP32 Bridge" cmd /k "cd /d "%CD%" && "%PYTHON_EXE%" scripts\run_esp32_bridge.py --port %ESP32_PORT%"

:AFTER_BRIDGE

echo.
echo [INFO] Services started.
echo Dashboard URL: http://127.0.0.1:8050
echo.

choice /C YN /N /M "Send a VALID test payload now? (Y/N): "
if errorlevel 2 goto ASK_ATTACK
call "%PYTHON_EXE%" scripts\send_data.py

:ASK_ATTACK
choice /C YN /N /M "Send an ATTACK test payload now? (Y/N): "
if errorlevel 2 goto DONE
call "%PYTHON_EXE%" scripts\send_data.py --attack

:DONE
echo.
echo [INFO] Launcher completed.
echo Keep the two opened terminals running for live monitoring.
pause
exit /b 0
