@echo off
REM Start Frida Server for Stellaris Reverse Engineering
REM Requires Administrator privileges for memory access

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script requires Administrator privileges.
    echo [ERROR] Right-click and select "Run as administrator".
    pause
    exit /b 1
)

REM Configuration
set FRIDA_PATH=C:\tools\frida
set FRIDA_PORT=27042
set BIND_ADDRESS=127.0.0.1

REM Check if frida-server exists
if not exist "%FRIDA_PATH%\frida-server.exe" (
    echo [ERROR] frida-server.exe not found at %FRIDA_PATH%
    echo [ERROR] Download from: https://github.com/frida/frida/releases
    pause
    exit /b 1
)

REM Display banner
echo ========================================
echo  Frida Server for Stellaris RE
echo ========================================
echo.
echo  Path: %FRIDA_PATH%\frida-server.exe
echo  Port: %FRIDA_PORT%
echo  Bind: %BIND_ADDRESS%
echo.

REM Check if already running
tasklist /FI "IMAGENAME eq frida-server.exe" 2>nul | find /I "frida-server.exe" >nul
if %errorLevel% equ 0 (
    echo [WARN] frida-server is already running.
    echo [WARN] Stopping existing instance...
    taskkill /F /IM frida-server.exe >nul 2>&1
    timeout /t 2 >nul
)

REM Start frida-server
echo [INFO] Starting frida-server...
echo [INFO] Press Ctrl+C to stop.
echo.

cd /d "%FRIDA_PATH%"
frida-server.exe -l %BIND_ADDRESS%:%FRIDA_PORT%

REM If we get here, server stopped
echo.
echo [INFO] frida-server stopped.
pause
