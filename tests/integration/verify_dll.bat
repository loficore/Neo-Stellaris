@echo off
REM verify_dll.bat — Verify DLL exports and dependencies
REM
REM This script checks that stellaris_quickjs.dll has the required exports
REM and can be loaded by the injector.

setlocal enabledelayedexpansion

echo ========================================
echo   DLL Verification Script
echo   stellaris_quickjs DLL
echo ========================================
echo.

REM Set paths
set "DLL_PATH=%~dp0..\..\zig-out\bin\stellaris_quickjs.dll"
set "LOADER_PATH=%~dp0..\..\zig-out\bin\stellaris-loader.exe"

REM Check if DLL exists
echo [1/4] Checking DLL exists...
if not exist "%DLL_PATH%" (
    echo [FAIL] DLL not found: %DLL_PATH%
    echo.
    echo Build the DLL first with: zig build
    goto :error
)
echo [PASS] DLL found: %DLL_PATH%
echo.

REM Check DLL file size
echo [2/4] Checking DLL file size...
for %%A in ("%DLL_PATH%") do set "DLL_SIZE=%%~zA"
if %DLL_SIZE% LSS 10000 (
    echo [WARN] DLL seems too small (%DLL_SIZE% bytes)
    echo This might indicate a build issue.
) else (
    echo [PASS] DLL size: %DLL_SIZE% bytes
)
echo.

REM Check if dumpbin is available (Visual Studio)
echo [3/4] Checking DLL exports...
where dumpbin >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Using dumpbin to check exports...
    dumpbin /EXPORTS "%DLL_PATH%" | findstr /i "PushCApplicationPtr DllMain"
    if %ERRORLEVEL% EQU 0 (
        echo [PASS] Required exports found
    ) else (
        echo [FAIL] Required exports not found
        echo Expected: PushCApplicationPtr, DllMain
    )
) else (
    echo [INFO] dumpbin not available, skipping export check
    echo Install Visual Studio Build Tools for detailed DLL analysis
)
echo.

REM Check if loader exists
echo [4/4] Checking loader...
if exist "%LOADER_PATH%" (
    echo [PASS] Loader found: %LOADER_PATH%
) else (
    echo [INFO] Loader not found at expected path
    echo Build the loader separately from src/loader/
)
echo.

REM Summary
echo ========================================
echo   Verification Complete
echo ========================================
echo.
echo Next steps:
echo   1. Start Stellaris
echo   2. Run: stellaris-loader.exe "%DLL_PATH%"
echo   3. Check console output for success
echo.

goto :end

:error
echo.
echo Verification failed. Please check the errors above.
exit /b 1

:end
exit /b 0
