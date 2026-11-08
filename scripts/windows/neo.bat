@echo off
rem neo.bat -- the player entry point.  Double-click it.
rem
rem It runs neo_install.py beside this file with no arguments, which means "find
rem the game, find the newest project, install both halves, launch and inject".
rem Everything it prints is one line: NEO_PLAY ok ... / NEO_PLAY fail reason=<tag>.
rem
rem The only tag this file reports by itself is python_missing: every tag after
rem the interpreter exists comes from neo_install.py's FAILURE_TAGS.  A window
rem opened by a double-click closes on exit, so a failure pauses -- except under
rem --debug, where the traceback is worth reading in a real console.
setlocal
cd /d "%~dp0"

set "PYTHON=python"
where python >nul 2>nul
if errorlevel 1 (
    where py >nul 2>nul
    if errorlevel 1 (
        echo NEO_PLAY fail reason=python_missing
        echo Install Python 3.9+ and tick "Add python.exe to PATH", then run this again.
        pause
        exit /b 2
    )
    set "PYTHON=py -3"
)

%PYTHON% "%~dp0neo_install.py" %*
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
    echo.
    echo Neo did not start: the NEO_PLAY line above says why.
    echo The tag table is in docs\runtime-js-sdk.md.
    echo %* | findstr /c:"--debug" >nul || pause
)
exit /b %RC%
