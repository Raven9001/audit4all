@echo off
setlocal EnableExtensions
cd /d "%~dp0"

title AUDIT4ALL Launcher

echo ========================================================
echo   AUDIT4ALL - Launcher
echo ========================================================
echo.

where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python was not found in your PATH.
    echo Please install Python 3 from https://www.python.org/downloads/
    echo Make sure to tick "Add python.exe to PATH" during installation.
    echo.
    pause
    exit /b 1
)

net session >nul 2>&1
if errorlevel 1 (
    echo This window is not running as administrator.
    echo Some checks need it to give you full results.
    echo.
    choice /c YN /n /m "Restart as administrator now? [Y/N] "
    if not errorlevel 2 (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
        exit /b
    )
    echo.
)

python -c "import psutil, requests, scapy" >nul 2>&1
if errorlevel 1 (
    echo Installing required packages: psutil, requests, scapy
    python -m pip install --upgrade pip >nul 2>&1
    python -m pip install psutil requests scapy
    if errorlevel 1 (
        echo.
        echo [ERROR] Failed to install one or more required packages.
        echo Check your internet connection and try again.
        echo.
        pause
        exit /b 1
    )
)

echo.
echo How would you like to open AUDIT4ALL?
echo   [1] Desktop App
echo   [2] Web Browser App
echo.
choice /c 12 /n /m "Press 1 or 2: "

if errorlevel 2 goto launch_web
goto launch_desktop

:launch_desktop
echo.
echo Starting AUDIT4ALL Desktop App...
python audit4all.py
goto after_run

:launch_web
python -c "import streamlit" >nul 2>&1
if errorlevel 1 (
    echo Installing Streamlit for the browser version...
    python -m pip install streamlit
)
echo.
echo Starting AUDIT4ALL Web App...
python -m streamlit run app.py
goto after_run

:after_run
if errorlevel 1 (
    echo.
    echo [NOTE] The app exited with a message or error above.
    pause
)
endlocal
