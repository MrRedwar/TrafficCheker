@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0traffic-checker-app.ps1"
if errorlevel 1 (
    echo.
    echo TrafficChecker failed to start.
    pause
)
