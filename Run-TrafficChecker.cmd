@echo off
setlocal
cd /d "%~dp0"
py -3.13 traffic_checker_app.py
if errorlevel 1 py traffic_checker_app.py
if errorlevel 1 python traffic_checker_app.py
if errorlevel 1 (
    echo.
    echo TrafficChecker failed to start.
    pause
)
