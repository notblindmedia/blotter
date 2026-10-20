@echo off
cd /d "%~dp0"
title Blotter
if not exist ".venv\Scripts\python.exe" (
    echo Blotter isn't set up yet. Double-click setup.bat first.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" -m blotter %*
if errorlevel 1 pause
