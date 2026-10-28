@echo off
cd /d "%~dp0.."
title Blotter false-alarm test
if not exist ".venv\Scripts\python.exe" (
    echo Blotter isn't set up yet. Double-click setup.bat first.
    pause
    exit /b 1
)
set "FOLDER=%~1"
if "%FOLDER%"=="" set /p "FOLDER=Folder of trusted files to check: "
".venv\Scripts\python.exe" tools\false_alarm_test.py "%FOLDER%"
pause
