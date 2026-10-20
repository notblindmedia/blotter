@echo off
setlocal
cd /d "%~dp0"
title Blotter setup
echo.
echo  Blotter setup
echo  -------------
echo  This creates a private Python folder (.venv) inside the Blotter folder
echo  and installs the parts Blotter needs. Nothing else on the PC changes.
echo.

rem --- 1. Find Python 3.12 -----------------------------------------------
set "PY="
py -3.12 -c "pass" >nul 2>&1 && set "PY=py -3.12"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set PY="%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if defined PY goto have_python

echo  Python 3.12 isn't installed.
where winget >nul 2>&1
if errorlevel 1 goto manual_python
choice /c YN /m " Install Python 3.12 now with winget (Microsoft's app installer)"
if errorlevel 2 goto manual_python
winget install --id Python.Python.3.12 --exact --scope user --accept-package-agreements --accept-source-agreements
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    set PY="%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    goto have_python
)
echo.
echo  Python was installed, but this window can't see it yet.
echo  Close this window and double-click setup.bat again.
goto failed

:manual_python
echo.
echo  Install Python 3.12 from https://www.python.org/downloads/windows/
echo  then double-click setup.bat again.
goto failed

:have_python
echo  Using Python 3.12.

rem --- 2. Create the private Python folder --------------------------------
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import sys; sys.exit(sys.version_info[:2] != (3, 12))" >nul 2>&1
    if errorlevel 1 (
        echo  The old .venv folder uses another Python version; rebuilding it.
        %PY% -m venv --clear .venv || goto failed
    )
) else (
    echo  Creating .venv ...
    %PY% -m venv .venv || goto failed
)

rem --- 3. Install the exact pinned packages -------------------------------
rem --require-hashes: refuse any package whose checksum differs from requirements.txt
rem --only-binary: install ready-made packages only, never run build scripts
echo  Installing packages (this takes a minute the first time) ...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check --no-input ^
    --require-hashes --only-binary=:all: -r requirements.txt
if errorlevel 1 goto failed

echo.
echo  Setup finished. Double-click "Start Blotter.bat" to use Blotter.
echo.
pause
exit /b 0

:failed
echo.
echo  Setup didn't finish. The lines above say what went wrong.
echo.
pause
exit /b 1
