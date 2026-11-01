@echo off
setlocal
cd /d "%~dp0"
title Blotter release signing
echo.
echo  Blotter release signing (main PC only)
echo  --------------------------------------

rem --- Python 3.12 and a private folder with the pinned cryptography package ---
if exist ".venv\Scripts\python.exe" goto ready
set "PY="
py -3.12 -c "pass" >nul 2>&1 && set "PY=py -3.12"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set PY="%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PY (
    echo  Python 3.12 is needed. Install it from https://www.python.org/downloads/windows/
    echo  then run this again.
    goto failed
)
echo  First run: making a private Python folder here and installing cryptography ...
%PY% -m venv .venv || goto failed
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check --no-input ^
    --require-hashes --only-binary=:all: --no-deps -r requirements.txt
if errorlevel 1 goto failed

:ready
if "%~1"=="" goto usage
".venv\Scripts\python.exe" sign_release.py %*
echo.
pause
exit /b

:usage
echo.
echo  To make the release key (once):   sign-release.bat new-key
echo  To sign a release: drag blotter-X.Y.Z.json onto sign-release.bat
echo  (the matching blotter-X.Y.Z.zip must be in the same folder).
echo.
pause
exit /b 1

:failed
echo.
echo  That didn't finish. The lines above say what went wrong.
echo.
pause
exit /b 1
