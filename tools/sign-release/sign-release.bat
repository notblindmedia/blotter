@echo off
setlocal
cd /d "%~dp0"
title Blotter release signing
echo.
echo  Blotter release signing (signing PC only)
echo  -----------------------------------------

rem --- 1. Find a 64-bit Python 3.12. The first one that really is 3.12 wins:
rem     BLOTTER_PYTHON (full path to python.exe), the one remembered from the last run,
rem     python on PATH, the py launcher, the standard per-user install.
rem     Portable Pythons (the NuGet package, for example) work: only pip is needed, no venv.
set "PY="
set "REMEMBERED="
if defined BLOTTER_PYTHON goto from_setting
if exist "python-path.txt" set /p REMEMBERED=<"python-path.txt"
if defined REMEMBERED call :try "%REMEMBERED%"
if defined PY goto have_python
for /f "usebackq delims=" %%i in (`python -c "import sys; print(sys.executable)" 2^>nul`) do call :try "%%i"
if defined PY goto have_python
for /f "usebackq delims=" %%i in (`py -3.12 -c "import sys; print(sys.executable)" 2^>nul`) do call :try "%%i"
if defined PY goto have_python
call :try "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if defined PY goto have_python
echo  No 64-bit Python 3.12 found. Either put its folder on PATH, or tell the kit
echo  where python.exe is, for example:
echo      set BLOTTER_PYTHON=D:\Python312\python.exe
echo  then run sign-release.bat again in the same window.
goto failed

:from_setting
set "BLOTTER_PYTHON=%BLOTTER_PYTHON:"=%"
call :try "%BLOTTER_PYTHON%"
if defined PY goto have_python
echo  BLOTTER_PYTHON is "%BLOTTER_PYTHON%", but that isn't a 64-bit Python 3.12 python.exe.
goto failed

:have_python
echo  Using Python 3.12: %PY%
> "python-path.txt" echo %PY%

rem --- 2. The kit's packages, pinned with checksums, into .deps in this folder ---------
rem --require-hashes: refuse any package whose checksum differs from requirements.txt
rem --only-binary: ready-made packages only, no build scripts run
rem --no-deps: requirements.txt is the complete list, nothing else gets pulled in
if exist ".deps\installed.txt" goto ready
"%PY%" -m pip --version >nul 2>&1
if errorlevel 1 goto no_pip
echo  First run: installing cryptography and its two helpers into .deps ...
if exist ".deps" rmdir /s /q ".deps"
"%PY%" -m pip install --disable-pip-version-check --no-input --require-hashes --only-binary=:all: --no-deps --target .deps -r requirements.txt
if errorlevel 1 goto failed
> ".deps\installed.txt" echo cffi 2.1.1, cryptography 50.0.2, pycparser 3.11 (requirements.txt)

:ready
if "%~1"=="" goto usage
rem -I: Python ignores PATH-style settings and this folder's other files; sign_release.py adds only .deps
"%PY%" -I sign_release.py %*
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

:no_pip
echo  This Python has no pip, which the kit needs to install cryptography.
goto failed

:failed
echo.
echo  That didn't finish. The lines above say what went wrong.
echo.
pause
exit /b 1

rem --- :try "path" sets PY if that file is a 64-bit Python 3.12 -----------------------
:try
if not exist "%~1" exit /b
"%~1" -c "import sys; sys.exit(not (sys.version_info[:2] == (3, 12) and sys.maxsize > 2**32))" >nul 2>&1 && set "PY=%~1"
exit /b
