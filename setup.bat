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
rem --no-deps: requirements.txt is the complete list, nothing else gets pulled in
echo  Installing packages (this takes a few minutes the first time) ...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check --no-input ^
    --require-hashes --only-binary=:all: --no-deps -r requirements.txt
if errorlevel 1 goto failed

rem --- 4. Rules: YARA Forge, capa and the signed intel pack (a few MB, checked) ---
echo.
echo  Downloading the rules Blotter uses (YARA Forge, capa, intel pack) ...
".venv\Scripts\python.exe" -m blotter.updates

rem --- 5. API keys (optional) ----------------------------------------------
echo.
echo  VirusTotal and MalwareBazaar keys are optional. Blotter works without them;
echo  only those two answers are missing. They are free; README.txt says where to get them.
choice /c YS /m " Add keys now (Y) or skip (S)"
if errorlevel 2 goto keys_done
".venv\Scripts\python.exe" -m blotter.keysetup
:keys_done

rem --- 6. ClamAV (optional) ----------------------------------------------
echo.
echo  ClamAV is a second antivirus engine that runs only while Blotter is open.
echo  It downloads about 225 MB once, plus about 110 MB of signatures, and uses
echo  about 1.5 GB of memory while Blotter runs. You can turn it off in Settings.
choice /c YN /m " Set up ClamAV now"
if errorlevel 2 goto done
".venv\Scripts\python.exe" -m blotter.updates --clamav

:done

rem --- 7. Desktop shortcut (optional; it only opens Blotter when double-clicked) ---
echo.
choice /c YN /m " Put a Blotter shortcut on your desktop"
if errorlevel 2 goto shortcut_done
".venv\Scripts\python.exe" -m blotter.shortcut
:shortcut_done

rem --- 8. The check code of Blotter's signing keys ------------------------
echo.
echo  If the person who gave you Blotter sent you a check code, compare it with
echo  this one. All 12 characters must be the same; if not, stop and ask them.
".venv\Scripts\python.exe" -m blotter.signing

echo.
echo  Setup finished. Double-click the Blotter shortcut (or "Start Blotter.bat")
echo  to use Blotter.
echo  To get a newer version later, double-click update.bat.
echo.
pause
exit /b 0

:failed
echo.
echo  Setup didn't finish. The lines above say what went wrong.
echo.
pause
exit /b 1
