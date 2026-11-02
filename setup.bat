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

if /i not "%PROCESSOR_ARCHITECTURE%"=="ARM64" if /i not "%PROCESSOR_ARCHITEW6432%"=="ARM64" goto not_arm
echo  This PC has an ARM processor (Windows on ARM, such as a Snapdragon laptop).
echo  Blotter doesn't work on those: it needs an Intel or AMD processor.
echo  Setup stopped here and nothing on this PC was changed.
echo.
pause
exit /b 1
:not_arm

rem --- 0. A good place for the Blotter folder ---------------------------
rem Two common traps: Windows' "Extract All" makes a blotter-X.Y.Z folder inside a blotter-X.Y.Z folder, and a
rem Desktop or Documents folder backed up by OneDrive syncs the thousands of files in .venv. Offer a copy in
rem %USERPROFILE%\Blotter (never synced) and continue setup there; the old folder can be deleted afterwards.
set "HERE=%~dp0"
set "HERE=%HERE:~0,-1%"
set "TARGET=%USERPROFILE%\Blotter"
if /i "%HERE%"=="%TARGET%" goto place_ok
set "WHY="
if /i not "%HERE:OneDrive=%"=="%HERE%" set "WHY=onedrive"
for %%A in ("%HERE%") do set "SELF=%%~nxA"
for %%A in ("%HERE%\..") do for %%B in ("%%~fA") do set "PARENT=%%~nxB"
if not defined WHY if /i "%SELF:~0,8%"=="blotter-" if /i "%PARENT:~0,8%"=="blotter-" set "WHY=double"
if not defined WHY goto place_ok
if "%WHY%"=="onedrive" goto place_onedrive
echo  This Blotter folder sits inside another Blotter folder, which Windows'
echo  "Extract All" does. It works, but it is easy to lose track of.
goto place_offer
:place_onedrive
echo  This Blotter folder is inside OneDrive, which would copy the thousands of
echo  files setup adds to the internet and can later hide them from Blotter.
:place_offer
echo  A better place is %TARGET%.
if exist "%TARGET%" goto place_taken
choice /c YN /m " Copy Blotter there and continue setup from there"
if errorlevel 2 goto place_stay
robocopy "%HERE%" "%TARGET%" /E /XD .venv .git /NFL /NDL /NJH /NJS /NP >nul
if errorlevel 8 goto place_failed
echo.
echo  Copied. Setup continues in a new window, from %TARGET%.
echo  When it has finished, you can delete this folder: %HERE%
echo  From now on, Blotter is in %TARGET%.
echo.
start "Blotter setup" "%TARGET%\setup.bat"
pause
exit /b 0
:place_taken
echo  There is already a folder there. If it is Blotter, close this window and
echo  double-click setup.bat in %TARGET% instead.
choice /c YN /m " Set up Blotter here anyway"
if errorlevel 2 goto place_quit
goto place_ok
:place_quit
echo.
pause
exit /b 1
:place_failed
echo  Copying didn't work, so setup continues here.
goto place_ok
:place_stay
echo  OK, setting up here.
:place_ok
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
