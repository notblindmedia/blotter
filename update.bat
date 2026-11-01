@echo off
setlocal
cd /d "%~dp0"
title Blotter update
rem Everything runs as one block on purpose. Windows reads a .bat file bit by bit while running it, and an
rem update may replace this file; a block is read in full before it starts, so a new update.bat can't
rem confuse this run. No brackets in the echo lines below: they would end the block.
(
    echo.
    echo  Blotter update
    echo  --------------
    echo  Checks GitHub for a newer Blotter. It installs one only if the release key
    echo  signed it, it is newer than this one, and you say yes.
    echo.
    if not exist ".venv\Scripts\python.exe" (
        echo  Blotter isn't set up yet. Double-click setup.bat first.
        echo.
        pause
        exit /b 1
    )
    ".venv\Scripts\python.exe" -m blotter.selfupdate
    if errorlevel 3 if not errorlevel 4 (
        echo.
        echo  Installing the exact, checksum-verified parts the new version needs ...
        ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check --no-input --require-hashes --only-binary=:all: --no-deps -r requirements.txt
        if errorlevel 1 echo  That didn't finish. Double-click setup.bat to finish the update.
    )
    echo.
    pause
    exit /b
)
