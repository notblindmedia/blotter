"""A desktop shortcut to "Start Blotter.bat", made only when setup.bat asks and the user says yes.

    python -m blotter.shortcut     makes (or replaces) Blotter.lnk on the user's desktop

Windows makes .lnk files through its WScript.Shell object, so this runs one PowerShell command. The paths go
in as environment variables, never inside the command text, so no folder name can change what it does.
Nothing starts by itself: the shortcut only opens Blotter when it is double-clicked.
"""

import os
import subprocess
import sys
from pathlib import Path

from . import config

NAME = "Blotter.lnk"
COMMAND = (
    "$ErrorActionPreference = 'Stop'; "
    "$folder = if ($env:BLOTTER_SHORTCUT_FOLDER) { $env:BLOTTER_SHORTCUT_FOLDER } "
    "else { [Environment]::GetFolderPath('Desktop') }; "
    "$path = Join-Path $folder $env:BLOTTER_SHORTCUT_NAME; "
    "$s = (New-Object -ComObject WScript.Shell).CreateShortcut($path); "
    "$s.TargetPath = $env:BLOTTER_SHORTCUT_TARGET; "
    "$s.WorkingDirectory = $env:BLOTTER_SHORTCUT_ROOT; "
    "$s.Description = 'Check a file with Blotter before opening it'; "
    "$s.Save(); "
    "Write-Output $path"
)


def powershell() -> str:
    return str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0"
               / "powershell.exe")


def make(root: Path = config.ROOT, folder: Path | None = None) -> Path:
    """Makes the shortcut in `folder` (default: the desktop, wherever Windows keeps it) and returns its path."""
    target = root / "Start Blotter.bat"
    if not target.is_file():
        raise FileNotFoundError(f"{target} is missing")
    env = dict(os.environ, BLOTTER_SHORTCUT_NAME=NAME, BLOTTER_SHORTCUT_TARGET=str(target),
               BLOTTER_SHORTCUT_ROOT=str(root), BLOTTER_SHORTCUT_FOLDER=str(folder) if folder else "")
    done = subprocess.run([powershell(), "-NoProfile", "-NonInteractive", "-Command", COMMAND], env=env,
                          capture_output=True, text=True, timeout=60,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    path = Path(done.stdout.strip().splitlines()[-1]) if done.stdout.strip() else None
    if done.returncode or path is None or not path.is_file():
        raise OSError((done.stderr or done.stdout).strip() or "PowerShell didn't make the shortcut")
    return path


def main() -> int:
    try:
        path = make()
    except (OSError, subprocess.SubprocessError) as e:
        print(f"  Couldn't make the shortcut ({e}). Blotter works without it: double-click \"Start Blotter.bat\".")
        return 1
    print(f"  Shortcut made: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
