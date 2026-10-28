"""Write Blotter's harmless test files into a folder, for checking Blotter by hand.

    .venv\\Scripts\\python tools\\make_test_files.py ["C:\\Users\\you\\Desktop\\Blotter test files"]

None of them is malware. EICAR isn't written here: use the "Check the EICAR test file" button
on the Blotter page (Defender would remove an EICAR file the moment it is saved).
"""

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests import samples  # noqa: E402

README = """Blotter's harmless test files. None of them is malware, and nothing here runs by itself.

holiday-photo.jpg       a real, harmless program (Python's python.exe) renamed to look like a photo
                        Expected in Blotter: Suspicious ("really a Windows program, but its name ends in .jpg")
invoice.pdf.exe         the same program with a double ending
                        Expected: Suspicious ("looks like a .pdf file but runs as a .exe")
quarterly-report.docm   a Word document whose macro only shows a message box, set to run on opening
                        Expected: Unusual ("Its macro runs by itself as soon as the document is opened")
                        Don't open it in Word.
hello-obfuscated.ps1    a scrambled PowerShell script shaped like a download-and-run line; its address
                        ends in .invalid, which can never exist
                        Expected: Suspicious. Microsoft Defender may also react to it; that is fine.

Delete this folder when you're done.
"""


def main(argv) -> int:
    folder = Path(argv[0] if argv else Path.home() / "Desktop" / "Blotter test files")
    folder.mkdir(parents=True, exist_ok=True)
    exe = Path(sys.base_prefix) / "python.exe"
    shutil.copyfile(exe, folder / "holiday-photo.jpg")
    shutil.copyfile(exe, folder / "invoice.pdf.exe")
    (folder / "quarterly-report.docm").write_bytes(samples.docm())
    try:
        (folder / "hello-obfuscated.ps1").write_bytes(samples.obfuscated_ps1())
    except OSError as e:
        print(f"Windows refused to save hello-obfuscated.ps1 ({e.strerror or e}); Defender probably blocked it.")
    (folder / "README.txt").write_text(README.replace("\n", "\r\n"), encoding="utf-8", newline="")
    print(f"Test files written to {folder}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
