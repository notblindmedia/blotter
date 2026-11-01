"""setup.bat's optional key step: paste each API key, or just press Enter to skip it.

Keys go to Windows Credential Manager (blotter/keys.py), never into a file, and aren't shown while typed.
They can be added or changed later under Settings in Blotter.
"""

import getpass
import sys

from . import keys, settings

WHERE = {
    "virustotal": "VirusTotal: sign up at https://www.virustotal.com, open your profile menu, choose \"API key\".",
    "malwarebazaar": "MalwareBazaar: sign in at https://auth.abuse.ch and copy your \"Auth-Key\".",
}


def run(ask=getpass.getpass) -> int:
    if not keys.backend_ok():
        print(f"  Windows Credential Manager isn't available ({keys.backend_name()}), so keys can't be saved.")
        return 1
    saved = 0
    for name, label in keys.KNOWN.items():
        print(f"\n  {WHERE[name]}")
        while True:
            value = ask(f"  Paste your {label} key and press Enter (just Enter skips it; it isn't shown): ")
            if not value.strip():
                print(f"  {label}: skipped.")
                break
            try:
                keys.put(name, value)
            except ValueError as e:
                print(f"  {e} Try again, or press Enter to skip.")
                continue
            print(f"  {label}: saved ({len(value.strip())} characters).")
            saved += 1
            break
    if saved:
        settings.update({"setup_done": True})  # the page then doesn't offer its own key step again
    return 0


if __name__ == "__main__":
    sys.exit(run())
