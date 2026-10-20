# Blotter

Blotter tells you whether a file is known malware, before you open it.
You drop a file on a page in your browser and get one of four answers, each with its reasons in plain sentences.

It runs on your own Windows 10 or 11 PC. Nothing is installed system-wide except Python.

## What Blotter does with your file

1. **Reads its bytes** and works out its fingerprint (a SHA-256 hash, a 64-character code unique to that exact file).
   Blotter never opens, runs or imports the file.
2. **Asks VirusTotal** (about 70 antivirus engines) and **MalwareBazaar** (a public collection of known malware)
   whether they know that fingerprint. **Only the fingerprint leaves your PC. The file is never uploaded.**
3. **Asks Microsoft Defender** on your PC to scan the file. If Defender finds a threat, it quarantines
   Blotter's copy, and Blotter reports that as a detection.

Blotter works on a temporary copy in `%LOCALAPPDATA%\Blotter\incoming` and deletes the copy when the scan ends.
Your original file is not touched.

## The four answers

| Answer | Meaning |
|---|---|
| **Malicious** | At least one check recognises the file as malware: Defender detects it, MalwareBazaar lists it, or 3 or more VirusTotal engines flag it. |
| **Suspicious** | A warning sign without a clear detection, for example 1 or 2 VirusTotal engines out of 70 (often a false alarm, but worth care). |
| **No known detections** | None of the checks that ran recognise the file. This is not a promise that the file is harmless: brand-new or rare malware can go unrecognised. |
| **Couldn't check** | No check could run (no internet, no keys, Defender switched off). |

Blotter never calls a file "safe".

## Setup (once)

1. Double-click **`setup.bat`**. If Python 3.12 isn't installed, it offers to install it with winget.
   It then makes a private Python folder (`.venv`) inside the Blotter folder and installs exact,
   checksum-verified versions of the parts Blotter needs (listed in `requirements.txt`).
2. Get two free API keys:
   - **VirusTotal**: sign up at [virustotal.com](https://www.virustotal.com), open your profile menu, choose **API key**.
   - **MalwareBazaar**: sign in at [auth.abuse.ch](https://auth.abuse.ch) and copy your **Auth-Key**.

## Using it

1. Double-click **`Start Blotter.bat`**. A black window opens (keep it open) and your browser shows Blotter
   at http://127.0.0.1:4848.
2. The first time, Blotter asks for the two keys. Paste them and press **Save keys**. They are stored in
   **Windows Credential Manager** (under "Blotter"), never in a file. Change or remove them any time under **Keys**.
3. Drop a file on the page (or click to choose one). The answer appears in a few seconds.
   Open **Details** for the fingerprint, which antivirus engines flagged it, and links to the file's page
   on VirusTotal and MalwareBazaar.
4. To stop Blotter, close the black window.

**Quota:** a free VirusTotal key allows 4 lookups a minute and 500 a day. Blotter waits for a free slot
rather than going over. Answers from VirusTotal and MalwareBazaar are remembered, so checking the same file
again costs nothing. **Check again online** (under Details) asks them afresh.

## Checking that it works

- **A normal file**: drop a program installer you trust, for example the Python installer. Expected: **No known detections**.
- **A detection**: press **Check the EICAR test file** on the Blotter page. EICAR is a standard test file
  that every antivirus is built to detect; it contains no real malware. Expected: **Malicious**, with
  Defender's reason. Windows will show a "Threats found" notice and quarantine Blotter's copy. That is
  the expected result, not an error.

## Where things are

| What | Where |
|---|---|
| The program | this folder (`blotter\` holds the code, `blotter\checks\` one file per check) |
| Remembered answers | `%LOCALAPPDATA%\Blotter\cache.sqlite3` (delete it to forget them) |
| Temporary copies | `%LOCALAPPDATA%\Blotter\incoming` (emptied after each scan and at start-up) |
| API keys | Windows Credential Manager, entries named "Blotter" |

Blotter only answers on this PC (127.0.0.1) and refuses requests from other websites open in your browser.

## For developers

- Tests: `.venv\Scripts\python -m unittest discover -s tests -t .` (they never touch the real keys,
  cache or Defender).
- **Adding a check** (phase 2): add a module to `blotter/checks/` with `ID`, `NAME`, `ORDER`, `TIMEOUT`,
  `CACHE`, `NEEDS_FILE` and `scan(path) -> list[Finding]`. It is picked up automatically; see
  `blotter/checks/__init__.py`. The runner gives every check its own timeout, and a crashing check only
  marks itself "couldn't check".
- **Updating packages**: versions are pinned with checksums in `requirements.txt`, and setup installs with
  `--require-hashes --only-binary=:all:` (no build scripts run). Change them only on purpose, pick releases
  at least two weeks old, and regenerate the checksums from PyPI.
