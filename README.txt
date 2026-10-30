BLOTTER

Blotter is an all-round file checker: it tells you whether a file is known
malware, or looks like it, before you open it. It handles the files people
actually download and get sent: installers and programs, Office documents,
PDFs, scripts and shortcuts, and zip, rar and 7z archives (it looks inside).
You drop a file on a page in your browser and get one of six answers, each
with its reasons in plain sentences.

Some legitimate files do things malware also does, game mods, cheats and
admin tools for example. Blotter handles those carefully: it says what the
file can do and that harmless tools do the same, instead of calling it
malware.

It runs on your own Windows 10 or 11 PC. It never needs admin rights.
Nothing is installed system-wide except Python.


WHAT BLOTTER DOES WITH YOUR FILE

Blotter never opens, runs or imports the file. It only reads its bytes, and
every check that reads them runs in its own separate process with a time
limit and a memory limit, so a file built to crash a checker can't harm
Blotter or your PC.

The checks that take the file apart run in a Windows sandbox (an
"AppContainer", the same kind Windows uses for Store apps). Inside it a
check has no network at all, and it can't open any of your files: only the
one file being checked, Blotter's own program files and rules, and a scratch
folder that is deleted afterwards. No admin rights are needed. If Windows
can't provide the sandbox, Blotter uses a weaker "low-integrity" box (it can't
change anything on the PC, but it could read files and reach the network);
if that doesn't work either, only the time and memory limits remain.
Settings shows which one is in use. Defender, ClamAV and the signature check
hand the file to those engines, which do their own reading; they run outside
the sandbox.

1. What it really is
   - The real file type, from the first bytes (a program, a document, a
     picture ...), compared with its name. Names that lie are flagged, for
     example a program called holiday-photo.jpg, or invoice.pdf.exe (Windows
     often hides the ".exe", so it looks like a PDF).
   - Zip, rar and 7z archives are unpacked and every file inside is checked.
     Locked archives are tried with the password "infected" (what malware
     researchers use); if that doesn't open them, the result asks you for
     the password and checks again. The password is only kept in memory for
     that check (and for a moment in the sandbox's scratch folder), never
     saved. Blotter keeps the locked archive's copy for 30 minutes while it
     waits. Limits stop "zip bombs" (archives built to unpack into
     something enormous): 500 MB in total, 1000 files, 3 archives deep, and
     nothing packed more than 100 times smaller than its real size.
     A zip whose table of contents is broken (Windows says it is invalid) is
     still read: Blotter walks each file's own header, the way 7-Zip, WinRAR
     and tar do, so breaking a zip can't hide a program from it. If files
     inside are damaged or the zip is cut off, the answer is "Couldn't fully
     check" (whatever could be read is still checked).
     Zips hidden in other files are found and checked too: a zip glued after
     a picture or a PDF, two zips back to back, a zip whose first bytes were
     overwritten, and a zip appended after a program (self-extracting
     installers do that; the card says so without counting it as a warning).
     A zip hidden after a picture, a document (PDF, Word, Excel, PowerPoint,
     OpenDocument, RTF) or a Java program (.jar) makes the answer at least
     "Unusual", even when the files in it are clean, and the Office macro
     check still reads the document part (the card names the document, not
     "a ZIP archive", and lists each macro once). Two plain zips back to back only
     get a note. A zip inside an older Word file's own data (newer Word keeps
     its theme there) is unpacked and checked without the warning.
     Zips a program keeps inside its own code and resources are left alone.

2. What it can do
   - YARA rules: the YARA Forge "core" collection (about 5,000 rules for known
     malware and tools, updated weekly) plus Blotter's own rules in the
     "rules" folder.
   - capa (by Mandiant) reads a program's machine code and names its
     abilities, such as "injects code into other programs" or "starts itself
     with Windows". It looks at the program itself, without data appended
     after it (installer payloads or padding). capa is the deep check: it can
     take minutes, so the card shows the other checks' answer first with
     "Deep check still running…", and updates when capa finishes (it gets up
     to 15 minutes). Engine detections never wait for it. Deep checks run
     one at a time, oldest first, at below-normal CPU priority, so checking
     a batch of files can't slow the PC down; a file that waits says "Deep
     check queued, 3rd in line" (its 15 minutes start when its turn comes).
     Closing Blotter cancels the queue and stops the deep check that is
     running; anything left behind is removed at the next start. Its
     answers are remembered, so checking the same program
     again is instant. Blotter runs capa with a speed fix for vivisect (the
     disassembler capa uses), made for vivisect 1.3.2 only; with any other
     version capa runs without it (slower, same results) and the card says
     so.
   - Program check: is it digitally signed, by whom, and is the signature
     still valid? Windows also checks its catalog files, so its own programs
     (System32) count as signed by Microsoft even as copies. Is it packed
     (its code hidden until it runs)? Is it padded with empty filler to look
     bigger than it is? Does it use risky combinations of Windows functions?
   - A valid signature from a well-known publisher quiets the warnings about
     what a program can do (Microsoft's own tools can do a lot). Those
     abilities stay listed on the card but don't raise the answer. The list
     is short and you can edit it: rules\trusted-publishers.txt (Microsoft,
     Google, Apple, Valve, Mozilla, NVIDIA, AMD, Intel, Adobe, Oracle,
     Discord, Python, Git for Windows, Tailscale, Node.js, Roblox, Anthropic,
     Obsidian, NetEase). Any other valid signature counts for
     a little: it forgives one warning sign, no more, because any company
     can buy a signing certificate. Engine detections that name malware are
     never quieted, and a certificate on the stolen list
     (rules\stolen-certificates.txt) counts as a warning, not as trust. That
     list starts empty: it will be filled from abuse.ch's blocklist of
     abused code-signing certificates by the weekly update (planned), never
     from memory.
   - Office documents: macros (with oletools), auto-run macros, scrambled
     macro code, documents that fetch content from the internet.
   - RTF documents (oletools' rtfobj): the objects embedded in them. RTF
     can't hold macros, but its objects are how RTF attacks work: an old
     Equation Editor object, a linked object that fetches a document from
     the internet (OLE2Link), objects oletools ties to known Office flaws,
     a program packed inside ("OLE Package"), or a broken object. Which
     objects are tied to which flaw comes from oletools' own list.
   - PDFs: JavaScript, actions that run by themselves when the PDF opens,
     "Launch" actions that start programs, files packed inside, and names
     disguised to slip past scanners. Read as bytes, never opened.
   - Scripts and shortcuts (.ps1 .bat .cmd .vbs .js .hta .wsf .lnk ...):
     download-and-run lines, hidden windows, encoded commands, scrambled
     code, attempts to switch off Microsoft Defender. Web requests that only
     go to this PC itself (127.0.0.1, localhost) don't count as downloads,
     and neither do download commands that only appear in comments or in a
     list of names (a blocklist such as ['curl', 'wget', 'iwr']). Such a
     list only counts as harmless if nothing else in the script runs text it
     gets at run time: PowerShell's iex / Invoke-Expression, Invoke-Command,
     & or . with a variable, Start-Process, cmd /c or powershell with a
     variable, [scriptblock]::Create, $ExecutionContext, Add-Type;
     JavaScript's eval, Function(), child_process or WScript.Shell with a
     variable; VBScript's Execute, ExecuteGlobal, Eval or .Run with a
     variable; a batch variable run as a command. If any of those is there,
     the lists count like any other code.
     JavaScript files (.js) get their own patterns, because web-app bundles
     are minified (long lines, short names) and use RegExp .exec(),
     String.fromCharCode() and eval() all the time. For them only these
     count: code that starts programs (WScript.Shell, child_process, a
     shell command), a download that is saved to disk or run, and the marks
     obfuscators leave (_0x names, a big list of strings fed into eval or
     Function, a packer, eval of decoded text, long lists of char codes).

3. Who knows it
   - ClamAV (an open-source antivirus) and Microsoft Defender scan it here on
     your PC. ClamAV's generic guesses (names starting with Heuristics. or
     PUA., packer names like Win.Packed.*, and .Generic names) are a warning
     sign, not a detection: Suspicious at most, and Unusual for a program
     signed by a well-known publisher ("ClamAV's generic packer guess; the
     file is signed by ..."). Names of real malware families stay Malicious.
   - CIRCL hashlookup (no account needed) says whether it is known, common
     software. That lowers suspicion. Files under 1 KB aren't looked up:
     empty and tiny files share fingerprints with unrelated files.
   - With optional free keys: VirusTotal (about 70 antivirus engines) and
     MalwareBazaar (a public collection of known malware).
   For these online lookups only the file's fingerprint (its SHA-256, a
   64-character code unique to that exact file) leaves your PC. The file
   itself is never uploaded.

Blotter works on a temporary copy in %LOCALAPPDATA%\Blotter\incoming and
deletes the copy when the check ends. Your original file is not touched.


THE SIX ANSWERS

Malicious
  A check recognises the file as malware: Defender, ClamAV, MalwareBazaar,
  a YARA rule for a known malware family, or 3 or more VirusTotal engines.

Suspicious
  Warning signs, but no clear detection. Either
  - risky abilities PLUS something that hides: scrambled code, a name that
    lies, a packed program without a signature, or VirusTotal has never seen
    the file (this needs a VirusTotal key: without one, VirusTotal counts
    as "not checked" and never adds a warning; the card then says
    "VirusTotal: not checked (no key)"); or
  - a program or script dressed up as another kind of file; or
  - a warning on its own: 1 or 2 VirusTotal engines, a broken signature, an
    auto-run macro that can run programs, a broad malware rule, a ClamAV
    generic guess.

Unusual
  It can do risky things, but nothing hides it and nothing recognises it.
  Admin and system tools, installers that set up services, and game mods or
  cheats can land here. Only use it if you trust where it came from.

No known detections
  None of the checks found anything. This is not a promise that the file is
  harmless: brand-new or rare malware can go unrecognised.

Couldn't fully check
  Part of the file was over a limit: too big for a check (for example
  programs over 25 MB for capa), archives nested too deep, a check that took
  too long (capa: 15 minutes) or ran out of memory, or a locked archive.
  Or a check made for this kind of file failed on it: an archive that can't
  be unpacked, capa that couldn't analyse a program, an Office, RTF or PDF
  file that couldn't be read. The same when YARA failed, or when no
  antivirus engine could scan the file (Defender and ClamAV both failed, or
  ClamAV failed in test mode, where Defender isn't used). One engine failing
  while the other scans, or an online lookup failing, stays a note. The card
  names the check and its error.
  Blotter then never says "No known detections", because what it couldn't
  check might be the dangerous part. Warnings it did find still show (and
  Malicious or Suspicious still win).
  Exception: for a program signed by a well-known publisher that capa had to
  skip (too big or too slow), the card says "Signed by <publisher>, deep
  check skipped" instead. Unsigned programs, and programs signed by anyone
  else, keep "Couldn't fully check".
  An unsigned program padded with lots of empty filler is Suspicious on its
  own (a trick to get past scanners' size limits).

Couldn't check
  None of the checks could run.

Weak signs are things ordinary programs do all the time (a program making
its own memory runnable, talking to a device driver, .NET loading its own
parts, compressed .NET resources, code that checks card-like numbers). On
their own they don't change the answer; they only show under Details. They
count when the program is also unsigned, packed, or unknown to VirusTotal:
one of those makes it Unusual; two of those, or one plus hiding or a lying
name, makes it Suspicious.

Each risky ability comes with what else does the same, for example:
"It can inject code into other running programs. Cheats, mod loaders and
some overlays do that too, but so does malware."

Blotter never calls a file "safe".


SETUP (ONCE)

1. Double-click setup.bat.
   - If Python 3.12 isn't installed, it offers to install it with winget.
   - It makes a private Python folder (.venv) inside the Blotter folder and
     installs exact, checksum-verified, ready-made versions of the parts
     Blotter needs (listed in requirements.txt). No build scripts run.
   - It downloads the rules (YARA Forge and capa, a few MB, checked by
     checksum).
   - It asks whether to set up ClamAV (about 225 MB once, plus about 110 MB
     of signatures). Say N to skip; you can run setup.bat again later.

2. API keys are optional. Blotter works without them; only the VirusTotal
   and MalwareBazaar answers are missing. If you want them:
   - VirusTotal: sign up at https://www.virustotal.com, open your profile
     menu and choose "API key".
   - MalwareBazaar: sign in at https://auth.abuse.ch and copy your
     "Auth-Key".


USING IT

1. Double-click "Start Blotter.bat". A black window opens (keep it open)
   and your browser shows Blotter at http://127.0.0.1:4848
   Blotter only answers a page it opened itself: each start makes a new
   secret code, puts it in the address once and swaps it for a cookie only
   this page can use. A bookmark therefore won't work after a restart; just
   double-click "Start Blotter.bat" again (it also reopens a running Blotter).
   The first start takes a few seconds longer: Blotter copies a private
   Python (about 35 MB) for its sandbox.

2. The first time, a short setup offers the two keys. Paste them and press
   "Save keys", or press "Skip for now". Keys are stored in Windows
   Credential Manager (under "Blotter"), never in a file. Change them any
   time under Settings.

3. Check a file, either way:
   - Drop it on the page (or click the box). Blotter checks a copy. You can
     drop or choose several files at once: Blotter checks them all, opens
     the first one's card and lists every file under "Checked since Blotter
     started".
   - "Choose a file on this PC..." (or paste its path). Blotter then knows
     where the real file is, so it can quarantine it from the result.

4. The answer appears in a few seconds to a minute. For programs, capa (the
   deep check) may still be working: the card then says "Deep check still
   running…" (or "Deep check queued, 2nd in line" while other files' deep
   checks go first) and updates by itself when it is done (up to 15 minutes
   each). The answer can still change until then. Under the answer:
   - "Open on VirusTotal" opens the file's VirusTotal page in your browser.
     Only the fingerprint is in the address; nothing is uploaded.
   - "Trust this file" puts it on your own trusted list (by fingerprint).
     Trust quiets warnings about what a file can do, and a result where
     only 1 or 2 VirusTotal engines flag the file (often false alarms; the
     card then says "You trusted this file; 1 VirusTotal engine flags it").
     It never lowers a detection by Defender, ClamAV, MalwareBazaar, YARA,
     capa's malware families or 3 or more VirusTotal engines, and never a
     check that couldn't finish. A Malicious result can't
     be trusted at all; if a file you trusted earlier is detected later, the
     card says Malicious and "you trusted this file before, but it is now
     detected" (your trust stays saved until you remove it). If the file
     changes by even one byte, the trust ends. Undo it under Settings.
   - When several engines name the same threat, the card shows one line,
     e.g. "Recognised as EICAR test file by Defender, ClamAV, YARA and
     Blotter." Each engine's own line is under Details.
   - "Quarantine" (only for files chosen on this PC) moves the file into
     %LOCALAPPDATA%\Blotter\quarantine with a .blotted ending, so it can't be
     opened by a double-click. "Put back" under Settings restores it.
   - "Details" shows the fingerprint and what every check said.
   Below the card, "Checked since Blotter started" lists every file of
   this session, newest first, with its answer and its deep check ("deep
   check queued, 2nd in line", "deep check running…"). It updates by
   itself; click a file to open its card. The list lives only in
   Blotter's memory: closing Blotter clears it.

5. To stop Blotter, close the black window. ClamAV stops with it.

6. After an update (new Blotter files), close the black window and start
   Blotter again. Double-clicking "Start Blotter.bat" while Blotter runs
   only reopens the page of the running, older Blotter. The page notices
   this and says "Blotter was updated while it was running".

7. Test mode, for test runs (Claude's sessions always use it):
   "Start Blotter.bat" --test-mode (or python -m blotter --test-mode).
   The Microsoft Defender check is left out, every card says "Test mode:
   Defender off", and the EICAR button is hidden. It refuses to start
   while a normal Blotter runs (close that one first). For a full check,
   close it and start Blotter normally.

Quota: a free VirusTotal key allows 4 lookups a minute and 500 a day.
Blotter waits for a free slot rather than going over. Online answers are
remembered, so checking the same file again costs nothing. "Check again
online" (under Details) asks afresh.


SETTINGS

- API keys (optional).
- ClamAV on or off. ClamAV keeps its signatures in memory (about 1-1.5 GB)
  while it runs. It starts with the first check and stops again after 10
  minutes without one, so it only holds that memory while you check files;
  turn it off if the PC needs the memory even then.
- Rules: when YARA Forge was last downloaded; "Update rules now". Blotter
  also refreshes YARA Forge by itself once a week when it starts.
- Files you trust, and the quarantine, each with an undo button.
- The list of internet addresses Blotter uses.


CLAMAV

ClamAV runs portably from %LOCALAPPDATA%\Blotter\clamav: no service, no admin
rights, nothing in Program Files. Blotter starts it with the first check that
needs it (that check waits up to a minute while ClamAV loads), stops it after
10 minutes without a check, and it always ends when Blotter ends. If two
Blotters run at once (the app and a test run), they share one ClamAV: it
only stops when neither uses it any more, also if one of them crashed.
Blotter only sends a file to ClamAV after checking that the program on
ClamAV's port is its own clamd.exe; if another program has the port, the
card says "ClamAV port taken by another program" and ClamAV counts as
unavailable. Its signatures (in %LOCALAPPDATA%\Blotter\clamav-db)
are refreshed once a day by ClamAV's own updater, freshclam, while Blotter
is open. It listens only on this PC (127.0.0.1, port 4849).
To set it up later: run setup.bat again and answer Y.


IF WINDOWS OR AN ANTIVIRUS WARNS ABOUT BLOTTER'S OWN FOLDERS

Blotter's rules describe malware, so they contain pieces of it (names and
byte patterns, never working malware). To keep antivirus programs from
mistaking them for malware, Blotter stores the YARA rules encrypted, in
%LOCALAPPDATA%\Blotter\rules\yara-forge-core.7z and compiled.7z, and only
unpacks them in memory while checking a file. (The password is
"blotter-rules". It isn't a secret; it only keeps scanners out.) Blotter's
own ClamAV never looks at these folders.

If Windows Security, or another antivirus on a friend's PC, still shows an
alert:
1. Look at the file it names (Windows Security > Virus & threat protection
   > Protection history).
2. If it is inside one of Blotter's own folders:
     %LOCALAPPDATA%\Blotter\rules        rules (capa's rules are plain text)
     %LOCALAPPDATA%\Blotter\clamav-db    ClamAV's signatures
     the "rules" folder next to this README
   it is a false alarm about rule files. The simplest fix: let the
   antivirus remove it, then press "Update rules now" under Settings (or
   run setup.bat again) to fetch a fresh copy. Only choose "Allow on device"
   if you are sure of the path.
3. If it is in %LOCALAPPDATA%\Blotter\quarantine, the antivirus found a
   real threat in a file you quarantined with Blotter. Let it remove it.
4. If it names any other place (for example %LOCALAPPDATA%\Blotter\incoming,
   where the copy being checked sits), it is about the file you were
   checking, not about Blotter. Treat that file as malware.
Blotter never asks you to switch your antivirus off, and it never needs an
exclusion.


CHECKING THAT IT WORKS

- A normal file: drop a program installer you trust, for example the
  Python installer. Expected: No known detections (or Unusual, with the
  reason, if it is a tool that can do risky things).

- EICAR: press "Check the EICAR test file" on the Blotter page. EICAR is a
  standard test file that every antivirus is built to detect; it contains
  no real malware. Expected: Malicious. Windows will show a "Threats found"
  notice and quarantine Blotter's copy. That is the expected result, not an
  error.

- More harmless test files: double-click tools\Make test files.bat. It
  writes a folder "Blotter test files" on your Desktop with a renamed
  program, a double-ending program, a Word document with a harmless
  auto-run macro, and a scrambled PowerShell script. Its README.txt lists
  what Blotter should answer for each. Don't open them; drop them on Blotter.


FALSE-ALARM TEST

Put about 100 files you trust (installers, programs, documents, PDFs,
scripts, archives, and some game mods) in one folder. Drag that folder onto
tools\False alarm test.bat (or double-click it and type the folder). Close
Blotter first: the test uses the PC fully. It checks one file at a time,
prints how many got each answer, then lists every file that didn't get "No
known detections", with its reasons. Target: 0 Malicious and at most 5
Suspicious.
The report is saved in %LOCALAPPDATA%\Blotter even if the run stops early
(each result is also saved the moment it is known, in a .jsonl file next to
it). The test waits for each file's final answer, after the deep check. Big
programs take a minute or two each for capa (a few up to 15); with a
VirusTotal key, lookups add 15 seconds a file (4 a minute). To skip the online
lookups, open a command window in the Blotter folder and run:

    .venv\Scripts\python tools\false_alarm_test.py "D:\My trusted files" --offline

Your trusted list is ignored during this test.


WHERE THINGS ARE

- The program: this folder. "blotter" holds the code, "blotter\checks"
  has one file per check, "blotter\analyze" the shared readers, "rules" our
  own YARA rules, "tools" the test helpers.
- Remembered answers: %LOCALAPPDATA%\Blotter\cache.sqlite3
  (delete it to forget them).
- Trusted files: %LOCALAPPDATA%\Blotter\trusted.sqlite3
- Settings: %LOCALAPPDATA%\Blotter\settings.json (no secrets in it).
- Quarantine: %LOCALAPPDATA%\Blotter\quarantine
- Downloaded rules: %LOCALAPPDATA%\Blotter\rules ; ClamAV: ...\clamav and
  ...\clamav-db
- Temporary copies and the sandbox's scratch folders:
  %LOCALAPPDATA%\Blotter\incoming (emptied after each check and at start-up).
  Files unpacked from archives get neutral names (m0001.blotter) in a fresh
  folder there, so a name like ..\evil.exe, C:\ or CON inside an archive
  can't write anywhere else. Unpack folders are deleted by one function
  (blotter\cleanup.py) that refuses anything outside "incoming" or the
  sandbox's own work folder and removes links and junctions themselves,
  never what they point to.
- The sandbox's private Python: %LOCALAPPDATA%\Blotter\runtime. Blotter gives
  its sandbox read access to that folder, the Blotter folder and the rules
  folder (Windows permissions, recorded in sandbox-grants.txt). Nothing
  outside Blotter's own folders is changed.
- This start's secret page code: %LOCALAPPDATA%\Blotter\session-token
  (deleted when Blotter closes).
- API keys: Windows Credential Manager, entries named "Blotter".


INTERNET ADDRESSES

Every address Blotter may contact is listed in blotter\network.py, with the
reason; Blotter refuses any other, even when redirected. A test fails if
the code mentions an address that isn't on the list.

Lookups (only the file's fingerprint is sent):
  www.virustotal.com      VirusTotal (only with your key)
  mb-api.abuse.ch         MalwareBazaar (only with your key)
  hashlookup.circl.lu     CIRCL hashlookup (no key)
Downloads (send nothing about your files):
  api.github.com, github.com, release-assets.githubusercontent.com,
  objects.githubusercontent.com   YARA Forge rules, the ClamAV program
  codeload.github.com, raw.githubusercontent.com   capa rules and signatures
  database.clamav.net     ClamAV's daily signatures (through freshclam)

Blotter itself only answers on this PC (127.0.0.1). Every request needs this
start's secret code, must name 127.0.0.1 or localhost with Blotter's exact
port, and is refused if it comes from another website open in your browser.
Anything that changes something (checking by path, trust, quarantine,
settings, keys) only works as a POST with the code in a header.


FOR DEVELOPERS

Tests (they never touch the real keys, cache, settings or Defender, and
never write EICAR or the scrambled test script to disk):

    .venv\Scripts\python -m unittest discover -s tests -t .

Adding a check:
- Add a module to blotter\checks with ID, NAME, ORDER, TIMEOUT, CACHE,
  NEEDS_FILE and scan(path) -> list[Finding]. It is picked up automatically
  (see blotter\checks\__init__.py).
- NEEDS_FILE = True: the check runs in its own process (blotter\worker.py)
  inside a Windows job object with a memory limit (blotter\procs.py), and,
  unless the module says SANDBOX = False, inside the AppContainer
  (blotter\sandbox.py). Checks that only send the hash run in a thread.
- A check that stops early because of a limit returns a finding with the
  "unchecked" signal (findings.unchecked); the answer then can't be
  "No known detections".
- Findings carry a level (malicious, suspicious, note, clear, unknown,
  skipped, error) and signals (risky, hiding, lying_name, disguised, packed,
  signed, unknown_online, known_good, unchecked). blotter\verdict.py turns
  them into the answer; its first lines describe the rules.
- Own YARA rules: put a .yar file in "rules"; see rules\eicar.yar for the
  meta fields Blotter reads.

Updating packages:
- Versions are pinned with checksums in requirements.txt, and setup
  installs with --require-hashes --only-binary=:all: --no-deps (no build
  scripts run, and nothing outside the list is installed).
- Change them only on purpose, pick releases at least two weeks old, and
  regenerate the checksums from PyPI. oletools' helper win-unicode-console
  is left out on purpose: it has no ready-made package and only serves a
  command-line tool Blotter doesn't use.
- capa's rules and signatures are pinned to the capa version (9.4.0) in
  blotter\updates.py; update them together with flare-capa.
