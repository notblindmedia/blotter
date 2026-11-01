BLOTTER RELEASE SIGNING KIT (MAIN PC ONLY)

This folder makes and uses Blotter's release key. update.bat on every
friend's PC installs a new Blotter only if this key signed it. The key's
private half stays on this PC (and your offline backup), never on the PC
that builds the releases.

Keep this folder, the key and the Python it uses in a folder no Claude
session works in. Whatever runs while you sign sees the unlocked key, so
a program that can change the kit or its Python could copy it.

What you need: Windows, 64-bit Python 3.12 with pip. An installed Python
or a portable one (for example the NuGet package) both work. The kit
looks for it in this order and uses the first that really is 3.12:
  1. BLOTTER_PYTHON, if you set it in the window first:
         set BLOTTER_PYTHON=D:\Python312\python.exe
  2. the Python it used last time (remembered in python-path.txt here,
     so dragging a file onto sign-release.bat works later),
  3. python on PATH, 4. the py launcher, 5. the standard install folder.
The first run installs cryptography and its two helpers (cffi,
pycparser) into a .deps folder here, at the exact versions in
requirements.txt; pip refuses any file whose checksum doesn't match and
runs no build scripts. Nothing outside this folder changes.


ONCE: MAKE THE RELEASE KEY

1. Copy this folder to the main PC, into a folder no Claude session
   works in.
2. Open a Command Prompt in it and type:
       sign-release.bat new-key
3. Choose a passphrase of at least 12 characters and type it twice. Nobody
   can sign a release without it; nobody can recover it for you.
4. It shows a public key and a fingerprint (8 groups of 4 characters) and
   saves both in blotter-release-key.pub.txt. Send the public key to Claude
   on the Blotter PC; it is not secret. Give friends the fingerprint.
5. Back up blotter-release-key.pem and the passphrase offline right away
   (a USB stick in a drawer, a password manager). Lose them and friends'
   copies of Blotter can't accept new releases any more.
   Never copy blotter-release-key.pem to the Blotter PC or anywhere online.

The kit looks for blotter-release-key.pem in its own folder. If you keep
the key somewhere else (another folder, a USB stick), tell the kit where,
in the Command Prompt window, before signing:
       set BLOTTER_RELEASE_KEY=E:\keys\blotter-release-key.pem
That setting lasts only for that window, so then sign from the same
window (step 2 below, typed instead of dragged).


EVERY RELEASE: SIGN IT

1. Claude prepares two files on the Blotter PC: blotter-X.Y.Z.zip and
   blotter-X.Y.Z.json (the manifest: version, the zip's checksum, what
   changed). Copy both into one folder on this PC.
2. Drag blotter-X.Y.Z.json onto sign-release.bat, or type in the window:
       sign-release.bat "D:\path\to\blotter-X.Y.Z.json"
3. It checks that the zip matches the manifest, shows the version and what
   changed, and asks. Type y, then the passphrase.
4. It writes blotter-X.Y.Z.json.sig next to the manifest.
5. Publish all three files (zip, .json, .json.sig) on a GitHub release
   tagged vX.Y.Z. A release without the .sig file is refused by update.bat.
