BLOTTER RELEASE SIGNING KIT (MAIN PC ONLY)

This folder makes and uses Blotter's release key. update.bat on every
friend's PC installs a new Blotter only if this key signed it. The key's
private half stays on this PC (and your offline backup), never on the PC
that builds the releases.

What you need: Windows, 64-bit, Python 3.12 (https://www.python.org).
The first run makes a private Python folder (.venv) here and installs one
package, cryptography, at a pinned version with a checked checksum.


ONCE: MAKE THE RELEASE KEY

1. Copy this folder to the main PC (for example Documents\blotter-signing).
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


EVERY RELEASE: SIGN IT

1. Claude prepares two files on the Blotter PC: blotter-X.Y.Z.zip and
   blotter-X.Y.Z.json (the manifest: version, the zip's checksum, what
   changed). Copy both into one folder on this PC.
2. Drag blotter-X.Y.Z.json onto sign-release.bat.
3. It checks that the zip matches the manifest, shows the version and what
   changed, and asks. Type y, then the passphrase.
4. It writes blotter-X.Y.Z.json.sig next to the manifest.
5. Publish all three files (zip, .json, .json.sig) on a GitHub release
   tagged vX.Y.Z. A release without the .sig file is refused by update.bat.
