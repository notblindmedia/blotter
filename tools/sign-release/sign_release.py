"""Blotter's release key: make it once and sign releases with it, on the signing PC only.

    sign-release.bat new-key            make the release key (asks for a passphrase twice)
    sign-release.bat blotter-X.Y.Z.json  check the zip next to it and sign the manifest (or drag the .json
                                         onto sign-release.bat)

The private key is blotter-release-key.pem, encrypted with your passphrase: next to this script, or wherever
BLOTTER_RELEASE_KEY points (full path to the .pem). Keep it in a folder no Claude session works in, and
never copy it to the PC that builds releases. Back it up (and the passphrase) somewhere offline:
without it no friend's Blotter accepts a new release. The public key (blotter-release-key.pub.txt) isn't
secret; it goes into Blotter's blotter\\signing.py (CODE_KEY).
"""

import base64
import getpass
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / ".deps"))  # sign-release.bat installs the pinned packages there

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (BestAvailableEncryption, Encoding, PrivateFormat,
                                                          PublicFormat, load_pem_private_key)

KEY_FILE = Path(os.environ.get("BLOTTER_RELEASE_KEY", "").strip('" ') or HERE / "blotter-release-key.pem")
PUBLIC_FILE = KEY_FILE.with_name("blotter-release-key.pub.txt")
RELEASE = b"blotter release manifest v1\n"  # must equal RELEASE in Blotter's blotter\signing.py
MIN_PASSPHRASE = 12


class Stop(Exception):
    pass


def public_b64(private) -> str:
    return base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")


def fingerprint(public: str) -> str:
    digest = hashlib.sha256(base64.b64decode(public)).hexdigest().upper()[:32]
    return " ".join(digest[i:i + 4] for i in range(0, 32, 4))


def new_key(key_file=KEY_FILE, ask=getpass.getpass) -> str:
    if key_file.exists():
        raise Stop(f"{key_file.name} already exists. A release key is made once and never replaced here")
    first = ask(f"Choose a passphrase for the release key (at least {MIN_PASSPHRASE} characters): ")
    if len(first) < MIN_PASSPHRASE:
        raise Stop(f"the passphrase needs at least {MIN_PASSPHRASE} characters")
    if ask("Type it again: ") != first:
        raise Stop("the two passphrases differ")
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(first.encode("utf-8")))
    key_file.write_bytes(pem)
    public = public_b64(private)
    key_file.with_name(PUBLIC_FILE.name).write_text(
        f"Blotter release key (public, not secret)\nCODE_KEY = \"{public}\"\nFingerprint: {fingerprint(public)}\n",
        encoding="utf-8")
    return public


def check_release(manifest_path: Path) -> tuple[bytes, dict]:
    """The manifest's bytes and contents, after checking the zip next to it matches."""
    if not manifest_path.is_file():
        raise Stop(f"there is no file {manifest_path}")
    data = manifest_path.read_bytes()
    m = json.loads(data.decode("utf-8"))
    if m.get("kind") != "blotter-release" or m.get("format") != 1:
        raise Stop(f"{manifest_path.name} isn't a Blotter release manifest")
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(m.get("version"))) or m.get("zip") != f"blotter-{m['version']}.zip":
        raise Stop("the manifest's version or zip name is odd")
    zip_path = manifest_path.with_name(m["zip"])
    if not zip_path.is_file():
        raise Stop(f"{m['zip']} must be in the same folder as {manifest_path.name}")
    body = zip_path.read_bytes()
    if len(body) != m.get("size") or hashlib.sha256(body).hexdigest() != m.get("sha256"):
        raise Stop(f"{m['zip']} doesn't match the manifest (size or SHA-256 differ). Don't sign it")
    return data, m


def sign(manifest_path: Path, key_file=KEY_FILE, ask=getpass.getpass, confirm=input) -> Path:
    data, m = check_release(manifest_path)
    if not key_file.is_file():
        raise Stop(f"no release key at {key_file}. If you moved it, first type: set BLOTTER_RELEASE_KEY=<full path "
                   f"to blotter-release-key.pem>, then run sign-release.bat again in the same window")
    print(f"\n  Blotter {m['version']}, commit {m.get('commit', '?')[:12]}")
    print(f"  {m['zip']}: {m['size']:,} bytes, SHA-256 {m['sha256']}")
    print("  What changed:")
    for line in m.get("changes") or ["(no notes)"]:
        print(f"   - {line}")
    if confirm("\n  Sign this release? Type y and press Enter: ").strip().lower() not in ("y", "yes"):
        raise Stop("not signed")
    try:
        private = load_pem_private_key(key_file.read_bytes(), ask("Release key passphrase: ").encode("utf-8"))
    except (ValueError, TypeError):
        raise Stop("wrong passphrase (or the key file is damaged)") from None
    signature = base64.b64encode(private.sign(RELEASE + data)).decode("ascii")
    private.public_key().verify(base64.b64decode(signature), RELEASE + data)  # raises if anything went wrong
    out = manifest_path.with_name(manifest_path.name + ".sig")
    out.write_text(signature + "\n", encoding="ascii")
    print(f"\n  Signed with the release key {fingerprint(public_b64(private))}.")
    return out


def main(argv) -> int:
    try:
        if argv[:1] == ["new-key"]:
            public = new_key()
            print(f"\n  Release key made: {KEY_FILE}")
            print(f"  Public key (send it to Claude for Blotter): {public}")
            print(f"  Fingerprint (to compare once it is built into Blotter): {fingerprint(public)}")
            print(f"  Both are also in {PUBLIC_FILE.name}. Back up the .pem and the passphrase offline now.")
        elif len(argv) == 1 and argv[0].lower().endswith(".json"):
            out = sign(Path(argv[0]))
            print(f"  Wrote {out}. Bring it back with the zip and the .json; publish all three.")
        else:
            print(__doc__)
            return 1
    except Stop as e:
        print(f"\n  Stopped: {e}.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
