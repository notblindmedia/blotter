"""The intel pack, built on this PC with the pack key (which can only sign data lists, never code).

    .venv\\Scripts\\python tools\\intel_pack.py new-key        once: make the pack key
    .venv\\Scripts\\python tools\\intel_pack.py stolen-list    refill rules\\stolen-certificates.txt from abuse.ch
    .venv\\Scripts\\python tools\\intel_pack.py build [--out FOLDER]   fetch abuse.ch's list, sign the pack

The pack key's private half is kept in Windows Credential Manager ("Blotter intel pack"), never in a file,
and is never shown. Its public half goes into blotter\\signing.py (PACK_KEY).
abuse.ch is asked with the MalwareBazaar key from Blotter's own keys (Settings > Keys).
The pack is published by hand: upload intel-pack.json and intel-pack.json.sig to the GitHub release
"intel-pack" (see README.txt, FOR DEVELOPERS). Nothing here runs by itself.
"""

import argparse
import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import keyring  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from blotter import config, intel, keys, network, signing  # noqa: E402

KEYRING_SERVICE = "Blotter intel pack"
KEY_NAME = "pack-key"
CSCB_URL = "https://mb-api.abuse.ch/api/v1/"
MIN_LISTED = 50  # a real blocklist has far more; fewer means a broken answer


class PackError(Exception):
    pass


def new_key() -> str:
    if keyring.get_password(KEYRING_SERVICE, KEY_NAME):
        raise PackError("a pack key already exists; it is never replaced by this command")
    private = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    raw = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    keyring.set_password(KEYRING_SERVICE, KEY_NAME, base64.b64encode(raw).decode("ascii"))
    return signing.public_b64(private)


def pack_key() -> Ed25519PrivateKey:
    stored = keyring.get_password(KEYRING_SERVICE, KEY_NAME)
    if not stored:
        raise PackError("there is no pack key yet (tools\\intel_pack.py new-key)")
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(stored))
    if signing.public_b64(private) != signing.PACK_KEY:
        raise PackError("the pack key in Credential Manager isn't the one built into blotter\\signing.py")
    return private


def fetch_cscb() -> list[dict]:
    key = keys.get("malwarebazaar")
    if not key:
        raise PackError("Blotter has no MalwareBazaar (abuse.ch) key; add it under Settings > Keys")
    response = network.post(CSCB_URL, data={"query": "get_cscb"}, headers={"Auth-Key": key}, timeout=(10, 120))
    if response.status_code != 200:
        raise PackError(f"abuse.ch answered HTTP {response.status_code}")
    body = response.json()
    entries = body.get("data") if isinstance(body, dict) else body
    if isinstance(body, dict) and body.get("query_status") not in (None, "ok"):
        raise PackError(f"abuse.ch said {body.get('query_status')!r}")
    if not isinstance(entries, list):
        raise PackError("abuse.ch's answer has no list")
    listed = sum(1 for e in entries if isinstance(e, dict) and str(e.get("cscb_listed")).lower() == "true")
    if listed < MIN_LISTED:
        raise PackError(f"abuse.ch's list has only {listed} listed certificates, which looks broken")
    return [e for e in entries if isinstance(e, dict)]


def stolen_list() -> str:
    fetched = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return intel.stolen_list_from_cscb(fetch_cscb(), fetched)


def build(out: Path) -> Path:
    private = pack_key()
    pack = {"kind": intel.KIND, "format": 1,
            "made": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "source": "abuse.ch Code Signing Certificate Blocklist (MalwareBazaar get_cscb)",
            "files": {"stolen-certificates.txt": stolen_list()}}
    body = (json.dumps(pack, indent=1) + "\n").encode("utf-8")
    signature = signing.sign(private, signing.PACK, body)
    signing.verify(signing.PACK_KEY, signing.PACK, body, signature)
    out.mkdir(parents=True, exist_ok=True)
    (out / "intel-pack.json").write_bytes(body)
    (out / "intel-pack.json.sig").write_text(signature + "\n", encoding="ascii")
    return out


def main(argv) -> int:
    parser = argparse.ArgumentParser(description="Blotter's intel pack (data lists, signed with the pack key).")
    parser.add_argument("command", choices=["new-key", "stolen-list", "build"])
    parser.add_argument("--out", type=Path, default=config.HOME / "intel-pack-build")
    args = parser.parse_args(argv)
    try:
        if args.command == "new-key":
            public = new_key()
            print(f"Pack key made and kept in Credential Manager ({KEYRING_SERVICE}).")
            print(f"  Public key for blotter\\signing.py: PACK_KEY = \"{public}\"")
            print(f"  Fingerprint: {signing.fingerprint(public)}")
        elif args.command == "stolen-list":
            text = stolen_list()
            (ROOT / "rules" / "stolen-certificates.txt").write_text(text, encoding="utf-8", newline="\r\n")
            print(f"rules\\stolen-certificates.txt refilled: {intel._hex_list(text)} certificates.")
        else:
            folder = build(args.out)
            print(f"Signed intel pack in {folder}: intel-pack.json and intel-pack.json.sig")
            print("Upload both to the GitHub release 'intel-pack' (replace the old ones).")
    except (PackError, signing.BadSignature) as e:
        print(f"Stopped: {e}.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
