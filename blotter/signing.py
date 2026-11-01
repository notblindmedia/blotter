"""Ed25519 signatures for Blotter's releases and its intel pack (the pinned cryptography package).

Two keys with one job each; both public halves are built in here:
- The code key signs releases. update.bat installs nothing else. Its private half lives only on the
  maintainer's signing PC (tools/sign-release), never on the PC that builds the release.
- The pack key signs the weekly intel pack: plain data lists, never code (blotter/intel.py).
Every signature covers a purpose line plus the exact bytes, so a pack signature can't pass as a release
signature, even if both keys were the same.

    python -m blotter.signing     shows both keys' fingerprints (setup.bat does this)
"""

import base64
import binascii
import hashlib
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# Base64 of each 32-byte public key. Empty means "not made yet": everything signed with it is refused.
CODE_KEY = "EPI4e/Noa42vIciK/Wff6TTFSQD1gDgj6gCbll79//I="  # made 2026-11-01 on the signing PC; C7FB D957 ...
PACK_KEY = "uQaqrWYeeLub+fivxJLH+Sc4PzJ7JoSq0Z75KcqiUOo="  # made 2026-11-01; fingerprint 54E1 1404 9925 BB12 ...

RELEASE = b"blotter release manifest v1\n"
PACK = b"blotter intel pack v1\n"


class BadSignature(Exception):
    pass


def _raw(public_b64: str) -> bytes:
    try:
        raw = base64.b64decode(public_b64, validate=True)
    except (binascii.Error, ValueError):
        raw = b""
    if len(raw) != 32:
        raise BadSignature("no valid public key is built into this copy of Blotter")
    return raw


def fingerprint(public_b64: str) -> str:
    """The first 128 bits of the key's SHA-256, as 8 groups of 4: easy to read out and compare."""
    digest = hashlib.sha256(_raw(public_b64)).hexdigest().upper()[:32]
    return " ".join(digest[i:i + 4] for i in range(0, 32, 4))


def public_b64(private: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")


def sign(private: Ed25519PrivateKey, purpose: bytes, data: bytes) -> str:
    return base64.b64encode(private.sign(purpose + data)).decode("ascii")


def verify(public: str, purpose: bytes, data: bytes, signature: bytes | str) -> None:
    """Raises BadSignature unless `signature` (base64) is the key's signature of purpose + data."""
    key = Ed25519PublicKey.from_public_bytes(_raw(public))
    try:
        key.verify(base64.b64decode(signature.strip(), validate=True), purpose + data)
    except (binascii.Error, ValueError, InvalidSignature):
        raise BadSignature("the signature doesn't match: the file was changed or signed with another key") from None


def describe() -> list[str]:
    lines = []
    for name, key in (("Release key (code)", CODE_KEY), ("Intel pack key (data)", PACK_KEY)):
        try:
            lines.append(f"{name}: {fingerprint(key)}")
        except BadSignature:
            lines.append(f"{name}: not built into this copy yet")
    return lines


def main() -> int:
    for line in describe():
        print(" ", line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
