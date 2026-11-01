"""The intel pack: security data lists Blotter fetches between releases, signed with the pack key.

A pack is one JSON file plus its signature (intel-pack.json and intel-pack.json.sig on the GitHub release
"intel-pack"). It may only carry the plain lists named in FILES, each checked line by line, so even a
stolen pack key can't put code on anyone's PC. An older pack than the one installed is refused.
The lists land in %LOCALAPPDATA%\\Blotter\\intel and are used on top of the ones in the rules folder.

    python -m blotter.intel     fetch and install the newest pack now
"""

import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

from . import config, network, signing

PACK_URL = "https://github.com/notblindmedia/blotter/releases/download/intel-pack/intel-pack.json"
KIND = "blotter-intel-pack"
CHECK_EVERY = 24 * 3600
MAX_PACK = 4 * 1024 ** 2
MAX_LIST = 2 * 1024 ** 2
HEX = re.compile(r"[0-9a-f]{2,64}")


def _hex_list(text: str) -> int:
    """A certificate list (rules/stolen-certificates.txt format): one hex value per line, # starts a note."""
    count = 0
    for number, line in enumerate(text.splitlines(), 1):
        value = line.partition("#")[0].replace(" ", "").replace(":", "").lower()
        if value and not HEX.fullmatch(value):
            raise IntelError(f"line {number} of the certificate list isn't a serial number or thumbprint")
        count += bool(value)
    return count


FILES = {"stolen-certificates.txt": _hex_list}


class IntelError(Exception):
    pass


def folder():
    return config.HOME / "intel"


def installed() -> dict:
    """What the installed pack said about itself: {'made', 'counts'}, or {} before the first pack."""
    try:
        return json.loads((folder() / "pack.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _when(stamp) -> datetime:
    try:
        when = datetime.fromisoformat(str(stamp))
    except ValueError:
        raise IntelError("the pack has no readable date") from None
    if when.tzinfo is None:
        raise IntelError("the pack's date has no time zone")
    return when


def _write(path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.replace(tmp, path)


def apply(pack: bytes, signature: bytes | str) -> str:
    """Check a downloaded pack and install it. Raises IntelError (or signing.BadSignature) if refused."""
    if len(pack) > MAX_PACK:
        raise IntelError("the pack is bigger than a pack can be")
    signing.verify(signing.PACK_KEY, signing.PACK, pack, signature)
    try:
        data = json.loads(pack.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise IntelError("the pack isn't readable JSON") from None
    if not isinstance(data, dict) or data.get("kind") != KIND or data.get("format") != 1:
        raise IntelError("it isn't a Blotter intel pack (format 1)")
    made = _when(data.get("made"))
    if made > datetime.now(timezone.utc) + timedelta(days=1):
        raise IntelError("the pack is dated in the future")
    before = installed().get("made")
    if before and made <= _when(before):
        if made == _when(before):
            return f"Intel pack from {made:%Y-%m-%d} is already installed."
        raise IntelError(f"it is older ({made:%Y-%m-%d}) than the installed pack ({_when(before):%Y-%m-%d})")
    files = data.get("files")
    if not isinstance(files, dict) or not files:
        raise IntelError("the pack has no lists")
    counts = {}
    for name, text in files.items():
        if name not in FILES:
            raise IntelError(f"the pack carries {name!r}, which a pack may not contain")
        if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_LIST:
            raise IntelError(f"{name} in the pack isn't a plain list of a sensible size")
        counts[name] = FILES[name](text)
    for name, text in files.items():
        _write(folder() / name, text)
    _write(folder() / "pack.json", json.dumps({"made": made.isoformat(), "counts": counts}, indent=2))
    listed = ", ".join(f"{n} ({c} entries)" for n, c in counts.items())
    return f"Intel pack from {made:%Y-%m-%d} installed: {listed}."


def _fetch(url: str, limit: int) -> bytes | None:
    """The file's bytes, None if it isn't published (HTTP 404)."""
    response = network.get(url, stream=True, timeout=(10, 60))
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise IntelError(f"GitHub answered HTTP {response.status_code}")
    body = b""
    for chunk in response.iter_content(256 * 1024):
        body += chunk
        if len(body) > limit:
            raise IntelError("the download is bigger than a pack can be")
    return body


def refresh(force=False) -> str:
    """Fetch and install the newest pack (at most once a day unless forced). One line saying what happened."""
    marker = folder() / "last-check"
    if not force and marker.is_file() and time.time() - marker.stat().st_mtime < CHECK_EVERY:
        return "Intel pack checked less than a day ago; kept it."
    try:
        pack = _fetch(PACK_URL, MAX_PACK)
        signature = _fetch(PACK_URL + ".sig", 1024) if pack is not None else None
        if pack is None or signature is None:
            line = "No intel pack is published yet; the lists in the rules folder are used."
        else:
            line = apply(pack, signature)
    except (IntelError, signing.BadSignature) as e:
        line = f"Intel pack refused, the installed lists stay: {e}."
    except Exception as e:  # network errors and the like
        return f"Intel pack update failed: {type(e).__name__}: {e}"
    _write(marker, time.strftime("%Y-%m-%d %H:%M:%S"))
    return line


def stolen_list_from_cscb(entries, fetched: str) -> str:
    """rules/stolen-certificates.txt from abuse.ch's Code Signing Certificate Blocklist (MalwareBazaar's
    get_cscb answer): each listed certificate's SHA-256 thumbprint, with its name, reason and date."""
    rows = {}
    for e in sorted(entries, key=lambda e: str(e.get("time_stamp") or "")):
        if str(e.get("cscb_listed")).lower() != "true":
            continue
        thumb = re.sub(r"[\s:]", "", str(e.get("thumbprint") or "")).lower()
        algorithm = str(e.get("thumbprint_algorithm") or "").upper()
        if not ((algorithm == "SHA256" and len(thumb) == 64) or (algorithm == "SHA1" and len(thumb) == 40)) \
                or not HEX.fullmatch(thumb):
            continue
        note = "; ".join(str(e.get(k) or "?") for k in ("subject_cn", "cscb_reason"))
        note = re.sub(r"[\x00-\x1f\x7f]+", " ", note)[:200]
        rows[thumb] = f"{thumb}  # {note}; listed {str(e.get('time_stamp') or '?')[:10]}"
    head = [
        "# Code-signing certificates known to be stolen or abused to sign malware.",
        "# A program signed with one of these gets no publisher trust at all and is at least Suspicious,",
        "# whatever Windows says about the signature.",
        "#",
        "# Source: abuse.ch's Code Signing Certificate Blocklist (MalwareBazaar API, query get_cscb),",
        f"# fetched {fetched}: {len(rows)} certificates. Each line is the certificate's SHA-256",
        "# thumbprint, then # and abuse.ch's name for it, the reason and the date it was listed.",
        "# Security data never comes from memory: refill this list with tools\\intel_pack.py, not by hand.",
        "# The signed weekly intel pack adds newer entries in %LOCALAPPDATA%\\Blotter\\intel; Blotter uses both.",
        "#",
        "# A manual entry needs a source in its note: a serial number or SHA-1/SHA-256 thumbprint (hex; spaces",
        "# and colons are ignored), then # and the note.",
        "",
    ]
    return "\n".join(head + list(rows.values())) + "\n"


def main(argv) -> int:
    print(" ", refresh(force=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
