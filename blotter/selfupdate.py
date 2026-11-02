"""update.bat: install a newer Blotter, only if the release key signed it and you say yes.

1. Asks GitHub for Blotter's newest release (drafts and pre-releases don't count).
2. Downloads its small manifest (blotter-X.Y.Z.json) and the signature (.json.sig) and checks the signature
   with the release key built into this copy (blotter/signing.py). Unsigned or tampered: refused.
3. The signed manifest names the version, the zip's size and SHA-256 and what changed. A version that isn't
   newer than this one is refused, so nobody can push you back to an older Blotter with known faults.
4. Shows what changed and asks. Only after "y" it downloads the zip, checks it against the manifest,
   and swaps the program folders and files (the old ones stay in .update-old until the next update).
Your .venv, settings, keys, cache and trusted list are never touched. Nothing here runs by itself.

Exit codes: 0 done or nothing to do, 1 refused or failed, 3 installed and requirements.txt changed
(update.bat then installs the pinned packages, after this program has closed).
"""

import hashlib
import io
import json
import os
import re
import shutil
import sys
import time
import zipfile
from pathlib import Path

from . import __version__, config, network, signing

RELEASES = "https://api.github.com/repos/notblindmedia/blotter/releases?per_page=30"
KIND = "blotter-release"
MAX_MANIFEST = 64 * 1024
MAX_ZIP = 100 * 1024 ** 2
NEVER_REPLACED = {".venv", ".git", ".update-old", ".update-new", "STATUS.md"}
REQUIREMENTS_CHANGED = 3


class Refused(Exception):
    pass


def version(text) -> tuple | None:
    m = re.fullmatch(r"v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})", str(text or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


def _name(v: tuple) -> str:
    return ".".join(map(str, v))


def _fetch(url: str, limit: int) -> bytes:
    response = network.get(url, stream=True, timeout=(10, 120))
    if response.status_code != 200:
        raise Refused(f"GitHub answered HTTP {response.status_code} for {url.rsplit('/', 1)[-1]}")
    body = io.BytesIO()
    for chunk in response.iter_content(1024 * 1024):
        body.write(chunk)
        if body.tell() > limit:
            raise Refused(f"{url.rsplit('/', 1)[-1]} is bigger than it may be")
    return body.getvalue()


def newest_release() -> dict | None:
    response = network.get(RELEASES, headers={"Accept": "application/vnd.github+json"}, timeout=(10, 30))
    if response.status_code != 200:
        raise Refused(f"GitHub answered HTTP {response.status_code} when asked for Blotter's releases")
    releases = [r for r in response.json() if isinstance(r, dict) and not r.get("draft")
                and not r.get("prerelease") and version(r.get("tag_name"))]
    return max(releases, key=lambda r: version(r["tag_name"]), default=None)


def check(release: dict, current: tuple) -> tuple[dict, str]:
    """The release's signed manifest and the zip's address. Raises Refused unless all is well."""
    v = version(release.get("tag_name"))
    if not v or v <= current:
        raise Refused(f"version {release.get('tag_name')} isn't newer than this one ({_name(current)})")
    assets = {a.get("name"): a.get("browser_download_url") for a in release.get("assets") or []}
    base = f"blotter-{_name(v)}"
    manifest_url, signature_url = assets.get(base + ".json"), assets.get(base + ".json.sig")
    if not manifest_url or not signature_url:
        raise Refused(f"release {_name(v)} isn't signed")
    manifest = _fetch(manifest_url, MAX_MANIFEST)
    try:
        signing.verify(signing.CODE_KEY, signing.RELEASE, manifest, _fetch(signature_url, 1024))
    except signing.BadSignature as e:
        raise Refused(f"release {_name(v)}: {e}") from None
    m = json.loads(manifest.decode("utf-8"))
    if m.get("kind") != KIND or m.get("format") != 1:
        raise Refused("the signed manifest isn't a Blotter release manifest (format 1)")
    signed = version(m.get("version"))
    if signed != v:
        raise Refused(f"the signed manifest is for version {m.get('version')}, not {_name(v)}")
    if m.get("zip") != base + ".zip" or not assets.get(m["zip"]):
        raise Refused(f"release {_name(v)} has no {base}.zip")
    if not re.fullmatch(r"[0-9a-f]{64}", str(m.get("sha256"))) or not isinstance(m.get("size"), int):
        raise Refused("the signed manifest has no usable checksum")
    return m, assets[m["zip"]]


def _members(archive: zipfile.ZipFile, prefix: str) -> set:
    """Top-level names in the zip; refuses anything outside prefix or with a strange path."""
    tops = set()
    for info in archive.infolist():
        name = info.filename
        if not name.startswith(prefix) or "\\" in name or ":" in name:
            raise Refused(f"the zip contains {name!r}, outside {prefix}")
        parts = name[len(prefix):].split("/")
        if any(p in (".", "..") for p in parts) or (parts[0] == "" and len(parts) > 1):
            raise Refused(f"the zip contains a strange path: {name!r}")
        if parts[0]:
            tops.add(parts[0])
    if NEVER_REPLACED & tops:
        raise Refused(f"the zip contains {sorted(NEVER_REPLACED & tops)}, which an update may not replace")
    if not {"blotter", "setup.bat"} <= tops:
        raise Refused("the zip doesn't look like Blotter (no blotter folder or setup.bat)")
    return tops


def _move(source: Path, target: Path) -> None:
    for attempt in range(5):  # an antivirus scan can hold a file for a moment
        try:
            os.replace(source, target)
            return
        except OSError:
            if attempt == 4:
                raise
            time.sleep(1)


def install(root: Path, body: bytes, manifest: dict) -> bool:
    """Swap in the release. Returns True if requirements.txt changed. Raises Refused (old version kept)."""
    if len(body) != manifest["size"] or hashlib.sha256(body).hexdigest() != manifest["sha256"]:
        raise Refused("the downloaded zip doesn't match the signed checksum, so nothing was installed")
    v = manifest["version"]
    prefix = f"blotter-{v}/"
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        tops = _members(archive, prefix)
        init = archive.read(prefix + "blotter/__init__.py").decode("utf-8", "replace")
        if f'__version__ = "{v}"' not in init:
            raise Refused(f"the zip's program doesn't say it is version {v}")
        new, old = root / ".update-new", root / ".update-old"
        shutil.rmtree(new, ignore_errors=True)
        shutil.rmtree(old, ignore_errors=True)
        for info in archive.infolist():
            rel = info.filename[len(prefix):]
            if not rel or info.is_dir():
                continue
            target = new.joinpath(*rel.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
    before = (root / "requirements.txt").read_bytes() if (root / "requirements.txt").is_file() else b""
    old.mkdir()
    done = []  # (name, had an old one)
    try:
        for name in sorted(tops):
            had = (root / name).exists()
            if had:
                _move(root / name, old / name)
            done.append((name, had))
            _move(new / name, root / name)
    except OSError as e:
        for name, had in reversed(done):  # put the old version back exactly as it was
            if (root / name).exists() and (not had or (old / name).exists()):
                shutil.rmtree(root / name) if (root / name).is_dir() else (root / name).unlink()
            if had and (old / name).exists():
                os.replace(old / name, root / name)
        raise Refused(f"couldn't replace {e.filename or 'a file'} (is a Blotter file open?); "
                      "the old version is back in place") from None
    finally:
        shutil.rmtree(new, ignore_errors=True)
    return (root / "requirements.txt").read_bytes() != before


def _running() -> bool:
    from .__main__ import _ping
    return _ping() != ""


def run(root: Path = config.ROOT, current: str = __version__, ask=input) -> int:
    now = version(current)
    print(f"  This Blotter is version {current}.")
    if (root / ".git").exists():
        print("  This is a developer copy (a Git folder). Update it with git, not update.bat.")
        return 1
    if _running():
        print("  Blotter (or another program) is running on its port. Close Blotter's window, then run update.bat again.")
        return 1
    try:
        release = newest_release()
        if release is None or version(release["tag_name"]) <= now:
            print("  You have the newest version. Nothing was changed.")
            return 0
        manifest, zip_url = check(release, now)
    except Refused as e:
        print(f"  Update refused: {e}. Nothing was changed.")
        return 1
    print(f"\n  Blotter {manifest['version']} is available, signed with the release key")
    print(f"  (check code {signing.check_code()}).\n\n  What changed:")
    for line in manifest.get("changes") or ["(no notes)"]:
        print(f"   - {line}")
    print()
    if ask("  Install it now? Type y and press Enter (anything else: no): ").strip().lower() not in ("y", "yes"):
        print("  Nothing was changed.")
        return 0
    try:
        changed = install(root, _fetch(zip_url, MAX_ZIP), manifest)
    except Refused as e:
        print(f"  Update refused: {e}.")
        return 1
    print(f"  Blotter {manifest['version']} is installed. The old version is in the .update-old folder.")
    if changed:
        print("  The list of parts changed; update.bat installs them next.")
        return REQUIREMENTS_CHANGED
    return 0


if __name__ == "__main__":
    sys.exit(run())
