"""Download the rules and tools Blotter uses, into %LOCALAPPDATA%\\Blotter. Every download is checked by checksum.

    python -m blotter.updates            YARA Forge rules + capa rules and signatures
    python -m blotter.updates --clamav   also ClamAV (about 225 MB) and its first signature download

- YARA Forge "core" rules: the newest weekly release; the checksum comes from GitHub's release data.
- capa rules and library signatures: the version that matches the installed capa, pinned by checksum.
- ClamAV: a fixed version, pinned by checksum. Its signatures then update daily through ClamAV's own freshclam.
"""

import hashlib
import io
import os
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path

from . import config, network

FORGE_RELEASE = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
FORGE_ASSET = "yara-forge-rules-core.zip"
FORGE_MEMBER = "packages/core/yara-rules-core.yar"
FORGE_MAX_AGE = 7 * 24 * 3600

CAPA_VERSION = "9.4.0"
CAPA_RULES = ("https://codeload.github.com/mandiant/capa-rules/zip/refs/tags/v9.4.0",
              "79e37bb648dd7a912ff49e8d89bff022ea156d2567f8fe5080f9d6d03067ee02")
CAPA_SIGS = [
    ("1_flare_msvc_rtf_32_64.sig",
     "e0042918fa80d432a1914680816996ac397afc30b05d3161192f29de63e66e79"),
    ("2_flare_msvc_atlmfc_32_64.sig",
     "c6f6084f1553f3a4a515bcefe7a72fe2b3564c8338c01fa9add1166276bf09f1"),
    ("3_flare_common_libs.sig",
     "6fa7dda3ffb523d2f555348db47c67b9820a40153bfacd543c9ea02a1ecd83a8"),
]
CAPA_SIGS_URL = "https://raw.githubusercontent.com/mandiant/capa/v9.4.0/sigs/"

CLAMAV_VERSION = "1.5.4"
CLAMAV_ZIP = ("https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/clamav-1.5.4.win.x64.zip",
              "0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395")
MAX_DOWNLOAD = 400 * 1024 ** 2


class UpdateError(Exception):
    pass


def download(url, sha256=None, limit=MAX_DOWNLOAD) -> bytes:
    """Fetch url (only addresses in network.py), refuse anything bigger than limit or with the wrong checksum."""
    response = network.get(url, stream=True, timeout=(10, 120))
    if response.status_code != 200:
        raise UpdateError(f"{url} answered HTTP {response.status_code}")
    data = io.BytesIO()
    for chunk in response.iter_content(1024 * 1024):
        data.write(chunk)
        if data.tell() > limit:
            raise UpdateError(f"{url} is bigger than expected")
    body = data.getvalue()
    if sha256 and hashlib.sha256(body).hexdigest() != sha256.lower():
        raise UpdateError(f"the download from {url} doesn't match its checksum, so it wasn't used")
    return body


def _write_atomic(target: Path, data: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, target)


def _safe_extract(archive: zipfile.ZipFile, folder: Path, keep=lambda name: True, strip=1) -> int:
    """Unpack only plain files under folder; no absolute paths, no '..'."""
    count = 0
    for info in archive.infolist():
        parts = info.filename.replace("\\", "/").split("/")[strip:]
        if info.is_dir() or not parts or any(p in ("", ".", "..") or ":" in p for p in parts):
            continue
        if not keep(info.filename):
            continue
        target = folder.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(info) as src, open(target, "wb") as out:
            shutil.copyfileobj(src, out)
        count += 1
    return count


def yara_forge(force=False) -> str:
    if not force and config.YARA_FORGE.is_file() and time.time() - config.YARA_FORGE.stat().st_mtime < FORGE_MAX_AGE:
        return "YARA Forge rules are less than a week old; kept them."
    release = network.get(FORGE_RELEASE, headers={"Accept": "application/vnd.github+json"}, timeout=(10, 30))
    if release.status_code != 200:
        raise UpdateError(f"GitHub answered HTTP {release.status_code} for the YARA Forge release")
    info = release.json()
    asset = next((a for a in info.get("assets", []) if a.get("name") == FORGE_ASSET), None)
    digest = (asset or {}).get("digest") or ""
    if not asset or not digest.startswith("sha256:"):
        raise UpdateError("the YARA Forge release has no core package with a checksum")
    body = download(asset["browser_download_url"], digest.split(":", 1)[1], limit=50 * 1024 ** 2)
    with zipfile.ZipFile(io.BytesIO(body)) as z:
        text = z.read(FORGE_MEMBER)
    import yara
    yara.compile(source=text.decode("utf-8"))  # refuse a broken rules file before it replaces a working one
    from .analyze import yararules
    yararules.save_forge(text)  # encrypted at rest; never written as a plain .yar file
    return f"YARA Forge core rules {info.get('tag_name', '')} installed."


def capa(force=False) -> str:
    rules = config.CAPA_RULES
    marker = rules / ".version"
    if force or not marker.is_file() or marker.read_text().strip() != CAPA_VERSION:
        body = download(*CAPA_RULES, limit=50 * 1024 ** 2)
        tmp = rules.with_name("capa.new")
        shutil.rmtree(tmp, ignore_errors=True)
        with zipfile.ZipFile(io.BytesIO(body)) as z:
            count = _safe_extract(z, tmp, keep=lambda n: n.endswith(".yml") and "/.github/" not in n)
        if count < 500:
            raise UpdateError("the capa rules download looks incomplete")
        (tmp / ".version").write_text(CAPA_VERSION)
        shutil.rmtree(rules, ignore_errors=True)
        os.replace(tmp, rules)
    for name, sha in CAPA_SIGS:
        target = config.CAPA_SIGS / name
        if force or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != sha:
            _write_atomic(target, download(CAPA_SIGS_URL + name, sha, limit=50 * 1024 ** 2))
    return f"capa rules and signatures {CAPA_VERSION} installed."


def clamav() -> str:
    exe = config.CLAMAV_DIR / "clamd.exe"
    marker = config.CLAMAV_DIR / ".version"
    if exe.is_file() and marker.is_file() and marker.read_text().strip() == CLAMAV_VERSION:
        return f"ClamAV {CLAMAV_VERSION} is already set up."
    body = download(*CLAMAV_ZIP)
    tmp = config.CLAMAV_DIR.with_name("clamav.new")
    shutil.rmtree(tmp, ignore_errors=True)
    with zipfile.ZipFile(io.BytesIO(body)) as z:
        _safe_extract(z, tmp)
    if not (tmp / "clamd.exe").is_file():
        raise UpdateError("the ClamAV download doesn't contain clamd.exe")
    (tmp / ".version").write_text(CLAMAV_VERSION)
    shutil.rmtree(config.CLAMAV_DIR, ignore_errors=True)
    os.replace(tmp, config.CLAMAV_DIR)
    return f"ClamAV {CLAMAV_VERSION} set up in {config.CLAMAV_DIR}."


def rules(force=False) -> list[str]:
    """YARA Forge (force: even if less than a week old) + capa (only if missing or the wrong version).
    Returns one line per part; failures are reported, not raised."""
    done = []
    from .analyze import yararules
    yararules.migrate()
    for name, job in (("YARA Forge", lambda: yara_forge(force)), ("capa", capa)):
        try:
            done.append(job())
        except (UpdateError, OSError, ValueError, zipfile.BadZipFile) as e:
            done.append(f"{name} update failed: {e}")
        except Exception as e:  # network errors and the like
            done.append(f"{name} update failed: {type(e).__name__}: {e}")
    return done


def main(argv) -> int:
    for line in rules(force="--force" in argv):
        print(" ", line)
    if "--clamav" in argv:
        try:
            print(" ", clamav())
            from . import clamav as clam
            print("  Downloading ClamAV's signatures (about 250 MB, a few minutes) ...")
            print(" ", clam.freshclam())
        except Exception as e:
            print(f"  ClamAV setup failed: {e}")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
