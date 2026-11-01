"""Build a release zip and its manifest here, to be signed on the signing PC (tools\\sign-release).

    .venv\\Scripts\\python tools\\make_release.py [--out FOLDER]

- Only committed files go in (git archive of HEAD), so STATUS.md, .venv and unsaved work stay out. Refuses
  while tracked files have uncommitted changes, or if a private-looking file (STATUS.md, keys) would go in.
- Left out: the tests and the developer tools (release, intel pack, signing kit).
- Reproducible: the same commit gives the same bytes (sorted names, the commit's date on every file).
- The manifest blotter-X.Y.Z.json names the version, commit, the zip's size and SHA-256, and what changed
  (the section for this version in CHANGES.txt). This PC never signs it: the release key isn't here.
"""

import argparse
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEFT_OUT = ("tests/", "tools/sign-release/", "tools/make_release.py", "tools/intel_pack.py",
            ".gitignore", ".gitattributes")
PRIVATE = re.compile(r"(^|/)(STATUS\.md|\.env)$|\.(pem|key|p12|pfx)$", re.IGNORECASE)


class ReleaseError(Exception):
    pass


def git(repo: Path, *args) -> bytes:
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
    if done.returncode:
        raise ReleaseError(f"git {' '.join(args)} failed: {done.stderr.decode(errors='replace').strip()}")
    return done.stdout


def changes(text: str, version: str) -> list[str]:
    """The '- ' lines under the line that is just `version` in CHANGES.txt."""
    out, inside = [], False
    for line in text.splitlines():
        if inside and line.startswith("  ") and line.strip() and out:
            out[-1] += " " + line.strip()  # a note going on over several lines
        elif inside and line.startswith("- "):
            out.append(line[2:].strip())
        elif re.fullmatch(r"\S+", line) and not line.startswith("-"):
            inside = line == version
    return out


def build(repo: Path, out: Path | None = None) -> dict:
    """Write blotter-X.Y.Z.zip and blotter-X.Y.Z.json into out; returns the manifest."""
    if git(repo, "status", "--porcelain", "--untracked-files=no").strip():
        raise ReleaseError("tracked files have uncommitted changes; commit them first")
    init = git(repo, "show", "HEAD:blotter/__init__.py").decode("utf-8")
    version = re.search(r'__version__ = "(\d+\.\d+\.\d+)"', init)
    if not version:
        raise ReleaseError("blotter/__init__.py has no __version__")
    version = version.group(1)
    notes = changes(git(repo, "show", "HEAD:CHANGES.txt").decode("utf-8"), version)
    if not notes:
        raise ReleaseError(f"CHANGES.txt has no section for {version}")
    commit = git(repo, "rev-parse", "HEAD").decode().strip()
    stamp = int(git(repo, "log", "-1", "--format=%ct", "HEAD").decode().strip())
    date = time.gmtime(max(stamp, 315532800))[:6]  # zip dates start in 1980
    prefix = f"blotter-{version}/"
    files = {}
    with tarfile.open(fileobj=io.BytesIO(git(repo, "archive", "--format=tar", "HEAD"))) as tar:
        for member in tar.getmembers():
            if not member.isfile() or member.name.startswith(LEFT_OUT):
                continue
            if PRIVATE.search(member.name):
                raise ReleaseError(f"{member.name} looks private and must never be in a release")
            files[member.name] = tar.extractfile(member).read()
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as z:
        for name in sorted(files):
            info = zipfile.ZipInfo(prefix + name, date_time=date)
            info.external_attr = 0o644 << 16
            info.create_system = 0
            z.writestr(info, files[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    body = data.getvalue()
    manifest = {"kind": "blotter-release", "format": 1, "version": version, "commit": commit,
                "zip": f"blotter-{version}.zip", "size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                "changes": notes}
    if out is None:
        sys.path.insert(0, str(ROOT))
        from blotter import config
        out = config.HOME / "releases" / version
    out.mkdir(parents=True, exist_ok=True)
    (out / manifest["zip"]).write_bytes(body)
    (out / f"blotter-{version}.json").write_bytes((json.dumps(manifest, indent=2) + "\n").encode("utf-8"))
    manifest["folder"] = str(out)
    return manifest


def main(argv) -> int:
    parser = argparse.ArgumentParser(description="Build a Blotter release zip and manifest (unsigned).")
    parser.add_argument("--out", type=Path, help="folder for the zip and manifest")
    args = parser.parse_args(argv)
    try:
        m = build(ROOT, args.out)
    except ReleaseError as e:
        print(f"Release not built: {e}.")
        return 1
    print(f"Blotter {m['version']} (commit {m['commit'][:12]}), {len(m['changes'])} change notes.")
    print(f"  {m['folder']}\\{m['zip']}  {m['size']:,} bytes")
    print(f"  SHA-256 {m['sha256']}")
    print(f"  {m['folder']}\\blotter-{m['version']}.json  (the manifest to sign)")
    print("Next: copy both files to the main PC, drag the .json onto sign-release.bat, bring back the .json.sig.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
