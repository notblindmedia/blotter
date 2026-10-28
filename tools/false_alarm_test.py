"""False-alarm test: check every file in a folder you trust and count the verdicts.

    .venv\\Scripts\\python tools\\false_alarm_test.py "D:\\Trusted files" [--offline] [--skip capa,clamav] [--parallel 2]

Target for about 100 trusted files (game mods included): 0 Malicious, at most 5 Suspicious.
The originals are only read; Blotter checks copies. Your "Trust this file" list is ignored here,
so the numbers show what Blotter says on its own. A report is saved in %LOCALAPPDATA%\\Blotter.
"""

import argparse
import hashlib
import sys
import time
import uuid
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blotter import clamav, config, settings  # noqa: E402
from blotter.app import clean_incoming  # noqa: E402
from blotter.cache import Cache  # noqa: E402
from blotter.checks import load_checks  # noqa: E402
from blotter.runner import Runner  # noqa: E402

ORDER = ["malicious", "suspicious", "unusual", "no_known_detections", "couldnt_check"]
TITLES = {"malicious": "Malicious", "suspicious": "Suspicious", "unusual": "Unusual",
          "no_known_detections": "No known detections", "couldnt_check": "Couldn't check"}
JOB_TIMEOUT = 15 * 60


def copy_for_check(source: Path):
    config.INCOMING.mkdir(parents=True, exist_ok=True)
    target = config.INCOMING / f"{uuid.uuid4().hex}.blotter"
    digest, size = hashlib.sha256(), 0
    with open(source, "rb") as src, open(target, "wb") as out:
        while chunk := src.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
            out.write(chunk)
    return target, size, digest.hexdigest()


def wait_for_clamav():
    if not (settings.load()["clamav"] and clamav.installed()):
        return "ClamAV: off or not set up, so it is skipped."
    clamav.service.start()
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        state = clamav.service.state
        if state == "ready":
            return "ClamAV: running."
        if state in ("failed", "off", "not_installed"):
            return f"ClamAV: {state} ({clamav.service.message})."
        time.sleep(2)
    return "ClamAV: still not ready after 10 minutes."


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("folder")
    parser.add_argument("--offline", action="store_true", help="skip VirusTotal, MalwareBazaar and CIRCL")
    parser.add_argument("--skip", default="", help="check IDs to leave out, e.g. capa,clamav")
    parser.add_argument("--parallel", type=int, default=2, help="files checked at the same time (default 2)")
    parser.add_argument("--limit", type=int, default=0, help="stop after this many files")
    args = parser.parse_args(argv)

    folder = Path(args.folder.strip('"'))
    if not folder.is_dir():
        print(f"Not a folder: {folder}")
        return 2
    files = sorted(p for p in folder.rglob("*") if p.is_file() and p.stat().st_size <= config.MAX_UPLOAD)
    if args.limit:
        files = files[:args.limit]
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    checks = [c for c in load_checks() if c.ID not in skip and not (args.offline and getattr(c, "CACHE", False))]
    print(f"Checking {len(files)} files in {folder}")
    print("Checks: " + ", ".join(c.NAME for c in checks))
    if any(c.ID == "clamav" for c in checks):
        print(wait_for_clamav())
    clean_incoming()
    from blotter.analyze import yararules
    yararules.migrate()

    runner = Runner(Cache(config.DB_PATH), checks, trust=None)
    results = []
    pending = list(enumerate(files, 1))
    running = []
    started = time.monotonic()
    try:
        while pending or running:
            while pending and len(running) < max(1, args.parallel):
                n, source = pending.pop(0)
                try:
                    copy, size, sha = copy_for_check(source)
                except OSError as e:
                    results.append((source, "couldnt_check", [f"Couldn't read it ({e.strerror or e})."]))
                    print(f"[{n}/{len(files)}] Couldn't read   {source.relative_to(folder)}")
                    continue
                job = runner.start(copy, source.name, size, sha)
                running.append((n, source, job, time.monotonic()))
            time.sleep(0.5)
            for item in list(running):
                n, source, job, t0 = item
                if job.state == "done" or time.monotonic() - t0 > JOB_TIMEOUT:
                    running.remove(item)
                    verdict = job.verdict or {"verdict": "couldnt_check", "reasons": ["timed out"]}
                    results.append((source, verdict["verdict"], verdict["reasons"]))
                    print(f"[{n}/{len(files)}] {TITLES[verdict['verdict']]:<20} {source.relative_to(folder)}")
    finally:
        clamav.service.stop("stopped")

    counts = Counter(v for _, v, _ in results)
    lines = [f"Blotter false-alarm test, {time.strftime('%Y-%m-%d %H:%M')}", f"Folder: {folder}",
             f"Files: {len(results)} in {(time.monotonic() - started) / 60:.0f} minutes",
             "Checks: " + ", ".join(c.NAME for c in checks), ""]
    for key in ORDER:
        lines.append(f"  {TITLES[key]:<20} {counts.get(key, 0)}")
    met = counts.get("malicious", 0) == 0 and counts.get("suspicious", 0) <= 5
    lines += ["", f"Target (0 Malicious, at most 5 Suspicious): {'MET' if met else 'NOT MET'}", ""]
    for key in ("malicious", "suspicious", "unusual", "couldnt_check"):
        hits = [(s, r) for s, v, r in results if v == key]
        if hits:
            lines.append(f"--- {TITLES[key]} ---")
            for source, reasons in hits:
                lines.append(f"{source.relative_to(folder)}")
                for reason in reasons[:4]:
                    lines.append(f"    - {reason}")
            lines.append("")
    report = "\n".join(lines)
    print("\n" + report)
    out = config.HOME / f"false-alarm-test-{time.strftime('%Y%m%d-%H%M')}.txt"
    out.write_text(report, encoding="utf-8")
    print(f"Report saved: {out}")
    return 0 if met else 1


if __name__ == "__main__":
    sys.exit(main())
