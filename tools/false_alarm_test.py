"""False-alarm test: check every file in a folder you trust and count the verdicts.

    .venv\\Scripts\\python tools\\false_alarm_test.py "D:\\Trusted files" [--offline] [--skip capa,clamav] [--parallel 1]

Target for about 100 trusted files (game mods included): 0 Malicious, at most 5 Suspicious.
The originals are only read; Blotter checks copies, one file at a time by default (capa uses a lot
of the PC; checking several at once makes it run out of time). Your "Trust this file" list is ignored
here, so the numbers show what Blotter says on its own.
Each result is saved as soon as it is known (a .jsonl file), and the report is always written, even if
the run stops early or you press Ctrl+C. Both go to %LOCALAPPDATA%\\Blotter.
"""

import argparse
import hashlib
import json
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
from blotter.verdict import VERDICTS  # noqa: E402

ORDER = ["malicious", "suspicious", "unusual", "no_known_detections", "couldnt_fully_check", "couldnt_check"]
JOB_TIMEOUT = 15 * 60


def title(key: str) -> str:
    """The answer's name; one Blotter adds later still prints instead of stopping the run."""
    return VERDICTS[key][0] if key in VERDICTS else key


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


def check_folder(folder: Path, files, runner, parallel=1, log=None, say=print) -> list:
    """Check files; returns [(path, verdict key, reasons)]. Each result is appended to `log` (jsonl) at once."""
    results = []
    pending = list(enumerate(files, 1))
    running = []

    def record(n, source, key, reasons, job=None):
        results.append((source, key, reasons))
        say(f"[{n}/{len(files)}] {title(key):<20} {source.relative_to(folder)}")
        if log is not None:
            entry = {"file": str(source.relative_to(folder)), "verdict": key, "reasons": reasons}
            if job is not None:
                entry["checks"] = job.to_dict()["checks"]
            log.write(json.dumps(entry) + "\n")
            log.flush()

    while pending or running:
        while pending and len(running) < max(1, parallel):
            n, source = pending.pop(0)
            try:
                copy, size, sha = copy_for_check(source)
            except OSError as e:
                record(n, source, "couldnt_check", [f"Couldn't read it ({e.strerror or e})."])
                continue
            running.append((n, source, runner.start(copy, source.name, size, sha), time.monotonic()))
        time.sleep(0.2)
        for item in list(running):
            n, source, job, t0 = item
            if job.state == "done" or time.monotonic() - t0 > JOB_TIMEOUT:
                running.remove(item)
                verdict = job.verdict or {"verdict": "couldnt_check", "reasons": ["Blotter stopped waiting."]}
                record(n, source, verdict["verdict"], verdict["reasons"], job)
    return results


def report(folder, results, checks, minutes, total, stopped=None) -> tuple[str, bool]:
    counts = Counter(v for _, v, _ in results)
    lines = [f"Blotter false-alarm test, {time.strftime('%Y-%m-%d %H:%M')}", f"Folder: {folder}",
             f"Files: {len(results)} of {total} in {minutes:.0f} minutes",
             "Checks: " + ", ".join(c.NAME for c in checks), ""]
    if stopped:
        lines += [f"THE RUN STOPPED EARLY: {stopped}", ""]
    for key in ORDER + sorted(set(counts) - set(ORDER)):
        lines.append(f"  {title(key):<20} {counts.get(key, 0)}")
    met = counts.get("malicious", 0) == 0 and counts.get("suspicious", 0) <= 5 and not stopped
    lines += ["", f"Target (0 Malicious, at most 5 Suspicious): {'MET' if met else 'NOT MET'}", ""]
    for key in [k for k in ORDER + sorted(set(counts) - set(ORDER)) if k != "no_known_detections"]:
        hits = [(s, r) for s, v, r in results if v == key]
        if hits:
            lines.append(f"--- {title(key)} ---")
            for source, reasons in hits:
                lines.append(f"{source.relative_to(folder)}")
                for reason in reasons[:4]:
                    lines.append(f"    - {reason}")
            lines.append("")
    return "\n".join(lines), met


def main(argv=None, checks=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("folder")
    parser.add_argument("--offline", action="store_true", help="skip VirusTotal, MalwareBazaar and CIRCL")
    parser.add_argument("--skip", default="", help="check IDs to leave out, e.g. capa,clamav")
    parser.add_argument("--parallel", type=int, default=1, help="files checked at the same time (default 1)")
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
    if checks is None:
        checks = load_checks()
    checks = [c for c in checks if c.ID not in skip and not (args.offline and getattr(c, "CACHE", False)
                                                              and not getattr(c, "NEEDS_FILE", False))]
    print(f"Checking {len(files)} files in {folder}, {args.parallel} at a time")
    print("Checks: " + ", ".join(c.NAME for c in checks))
    if any(c.ID == "clamav" for c in checks):
        print(wait_for_clamav())
    clean_incoming()
    from blotter.analyze import yararules
    yararules.migrate()

    config.HOME.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    log_path = config.HOME / f"false-alarm-test-{stamp}.jsonl"
    out = config.HOME / f"false-alarm-test-{stamp}.txt"
    runner = Runner(Cache(config.DB_PATH), checks, trust=None)
    results, stopped, started = [], None, time.monotonic()
    try:
        with open(log_path, "w", encoding="utf-8") as log:
            results = check_folder(folder, files, runner, args.parallel, log)
    except KeyboardInterrupt:
        stopped = "stopped by Ctrl+C"
    except Exception as e:  # never lose the results so far
        stopped = f"{type(e).__name__}: {e}"
    finally:
        clamav.service.stop("stopped")
        if not results and log_path.exists():  # crashed mid-run: rebuild from what was already saved
            for line in log_path.read_text(encoding="utf-8").splitlines():
                entry = json.loads(line)
                results.append((folder / entry["file"], entry["verdict"], entry["reasons"]))
        text, met = report(folder, results, checks, (time.monotonic() - started) / 60, len(files), stopped)
        out.write_text(text, encoding="utf-8")
        print("\n" + text)
        print(f"Report saved: {out}")
        print(f"Every result in full: {log_path}")
    return 0 if met else 1


if __name__ == "__main__":
    sys.exit(main())
