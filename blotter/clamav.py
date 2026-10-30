"""ClamAV, the open-source antivirus engine, run portably while Blotter is open. No admin rights, no service.

Blotter starts ClamAV's scanner (clamd.exe) with the first check that needs it, lets go of it again after
10 minutes without a check, and lets go when it closes. Every Blotter on this PC that uses ClamAV (the app, a
test runner) shares the one clamd: each holds a named job (procs.Job), and Windows ends clamd only with the last
hold, also when a Blotter crashes or its window is just closed. Signatures live in %LOCALAPPDATA%\\Blotter\\clamav-db
and are refreshed once a day by ClamAV's own freshclam. Turn it off in Settings to save memory
(clamd holds its signatures in about 1-1.5 GB of RAM).
"""

import json
import re
import socket
import struct
import subprocess
import threading
import time

from . import config, procs, settings

FRESHCLAM_TIMEOUT = 30 * 60
UPDATE_EVERY = 24 * 3600
START_TIMEOUT = 300
IDLE_STOP = 10 * 60  # clamd stops after this long without a check (it holds about 1 GB while it runs)
TICK = 30
STATE_FILE = config.HOME / "clamav-state.json"


def job_name() -> str:
    """The job every Blotter on this PC holds while it uses the clamd on this port."""
    return f"Local\\Blotter-clamd-{config.CLAMD_PORT}"


def clamd_command(conf) -> list:
    return [str(config.CLAMAV_DIR / "clamd.exe"), f"--config-file={conf}"]


def installed() -> bool:
    return (config.CLAMAV_DIR / "clamd.exe").is_file() and (config.CLAMAV_DIR / "freshclam.exe").is_file()


def has_signatures() -> bool:
    return any(config.CLAMAV_DB.glob("daily.c[lv]d")) and any(config.CLAMAV_DB.glob("main.c[lv]d"))


def signatures_age() -> float:
    files = list(config.CLAMAV_DB.glob("daily.c[lv]d"))
    return time.time() - max(f.stat().st_mtime for f in files) if files else float("inf")


def regex_path(path) -> str:
    """A folder as a ClamAV ExcludePath pattern (a regular expression, so backslashes are doubled)."""
    return re.sub(r"([\\.^$|?*+()\[\]{}])", r"\\\1", str(path))


def _write_configs() -> tuple:
    config.CLAMAV_DB.mkdir(parents=True, exist_ok=True)
    # Blotter only ever streams the one file being checked to clamd (INSTREAM), so clamd never walks
    # these folders. The exclusions are a second guard: Blotter's rules describe malware and its
    # quarantine holds what you moved there; neither should ever be reported as a find.
    excluded = [config.HOME / "rules", config.QUARANTINE, config.OWN_RULES, config.CLAMAV_DB]
    clamd = config.HOME / "clamd.conf"
    fresh = config.HOME / "freshclam.conf"
    clamd.write_text("\n".join([
        f"TCPSocket {config.CLAMD_PORT}",
        "TCPAddr 127.0.0.1",
        f"DatabaseDirectory {config.CLAMAV_DB}",
        "Foreground yes",
        "MaxThreads 4",
        "StreamMaxLength 2000M",
        "MaxFileSize 2000M",
        "MaxScanSize 2000M",
        "MaxRecursion 10",
        "MaxFiles 5000",
        "AlertExceedsMax yes",  # say so when a file is over a limit, instead of quietly answering OK
        "SelfCheck 3600",
        *[f"ExcludePath ^{regex_path(folder)}" for folder in excluded],
        "",
    ]), encoding="utf-8")
    fresh.write_text("\n".join([
        f"DatabaseDirectory {config.CLAMAV_DB}",
        "DatabaseMirror database.clamav.net",
        "ScriptedUpdates yes",
        "",
    ]), encoding="ascii")
    return clamd, fresh


def freshclam() -> str:
    """Download or refresh the signatures. Blocks; returns a sentence."""
    _, fresh = _write_configs()
    command = [str(config.CLAMAV_DIR / "freshclam.exe"), f"--config-file={fresh}", f"--datadir={config.CLAMAV_DB}",
               "--stdout"]
    code, out, err = procs.run(command, timeout=FRESHCLAM_TIMEOUT)
    text = (out + err).decode("utf-8", "replace")
    if code is None:
        raise RuntimeError("freshclam took longer than 30 minutes")
    if code not in (0, 1) or not has_signatures():
        last = [line for line in text.splitlines() if line.strip()][-1:] or [f"exit code {code}"]
        raise RuntimeError(f"freshclam failed: {last[0][:200]}")
    return "ClamAV's signatures are up to date."


def ask(command: bytes, timeout=10) -> str:
    """Send one clamd command (PING, VERSION, RELOAD) and return the answer."""
    with socket.create_connection(("127.0.0.1", config.CLAMD_PORT), timeout=timeout) as s:
        s.sendall(b"z" + command + b"\0")
        return _read_reply(s)


def _read_reply(s) -> str:
    data = b""
    while not data.endswith(b"\0"):
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.rstrip(b"\0").decode("utf-8", "replace").strip()


def scan_stream(stream, timeout=120) -> str:
    """Stream bytes to clamd (INSTREAM) and return its answer, e.g. 'stream: OK' or 'stream: X FOUND'."""
    with socket.create_connection(("127.0.0.1", config.CLAMD_PORT), timeout=timeout) as s:
        s.sendall(b"zINSTREAM\0")
        while chunk := stream.read(1024 * 1024):
            s.sendall(struct.pack(">I", len(chunk)) + chunk)
        s.sendall(struct.pack(">I", 0))
        return _read_reply(s)


def read_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"state": "stopped"}


class Service:
    """Holds clamd while Blotter runs. States: off, not_installed, updating, sleeping, starting, ready, failed.

    clamd starts with the first check that needs it (wake) and is let go again after IDLE_STOP without one,
    so its signatures (about 1 GB of memory) aren't held the whole time Blotter is open. If another Blotter
    started it already, this one joins it instead of starting a second; it ends when no Blotter holds it."""

    def __init__(self):
        self.state, self.message = "stopped", ""
        self._job = None
        self._proc = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._want = False      # a check asked for clamd since it last went to sleep
        self._busy = 0          # checks using it right now
        self._last_used = 0.0   # time.monotonic() of the last check that started or finished

    def _set(self, state, message=""):
        self.state, self.message = state, message
        try:
            config.HOME.mkdir(parents=True, exist_ok=True)
            STATE_FILE.write_text(json.dumps({"state": state, "message": message, "at": time.time()}),
                                  encoding="utf-8")
        except OSError:
            pass

    def status(self) -> dict:
        return {"state": self.state, "message": self.message, "installed": installed(),
                "enabled": settings.load()["clamav"]}

    def start(self) -> None:
        """At Blotter's start and when switched on: refresh the signatures if due, but don't load clamd yet."""
        self._run()

    def wake(self) -> None:
        """A check needs ClamAV: start clamd unless it runs already. Pair every wake() with a release()."""
        with self._lock:
            self._busy += 1
            self._last_used = time.monotonic()
            self._want = True
        if self.state not in ("ready", "starting", "updating") and settings.load()["clamav"] and installed():
            # Say so at once: the check (in its own process) waits while it reads "starting"
            self._set("starting", "ClamAV is starting for this check (takes up to a minute)")
        self._run()

    def release(self) -> None:
        with self._lock:
            self._busy = max(0, self._busy - 1)
            self._last_used = time.monotonic()

    def _run(self) -> None:
        with self._lock:
            thread = self._thread
        if thread and thread.is_alive() and self._stop.is_set():
            thread.join(timeout=10)  # switched off a moment ago: let that finish first
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def stop(self, state="off") -> None:
        self._stop.set()
        with self._lock:
            self._want = False
            self._end_clamd()
        self._left(state)

    def _end_clamd(self):
        """With self._lock held. Let go of clamd: Windows ends it (and anything it started) when no other Blotter
        holds it too."""
        if self._job and self._job.handle:
            self._job.close()
        elif self._proc:  # no job could be made: end the clamd this Blotter started itself
            try:
                self._proc.kill()
            except OSError:
                pass
        self._job = self._proc = None

    def _left(self, state):
        """After letting go: write the new state, unless another Blotter still uses clamd (its checks read the
        same state file and would think ClamAV had stopped: round 2's N6)."""
        if procs.Job.held(job_name()):
            self.state, self.message = state, ""
        else:
            self._set(state)

    def _ended(self) -> bool:
        """clamd ended (crashed) although this Blotter holds it."""
        if self._job and self._job.handle:
            return not self._job.active()
        return bool(self._proc) and self._proc.poll() is not None

    def _sleep(self) -> bool:
        """With self._lock held: go to sleep unless a check wants clamd. True when this thread should end."""
        if self._want and not self._stop.is_set():
            return False
        self._thread = None  # a wake() from now on starts a new thread
        if not self._stop.is_set():
            self._left("sleeping")
        return True

    def _loop(self):
        if not settings.load()["clamav"]:
            self._set("off")
            return
        if not installed():
            self._set("not_installed")
            return
        try:
            if not has_signatures() or signatures_age() > UPDATE_EVERY:
                self._set("updating", "Downloading ClamAV's signatures")
                freshclam()
        except Exception as e:
            self._set("failed", str(e)[:300])
            return
        with self._lock:
            if self._sleep():
                return
        try:
            self._launch()
        except Exception as e:
            self._failed(e)
            return
        next_update = time.monotonic() + 1800
        while not self._stop.wait(TICK):
            with self._lock:
                if self._busy == 0 and time.monotonic() - self._last_used > IDLE_STOP:
                    self._want = False
                    self._end_clamd()
                    self._sleep()
                    return
            if time.monotonic() > next_update:
                next_update = time.monotonic() + 1800
                if signatures_age() > UPDATE_EVERY:
                    try:
                        freshclam()
                        ask(b"RELOAD", timeout=30)
                    except Exception as e:
                        self.message = f"Last signature update failed: {str(e)[:200]}"
            if self._ended() and not self._stop.is_set():
                try:
                    self._launch()
                except Exception as e:
                    self._failed(e)
                    return

    def _failed(self, e):
        with self._lock:
            self._end_clamd()
        self._set("failed", str(e)[:300])

    def _launch(self):
        self._set("starting", "ClamAV is loading its signatures (takes up to a minute)")
        clamd_conf, _ = _write_configs()
        proc = None
        # One Blotter at a time decides whether clamd must be started; a second clamd on the same port would take
        # it over from the first.
        with procs.named_lock(job_name() + "-start"):
            with self._lock:
                if not (self._job and self._job.handle):
                    self._job = procs.Job(name=job_name())
                job = self._job
            if not job.active():
                proc = subprocess.Popen(clamd_command(clamd_conf), stdin=subprocess.DEVNULL,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        creationflags=procs.NO_WINDOW, cwd=str(config.CLAMAV_DIR))
                job.add(proc)
                with self._lock:
                    self._proc = proc
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline and not self._stop.is_set():
            if proc is not None and proc.poll() is not None:
                raise RuntimeError(f"clamd stopped while starting (exit code {proc.returncode})")
            if proc is None and not job.active():
                raise RuntimeError("clamd stopped while starting")
            try:
                if ask(b"PING", timeout=3) == "PONG":
                    self._set("ready", ask(b"VERSION"))
                    return
            except OSError:
                pass
            time.sleep(2)
        raise RuntimeError("clamd didn't get ready within 5 minutes")


service = Service()
