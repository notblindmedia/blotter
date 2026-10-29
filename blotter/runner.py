"""Runs every check on one file, each with its own timeout.

Checks that read the file's bytes run in a separate process (worker.py). Checks that only send
the SHA-256 to an online database run in a thread here, because they never touch the file and
the VirusTotal rate limit has to be shared between scans.

A job goes "running" -> "deep_check" -> "done". Checks marked BACKGROUND (capa, the deep check) don't
hold up the answer: once every other check has finished, the verdict is worked out and shown
("deep_check", with verdict["still_running"] naming what is still working), and it is worked out again
when the background check finishes. Engine detections are never held back by it.

Deep checks wait in one queue (DeepQueue) and run one at a time, oldest first, at below-normal CPU
priority, so a batch of files can't slow the PC down. Each one's time limit starts when it starts, not
while it waits. A waiting card shows its place in line (to_dict()["deep_queue"]). Runner.close(), when
Blotter closes, empties the queue, stops the deep check that is running and lets each job clean up.
"""

import threading
import time
import uuid
from pathlib import Path

from . import hashing, procs, worker
from .findings import ERROR, LEVELS, SKIPPED, UNCHECKED, Finding
from .verdict import decide

KEEP_JOBS = 100
KEEP_LOCKED = 30 * 60  # a locked archive's copy waits this long for its password, then it is deleted


class Job:
    def __init__(self, name, size, sha256, checks, source_path=None, password=None):
        self.id = uuid.uuid4().hex
        self.password = password  # an archive password the person typed in; never sent to the page
        self.retry_path = None    # the copy, kept while the archive waits for its password
        self.retry_timer = None
        self.name, self.size, self.sha256 = name, size, sha256
        self.source_path = source_path  # the real file, when chosen on this PC; None for uploads
        self.created = time.time()
        self.state = "running"
        self.verdict = None
        self.trusted = None
        self.queue = None  # the runner's DeepQueue, for this job's place in line
        self.test_mode = False
        self.thread = None  # the thread that runs the checks and then deletes the copy
        self.checks = {
            m.ID: {"id": m.ID, "name": m.NAME, "state": "waiting", "findings": [], "cached_at": None}
            for m in checks
        }

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "size": self.size, "sha256": self.sha256,
            "state": self.state, "verdict": self.verdict, "trusted": self.trusted,
            "source_path": self.source_path, "needs_password": bool(self.retry_path),
            "deep_queue": self.queue.position(self) if self.queue else None,  # 1 = next in line
            "test_mode": self.test_mode,
            "checks": [
                {**c, "findings": [f.to_dict() for f in c["findings"]]} for c in self.checks.values()
            ],
        }


def isolated(check) -> bool:
    """Real checks that read the file go to a worker process. (Test doubles run in a thread.)"""
    return getattr(check, "NEEDS_FILE", False) and getattr(check, "__name__", "").startswith(worker.PREFIX)


class Runner:
    def __init__(self, cache, checks, trust=None, test_mode=False):
        self.cache = cache
        self.test_mode = test_mode  # --test-mode: the Defender check is left out; cards say so
        self.trust = trust
        self.checks = list(checks)
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self.deep = DeepQueue(self)

    def start(self, path, name, size, sha256, save_error=None, force=False, source_path=None, password=None) -> Job:
        job = Job(name, size, sha256, self.checks, source_path=source_path, password=password)
        job.queue = self.deep
        job.test_mode = self.test_mode
        with self._lock:
            self.jobs[job.id] = job
            for old in list(self.jobs)[:-KEEP_JOBS]:
                del self.jobs[old]
        hashing.remember(path, sha256, name, password)
        job.thread = threading.Thread(target=self._run, args=(job, Path(path), save_error, force), daemon=True)
        job.thread.start()
        return job

    def recent(self) -> list[dict]:
        """One short line per checked file, newest first, for the page's list."""
        with self._lock:
            jobs = list(self.jobs.values())
        return [{"id": j.id, "name": j.name, "state": j.state, "created": j.created,
                 "verdict": (j.verdict or {}).get("verdict"), "title": (j.verdict or {}).get("title"),
                 "deep_queue": j.queue.position(j) if j.queue else None} for j in reversed(jobs)]

    def get(self, job_id) -> Job | None:
        with self._lock:
            return self.jobs.get(job_id)

    def rescore(self, job) -> None:
        """Work out the verdict again (after Trust / Stop trusting)."""
        with self._lock:
            self._score(job)

    def _score(self, job):
        job.trusted = self.trust.get(job.sha256) if self.trust else None
        findings = [f for c in job.checks.values() for f in c["findings"]]
        job.verdict = decide(findings, trusted=bool(job.trusted))
        still = [c["name"] for c in job.checks.values() if c["state"] != "done"]
        if still:
            job.verdict["still_running"] = still

    def close(self, wait=5.0) -> None:
        """Blotter is closing: empty the deep-check queue, stop the one that runs, and give the jobs a few
        seconds to finish and delete their copies (start-up deletes anything left)."""
        self.deep.close()
        end = time.monotonic() + wait
        with self._lock:
            threads = [j.thread for j in self.jobs.values() if j.thread]
        for t in threads:
            t.join(max(0.0, end - time.monotonic()))

    def _run(self, job, path, save_error, force):
        started, deep = [], []
        for check in self.checks:
            if getattr(check, "BACKGROUND", False):
                if not self._quick_answer(job, check, save_error, force):
                    item = DeepItem(job, check, path, save_error, force)
                    with self._lock:
                        job.checks[check.ID]["state"] = "queued"
                    if self.deep.submit(item):
                        deep.append(item)
                    else:
                        self._finish(job, check.ID, [_cancelled(check)])
                continue
            t = threading.Thread(target=self._run_check, args=(job, check, path, save_error, force), daemon=True)
            t.start()
            grace = 5 if isolated(check) else 0  # the worker enforces the timeout itself; this is a backstop
            started.append((check, t, time.monotonic() + check.TIMEOUT + grace))
        self._wait(job, started)
        if any(not item.done.is_set() for item in deep):
            with self._lock:
                self._score(job)
                job.state = "deep_check"  # the page shows this answer now; the deep check updates it later
        for item in deep:
            item.done.wait()  # DeepQueue always sets it: finished, out of time, or cancelled
        with self._lock:
            self._score(job)
            locked = any(f.details.get("needs_password") for c in job.checks.values() for f in c["findings"])
            if locked and path.exists():
                job.retry_path = path
                job.retry_timer = threading.Timer(KEEP_LOCKED, self._drop_copy, args=(job,))
                job.retry_timer.daemon = True
                job.retry_timer.start()
            job.state = "done"
        hashing.forget(path)
        if not locked:
            _delete(path)

    def _wait(self, job, started):
        for check, t, deadline in started:
            t.join(max(0.0, deadline - time.monotonic()))
            if t.is_alive():
                self._finish(job, check.ID, [_too_slow(check)])

    def retry_with_password(self, job_id, password) -> Job | None:
        """Check a locked archive again with the password the person typed. None if its copy is gone."""
        with self._lock:
            old = self.jobs.get(job_id)
            if not old or not old.retry_path or not old.retry_path.exists():
                return None
            path, old.retry_path = old.retry_path, None
            if old.retry_timer:
                old.retry_timer.cancel()
        return self.start(path, old.name, old.size, old.sha256, source_path=old.source_path, password=password)

    def _drop_copy(self, job):
        with self._lock:
            path, job.retry_path = job.retry_path, None
        if path:
            _delete(path)

    def _run_deep(self, item):
        """Run one deep check from the queue, with its own time limit; a cancel stops it at once."""
        check = item.check
        t = threading.Thread(target=self._run_check, daemon=True,
                             args=(item.job, check, item.path, item.save_error, item.force, item.cancel))
        t.start()
        deadline = time.monotonic() + check.TIMEOUT + (5 if isolated(check) else 0)
        while t.is_alive() and time.monotonic() < deadline and not item.cancel.is_set():
            t.join(0.25)
        if item.cancel.is_set() and isolated(check):
            t.join(5)  # the worker process is killed at once; this waits for its folder to be cleaned up
        if t.is_alive():
            self._finish(item.job, check.ID, [_cancelled(check) if item.cancel.is_set() else _too_slow(check)])

    def _quick_answer(self, job, check, save_error, force) -> bool:
        """Answers that need no work: a remembered one, or none because the copy couldn't be saved."""
        cached = None
        if getattr(check, "CACHE", False) and not force:
            cached = self.cache.get(job.sha256, _cache_id(check))
        if cached:
            self._finish(job, check.ID, cached[0], cached_at=cached[1])
            return True
        if save_error and getattr(check, "NEEDS_FILE", False):
            self._finish(job, check.ID, [Finding(
                check.ID, ERROR, f"{check.NAME} wasn't checked: Blotter couldn't save a copy of the file ({save_error}).")])
            return True
        return False

    def _run_check(self, job, check, path, save_error, force, cancel=None):
        if cancel is None and self._quick_answer(job, check, save_error, force):
            return  # (deep checks were asked before they were queued)
        with self._lock:
            job.checks[check.ID]["state"] = "running"
        background = getattr(check, "BACKGROUND", False)
        done = None
        try:
            prepare = getattr(check, "prepare", None)  # e.g. ClamAV starts its scanner if it is resting
            done = prepare() if callable(prepare) else None
            if isolated(check):
                findings = worker.run(check.__name__, path, job.name, job.sha256, timeout=check.TIMEOUT,
                                      sandboxed=getattr(check, "SANDBOX", True), password=job.password,
                                      priority=procs.BELOW_NORMAL if background else None, cancel=cancel)
            else:
                findings = check.scan(str(path))
            findings = _validate(check, findings)
        except worker.Cancelled:
            findings = [_cancelled(check)]
        except TimeoutError:
            findings = [_too_slow(check)]
        except Exception as e:  # a broken check must not break the others
            # A worker that dies (a parser crash, or the memory limit) didn't finish reading the file.
            signals = [UNCHECKED] if isolated(check) else []
            findings = [Finding(check.ID, ERROR, f"{check.NAME} failed unexpectedly ({type(e).__name__}).",
                                {"error": str(e)[:300]}, signals)]
        finally:
            if callable(done):
                done()
        # Remember only complete answers: not errors, skips (no key yet), or anything cut short by a limit.
        if getattr(check, "CACHE", False) and not any(f.level in (ERROR, SKIPPED) or UNCHECKED in f.signals
                                                      for f in findings):
            self.cache.put(job.sha256, _cache_id(check), findings)
        self._finish(job, check.ID, findings)

    def _finish(self, job, check_id, findings, cached_at=None):
        with self._lock:
            entry = job.checks[check_id]
            if entry["state"] == "done":
                return  # already timed out; ignore the late answer
            entry.update(state="done", findings=list(findings), cached_at=cached_at)


def _cache_id(check) -> str:
    """The cache key for a check; CACHE_VERSION lets a check retire old remembered answers."""
    version = getattr(check, "CACHE_VERSION", None)
    return f"{check.ID}@{version}" if version else check.ID


def _delete(path) -> None:
    """Remove Blotter's own temporary copy. Windows refuses while another program (an antivirus scanning the
    new file, for example) still has it open, so try a few times; start-up cleans up anything left."""
    for attempt in range(10):
        try:
            path.unlink(missing_ok=True)
            return
        except OSError:
            time.sleep(0.2 * (attempt + 1))


class DeepItem:
    """One deep check waiting in, or taken from, the DeepQueue."""

    def __init__(self, job, check, path, save_error, force):
        self.job, self.check, self.path, self.save_error, self.force = job, check, path, save_error, force
        self.done = threading.Event()    # set when it has an answer (or was cancelled)
        self.cancel = threading.Event()  # set when Blotter closes


class DeepQueue:
    """Deep checks, one at a time, oldest first, in one background thread."""

    def __init__(self, runner):
        self.runner = runner
        self.waiting: list[DeepItem] = []
        self.current: DeepItem | None = None
        self.closed = False
        self._cond = threading.Condition()
        self._thread = None

    def submit(self, item) -> bool:
        """Put a deep check in line. False once Blotter is closing."""
        with self._cond:
            if self.closed:
                return False
            self.waiting.append(item)
            if self._thread is None:
                self._thread = threading.Thread(target=self._loop, name="deep-checks", daemon=True)
                self._thread.start()
            self._cond.notify()
        return True

    def position(self, job) -> int | None:
        """The job's place in line (1 = next), or None when it isn't waiting."""
        with self._cond:
            for n, item in enumerate(self.waiting, 1):
                if item.job is job:
                    return n
        return None

    def close(self) -> None:
        with self._cond:
            self.closed = True
            dropped, self.waiting = self.waiting, []
            current = self.current
            self._cond.notify_all()
        for item in dropped:
            item.cancel.set()
            self.runner._finish(item.job, item.check.ID, [_cancelled(item.check)])
            item.done.set()
        if current:
            current.cancel.set()

    def _loop(self):
        while True:
            with self._cond:
                while not self.waiting and not self.closed:
                    self._cond.wait()
                if self.closed:
                    return
                item = self.current = self.waiting.pop(0)
            try:
                self.runner._run_deep(item)
            except Exception as e:  # never leave a job waiting
                self.runner._finish(item.job, item.check.ID, [Finding(
                    item.check.ID, ERROR, f"{item.check.NAME} failed unexpectedly ({type(e).__name__}).",
                    {"error": str(e)[:300]}, [UNCHECKED])])
            finally:
                with self._cond:
                    self.current = None
                item.done.set()


def _cancelled(check) -> Finding:
    return Finding(check.ID, ERROR, f"{check.NAME} was stopped because Blotter was closed.", {"cancelled": True},
                   [UNCHECKED])


def _too_slow(check) -> Finding:
    return Finding(check.ID, ERROR, f"{check.NAME} took longer than {duration(check.TIMEOUT)}, so Blotter stopped it.",
                   {}, [UNCHECKED])


def duration(seconds) -> str:
    """'15 minutes' for whole minutes from 2 minutes up, otherwise '90 seconds'."""
    return f"{seconds // 60} minutes" if seconds >= 120 and seconds % 60 == 0 else f"{seconds} seconds"


def _validate(check, findings) -> list[Finding]:
    findings = list(findings or [])
    if not findings or not all(isinstance(f, Finding) and f.level in LEVELS for f in findings):
        return [Finding(check.ID, ERROR, f"{check.NAME} gave no usable answer.")]
    return findings
