"""Runs every check on one file, each with its own timeout.

Checks that read the file's bytes run in a separate process (worker.py). Checks that only send
the SHA-256 to an online database run in a thread here, because they never touch the file and
the VirusTotal rate limit has to be shared between scans.
"""

import threading
import time
import uuid
from pathlib import Path

from . import hashing, worker
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
        self.checks = {
            m.ID: {"id": m.ID, "name": m.NAME, "state": "waiting", "findings": [], "cached_at": None}
            for m in checks
        }

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "size": self.size, "sha256": self.sha256,
            "state": self.state, "verdict": self.verdict, "trusted": self.trusted,
            "source_path": self.source_path, "needs_password": bool(self.retry_path),
            "checks": [
                {**c, "findings": [f.to_dict() for f in c["findings"]]} for c in self.checks.values()
            ],
        }


def isolated(check) -> bool:
    """Real checks that read the file go to a worker process. (Test doubles run in a thread.)"""
    return getattr(check, "NEEDS_FILE", False) and getattr(check, "__name__", "").startswith(worker.PREFIX)


class Runner:
    def __init__(self, cache, checks, trust=None):
        self.cache = cache
        self.trust = trust
        self.checks = list(checks)
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def start(self, path, name, size, sha256, save_error=None, force=False, source_path=None, password=None) -> Job:
        job = Job(name, size, sha256, self.checks, source_path=source_path, password=password)
        with self._lock:
            self.jobs[job.id] = job
            for old in list(self.jobs)[:-KEEP_JOBS]:
                del self.jobs[old]
        hashing.remember(path, sha256, name, password)
        threading.Thread(target=self._run, args=(job, Path(path), save_error, force), daemon=True).start()
        return job

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

    def _run(self, job, path, save_error, force):
        started = []
        for check in self.checks:
            t = threading.Thread(target=self._run_check, args=(job, check, path, save_error, force), daemon=True)
            t.start()
            grace = 5 if isolated(check) else 0  # the worker enforces the timeout itself; this is a backstop
            started.append((check, t, time.monotonic() + check.TIMEOUT + grace))
        for check, t, deadline in started:
            t.join(max(0.0, deadline - time.monotonic()))
            if t.is_alive():
                self._finish(job, check.ID, [_too_slow(check)])
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

    def _run_check(self, job, check, path, save_error, force):
        cached = None
        if getattr(check, "CACHE", False) and not force:
            cached = self.cache.get(job.sha256, check.ID)
        if cached:
            self._finish(job, check.ID, cached[0], cached_at=cached[1])
            return
        if save_error and getattr(check, "NEEDS_FILE", False):
            self._finish(job, check.ID, [Finding(
                check.ID, ERROR, f"{check.NAME} wasn't checked: Blotter couldn't save a copy of the file ({save_error}).")])
            return
        with self._lock:
            job.checks[check.ID]["state"] = "running"
        try:
            if isolated(check):
                findings = worker.run(check.__name__, path, job.name, job.sha256, timeout=check.TIMEOUT,
                                      sandboxed=getattr(check, "SANDBOX", True), password=job.password)
            else:
                findings = check.scan(str(path))
            findings = _validate(check, findings)
        except TimeoutError:
            findings = [_too_slow(check)]
        except Exception as e:  # a broken check must not break the others
            # A worker that dies (a parser crash, or the memory limit) didn't finish reading the file.
            signals = [UNCHECKED] if isolated(check) else []
            findings = [Finding(check.ID, ERROR, f"{check.NAME} failed unexpectedly ({type(e).__name__}).",
                                {"error": str(e)[:300]}, signals)]
        if getattr(check, "CACHE", False) and not any(f.level in (ERROR, SKIPPED) for f in findings):
            self.cache.put(job.sha256, check.ID, findings)
        self._finish(job, check.ID, findings)

    def _finish(self, job, check_id, findings, cached_at=None):
        with self._lock:
            entry = job.checks[check_id]
            if entry["state"] == "done":
                return  # already timed out; ignore the late answer
            entry.update(state="done", findings=list(findings), cached_at=cached_at)


def _delete(path) -> None:
    try:
        path.unlink(missing_ok=True)  # Blotter's own temporary copy
    except OSError:
        pass


def _too_slow(check) -> Finding:
    return Finding(check.ID, ERROR, f"{check.NAME} took longer than {check.TIMEOUT} seconds, so Blotter stopped it.",
                   {}, [UNCHECKED])


def _validate(check, findings) -> list[Finding]:
    findings = list(findings or [])
    if not findings or not all(isinstance(f, Finding) and f.level in LEVELS for f in findings):
        return [Finding(check.ID, ERROR, f"{check.NAME} gave no usable answer.")]
    return findings
