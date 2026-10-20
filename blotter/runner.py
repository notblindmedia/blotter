"""Runs every check on one file, each in its own thread with its own timeout."""

import threading
import time
import uuid
from pathlib import Path

from . import hashing
from .findings import ERROR, LEVELS, Finding
from .verdict import decide

KEEP_JOBS = 100


class Job:
    def __init__(self, name, size, sha256, checks):
        self.id = uuid.uuid4().hex
        self.name, self.size, self.sha256 = name, size, sha256
        self.created = time.time()
        self.state = "running"
        self.verdict = None
        self.checks = {
            m.ID: {"id": m.ID, "name": m.NAME, "state": "waiting", "findings": [], "cached_at": None}
            for m in checks
        }

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "size": self.size, "sha256": self.sha256,
            "state": self.state, "verdict": self.verdict,
            "checks": [
                {**c, "findings": [f.to_dict() for f in c["findings"]]} for c in self.checks.values()
            ],
        }


class Runner:
    def __init__(self, cache, checks):
        self.cache = cache
        self.checks = list(checks)
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def start(self, path, name, size, sha256, save_error=None, force=False) -> Job:
        job = Job(name, size, sha256, self.checks)
        with self._lock:
            self.jobs[job.id] = job
            for old in list(self.jobs)[:-KEEP_JOBS]:
                del self.jobs[old]
        hashing.remember(path, sha256)
        threading.Thread(target=self._run, args=(job, Path(path), save_error, force), daemon=True).start()
        return job

    def get(self, job_id) -> Job | None:
        with self._lock:
            return self.jobs.get(job_id)

    def _run(self, job, path, save_error, force):
        started = []
        for check in self.checks:
            t = threading.Thread(target=self._run_check, args=(job, check, path, save_error, force), daemon=True)
            t.start()
            started.append((check, t, time.monotonic() + check.TIMEOUT))
        for check, t, deadline in started:
            t.join(max(0.0, deadline - time.monotonic()))
            if t.is_alive():
                self._finish(job, check.ID, [Finding(
                    check.ID, ERROR, f"{check.NAME} took longer than {check.TIMEOUT} seconds, so Blotter stopped waiting.")])
        with self._lock:
            findings = [f for c in job.checks.values() for f in c["findings"]]
            job.verdict = decide(findings)
            job.state = "done"
        hashing.forget(path)
        try:
            path.unlink(missing_ok=True)  # Blotter's own temporary copy
        except OSError:
            pass

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
            findings = _validate(check, check.scan(str(path)))
        except Exception as e:  # a broken check must not break the others
            findings = [Finding(check.ID, ERROR, f"{check.NAME} failed unexpectedly ({type(e).__name__}).")]
        if getattr(check, "CACHE", False) and not any(f.level == ERROR for f in findings):
            self.cache.put(job.sha256, check.ID, findings)
        self._finish(job, check.ID, findings)

    def _finish(self, job, check_id, findings, cached_at=None):
        with self._lock:
            entry = job.checks[check_id]
            if entry["state"] == "done":
                return  # already timed out; ignore the late answer
            entry.update(state="done", findings=list(findings), cached_at=cached_at)


def _validate(check, findings) -> list[Finding]:
    findings = list(findings or [])
    if not findings or not all(isinstance(f, Finding) and f.level in LEVELS for f in findings):
        return [Finding(check.ID, ERROR, f"{check.NAME} gave no usable answer.")]
    return findings
