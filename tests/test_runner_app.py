import json
import tempfile
import threading
import time
import types
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from blotter import config
from blotter.cache import Cache
from blotter.findings import CLEAR, ERROR, MALICIOUS, Finding
from blotter.runner import Runner


def fake_check(id, level=CLEAR, cache=False, needs_file=False, timeout=5, delay=0.0, boom=False, ret=None):
    calls = []

    def scan(path):
        calls.append(path)
        time.sleep(delay)
        if boom:
            raise RuntimeError("broken")
        if ret is not None:
            return ret
        return [Finding(id, level, f"{id} says {level}.")]

    return types.SimpleNamespace(ID=id, NAME=id.title(), ORDER=1, TIMEOUT=timeout, CACHE=cache,
                                 NEEDS_FILE=needs_file, scan=scan, calls=calls)


def wait_done(job, seconds=10):
    end = time.time() + seconds
    while job.state != "done" and time.time() < end:
        time.sleep(0.02)
    return job


def copy_file():
    path = Path(tempfile.mkdtemp()) / "copy.blotter"
    path.write_bytes(b"data")
    return path


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.cache = Cache(Path(tempfile.mkdtemp()) / "c.sqlite3")

    def test_verdict_and_cleanup(self):
        path = copy_file()
        runner = Runner(self.cache, [fake_check("a"), fake_check("b", MALICIOUS)])
        job = wait_done(runner.start(path, "x.exe", 4, "s" * 64))
        self.assertEqual(job.verdict["verdict"], "malicious")
        self.assertFalse(path.exists(), "Blotter's temporary copy should be removed")

    def test_timeout_becomes_couldnt_check(self):
        runner = Runner(self.cache, [fake_check("slow", timeout=0.3, delay=3)])
        job = wait_done(runner.start(copy_file(), "x", 4, "s" * 64))
        self.assertEqual(job.verdict["verdict"], "couldnt_check")
        self.assertIn("took longer than", job.verdict["reasons"][0])

    def test_crash_and_empty_answers(self):
        runner = Runner(self.cache, [fake_check("boom", boom=True), fake_check("empty", ret=[]), fake_check("ok")])
        job = wait_done(runner.start(copy_file(), "x", 4, "s" * 64))
        levels = {c["id"]: c["findings"][0].level for c in job.checks.values()}
        self.assertEqual(levels, {"boom": ERROR, "empty": ERROR, "ok": CLEAR})
        self.assertEqual(job.verdict["verdict"], "no_known_detections")

    def test_rescan_uses_cache_and_costs_nothing(self):
        online = fake_check("online", cache=True)
        local = fake_check("local")
        runner = Runner(self.cache, [online, local])
        wait_done(runner.start(copy_file(), "x", 4, "h" * 64))
        job = wait_done(runner.start(copy_file(), "x", 4, "h" * 64))
        self.assertEqual(len(online.calls), 1, "second scan must come from the cache")
        self.assertEqual(len(local.calls), 2, "local checks always run again")
        self.assertIsNotNone(job.checks["online"]["cached_at"])
        wait_done(runner.start(copy_file(), "x", 4, "h" * 64, force=True))
        self.assertEqual(len(online.calls), 2, "'check again' skips the cache")

    def test_errors_are_not_cached(self):
        online = fake_check("online", level=ERROR, cache=True)
        runner = Runner(self.cache, [online])
        for _ in range(2):
            wait_done(runner.start(copy_file(), "x", 4, "e" * 64))
        self.assertEqual(len(online.calls), 2)

    def test_save_error_skips_file_checks(self):
        file_check = fake_check("file", needs_file=True)
        hash_check = fake_check("hash")
        runner = Runner(self.cache, [file_check, hash_check])
        job = wait_done(runner.start(copy_file(), "x", 4, "s" * 64, save_error="disk full"))
        self.assertEqual(file_check.calls, [])
        self.assertEqual(len(hash_check.calls), 1)
        self.assertIn("couldn't save", job.checks["file"]["findings"][0].text)


class AppTests(unittest.TestCase):
    """Starts the real web server on a test port with fake checks."""

    @classmethod
    def setUpClass(cls):
        import uvicorn

        from blotter.app import create_app

        cls.local = fake_check("local", needs_file=True)
        app = create_app(checks=[cls.local], cache=Cache(Path(tempfile.mkdtemp()) / "c.sqlite3"))
        cls.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=config.PORT, log_level="error"))
        threading.Thread(target=cls.server.run, daemon=True).start()
        for _ in range(100):
            if cls.server.started:
                break
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True

    def request(self, path, data=None, method=None, headers=None):
        req = urllib.request.Request(config.URL + path, data=data, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def test_page_and_ping(self):
        with urllib.request.urlopen(config.URL + "/", timeout=5) as r:
            self.assertIn(b"Drop a file here", r.read())
        self.assertEqual(self.request("/api/ping")[1]["app"], "blotter")

    def test_scan_round_trip(self):
        status, job = self.request("/api/scan", b"hello", "POST",
                                   {"X-Blotter": "1", "X-File-Name": "setup%20file.exe"})
        self.assertEqual(status, 200)
        self.assertEqual(job["name"], "setup file.exe")
        self.assertEqual(job["sha256"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        for _ in range(100):
            status, job = self.request(f"/api/jobs/{job['id']}")
            if job["state"] == "done":
                break
            time.sleep(0.05)
        self.assertEqual(job["verdict"]["title"], "No known detections")
        scanned = Path(self.local.calls[-1])
        self.assertEqual(scanned.suffix, ".blotter")
        self.assertFalse(scanned.exists())

    def test_refuses_other_websites(self):
        status, _ = self.request("/api/scan", b"x", "POST", {"Origin": "https://evil.example", "X-Blotter": "1"})
        self.assertEqual(status, 403)
        status, _ = self.request("/api/scan", b"x", "POST")  # no X-Blotter header
        self.assertEqual(status, 403)
        status, _ = self.request("/api/status", headers={"Host": "evil.example"})
        self.assertEqual(status, 403)

    def test_keys_are_never_sent_back(self):
        store = {}
        with mock.patch("keyring.set_password", lambda s, n, v: store.__setitem__(n, v)), \
             mock.patch("keyring.get_password", lambda s, n: store.get(n)), \
             mock.patch("blotter.keys.backend_ok", return_value=True):
            status, body = self.request("/api/keys", json.dumps({"service": "virustotal", "key": "abc123"}).encode(),
                                        "POST", {"X-Blotter": "1", "Content-Type": "application/json"})
            self.assertEqual(status, 200)
            self.assertEqual(body, {"keys": {"virustotal": True, "malwarebazaar": False}})
            status, body = self.request("/api/status")
            self.assertNotIn("abc123", json.dumps(body))
            status, body = self.request("/api/keys", json.dumps({"service": "virustotal", "key": "has space"}).encode(),
                                        "POST", {"X-Blotter": "1", "Content-Type": "application/json"})
            self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
