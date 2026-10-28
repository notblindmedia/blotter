import http.client
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
from blotter.findings import CLEAR, ERROR, MALICIOUS, Finding, detected, risky
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


TOKEN = "per-start-test-token"


class AppTests(unittest.TestCase):
    """Starts the real web server on a test port with fake checks."""

    @classmethod
    def setUpClass(cls):
        import uvicorn

        from blotter.app import create_app
        from blotter.trust import TrustList

        cls.local = fake_check("local", needs_file=True)
        cls.risky = fake_check("risky", ret=[risky("risky", "inject", "It can inject code.")])

        def engine_scan(path):  # a stand-in antivirus: "detects" one test content
            if Path(path).read_bytes().startswith(b"BLOTTER-DETECT-ME"):
                return [detected(Finding("engine", MALICIOUS, "The engine recognises it as Test.Thing."),
                                 "ClamAV", "Test.Thing")]
            return [Finding("engine", CLEAR, "The engine found nothing.")]

        cls.engine = types.SimpleNamespace(ID="engine", NAME="Engine", ORDER=1, TIMEOUT=5, CACHE=False,
                                           NEEDS_FILE=False, scan=engine_scan)
        app = create_app(checks=[cls.local, cls.risky, cls.engine],
                         cache=Cache(Path(tempfile.mkdtemp()) / "c.sqlite3"),
                         trust=TrustList(Path(tempfile.mkdtemp()) / "t.sqlite3"), token=TOKEN)
        cls.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=config.PORT, log_level="error"))
        threading.Thread(target=cls.server.run, daemon=True).start()
        for _ in range(100):
            if cls.server.started:
                break
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True

    def request(self, path, data=None, method=None, headers=None, token=True):
        headers = dict(headers or {})
        if token:
            headers.setdefault("X-Blotter-Token", TOKEN)
        req = urllib.request.Request(config.URL + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def test_page_and_ping(self):
        req = urllib.request.Request(config.URL + "/", headers={"X-Blotter-Token": TOKEN})
        with urllib.request.urlopen(req, timeout=5) as r:
            page = r.read()
        self.assertIn(b"Drop a file here", page)
        self.assertIn(f'<meta name="blotter-token" content="{TOKEN}">'.encode(), page)
        self.assertEqual(self.request("/api/ping")[1]["app"], "blotter")

    def test_scan_round_trip(self):
        status, job = self.request("/api/scan", b"hello", "POST",
                                   {"X-File-Name": "setup%20file.exe"})
        self.assertEqual(status, 200)
        self.assertEqual(job["name"], "setup file.exe")
        self.assertEqual(job["sha256"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        for _ in range(100):
            status, job = self.request(f"/api/jobs/{job['id']}")
            if job["state"] == "done":
                break
            time.sleep(0.05)
        self.assertEqual(job["verdict"]["title"], "Unusual")
        self.assertIsNone(job["source_path"], "an upload is only a copy")
        scanned = Path(self.local.calls[-1])
        self.assertEqual(scanned.suffix, ".blotter")
        self.assertFalse(scanned.exists())

    def test_refuses_other_websites(self):
        status, _ = self.request("/api/scan", b"x", "POST", {"Origin": "https://evil.example", "X-Blotter": "1"})
        self.assertEqual(status, 403)
        status, _ = self.request("/api/scan", b"x", "POST", token=False)  # no token
        self.assertEqual(status, 403)
        status, _ = self.request("/api/status", headers={"Host": "evil.example"})
        self.assertEqual(status, 403)

    def test_keys_are_never_sent_back(self):
        store = {}
        with mock.patch("keyring.set_password", lambda s, n, v: store.__setitem__(n, v)), \
             mock.patch("keyring.get_password", lambda s, n: store.get(n)), \
             mock.patch("blotter.keys.backend_ok", return_value=True):
            status, body = self.request("/api/keys", json.dumps({"service": "virustotal", "key": "abc123"}).encode(),
                                        "POST", {"Content-Type": "application/json"})
            self.assertEqual(status, 200)
            self.assertEqual(body, {"keys": {"virustotal": True, "malwarebazaar": False}})
            status, body = self.request("/api/status")
            self.assertNotIn("abc123", json.dumps(body))
            status, body = self.request("/api/keys", json.dumps({"service": "virustotal", "key": "has space"}).encode(),
                                        "POST", {"Content-Type": "application/json"})
            self.assertEqual(status, 400)

    def post(self, path, data=None):
        return self.request(path, json.dumps(data or {}).encode(), "POST",
                            {"Content-Type": "application/json"})

    def finished(self, job):
        for _ in range(200):
            status, job = self.request(f"/api/jobs/{job['id']}")
            if job["state"] == "done":
                return job
            time.sleep(0.05)
        self.fail("scan didn't finish")

    def test_status_and_settings(self):
        status, body = self.request("/api/status")
        self.assertEqual(status, 200)
        for key in ("settings", "clamav", "rules", "network", "trusted", "quarantine"):
            self.assertIn(key, body)
        self.assertIn("hashlookup.circl.lu", body["network"]["lookups"])
        status, body = self.post("/api/settings", {"setup_done": True})
        self.assertTrue(body["settings"]["setup_done"])
        status, _ = self.post("/api/settings", {"setup_done": "yes"})
        self.assertEqual(status, 400)
        status, _ = self.post("/api/settings", {"unknown": True})
        self.assertEqual(status, 400)

    def test_scan_by_path_trust_and_quarantine(self):
        folder = Path(tempfile.mkdtemp())
        original = folder / "mod-loader.dll"
        original.write_bytes(b"pretend program bytes")
        status, job = self.post("/api/scan-path", {"path": str(original)})
        self.assertEqual(status, 200)
        job = self.finished(job)
        self.assertEqual(job["source_path"], str(original))
        self.assertEqual(job["verdict"]["verdict"], "unusual")
        self.assertTrue(original.exists(), "checking never moves or changes the original")

        status, job = self.post(f"/api/jobs/{job['id']}/trust", {"trusted": True})
        self.assertEqual(job["verdict"]["verdict"], "no_known_detections")
        self.assertIn("trusted", job["verdict"]["summary"])
        status, job = self.post(f"/api/jobs/{job['id']}/trust", {"trusted": False})
        self.assertEqual(job["verdict"]["verdict"], "unusual")

        status, body = self.post(f"/api/jobs/{job['id']}/quarantine")
        self.assertEqual(status, 200, body)
        stored = Path(body["entry"]["stored"])
        self.assertFalse(original.exists())
        self.assertTrue(stored.exists())
        self.assertEqual(stored.suffix, ".blotted")
        status, body = self.post(f"/api/quarantine/{body['entry']['id']}/restore")
        self.assertEqual(status, 200)
        self.assertEqual(original.read_bytes(), b"pretend program bytes")

    def test_quarantine_refuses_changed_files_and_uploads(self):
        folder = Path(tempfile.mkdtemp())
        original = folder / "tool.exe"
        original.write_bytes(b"version 1")
        _, job = self.post("/api/scan-path", {"path": str(original)})
        job = self.finished(job)
        original.write_bytes(b"version 2")
        status, body = self.post(f"/api/jobs/{job['id']}/quarantine")
        self.assertEqual(status, 409)
        self.assertIn("changed", body["error"])
        self.assertTrue(original.exists())
        _, upload = self.request("/api/scan", b"bytes", "POST", {"X-File-Name": "a.exe"})
        upload = self.finished(upload)
        status, body = self.post(f"/api/jobs/{upload['id']}/quarantine")
        self.assertEqual(status, 400)
        self.assertIn("copy", body["error"])

    def test_scan_path_needs_a_real_file(self):
        for bad in ("relative.txt", str(Path(tempfile.mkdtemp()) / "missing.exe"), tempfile.mkdtemp()):
            status, _ = self.post("/api/scan-path", {"path": bad})
            self.assertEqual(status, 400, bad)

    # ---- every refusal of the local web server, one by one ----

    def raw(self, path, method="GET", headers=None, data=None):
        conn = http.client.HTTPConnection("127.0.0.1", config.PORT, timeout=10)
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for k, v in (headers or {}).items():
            conn.putheader(k, v)
        if data is not None:
            conn.putheader("Content-Length", str(len(data)))
        conn.endheaders(data)
        response = conn.getresponse()
        body = response.read()
        conn.close()
        return response.status, response.getheader("set-cookie") or "", response.getheader("location"), body

    def host(self):
        return {"Host": f"127.0.0.1:{config.PORT}"}

    def test_token_required_on_every_request(self):
        for path in ("/api/status", "/api/ping", "/static/app.js", "/favicon.ico", "/api/jobs/x"):
            self.assertEqual(self.raw(path, headers=self.host())[0], 403, path)
            self.assertEqual(self.raw(path, headers={**self.host(), "X-Blotter-Token": "wrong"})[0], 403, path)
        status, _, _, body = self.raw("/", headers=self.host())
        self.assertEqual(status, 403)
        self.assertIn(b"Start Blotter.bat", body)
        self.assertNotIn(TOKEN.encode(), body)

    def test_opening_with_the_token_sets_a_strict_cookie(self):
        status, cookie, location, _ = self.raw(f"/?token={TOKEN}", headers=self.host())
        self.assertEqual((status, location), (303, "/"), "the code is taken out of the address")
        self.assertIn(f"blotter_token={TOKEN}", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=strict", cookie.replace("Strict", "strict"))
        self.assertEqual(self.raw("/?token=wrong", headers=self.host())[0], 403)
        status, _, _, body = self.raw("/", headers={**self.host(), "Cookie": f"blotter_token={TOKEN}"})
        self.assertEqual(status, 200)
        self.assertIn(b"Drop a file here", body)
        self.assertEqual(self.raw("/api/status", headers={**self.host(), "Cookie": f"blotter_token={TOKEN}"})[0], 200)

    def test_changes_need_the_header_not_just_the_cookie(self):
        cookie = {**self.host(), "Cookie": f"blotter_token={TOKEN}", "Content-Type": "application/json"}
        self.assertEqual(self.raw("/api/settings", "POST", cookie, b"{}")[0], 403)
        self.assertEqual(self.raw("/api/settings", "POST", {**cookie, "X-Blotter-Token": TOKEN}, b"{}")[0], 200)

    def test_host_must_match_exactly(self):
        good = {"X-Blotter-Token": TOKEN}
        for host in ("evil.example", f"evil.example:{config.PORT}", "127.0.0.1", "localhost",
                     f"127.0.0.1:{config.PORT + 1}", f"127.0.0.1.evil.example:{config.PORT}", ""):
            self.assertEqual(self.raw("/api/status", headers={**good, "Host": host})[0], 403, host)
        for host in (f"127.0.0.1:{config.PORT}", f"localhost:{config.PORT}"):
            self.assertEqual(self.raw("/api/status", headers={**good, "Host": host})[0], 200, host)

    def test_origin_must_match_exactly(self):
        good = {**self.host(), "X-Blotter-Token": TOKEN}
        for origin in ("https://evil.example", "null", f"http://127.0.0.1:{config.PORT + 1}",
                       f"https://127.0.0.1:{config.PORT}", f"http://localhost.evil.example:{config.PORT}"):
            self.assertEqual(self.raw("/api/status", headers={**good, "Origin": origin})[0], 403, origin)
            self.assertEqual(self.raw("/api/settings", "POST", {**good, "Origin": origin}, b"{}")[0], 403, origin)
        self.assertEqual(self.raw("/api/status", headers={**good, "Origin": f"http://127.0.0.1:{config.PORT}"})[0], 200)

    def test_requests_from_other_sites_are_refused(self):
        good = {**self.host(), "X-Blotter-Token": TOKEN}
        for site in ("cross-site", "same-site"):
            self.assertEqual(self.raw("/api/status", headers={**good, "Sec-Fetch-Site": site})[0], 403, site)

    def test_malicious_files_cant_be_trusted(self):
        _, job = self.request("/api/scan", b"BLOTTER-DETECT-ME", "POST", {"X-File-Name": "bad.exe"})
        job = self.finished(job)
        self.assertEqual(job["verdict"]["verdict"], "malicious")
        status, body = self.post(f"/api/jobs/{job['id']}/trust", {"trusted": True})
        self.assertEqual(status, 409)
        self.assertIn("doesn't let you trust", body["error"])
        status, body = self.request("/api/status")
        self.assertNotIn(job["sha256"], [t["sha256"] for t in body["trusted"]])

    def test_password_endpoint(self):
        good = {**self.host(), "X-Blotter-Token": TOKEN, "Content-Type": "application/json"}
        self.assertEqual(self.raw("/api/jobs/unknown/password", "POST", good, b'{"password": "x"}')[0], 404)
        self.assertEqual(self.raw("/api/jobs/unknown/password", "POST", good, b'{"password": ""}')[0], 400)
        self.assertEqual(self.raw("/api/jobs/unknown/password", "GET", good)[0], 405)
        no_token = {k: v for k, v in good.items() if k != "X-Blotter-Token"}
        self.assertEqual(self.raw("/api/jobs/unknown/password", "POST", no_token, b'{"password": "x"}')[0], 403)

    def test_state_changes_are_post_only(self):
        good = {**self.host(), "X-Blotter-Token": TOKEN}
        for path in ("/api/scan-path", "/api/jobs/x/quarantine", "/api/jobs/x/trust", "/api/quarantine/x/restore",
                     "/api/trusted/" + "0" * 64 + "/remove", "/api/keys/virustotal/remove", "/api/settings",
                     "/api/scan", "/api/pick", "/api/updates"):
            for method in ("GET", "PUT", "DELETE"):
                self.assertEqual(self.raw(path, method, good)[0], 405, f"{method} {path}")


if __name__ == "__main__":
    unittest.main()
