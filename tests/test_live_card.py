"""The live card's path, end to end: upload over HTTP -> runner -> sandboxed worker -> JSON -> verdict ->
/api/jobs -> the reasons the page shows. And the page always matches the code that is running."""

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

from blotter import config, vault
from blotter.analyze import yararules
from blotter.cache import Cache
from blotter.trust import TrustList
from tests.test_detections import FORGE_EICAR

TOKEN = "live-card-test-token"
PORT = config.PORT + 10


def probe_check():
    """blotter.checks._probe as a real worker check (sandboxed, results come back as JSON)."""
    probe = types.ModuleType("blotter.checks._probe")
    probe.__name__ = "blotter.checks._probe"
    probe.ID, probe.NAME, probe.ORDER, probe.TIMEOUT = "probe", "Engines", 1, 120
    probe.NEEDS_FILE, probe.CACHE = True, False
    probe.scan = lambda path: []
    return probe


class LiveCardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import uvicorn

        from blotter.app import create_app

        # A stand-in YARA Forge pack in the test folder, so the worker finds it like the real one.
        vault.write(config.YARA_FORGE, {yararules.FORGE_MEMBER: FORGE_EICAR})
        cls.url = f"http://127.0.0.1:{PORT}"
        cls.patch = mock.patch.object(config, "PORT", PORT)
        cls.patch.start()
        cls.app = create_app(checks=[probe_check()], cache=Cache(Path(tempfile.mkdtemp()) / "c.sqlite3"),
                             trust=TrustList(Path(tempfile.mkdtemp()) / "t.sqlite3"), token=TOKEN)
        cls.server = uvicorn.Server(uvicorn.Config(cls.app, host="127.0.0.1", port=PORT, log_level="error"))
        threading.Thread(target=cls.server.run, daemon=True).start()
        for _ in range(100):
            if cls.server.started:
                break
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.patch.stop()
        config.YARA_FORGE.unlink(missing_ok=True)
        config.YARA_COMPILED.unlink(missing_ok=True)

    def call(self, path, data=None, headers=None):
        request = urllib.request.Request(self.url + path, data=data, method="POST" if data is not None else "GET",
                                         headers={"X-Blotter-Token": TOKEN, **(headers or {})})
        try:
            with urllib.request.urlopen(request, timeout=30) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def card(self, content: bytes) -> dict:
        status, body = self.call("/api/scan", content, {"X-File-Name": "eicar.com"})
        self.assertEqual(status, 200, body)
        job = json.loads(body)
        for _ in range(600):
            job = json.loads(self.call(f"/api/jobs/{job['id']}")[1])
            if job["state"] == "done":
                return job
            time.sleep(0.1)
        self.fail("scan didn't finish")

    def test_eicar_is_one_line_on_the_live_card(self):
        job = self.card(b"eicar-engines")
        reasons = job["verdict"]["reasons"]
        self.assertEqual(job["verdict"]["verdict"], "malicious")
        self.assertEqual(reasons[0], "Recognised as EICAR test file by Defender, ClamAV, YARA and Blotter.")
        self.assertEqual(sum("EICAR" in r for r in reasons), 1, reasons)
        details = [f for c in job["checks"] for f in c["findings"]]
        self.assertGreaterEqual(sum(f["level"] == "malicious" for f in details), 4, "Details keep each engine's line")

    def test_defender_line_without_a_name_joins_the_group(self):
        job = self.card(b"eicar-engines-unnamed")
        reasons = job["verdict"]["reasons"]
        self.assertEqual(reasons[0], "Recognised as EICAR test file by Defender, ClamAV, YARA and Blotter.")
        self.assertFalse(any("removed Blotter's copy" in r for r in reasons), reasons)

    def test_page_matches_the_running_code(self):
        status, page = self.call("/static/app.js")
        self.assertEqual(status, 200)
        self.assertIn(b"vtState", page)
        self.assertEqual(json.loads(self.call("/api/status")[1])["restart_needed"], False)
        # An update lands on disk while Blotter runs: the page it serves doesn't change, and it asks for a restart.
        from blotter import app as app_module
        with mock.patch.object(app_module, "code_fingerprint", return_value="something newer"):
            time.sleep(5.2)  # status re-checks the files at most every 5 seconds
            self.assertTrue(json.loads(self.call("/api/status")[1])["restart_needed"])
            self.assertEqual(self.call("/static/app.js")[1], page)


if __name__ == "__main__":
    unittest.main()
