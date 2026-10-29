"""Test mode (--test-mode: no Defender check, every card says so) and the page's list of this session's files
(newest first, memory only, updated while deep checks finish)."""

import io
import json
import tempfile
import threading
import time
import unittest
import warnings
from pathlib import Path
from unittest import mock

from blotter import __main__ as main
from blotter import config
from blotter.cache import Cache
from blotter.checks import load_checks
from blotter.runner import Runner
from blotter.trust import TrustList
from tests.test_deep_check import deep_check, wait_state
from tests.test_runner_app import copy_file, fake_check, wait_done

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "blotter" / "static"


def client_for(app):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient
    return TestClient(app, base_url=f"http://127.0.0.1:{config.PORT}", headers={"X-Blotter-Token": "t"})


def make_app(checks=None, test_mode=False):
    from blotter.app import create_app
    return create_app(checks=checks, cache=Cache(Path(tempfile.mkdtemp()) / "c.sqlite3"),
                      trust=TrustList(Path(tempfile.mkdtemp()) / "t.sqlite3"), token="t", test_mode=test_mode)


def defender_stand_in():
    calls = []
    check = fake_check("defender")
    check.scan = lambda path: calls.append(path) or []
    check.calls = calls
    return check


class TestModeTests(unittest.TestCase):
    def test_test_mode_leaves_the_real_defender_check_out(self):
        self.assertIn("defender", [c.ID for c in load_checks()])
        normal = client_for(make_app()).get("/api/status").json()
        tested = client_for(make_app(test_mode=True)).get("/api/status").json()
        self.assertIn("defender", [c["id"] for c in normal["checks"]])
        self.assertNotIn("defender", [c["id"] for c in tested["checks"]])
        self.assertFalse(normal["test_mode"])
        self.assertTrue(tested["test_mode"])
        self.assertEqual(len(tested["checks"]), len(normal["checks"]) - 1)

    def test_defender_never_runs_in_test_mode(self):
        defender = defender_stand_in()
        client = client_for(make_app(checks=[fake_check("fast"), defender], test_mode=True))
        job = client.post("/api/scan", content=b"hello", headers={"X-File-Name": "a.txt"}).json()
        self.assertTrue(job["test_mode"])
        self.assertEqual([c["id"] for c in job["checks"]], ["fast"])
        for _ in range(200):
            job = client.get(f"/api/jobs/{job['id']}").json()
            if job["state"] == "done":
                break
            time.sleep(0.02)
        self.assertEqual(job["state"], "done")
        self.assertEqual(defender.calls, [])
        # Without test mode the same check does run.
        client = client_for(make_app(checks=[fake_check("fast"), defender]))
        job = client.post("/api/scan", content=b"hello", headers={"X-File-Name": "a.txt"}).json()
        self.assertFalse(job["test_mode"])
        for _ in range(200):
            if defender.calls:
                break
            time.sleep(0.02)
        self.assertEqual(len(defender.calls), 1)

    def test_ping_says_whether_blotter_is_in_test_mode(self):
        self.assertTrue(client_for(make_app(test_mode=True)).get("/api/ping").json()["test_mode"])
        self.assertFalse(client_for(make_app()).get("/api/ping").json()["test_mode"])

    def test_start_reads_test_mode_from_the_ping(self):
        for body, state in (({"app": "blotter", "test_mode": True}, "blotter-test-mode"),
                            ({"app": "blotter", "test_mode": False}, "blotter"),
                            ({"app": "blotter"}, "blotter"),  # an older Blotter: Defender on
                            ({"app": "something"}, "other")):
            with mock.patch("urllib.request.urlopen", return_value=io.BytesIO(json.dumps(body).encode())):
                self.assertEqual(main._ping(), state)

    def test_test_mode_refuses_to_use_a_blotter_with_defender_on(self):
        with mock.patch.object(main, "_ping", return_value="blotter"), \
                mock.patch("sys.argv", ["blotter", "--test-mode"]), \
                mock.patch("webbrowser.open") as opened, mock.patch("builtins.print") as said:
            self.assertEqual(main.main(), 1)
        opened.assert_not_called()
        self.assertIn("Defender on", said.call_args[0][0])

    def test_a_running_test_mode_blotter_is_reused_and_named(self):
        for argv in (["blotter", "--test-mode"], ["blotter"]):
            with mock.patch.object(main, "_ping", return_value="blotter-test-mode"), \
                    mock.patch("sys.argv", argv), \
                    mock.patch("webbrowser.open") as opened, mock.patch("builtins.print") as said:
                self.assertEqual(main.main(), 0)
            opened.assert_called_once()
            if argv == ["blotter"]:
                self.assertIn("test mode (Defender off)", said.call_args[0][0])

    def test_the_start_file_passes_the_option_on(self):
        bat = (ROOT / "Start Blotter.bat").read_text()
        self.assertIn("-m blotter %*", bat)

    def test_every_card_shows_the_test_mode_line(self):
        page = (STATIC / "index.html").read_text(encoding="utf-8")
        script = (STATIC / "app.js").read_text(encoding="utf-8")
        self.assertIn('id="card-test-mode" hidden>Test mode: Defender off.', page)
        # The card, the "Checking…" card and the "Couldn't check" card all set it.
        self.assertIn('$("card-test-mode").hidden = !(job.test_mode || testMode);', script)
        self.assertEqual(script.count('$("card-test-mode").hidden = !testMode;'), 3)
        self.assertIn("testMode = !!s.test_mode;", script)
        self.assertIn('$("eicar").hidden = testMode;', script)


class RecentResultsTests(unittest.TestCase):
    def setUp(self):
        self.cache = Cache(Path(tempfile.mkdtemp()) / "c.sqlite3")

    def test_newest_first_with_verdict_and_deep_check_state(self):
        release = threading.Event()
        runner = Runner(self.cache, [fake_check("fast"), deep_check(release)])
        try:
            jobs = [runner.start(copy_file(), f"file{i}.exe", 4, f"{i}" * 64) for i in range(3)]
            for job in jobs:
                wait_state(job, "deep_check")
            recent = runner.recent()
            self.assertEqual([r["name"] for r in recent], ["file2.exe", "file1.exe", "file0.exe"])
            self.assertEqual([r["id"] for r in recent], [j.id for j in reversed(jobs)])
            self.assertEqual({r["state"] for r in recent}, {"deep_check"})
            self.assertEqual({r["verdict"] for r in recent}, {"no_known_detections"})
            self.assertEqual({r["title"] for r in recent}, {"No known detections"})
            # file0 runs its deep check, file1 and file2 wait in line.
            self.assertEqual([r["deep_queue"] for r in recent], [2, 1, None])
            self.assertEqual(set(recent[0]), {"id", "name", "state", "created", "verdict", "title", "deep_queue"})
        finally:
            release.set()
            for job in jobs:
                wait_done(job)
        self.assertEqual({r["state"] for r in runner.recent()}, {"done"})

    def test_a_file_still_checking_has_no_verdict_yet(self):
        runner = Runner(self.cache, [fake_check("slow", delay=0.5)])
        job = runner.start(copy_file(), "slow.exe", 4, "a" * 64)
        first = runner.recent()[0]
        self.assertEqual((first["state"], first["verdict"], first["title"]), ("running", None, None))
        wait_done(job)

    def test_the_list_is_memory_only(self):
        app = make_app(checks=[fake_check("fast")])
        client = client_for(app)
        job = client.post("/api/scan", content=b"hello", headers={"X-File-Name": "a.txt"}).json()
        listed = client.get("/api/jobs").json()["jobs"]
        self.assertEqual([j["id"] for j in listed], [job["id"]])
        wait_done(app.state.runner.get(job["id"]))
        # A new start (a new app with the same cache and trust files) starts with an empty list.
        self.assertEqual(client_for(make_app(checks=[fake_check("fast")])).get("/api/jobs").json(), {"jobs": []})
        self.assertFalse(any(config.HOME.glob("*recent*")))

    def test_the_list_needs_the_blotter_code(self):
        from fastapi.testclient import TestClient
        bare = TestClient(make_app(checks=[fake_check("fast")]), base_url=f"http://127.0.0.1:{config.PORT}")
        self.assertEqual(bare.get("/api/jobs").status_code, 403)

    def test_the_page_lists_and_opens_cards(self):
        page = (STATIC / "index.html").read_text(encoding="utf-8")
        script = (STATIC / "app.js").read_text(encoding="utf-8")
        self.assertIn('<ol id="recent-list"', page)
        self.assertIn('api("/api/jobs")', script)
        # Keeps refreshing while any file is still being checked; the open card follows its own job.
        self.assertIn('if (jobs.some((j) => j.state !== "done")) recentTimer = setTimeout(refreshRecent, 1500);',
                      script)
        self.assertIn('button.addEventListener("click", () => openJob(j.id));', script)
        self.assertIn('if (job.state !== "done") poll(id);', script)
        self.assertIn("if (currentJob?.id !== id) return;", script)
        # Names from scans go in as text, never as HTML.
        self.assertNotIn("innerHTML", script)


if __name__ == "__main__":
    unittest.main()
