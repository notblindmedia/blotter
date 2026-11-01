"""The deep check (capa) in the background: the card shows the other checks' answer first, says
"Deep check still running…", and is updated when capa finishes. Engine detections never wait for it,
and the false-alarm test waits for the final answer."""

import os
import sys
import tempfile
import threading
import time
import types
import unittest
import warnings
from pathlib import Path
from unittest import mock

from blotter import config
from blotter.cache import Cache
from blotter.checks import capabilities
from blotter.findings import CLEAR, MALICIOUS, NOTE, SIGNED, UNSIGNED, Finding, detected, risky
from blotter.runner import Runner
from blotter.trust import TrustList
from blotter.verdict import decide
from tests import samples
from tests.test_runner_app import copy_file, fake_check, wait_done

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import false_alarm_test  # noqa: E402


def deep_check(release, ret=None, timeout=5):
    """A stand-in capa: runs in the background and answers once `release` is set."""
    def scan(path):
        release.wait(timeout + 1)
        return ret or [Finding("deep", CLEAR, "capa found 12 ordinary abilities.")]

    return types.SimpleNamespace(ID="deep", NAME="Abilities (capa)", ORDER=55, TIMEOUT=timeout, CACHE=False,
                                 NEEDS_FILE=False, BACKGROUND=True, scan=scan)


def wait_state(job, state, seconds=10):
    end = time.time() + seconds
    while job.state != state and time.time() < end:
        time.sleep(0.02)
    return job


class DeepCheckTests(unittest.TestCase):
    def setUp(self):
        self.cache = Cache(Path(tempfile.mkdtemp()) / "c.sqlite3")

    def test_capa_is_the_background_check_with_15_minutes(self):
        self.assertTrue(capabilities.BACKGROUND)
        self.assertEqual(capabilities.TIMEOUT, 15 * 60)
        self.assertLess(capabilities.CAPA_TIMEOUT, capabilities.TIMEOUT)

    def test_a_well_known_publishers_program_gets_5_minutes(self):
        """The Doctor (after N7): 5 minutes for well-known publishers' programs, unsigned/unknown keep 15."""
        google = Finding("signature", CLEAR, "Signed.", {"trusted_publisher": "Google LLC"}, [SIGNED])
        other = Finding("signature", CLEAR, "Signed.", {"signed_by": "Some Small Company"}, [SIGNED])
        unsigned = Finding("signature", NOTE, "It isn't signed.", {}, [UNSIGNED])
        inside = Finding("archive", CLEAR, "Signed.", {"trusted_publisher": "Google LLC", "scope": "a.exe"}, [SIGNED])
        self.assertEqual(capabilities.time_limit([google]), 5 * 60)
        for findings in ([other], [unsigned], [inside], []):
            self.assertEqual(capabilities.time_limit(findings), 15 * 60)

    def test_capa_stops_itself_within_the_limit_the_worker_passes(self):
        path = copy_file()
        path.write_bytes(samples.minimal_pe())
        for limit, minutes in (("300", "5 minutes"), (None, "15 minutes")):
            env = {"BLOTTER_TIME_LIMIT": limit} if limit else {}
            with mock.patch.dict(os.environ, env), \
                    mock.patch.object(capabilities.procs, "run", return_value=(None, b"", b"")) as run, \
                    mock.patch.object(capabilities.config, "CAPA_RULES", Path(__file__).parent):
                if not limit:
                    os.environ.pop("BLOTTER_TIME_LIMIT", None)
                found = capabilities.scan(path)
            self.assertEqual(run.call_args.kwargs["timeout"], int(limit or 900) - 15)
            self.assertIn(f"within {minutes}", found[0].text)
        google = Finding("signature", CLEAR, "Signed.", {"trusted_publisher": "Google LLC"}, [SIGNED])
        self.assertEqual(decide([google, *found])["verdict"], "deep_check_unfinished")

    def test_the_runner_waits_for_the_signature_then_uses_the_shorter_limit(self):
        """Scaled down: 1 second instead of 5 minutes, 3 instead of 15. The signature check is a little slow, so
        the deep check must wait for it before picking its limit."""
        def stand_in_capa():
            never = threading.Event()
            return types.SimpleNamespace(
                ID="capa", NAME="Abilities (capa)", ORDER=55, TIMEOUT=3, CACHE=False, NEEDS_FILE=False,
                BACKGROUND=True, LIMIT_AFTER=("signature",), scan=lambda path: never.wait(10) and [],
                time_limit=lambda findings: 1 if capabilities.time_limit(findings) == capabilities.TRUSTED_TIMEOUT else 3)

        google = [Finding("signature", CLEAR, "Signed by Google LLC.", {"trusted_publisher": "Google LLC"}, [SIGNED])]
        unsigned = [Finding("signature", NOTE, "It isn't signed.", {}, [UNSIGNED])]
        for signature, verdict, most in ((google, "deep_check_unfinished", 2.5), (unsigned, "couldnt_fully_check", 5)):
            runner = Runner(self.cache, [fake_check("fast"), fake_check("signature", delay=0.4, ret=signature),
                                         stand_in_capa()])
            started = time.monotonic()
            job = wait_done(runner.start(copy_file(), "setup.exe", 4, "s" * 64), 10)
            took = time.monotonic() - started
            self.assertEqual(job.verdict["verdict"], verdict, job.verdict)
            self.assertLess(took, most)
            if signature is google:
                self.assertEqual(job.verdict["title"], "Signed by Google LLC, deep check couldn't finish")
                self.assertTrue(any("took longer than 1 seconds" in r for r in job.verdict["reasons"]))
            else:
                self.assertGreater(took, 2.9)

    def test_card_shows_first_then_updates(self):
        release = threading.Event()
        inject = [risky("deep", "inject", "It can inject code into other running programs.")]
        path = copy_file()
        runner = Runner(self.cache, [fake_check("fast"), deep_check(release, inject)])
        job = wait_state(runner.start(path, "x.exe", 4, "s" * 64), "deep_check")
        self.assertEqual(job.state, "deep_check")
        self.assertEqual(job.verdict["verdict"], "no_known_detections")
        self.assertEqual(job.verdict["still_running"], ["Abilities (capa)"])
        self.assertEqual(job.to_dict()["verdict"]["still_running"], ["Abilities (capa)"], "the page gets it too")
        self.assertTrue(path.exists(), "capa still needs Blotter's copy")
        release.set()
        wait_done(job)
        self.assertEqual(job.verdict["verdict"], "unusual")
        self.assertNotIn("still_running", job.verdict)
        self.assertFalse(path.exists(), "the copy goes once the deep check is done")

    def test_engine_detection_never_waits(self):
        release = threading.Event()
        engine = fake_check("engine", ret=[detected(Finding("engine", MALICIOUS, "ClamAV recognises it as Test.Thing."),
                                                    "ClamAV", "Test.Thing")])
        runner = Runner(self.cache, [engine, deep_check(release)])
        job = wait_state(runner.start(copy_file(), "x.exe", 4, "s" * 64), "deep_check")
        self.assertEqual(job.verdict["verdict"], "malicious")
        release.set()
        self.assertEqual(wait_done(job).verdict["verdict"], "malicious")

    def test_out_of_time_is_couldnt_fully_check(self):
        release = threading.Event()  # never set: the stand-in runs past its time
        runner = Runner(self.cache, [fake_check("fast"), deep_check(release, timeout=0.3)])
        job = wait_done(runner.start(copy_file(), "x.exe", 4, "s" * 64))
        self.assertEqual(job.verdict["verdict"], "couldnt_fully_check")
        self.assertTrue(any("took longer than" in r for r in job.verdict["reasons"]), job.verdict["reasons"])

    def test_no_deep_check_state_when_it_finishes_first(self):
        release = threading.Event()
        release.set()
        runner = Runner(self.cache, [fake_check("slow", delay=0.5), deep_check(release)])
        job = runner.start(copy_file(), "x.exe", 4, "s" * 64)
        seen = set()
        while job.state != "done":
            seen.add(job.state)
            time.sleep(0.01)
        self.assertNotIn("deep_check", seen)

    def test_trust_works_while_the_deep_check_runs(self):
        from blotter.app import create_app
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from fastapi.testclient import TestClient
        release = threading.Event()
        app = create_app(checks=[fake_check("fast"), deep_check(release)],
                         cache=self.cache, trust=TrustList(Path(tempfile.mkdtemp()) / "t.sqlite3"), token="t")
        client = TestClient(app, base_url=f"http://127.0.0.1:{config.PORT}", headers={"X-Blotter-Token": "t"})
        job = client.post("/api/scan", content=b"hello", headers={"X-File-Name": "a.exe"}).json()
        for _ in range(200):
            job = client.get(f"/api/jobs/{job['id']}").json()
            if job["state"] == "deep_check":
                break
            time.sleep(0.02)
        self.assertEqual(job["state"], "deep_check")
        answer = client.post(f"/api/jobs/{job['id']}/trust", json={"trusted": True})
        self.assertEqual(answer.status_code, 200, answer.text)
        self.assertTrue(answer.json()["trusted"])
        release.set()

    def test_false_alarm_test_waits_for_the_final_answer(self):
        release = threading.Event()
        inject = [risky("deep", "inject", "It can inject code into other running programs.")]
        runner = Runner(self.cache, [fake_check("fast"), deep_check(release, inject)])
        folder = Path(tempfile.mkdtemp())
        (folder / "a.exe").write_bytes(b"MZ test")
        threading.Timer(0.5, release.set).start()
        results = false_alarm_test.check_folder(folder, [folder / "a.exe"], runner, say=lambda _: None)
        self.assertEqual(results[0][1], "unusual", "the answer after capa, not the early one")


class Counting:
    """A stand-in capa that notes how many run at once and in which order. The first one waits for `gate`."""

    def __init__(self, timeout=5, seconds=0.05):
        self.lock, self.active, self.most, self.order = threading.Lock(), 0, 0, []
        self.gate = threading.Event()
        self.seconds = seconds
        self.check = types.SimpleNamespace(ID="deep", NAME="Abilities (capa)", ORDER=55, TIMEOUT=timeout,
                                           CACHE=False, NEEDS_FILE=False, BACKGROUND=True, scan=self.scan)

    def scan(self, path):
        with self.lock:
            self.active += 1
            self.most = max(self.most, self.active)
            first = not self.order
            self.order.append(Path(path).read_bytes())
        if first:
            self.gate.wait(10)
        time.sleep(self.seconds)
        with self.lock:
            self.active -= 1
        return [Finding("deep", CLEAR, "capa found 12 ordinary abilities.")]


def numbered_copy(n):
    path = Path(tempfile.mkdtemp()) / "copy.blotter"
    path.write_bytes(f"file {n}".encode())
    return path


class DeepQueueTests(unittest.TestCase):
    """Five files at once: their deep checks wait in line and run one at a time."""

    def setUp(self):
        self.cache = Cache(Path(tempfile.mkdtemp()) / "c.sqlite3")

    def start_five(self, runner):
        jobs, paths = [], []
        for n in range(1, 6):
            paths.append(numbered_copy(n))
            jobs.append(runner.start(paths[-1], f"file{n}.exe", 6, f"{n}" * 64))
            time.sleep(0.05)  # in this order
        return jobs, paths

    def test_five_files_one_at_a_time_in_order_with_places_in_line(self):
        deep = Counting()
        runner = Runner(self.cache, [fake_check("fast"), deep.check])
        jobs, paths = self.start_five(runner)
        for job in jobs:
            wait_state(job, "deep_check")
        self.assertEqual([j.state for j in jobs], ["deep_check"] * 5, "every card shows its answer while it waits")
        self.assertEqual([j.to_dict()["deep_queue"] for j in jobs], [None, 1, 2, 3, 4],
                         "the first runs; the others know their place (the 5th is 4th in line)")
        self.assertEqual(jobs[0].checks["deep"]["state"], "running")
        self.assertEqual({j.checks["deep"]["state"] for j in jobs[1:]}, {"queued"})
        deep.gate.set()
        for job in jobs:
            wait_done(job)
        self.assertEqual(deep.most, 1, "never two deep checks at once")
        self.assertEqual(deep.order, [f"file {n}".encode() for n in range(1, 6)], "oldest first")
        self.assertEqual([j.verdict["verdict"] for j in jobs], ["no_known_detections"] * 5)
        self.assertTrue(all(j.to_dict()["deep_queue"] is None for j in jobs))
        self.assertFalse(any(p.exists() for p in paths), "every copy is deleted")

    def test_time_limit_starts_when_its_turn_comes(self):
        deep = Counting(timeout=1, seconds=0.6)  # each takes 0.6 s of its 1 s; the 5th waits 2.4 s first
        deep.gate.set()
        runner = Runner(self.cache, [fake_check("fast"), deep.check])
        jobs, _ = self.start_five(runner)
        for job in jobs:
            wait_done(job, 15)
        self.assertEqual([j.verdict["verdict"] for j in jobs], ["no_known_detections"] * 5,
                         [j.verdict["reasons"] for j in jobs])

    def test_closing_cancels_the_queue_cleanly(self):
        deep = Counting()  # the first never gets past the gate
        runner = Runner(self.cache, [fake_check("fast"), deep.check])
        jobs, paths = self.start_five(runner)
        for job in jobs:
            wait_state(job, "deep_check")
        started = time.monotonic()
        runner.close(wait=5)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual([j.state for j in jobs], ["done"] * 5)
        for job in jobs:
            self.assertEqual(job.verdict["verdict"], "couldnt_fully_check")
            self.assertIn("Abilities (capa) was stopped because Blotter was closed.", job.verdict["reasons"])
        self.assertEqual(len(deep.order), 1, "the four waiting deep checks never started")
        self.assertFalse(any(p.exists() for p in paths), "every copy is deleted")
        late = wait_done(runner.start(numbered_copy(6), "late.exe", 6, "6" * 64))
        self.assertEqual(late.verdict["verdict"], "couldnt_fully_check", "nothing new joins a closed queue")
        deep.gate.set()

    def test_remembered_answers_skip_the_line(self):
        deep = Counting()
        deep.check.CACHE = True
        self.cache.put("7" * 64, "deep", [Finding("deep", CLEAR, "capa found 3 ordinary abilities.")])
        runner = Runner(self.cache, [fake_check("fast"), deep.check])
        busy = runner.start(numbered_copy(1), "busy.exe", 6, "1" * 64)
        wait_state(busy, "deep_check")
        known = wait_done(runner.start(numbered_copy(7), "known.exe", 6, "7" * 64), 3)
        self.assertEqual(known.state, "done", "a remembered capa answer doesn't wait behind busy.exe")
        deep.gate.set()
        wait_done(busy)


class ClosingBlotterTests(unittest.TestCase):
    """Closing Blotter's window (or Ctrl+C) runs one clean stop: the deep-check queue first, then ClamAV."""

    def test_stop_runs_once_and_closes_the_queue(self):
        from unittest import mock

        from blotter import __main__ as main
        calls = []
        app = types.SimpleNamespace(state=types.SimpleNamespace(
            runner=types.SimpleNamespace(close=lambda wait: calls.append(("queue", wait)))))
        with mock.patch("blotter.clamav.service.stop", lambda why: calls.append(("clamav", why))):
            stop = main._stopper(app)
            stop()
            stop()  # the window's X and the finally block both call it
        self.assertEqual(calls, [("queue", 3), ("clamav", "stopped")])

    def test_what_a_killed_blotter_left_behind_goes_at_the_next_start(self):
        # Windows kills Blotter if closing takes longer than 5 s: the next start removes the rest.
        from blotter.app import clean_incoming
        config.INCOMING.mkdir(parents=True, exist_ok=True)
        (config.INCOMING / "abc.blotter").write_bytes(b"copy")
        for name in ("work-abc", "unpack-abc"):
            (config.INCOMING / name).mkdir()
            (config.INCOMING / name / "request.json").write_text("{}")
        clean_incoming()
        self.assertEqual(list(config.INCOMING.iterdir()), [])

    @unittest.skipUnless(sys.platform == "win32", "Windows console events")
    def test_closing_the_window_calls_stop_but_ctrl_c_is_left_to_python(self):
        from blotter import __main__ as main
        events = []
        main._on_close(lambda: events.append("stop"))
        try:
            self.assertFalse(main._on_close.handler(0))  # Ctrl+C: Python's own handling (KeyboardInterrupt)
            self.assertEqual(events, [])
            for event in (2, 5, 6):  # the window's X, logging off, shutting down
                self.assertFalse(main._on_close.handler(event), "Windows still closes Blotter afterwards")
            self.assertEqual(events, ["stop"] * 3)
        finally:
            import ctypes
            ctypes.windll.kernel32.SetConsoleCtrlHandler(main._on_close.handler, False)


class DeepProcessTests(unittest.TestCase):
    """The real worker process: below-normal priority (and so is what it starts), and killed on close."""

    def probe(self):
        probe = types.ModuleType("blotter.checks._probe")
        probe.__name__ = "blotter.checks._probe"
        probe.ID, probe.NAME, probe.ORDER, probe.TIMEOUT = "probe", "Abilities (capa)", 55, 120
        probe.NEEDS_FILE, probe.CACHE, probe.BACKGROUND = True, False, True
        probe.scan = lambda path: []
        return probe

    def job(self, runner, content: bytes):
        config.INCOMING.mkdir(parents=True, exist_ok=True)
        path = config.INCOMING / f"{content.decode()}-{time.monotonic_ns()}.blotter"
        path.write_bytes(content)
        return runner.start(path, "x.exe", len(content), "a" * 64), path

    def test_deep_check_and_its_children_run_below_normal(self):
        from blotter import procs
        runner = Runner(Cache(Path(tempfile.mkdtemp()) / "c.sqlite3"), [self.probe()])
        job, _ = self.job(runner, b"priority")
        wait_done(job, 60)
        texts = [f.text for f in job.checks["probe"]["findings"]]
        self.assertEqual(texts, [f"priority: {procs.BELOW_NORMAL} {procs.BELOW_NORMAL}"])

    def test_fast_checks_keep_normal_priority(self):
        probe = self.probe()
        probe.BACKGROUND = False
        runner = Runner(Cache(Path(tempfile.mkdtemp()) / "c.sqlite3"), [probe])
        job, _ = self.job(runner, b"priority")
        wait_done(job, 60)
        self.assertEqual([f.text for f in job.checks["probe"]["findings"]], ["priority: 32 32"])  # NORMAL

    def test_closing_kills_the_running_worker(self):
        runner = Runner(Cache(Path(tempfile.mkdtemp()) / "c.sqlite3"), [self.probe()])
        job, path = self.job(runner, b"sleep")  # the probe would sleep 120 s
        wait_state(job, "deep_check", 30)
        for _ in range(200):
            if job.checks["probe"]["state"] == "running" and list(config.INCOMING.glob("work-*")):
                break
            time.sleep(0.05)
        started = time.monotonic()
        runner.close(wait=10)
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(job.state, "done")
        self.assertIn("Abilities (capa) was stopped because Blotter was closed.", job.verdict["reasons"])
        self.assertFalse(path.exists(), "the copy is deleted")
        self.assertEqual(list(config.INCOMING.glob("work-*")), [], "the worker's folder is cleaned up")


if __name__ == "__main__":
    unittest.main()
