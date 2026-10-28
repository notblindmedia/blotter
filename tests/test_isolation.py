"""Each check that reads the file runs in its own process, with a timeout and a memory limit."""

import socket
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from blotter import config, procs, sandbox, worker
from blotter.cache import Cache
from blotter.checks import filetype, load_checks
from blotter.findings import CLEAR, ERROR
from blotter.runner import Runner, isolated
from tests.test_runner_app import fake_check, wait_done


def probe_file(action: bytes) -> Path:
    path = Path(tempfile.mkdtemp()) / "probe.blotter"
    path.write_bytes(action)
    return path


class WorkerTests(unittest.TestCase):
    def test_real_check_runs_in_another_process(self):
        [finding] = worker.run("blotter.checks.filetype", probe_file(b"hello"), "notes.txt", "0" * 64, timeout=30)
        self.assertEqual(finding.level, CLEAR)
        self.assertIn(".txt", finding.text, "the original name reaches the worker")

    def test_hang_is_killed(self):
        start = time.monotonic()
        with self.assertRaises(TimeoutError):
            worker.run("blotter.checks._probe", probe_file(b"sleep"), "x", "0" * 64, timeout=3)
        self.assertLess(time.monotonic() - start, 15)

    def test_crash_is_reported(self):
        with self.assertRaisesRegex(RuntimeError, "broken on purpose"):
            worker.run("blotter.checks._probe", probe_file(b"crash"), "x", "0" * 64, timeout=30)

    def test_hard_exit_is_reported(self):
        with self.assertRaises(RuntimeError):
            worker.run("blotter.checks._probe", probe_file(b"exit"), "x", "0" * 64, timeout=30)

    def test_memory_limit(self):
        with mock.patch.object(config, "WORKER_MEMORY", 300 * 1024 * 1024):
            with self.assertRaises(RuntimeError):
                worker.run("blotter.checks._probe", probe_file(b"memory"), "x", "0" * 64, timeout=60)

    def test_printing_libraries_dont_confuse_it(self):
        [finding] = worker.run("blotter.checks._probe", probe_file(b"print"), "x", "0" * 64, timeout=30)
        self.assertEqual(finding.text, "The probe ran fine.")

    def test_only_blotter_checks_can_be_loaded(self):
        for name in ("os", "blotter.app", "blotter.checks.x;import os"):
            with self.assertRaisesRegex(RuntimeError, "not a Blotter check"):
                worker.run(name, probe_file(b"x"), "x", "0" * 64, timeout=30)

    def test_isolated_mode(self):
        self.assertEqual(worker.command()[1], "-I")


class SandboxTests(unittest.TestCase):
    """The sandbox (AppContainer) must stop a worker from using the network or reading any other file."""

    @classmethod
    def setUpClass(cls):
        state = sandbox.prepare()
        if state["mode"] != "appcontainer":
            raise unittest.SkipTest(f"AppContainer not available here: {state['why']}")
        cls.server = socket.socket()
        cls.server.bind(("127.0.0.1", 0))
        cls.server.listen()

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def probe(self, action: bytes, sandboxed=True) -> str:
        [finding] = worker.run("blotter.checks._probe", probe_file(action), "x", "0" * 64, timeout=60,
                               sandboxed=sandboxed)
        return finding.text

    def test_no_network_internet_or_this_pc(self):
        self.assertTrue(self.probe(b"net 1.1.1.1 443").startswith("network: blocked"))
        port = self.server.getsockname()[1]
        self.assertTrue(self.probe(f"net 127.0.0.1 {port}".encode()).startswith("network: blocked"))
        # the same probe outside the sandbox reaches the local test server: the block is the sandbox's doing
        self.assertEqual(self.probe(f"net 127.0.0.1 {port}".encode(), sandboxed=False), "network: open")

    def test_cannot_read_other_files(self):
        other = Path(tempfile.mkdtemp()) / "someone-elses-file.txt"
        other.write_text("private")
        self.assertTrue(self.probe(b"read " + str(other).encode()).startswith("read: blocked"))
        for private in (config.DB_PATH, config.SETTINGS_PATH, Path.home() / "Documents"):
            private.parent.mkdir(parents=True, exist_ok=True)
            if not private.exists():
                private.write_text("x") if private.suffix else private.mkdir(exist_ok=True)
            target = private if private.is_file() else next(iter(private.glob("*")), private)
            self.assertTrue(self.probe(b"read " + str(target).encode()).startswith("read: blocked"), target)
        self.assertEqual(self.probe(b"read " + str(other).encode(), sandboxed=False), "read: allowed")

    def test_can_read_only_its_own_file(self):
        path = probe_file(b"placeholder")
        path.write_bytes(b"read " + str(path).encode())
        [finding] = worker.run("blotter.checks._probe", path, "x", "0" * 64, timeout=60)
        self.assertEqual(finding.text, "read: allowed")

    def test_cannot_write_outside_its_work_folder(self):
        target = Path(tempfile.mkdtemp()) / "dropped.exe"
        self.assertTrue(self.probe(b"write " + str(target).encode()).startswith("write: blocked"))
        self.assertFalse(target.exists())

    def test_real_checks_still_work_inside(self):
        import zipfile
        from io import BytesIO
        data = BytesIO()
        with zipfile.ZipFile(data, "w") as z:
            z.writestr("invoice.pdf.exe", b"MZ" + bytes(200))
        path = probe_file(data.getvalue())
        found = worker.run("blotter.checks.archive", path, "a.zip", "0" * 64, timeout=120)
        self.assertTrue(any("invoice.pdf.exe" in f.text for f in found), [f.text for f in found])
        [ft] = worker.run("blotter.checks.yara_rules", path, "a.zip", "0" * 64, timeout=120)
        self.assertNotEqual(ft.level, ERROR, ft.text)


class LowIntegrityFallbackTests(unittest.TestCase):
    """If AppContainers aren't available, workers run with a low-integrity token instead."""

    def setUp(self):
        self.saved = dict(sandbox._state)

    def tearDown(self):
        sandbox._state.clear()
        sandbox._state.update(self.saved)

    def test_last_resort_job_box_still_checks_files(self):
        sandbox._state.update(mode="job-only", sid=None, why="test")
        [ran] = worker.run("blotter.checks._probe", probe_file(b"hello"), "x", "0" * 64, timeout=60)
        self.assertEqual(ran.text, "The probe ran fine.")

    def test_fallback_runs_and_cannot_write_to_normal_folders(self):
        sandbox._state.update(mode="low-integrity", sid=None, why="test")
        if not sandbox._works():
            # On the Doctor's PC the Inkwell folder refuses low-integrity readers, so Blotter skips this
            # level there; prepare() then picks the job box. Nothing more to test on such a PC.
            self.skipTest("a low-integrity worker can't read the Blotter folder on this PC")
        [ran] = worker.run("blotter.checks._probe", probe_file(b"hello"), "x", "0" * 64, timeout=60)
        self.assertEqual(ran.text, "The probe ran fine.")
        target = Path(tempfile.mkdtemp()) / "dropped.txt"
        [wrote] = worker.run("blotter.checks._probe", probe_file(b"write " + str(target).encode()), "x",
                             "0" * 64, timeout=60)
        self.assertTrue(wrote.text.startswith("write: blocked"), wrote.text)

    def test_prepare_falls_back_when_the_container_fails(self):
        sandbox._state.update(mode=None, sid=None, why="")
        with mock.patch.object(sandbox, "_container_sid", side_effect=OSError("policy says no")):
            state = sandbox.prepare()
        self.assertIn(state["mode"], ("low-integrity", "job-only"))
        self.assertIn("policy says no", state["why"])
        [ran] = worker.run("blotter.checks._probe", probe_file(b"hello"), "x", "0" * 64, timeout=60)
        self.assertEqual(ran.text, "The probe ran fine.")


class JobTests(unittest.TestCase):
    def test_children_die_with_the_job(self):
        code, _, _ = procs.run([sys.executable, "-c", "import time; time.sleep(60)"], timeout=1)
        self.assertIsNone(code)

    def test_normal_run(self):
        code, out, _ = procs.run([sys.executable, "-c", "print('hi')"], timeout=30)
        self.assertEqual((code, out.strip()), (0, b"hi"))


class RunnerIsolationTests(unittest.TestCase):
    def test_which_checks_are_isolated(self):
        by_id = {c.ID: c for c in load_checks()}
        for check_id in ("filetype", "archive", "defender", "clamav", "yara", "program", "capa", "macros", "pdf", "scripts"):
            self.assertTrue(isolated(by_id[check_id]), check_id)
        for check_id in ("virustotal", "malwarebazaar", "hashlookup"):
            self.assertFalse(isolated(by_id[check_id]), f"{check_id} only sends the hash")
        sandboxed = {c.ID for c in load_checks() if isolated(c) and getattr(c, "SANDBOX", True)}
        self.assertEqual(sandboxed, {"filetype", "archive", "yara", "program", "capa", "macros", "pdf", "scripts"},
                         "every check that parses the file runs in the sandbox")
        self.assertFalse(isolated(fake_check("x", needs_file=True)))

    def test_runner_uses_the_worker(self):
        path = Path(tempfile.mkdtemp()) / "copy.blotter"
        path.write_bytes(b"hello")
        runner = Runner(Cache(Path(tempfile.mkdtemp()) / "c.sqlite3"), [filetype])
        job = wait_done(runner.start(path, "letter.txt", 5, "0" * 64), seconds=30)
        [finding] = job.checks["filetype"]["findings"]
        self.assertIn(".txt", finding.text)

    def test_worker_timeout_becomes_couldnt_check(self):
        probe = types.ModuleType("blotter.checks._probe")
        probe.__name__ = "blotter.checks._probe"
        probe.ID, probe.NAME, probe.TIMEOUT, probe.NEEDS_FILE, probe.CACHE = "probe", "Probe", 2, True, False
        probe.scan = lambda p: []
        path = probe_file(b"sleep")
        runner = Runner(Cache(Path(tempfile.mkdtemp()) / "c.sqlite3"), [probe])
        job = wait_done(runner.start(path, "x", 5, "0" * 64), seconds=30)
        self.assertEqual(job.checks["probe"]["findings"][0].level, ERROR)
        self.assertIn("took longer", job.checks["probe"]["findings"][0].text)


if __name__ == "__main__":
    unittest.main()
