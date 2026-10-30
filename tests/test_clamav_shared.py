"""Round 2's N6: two Blotters on one PC (the app and a test runner, or two runners) share one ClamAV. One letting go,
going idle, closing or crashing must not stop it for the other; it ends with the last one. Two real processes
(tests/clamav_holder.py), each with Blotter's own clamav.Service, and a fake clamd that only answers PING.
Before using a running ClamAV, Blotter checks that what listens on its port is its own clamd.exe."""

import json
import os
import socket
import socketserver
import subprocess
import sys
import tempfile
import time
import threading
import unittest
from pathlib import Path
from unittest import mock

from blotter import clamav, config, settings
from blotter.checks import clamav as clamav_check
from blotter.findings import ERROR, SKIPPED, Finding
from blotter.verdict import decide
from tests.clamav_holder import _Answer

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == "win32", "named jobs are a Windows feature")
class SharedClamAVTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.env = {**os.environ, "BLOTTER_HOME": str(self.home), "BLOTTER_CLAMD_PORT": str(self.port)}
        self.blotters = []

    def tearDown(self):
        for p in self.blotters:
            p.kill()
            p.wait(10)
            p.stdin.close()
            p.stdout.close()

    def stand_in_listener(self):
        """Another program on ClamAV's port that even answers like clamd."""
        server = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), _Answer)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

    def blotter(self):
        # As a plain script: importing the tests package would give each one a home of its own
        p = subprocess.Popen([sys.executable, str(ROOT / "tests" / "clamav_holder.py")], env=self.env, text=True,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.blotters.append(p)
        return p

    def send(self, p, command):
        p.stdin.write(command + "\n")
        p.stdin.flush()

    def say(self, p, command):
        self.send(p, command)
        return p.stdout.readline().strip()

    def pong(self):
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=3) as s:
                s.sendall(b"zPING\0")
                return s.recv(16) == b"PONG\0"
        except OSError:
            return False

    def gone(self, timeout=15):
        deadline = time.monotonic() + timeout
        while self.pong() and time.monotonic() < deadline:
            time.sleep(0.1)
        return not self.pong()

    def state(self):
        return json.loads((self.home / "clamav-state.json").read_text(encoding="utf-8"))["state"]

    def starts(self):
        return (self.home / "fake-clamd-starts.txt").read_text(encoding="ascii").split()

    def test_closing_one_blotter_leaves_clamav_to_the_other(self):
        a, b = self.blotter(), self.blotter()
        self.send(a, "wake")
        self.send(b, "wake")  # both at once: only one starts clamd, the other joins it
        self.assertEqual([a.stdout.readline().strip(), b.stdout.readline().strip()], ["ready", "ready"])
        self.assertEqual(len(self.starts()), 1)
        self.assertEqual(self.say(a, "stop"), "stopped")
        time.sleep(0.5)
        self.assertTrue(self.pong())
        self.assertEqual(self.state(), "ready")  # B's checks would otherwise read "it isn't running"
        self.assertEqual(self.say(b, "stop"), "stopped")
        self.assertTrue(self.gone())
        self.assertEqual(self.state(), "stopped")

    def test_one_going_idle_doesnt_stop_it_for_the_other(self):
        a, b = self.blotter(), self.blotter()
        self.assertEqual(self.say(a, "wake"), "ready")
        self.assertEqual(self.say(b, "wake"), "ready")  # B is checking a file now
        self.assertEqual(self.say(a, "idle"), "sleeping")
        time.sleep(0.5)
        self.assertTrue(self.pong())
        self.assertEqual(self.state(), "ready")
        self.assertEqual(self.say(b, "idle"), "sleeping")
        self.assertTrue(self.gone())
        self.assertEqual(self.state(), "sleeping")
        self.assertEqual(self.say(a, "wake"), "ready")  # and it starts again with the next check
        self.assertEqual(len(self.starts()), 2)

    def test_a_crashed_blotter_neither_stops_it_nor_keeps_it_running(self):
        a, b = self.blotter(), self.blotter()
        self.assertEqual(self.say(a, "wake"), "ready")  # A started clamd
        self.assertEqual(self.say(b, "wake"), "ready")
        a.kill()  # like a crash: no goodbye
        a.wait(10)
        time.sleep(0.5)
        self.assertTrue(self.pong())
        b.kill()
        b.wait(10)
        self.assertTrue(self.gone())


    def test_another_program_on_clamavs_port_is_never_used(self):
        self.stand_in_listener()
        self.env["FAKE_CLAMD_IS_OWN"] = "0"  # Blotter's own clamd.exe is in its clamav folder, as in real use
        a = self.blotter()
        self.assertEqual(self.say(a, "wake"), "failed")
        state = json.loads((self.home / "clamav-state.json").read_text(encoding="utf-8"))
        self.assertIn("ClamAV port taken by another program", state["message"])
        self.assertIn(f"python.exe on port {self.port}", state["message"])
        self.assertFalse((self.home / "fake-clamd-starts.txt").exists())  # nor started a second one on top

    def test_the_check_sends_no_file_to_another_program_and_fails_closed(self):
        self.stand_in_listener()
        path = Path(tempfile.mkdtemp()) / "sample.txt"
        path.write_bytes(b"just text")
        with mock.patch.object(config, "CLAMD_PORT", self.port),                 mock.patch.object(clamav, "installed", lambda: True),                 mock.patch.object(clamav, "read_state", lambda: {"state": "ready", "message": ""}),                 mock.patch.object(clamav, "scan_stream", side_effect=AssertionError("file sent")),                 mock.patch.object(settings, "load", lambda: {"clamav": True}):
            found = clamav_check.scan(path)
        self.assertEqual(found[0].level, ERROR)
        self.assertIn("ClamAV port taken by another program", found[0].text)
        # Defender skipped (test mode) and ClamAV unusable: no antivirus engine scanned it
        result = decide([Finding("defender", SKIPPED, "Test mode."), *found, Finding("filetype", "clear", "Text.")])
        self.assertEqual(result["verdict"], "couldnt_fully_check")


if __name__ == "__main__":
    unittest.main()
