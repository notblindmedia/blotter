"""Round 2's N6: two Blotters on one PC (the app and a test runner, or two runners) share one ClamAV. One letting go,
going idle, closing or crashing must not stop it for the other; it ends with the last one. Two real processes
(tests/clamav_holder.py), each with Blotter's own clamav.Service, and a fake clamd that only answers PING."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
