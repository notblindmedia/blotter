"""ClamAV (against a fake clamd), CIRCL hashlookup, and the list of internet addresses."""

import io
import re
import socket
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import requests

from blotter import clamav, config, network, settings
from blotter.checks import clamav as clamav_check
from blotter.checks import hashlookup
from blotter.findings import CLEAR, ERROR, KNOWN_GOOD, MALICIOUS, NOTE, SKIPPED, SUSPICIOUS, UNKNOWN
from tests import samples


# The program FakeClamd runs in (this Python), standing in for Blotter's own clamd.exe where the check looks at
# who listens on ClamAV's port.
PYTHON = Path(getattr(sys, "_base_executable", sys.executable))


class FakeClamd:
    """Speaks just enough of clamd's protocol: zPING, zVERSION, zINSTREAM."""

    def __init__(self, verdict=b"stream: OK"):
        self.verdict = verdict
        self.received = b""
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", config.CLAMD_PORT))
        self.server.listen()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            with conn:
                command = b""
                while not command.endswith(b"\0"):
                    command += conn.recv(1)
                if command == b"zPING\0":
                    conn.sendall(b"PONG\0")
                elif command == b"zVERSION\0":
                    conn.sendall(b"ClamAV 1.5.4/28167/Tue Oct 27 07:00:00 2026\0")
                elif command == b"zINSTREAM\0":
                    data = b""
                    while True:
                        size = struct.unpack(">I", self._exact(conn, 4))[0]
                        if not size:
                            break
                        data += self._exact(conn, size)
                    self.received = data
                    conn.sendall(self.verdict + b"\0")

    @staticmethod
    def _exact(conn, n):
        out = b""
        while len(out) < n:
            out += conn.recv(n - len(out))
        return out

    def close(self):
        self.server.close()


class ClamAVTests(unittest.TestCase):
    def test_interpret(self):
        self.assertEqual(clamav_check.interpret("stream: OK")[0].level, CLEAR)
        [f] = clamav_check.interpret("stream: Win.Trojan.Agent-123 FOUND")
        self.assertEqual(f.level, MALICIOUS)
        self.assertEqual(f.details["signature"], "Win.Trojan.Agent-123")
        self.assertEqual(clamav_check.interpret("stream: Heuristics.Phishing.Email FOUND")[0].level, SUSPICIOUS)
        self.assertIn("EICAR", clamav_check.interpret("stream: Eicar-Signature FOUND")[0].text)
        self.assertEqual(clamav_check.interpret("INSTREAM size limit exceeded. ERROR")[0].level, ERROR)

    def test_signature_date_shown(self):
        [f] = clamav_check.interpret("stream: OK", "ClamAV 1.5.4/28167/Tue Oct 27 07:00:00 2026")
        self.assertIn("signatures from Tue Oct 27", f.text)

    def test_streams_the_file_to_clamd(self):
        fake = FakeClamd(b"stream: Eicar-Signature FOUND")
        try:
            self.assertEqual(clamav.ask(b"PING"), "PONG")
            answer = clamav.scan_stream(io.BytesIO(samples.eicar()))  # in memory, never written to disk
            self.assertEqual(fake.received, samples.eicar())
            self.assertEqual(clamav_check.interpret(answer)[0].level, MALICIOUS)
        finally:
            fake.close()

    def test_off_and_not_installed(self):
        with mock.patch.object(settings, "load", return_value={"clamav": False, "setup_done": True}):
            self.assertEqual(clamav_check.scan("x")[0].level, SKIPPED)
        self.assertEqual(clamav_check.scan("x")[0].level, SKIPPED)  # test folder has no ClamAV
        self.assertIn("isn't set up", clamav_check.scan("x")[0].text)

    def test_waits_for_ready_then_scans(self):
        path = Path(tempfile.mkdtemp()) / "a.blotter"
        path.write_bytes(b"hello")
        fake = FakeClamd()
        try:
            with mock.patch.object(clamav, "installed", return_value=True), \
                 mock.patch.object(clamav, "read_state", side_effect=[{"state": "starting"}, {"state": "ready", "message": ""}]), \
                 mock.patch.object(clamav, "clamd_exe", return_value=PYTHON), \
                 mock.patch("time.sleep"):
                [f] = clamav_check.scan(path)
            self.assertEqual(f.level, CLEAR)
            self.assertEqual(fake.received, b"hello")
        finally:
            fake.close()

    def test_a_copy_removed_before_clamavs_turn_is_not_called_unreachable(self):
        """The Doctor's EICAR test on the normal Blotter: Defender's real-time protection removed the copy first, and
        the card said "Blotter couldn't reach its ClamAV scanner (No such file or directory)"."""
        gone = Path(tempfile.mkdtemp()) / "eicar.blotter"  # never written: as if already removed
        fake = FakeClamd()
        try:
            with mock.patch.object(clamav, "installed", return_value=True), \
                 mock.patch.object(clamav, "read_state", return_value={"state": "ready", "message": ""}), \
                 mock.patch.object(clamav, "clamd_exe", return_value=PYTHON):
                [f] = clamav_check.scan(gone)
            self.assertEqual(f.level, ERROR)
            self.assertIn("ClamAV couldn't read Blotter's copy of the file (No such file or directory)", f.text)
            self.assertNotIn("reach", f.text)
            self.assertEqual(fake.received, b"", "nothing was sent")
        finally:
            fake.close()

    def test_failed_service_is_reported(self):
        with mock.patch.object(clamav, "installed", return_value=True), \
             mock.patch.object(clamav, "read_state", return_value={"state": "failed", "message": "no signatures"}):
            [f] = clamav_check.scan("x")
        self.assertEqual(f.level, ERROR)
        self.assertIn("no signatures", f.text)

    def test_config_files(self):
        clamd, fresh = clamav._write_configs()
        text = clamd.read_text()
        self.assertIn(f"TCPSocket {config.CLAMD_PORT}", text)
        self.assertIn("TCPAddr 127.0.0.1", text, "clamd must only listen on this PC")
        self.assertIn("DatabaseMirror database.clamav.net", fresh.read_text())


class HashlookupTests(unittest.TestCase):
    def test_known(self):
        [f] = hashlookup.interpret({"FileName": "notepad.exe", "ProductName": "Windows", "source": "NSRL"})
        self.assertEqual((f.level, f.signals), (CLEAR, [KNOWN_GOOD]))
        self.assertIn("notepad.exe", f.text)

    def test_known_but_flagged(self):
        [f] = hashlookup.interpret({"FileName": "x.exe", "KnownMalicious": "malshare"})
        self.assertEqual((f.level, f.signals), (NOTE, []))

    def test_not_found_and_hash_only(self):
        response = mock.Mock(status_code=404)
        with mock.patch("requests.request", return_value=response) as req:
            [f] = hashlookup.scan(samples_path())
        self.assertEqual(f.level, UNKNOWN)
        url = req.call_args.args[1]
        self.assertTrue(url.startswith("https://hashlookup.circl.lu/lookup/sha256/"))
        self.assertNotIn("data", req.call_args.kwargs, "nothing but the hash is sent")

    def test_offline(self):
        with mock.patch("requests.request", side_effect=requests.ConnectionError()):
            self.assertEqual(hashlookup.scan(samples_path())[0].level, ERROR)


def samples_path():
    path = Path(tempfile.mkdtemp()) / "a.blotter"
    path.write_bytes(b"some bytes " * 200)  # over 1 KB: CIRCL isn't asked about tinier files
    return path


class NetworkTests(unittest.TestCase):
    def test_refuses_unlisted_addresses(self):
        for url in ("https://example.com/x", "http://www.virustotal.com/", "https://evil.virustotal.com.example/"):
            with self.assertRaises(network.NotAllowed):
                network.check(url)
        network.check("https://hashlookup.circl.lu/lookup/sha256/00")

    def test_redirect_to_an_unlisted_address_is_refused(self):
        hop = mock.Mock(status_code=302, headers={"location": "https://somewhere-else.example/file"})
        with mock.patch("requests.request", return_value=hop):
            with self.assertRaises(network.NotAllowed):
                network.get("https://github.com/x")

    def test_every_address_in_the_code_is_listed(self):
        root = Path(__file__).parent.parent / "blotter"
        listed = network.ALLOWED | set(network.LINKS)
        for path in list(root.rglob("*.py")) + list(root.rglob("*.js")) + list(root.rglob("*.html")):
            for host in re.findall(r"https?://([a-z0-9.\-]+)", path.read_text(encoding="utf-8"), re.I):
                if host.endswith(".invalid") or host in ("127.0.0.1", "localhost"):
                    continue
                self.assertIn(host.lower(), listed, f"{host} in {path.name} is missing from network.py")

    def test_clamav_mirror_is_listed(self):
        self.assertIn("database.clamav.net", network.DOWNLOADS)


if __name__ == "__main__":
    unittest.main()
