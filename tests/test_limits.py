"""Anything over a size, depth or time limit gets "Couldn't fully check", never "No known detections"."""

import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from blotter import config, hashing
from blotter.cache import Cache
from blotter.checks import capabilities, clamav as clamav_check, macros, pdf, scripts
from blotter.findings import CLEAR, UNCHECKED, Finding
from blotter.runner import Runner
from blotter.verdict import decide
from tests import samples
from tests.test_catches import full_scan
from tests.test_runner_app import fake_check, wait_done

RAN = Finding("filetype", CLEAR, "It is a Windows program (EXE).")


def write(data: bytes) -> Path:
    path = Path(tempfile.mkdtemp()) / "a.blotter"
    path.write_bytes(data)
    return path


def fully(findings):
    v = decide([RAN, *findings])
    return v["verdict"], v["title"]


class LimitTests(unittest.TestCase):
    def assert_not_fully_checked(self, findings):
        self.assertTrue(any(UNCHECKED in f.signals for f in findings), [f.text for f in findings])
        self.assertEqual(fully(findings), ("couldnt_fully_check", "Couldn't fully check"))

    def test_capa_size_and_time(self):
        exe = write(samples.minimal_pe() + bytes(2000))
        with mock.patch.object(capabilities, "MAX_SIZE", 1000), \
             mock.patch.object(config, "CAPA_RULES", Path(tempfile.mkdtemp())):
            self.assert_not_fully_checked(capabilities.scan(exe))
        with mock.patch.object(config, "CAPA_RULES", Path(tempfile.mkdtemp())), \
             mock.patch("blotter.procs.run", return_value=(None, b"", b"")):
            self.assert_not_fully_checked(capabilities.scan(exe))

    def test_documents_pdfs_and_scripts_over_their_read_limit(self):
        with mock.patch.object(macros, "MAX_SIZE", 100):
            self.assert_not_fully_checked(macros.scan(write(samples.docm())))
        with mock.patch.object(pdf, "MAX_READ", 20):
            self.assert_not_fully_checked(pdf.scan(write(b"%PDF-1.7\n" + b" " * 100)))
        path = write(b"Write-Host hi\r\n" + b"# padding\r\n" * 50)
        hashing.remember(path, "0" * 64, "big.ps1")
        try:
            with mock.patch.object(scripts.scripts, "MAX_TEXT", 30):
                self.assert_not_fully_checked(scripts.scan(path))
        finally:
            hashing.forget(path)

    def test_pdf_object_streams_over_budget(self):
        import zlib
        inner = zlib.compress(bytes(5000))
        data = b"%PDF-1.7\n1 0 obj\n<< /Type /ObjStm /Filter /FlateDecode >>\nstream\n" + inner + b"\nendstream\n"
        with mock.patch.object(pdf, "MAX_UNPACKED", 100):
            self.assert_not_fully_checked(pdf.analyze("pdf", data))

    def test_yara_timeout(self):
        import yara
        from blotter.analyze import yararules
        rules = mock.Mock(match=mock.Mock(side_effect=yara.TimeoutError("slow")))
        self.assert_not_fully_checked(yararules.scan_target(rules, "yara", data=b"x"))

    def test_clamav_size_limit(self):
        self.assert_not_fully_checked(clamav_check.interpret("stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND"))

    def test_runner_timeout_and_worker_failure(self):
        slow = fake_check("slow", timeout=0.3, delay=3)
        runner = Runner(Cache(Path(tempfile.mkdtemp()) / "c.sqlite3"), [fake_check("ok"), slow])
        job = wait_done(runner.start(write(b"x"), "x", 1, "0" * 64))
        self.assertEqual(job.verdict["verdict"], "couldnt_fully_check", job.verdict)
        broken = types.ModuleType("blotter.checks._probe")
        broken.__name__ = "blotter.checks._probe"
        broken.ID, broken.NAME, broken.TIMEOUT, broken.NEEDS_FILE, broken.CACHE = "probe", "Probe", 60, True, False
        runner = Runner(Cache(Path(tempfile.mkdtemp()) / "c.sqlite3"), [fake_check("ok"), broken])
        job = wait_done(runner.start(write(b"crash"), "x", 5, "0" * 64), seconds=60)
        self.assertEqual(job.verdict["verdict"], "couldnt_fully_check", "a crashed parser didn't finish reading")

    def test_nothing_ran_stays_couldnt_check(self):
        self.assertEqual(decide([Finding("x", "error", "timed out", {}, [UNCHECKED])])["verdict"], "couldnt_check")

    def test_trust_doesnt_hide_an_unfinished_check(self):
        v = decide([RAN, Finding("capa", "note", "too big", {}, [UNCHECKED])], trusted=True)
        self.assertEqual(v["verdict"], "couldnt_fully_check")

    def test_big_unsigned_program_is_not_fully_checked(self):
        """A program whose real code is over capa's 25 MB limit (no padding, no signature): never 'No known
        detections'. (Padding is handled separately: tests/test_trusted_files.py.)"""
        job = full_scan(samples.pe_with_section(30 * 1024 * 1024), "bigtool.exe")
        self.assertEqual(job.verdict["verdict"], "couldnt_fully_check", job.verdict)
        self.assertEqual(job.verdict["title"], "Couldn't fully check")
        self.assertTrue(any("over 25 MB" in r for r in job.verdict["reasons"]), job.verdict["reasons"])


if __name__ == "__main__":
    unittest.main()
