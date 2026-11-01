"""The harmless test files must be caught. Defender is stubbed (real Defender tests are run by hand).

EICAR and the obfuscated script stay in memory: written to disk, they could set off Defender
during a test run. The renamed program and the Word document go through the full runner.
"""

import re
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from blotter.analyze import filetype as ft
from blotter.analyze import yararules
from blotter.cache import Cache
from blotter.checks import clamav as clamav_check
from blotter.checks import filetype as filetype_check
from blotter.checks import load_checks
from blotter.checks import scripts as scripts_check
from blotter.findings import CLEAR, Finding
from blotter.runner import Runner
from blotter.verdict import decide
from tests import samples
from tests.test_runner_app import wait_done

STUB_DEFENDER = types.SimpleNamespace(ID="defender", NAME="Microsoft Defender (stub)", ORDER=30, TIMEOUT=5,
                                      CACHE=False, NEEDS_FILE=False,
                                      scan=lambda p: [Finding("defender", CLEAR, "Defender stub: not run in tests.")])


def full_scan(data: bytes, name: str):
    checks = [STUB_DEFENDER if c.ID == "defender" else c for c in load_checks()]
    path = Path(tempfile.mkdtemp()) / "copy.blotter"
    path.write_bytes(data)
    runner = Runner(Cache(Path(tempfile.mkdtemp()) / "c.sqlite3"), checks)
    with mock.patch("requests.request", return_value=mock.Mock(status_code=404)):  # no network in tests
        job = wait_done(runner.start(path, name, len(data), "0" * 64), seconds=400)
    return job


class CatchTests(unittest.TestCase):
    def test_eicar_in_memory_is_malicious(self):
        rules = yararules.load()
        findings = yararules.scan_target(rules, "yara", data=samples.eicar())
        findings += clamav_check.interpret("stream: Eicar-Signature FOUND")  # what ClamAV answers for it
        self.assertEqual(decide(findings)["verdict"], "malicious")

    def test_page_button_builds_the_same_eicar(self):
        js = (Path(__file__).parent.parent / "blotter" / "static" / "app.js").read_text(encoding="utf-8")
        pieces = re.search(r'const text = \[(.+?)\]\.join\(""\)', js).group(1)
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', pieces)
        built = "".join(p.replace("\\\\", "\\") for p in parts)  # JavaScript's \\ is one backslash
        self.assertEqual(built.encode(), samples.eicar())

    def test_renamed_program_is_suspicious(self):
        exe = (Path(sys.base_prefix) / "python.exe").read_bytes()  # a real, harmless, signed program
        job = full_scan(exe, "holiday-photo.jpg")
        self.assertEqual(job.verdict["verdict"], "suspicious", job.verdict)
        self.assertTrue(any("really a Windows program" in r for r in job.verdict["reasons"]))

    def test_docm_with_auto_run_macro_is_caught(self):
        job = full_scan(samples.docm(), "quarterly-report.docm")
        self.assertIn(job.verdict["verdict"], ("unusual", "suspicious"), job.verdict)
        self.assertTrue(any("runs by itself" in r for r in job.verdict["reasons"]))

    def test_obfuscated_ps1_in_memory_is_suspicious(self):
        text = ft.FileType("text", "a text file", "text", {})
        findings = filetype_check.judge(text, "hello.ps1") + scripts_check.judge(text, "hello.ps1", samples.obfuscated_ps1())
        verdict = decide(findings)
        self.assertEqual(verdict["verdict"], "suspicious", verdict)

    def test_harmless_files_stay_quiet(self):
        job = full_scan(b"Just a shopping list.\r\nMilk\r\nBread\r\n", "list.txt")
        self.assertEqual(job.verdict["verdict"], "no_known_detections", job.verdict)


if __name__ == "__main__":
    unittest.main()
