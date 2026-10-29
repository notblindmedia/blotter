import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import vt

from blotter.checks import defender, load_checks, malwarebazaar, virustotal
from blotter.findings import CLEAR, ERROR, MALICIOUS, SKIPPED, SUSPICIOUS, UNKNOWN, UNKNOWN_ONLINE

SHA = "a" * 64


def temp_file(data=b"just some bytes"):
    folder = Path(tempfile.mkdtemp())
    path = folder / "sample.blotter"
    path.write_bytes(data)
    return path


class RegistryTests(unittest.TestCase):
    def test_all_checks_in_order(self):
        checks = load_checks()
        self.assertEqual([c.ID for c in checks],
                         ["filetype", "archive", "virustotal", "malwarebazaar", "hashlookup", "defender", "clamav",
                          "yara", "signature", "program", "capa", "macros", "rtf", "pdf", "scripts"])
        for c in checks:
            self.assertTrue(c.TIMEOUT > 0)
            self.assertTrue(callable(c.scan))

    def test_missing_part_doesnt_stop_blotter(self):
        import importlib
        real = importlib.import_module

        def fake(name, *a):
            if name.endswith(".yara_rules"):
                raise ImportError("No module named 'yara'")
            return real(name, *a)

        with mock.patch("importlib.import_module", side_effect=fake):
            checks = {c.ID: c for c in load_checks()}
        [finding] = checks["yara_rules"].scan("x")
        self.assertEqual(finding.level, ERROR)
        self.assertIn("Run setup.bat again", finding.text)


def vt_data(stats, results=None, label=None):
    attrs = {"last_analysis_stats": stats, "last_analysis_results": results or {}, "last_analysis_date": 1760000000}
    if label:
        attrs["popular_threat_classification"] = {"suggested_threat_label": label}
    return {"data": {"attributes": attrs}}


class VirusTotalTests(unittest.TestCase):
    def test_many_engines_is_malicious(self):
        results = {"EngineA": {"category": "malicious", "result": "Trojan.X"},
                   "EngineB": {"category": "undetected", "result": None}}
        [finding] = virustotal.interpret(SHA, vt_data({"malicious": 40, "undetected": 30}, results, "trojan.x"))
        self.assertEqual(finding.level, MALICIOUS)
        self.assertIn("40 of 70 antivirus engines flag", finding.text)
        self.assertIn("trojan.x", finding.text)
        self.assertEqual(finding.details["flagged"], [{"engine": "EngineA", "category": "malicious", "result": "Trojan.X"}])

    def test_one_engine_is_suspicious(self):
        [finding] = virustotal.interpret(SHA, vt_data({"malicious": 1, "undetected": 69}))
        self.assertEqual(finding.level, SUSPICIOUS)
        self.assertIn("1 of 70 antivirus engines flags", finding.text)

    def test_suspicious_only(self):
        [finding] = virustotal.interpret(SHA, vt_data({"suspicious": 2, "undetected": 68}))
        self.assertEqual(finding.level, SUSPICIOUS)

    def test_nothing_flagged(self):
        [finding] = virustotal.interpret(SHA, vt_data({"undetected": 60, "harmless": 0, "type-unsupported": 10}))
        self.assertEqual(finding.level, CLEAR)
        self.assertIn("none of the 60 antivirus engines", finding.text)

    def test_no_results_yet(self):
        [finding] = virustotal.interpret(SHA, vt_data({}))
        self.assertEqual(finding.level, UNKNOWN)

    def test_no_key(self):
        with mock.patch("blotter.keys.get", return_value=None):
            [finding] = virustotal.scan(temp_file())
        self.assertEqual(finding.level, SKIPPED, "keys are optional: no key is not an error")
        self.assertIn("no API key", finding.text)

    def test_not_found(self):
        with mock.patch("blotter.keys.get", return_value="k"), \
             mock.patch.object(virustotal, "_lookup", mock.AsyncMock(return_value=None)):
            [finding] = virustotal.scan(temp_file())
        self.assertEqual(finding.level, UNKNOWN)
        self.assertIn("no record", finding.text)
        self.assertEqual(finding.signals, [UNKNOWN_ONLINE])

    def test_bad_key(self):
        error = vt.APIError("WrongCredentialsError", "bad key")
        with mock.patch("blotter.keys.get", return_value="k"), \
             mock.patch.object(virustotal, "_lookup", mock.AsyncMock(side_effect=error)):
            [finding] = virustotal.scan(temp_file())
        self.assertEqual(finding.level, ERROR)
        self.assertIn("rejected the API key", finding.text)

    def test_hash_is_what_gets_looked_up(self):
        path = temp_file(b"")
        lookup = mock.AsyncMock(return_value=None)
        with mock.patch("blotter.keys.get", return_value="k"), mock.patch.object(virustotal, "_lookup", lookup):
            virustotal.scan(path)
        self.assertEqual(lookup.call_args.args[1], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


class NoKeyIsNotCheckedTests(unittest.TestCase):
    """Without a key VirusTotal is 'not checked', never 'never seen': friends without keys get no extra warnings."""

    def vt_answers(self):
        path = temp_file(b"the same file both times")
        with mock.patch("blotter.keys.get", return_value=None):
            no_key = virustotal.scan(path)
        with mock.patch("blotter.keys.get", return_value="k"), \
             mock.patch.object(virustotal.limiter, "acquire", return_value=True), \
             mock.patch.object(virustotal, "_lookup", mock.AsyncMock(return_value=None)):
            not_found = virustotal.scan(path)
        return no_key, not_found

    def test_no_key_carries_no_signal(self):
        no_key, not_found = self.vt_answers()
        self.assertEqual(no_key[0].signals, [])
        self.assertEqual(no_key[0].details["not_checked"], "no_key")
        self.assertEqual(not_found[0].signals, [UNKNOWN_ONLINE])

    def test_same_verdict_as_not_found_minus_that_sign(self):
        from blotter.findings import (HIDING, LYING_NAME, NOTE, PACKED, UNSIGNED, Finding as F, risky, weak)
        from blotter.verdict import decide

        no_key, not_found = self.vt_answers()
        without_sign = [F(f.check, f.level, f.text, f.details, [s for s in f.signals if s != UNKNOWN_ONLINE])
                        for f in not_found]
        ran = F("filetype", CLEAR, "It is a Windows program (EXE).")
        situations = {
            "plain file": [],
            "risky ability": [risky("capa", "inject", "It can inject code.")],
            "risky + hiding": [risky("capa", "inject", "x"), F("capa", NOTE, "anti-debug", {}, [HIDING])],
            "weak + unsigned": [weak("capa", "memory", "x"), F("program", NOTE, "unsigned", {}, [UNSIGNED])],
            "weak + packed": [weak("capa", "memory", "x"), F("program", NOTE, "packed", {}, [PACKED])],
            "lying name": [F("filetype", NOTE, "wrong ending", {}, [LYING_NAME])],
            "a detection": [F("clamav", MALICIOUS, "ClamAV recognises it.")],
        }
        raised = []
        for name, others in situations.items():
            with_no_key = decide([ran, *others, *no_key])
            with_key = decide([ran, *others, *without_sign])
            self.assertEqual(with_no_key["verdict"], with_key["verdict"], name)
            self.assertEqual(with_no_key["title"], with_key["title"], name)
            if decide([ran, *others, *not_found])["verdict"] != with_no_key["verdict"]:
                raised.append(name)
        # and the sign itself does matter when a key really says "never seen"
        self.assertIn("risky ability", raised)
        self.assertIn("weak + unsigned", raised)


class RateLimiterTests(unittest.TestCase):
    def test_four_a_minute(self):
        now = [0.0]
        sleeps = []

        def sleep(s):
            sleeps.append(s)
            now[0] += s

        limiter = virustotal.RateLimiter(4, 60, clock=lambda: now[0], sleep=sleep)
        for _ in range(4):
            self.assertTrue(limiter.acquire(0))
        self.assertFalse(limiter.acquire(10))   # would need to wait about 60 s
        self.assertTrue(limiter.acquire(65))    # waits for the oldest slot
        self.assertGreaterEqual(now[0], 60)


class MalwareBazaarTests(unittest.TestCase):
    def test_known_sample(self):
        body = {"query_status": "ok", "data": [{"signature": "AgentTesla", "first_seen": "2026-01-02 10:00:00",
                                                "tags": ["exe"], "file_type": "exe"}]}
        [finding] = malwarebazaar.interpret(SHA, body)
        self.assertEqual(finding.level, MALICIOUS)
        self.assertEqual(finding.text,
                         "MalwareBazaar lists this file as a known malware sample (AgentTesla), first reported 2026-01-02.")

    def test_not_found(self):
        [finding] = malwarebazaar.interpret(SHA, {"query_status": "hash_not_found"})
        self.assertEqual(finding.level, CLEAR)

    def test_bad_key_status(self):
        [finding] = malwarebazaar.interpret(SHA, {"query_status": "unknown_auth_key"})
        self.assertEqual(finding.level, ERROR)
        self.assertIn("rejected", finding.text)

    def test_request_shape_and_timeout(self):
        response = mock.Mock(status_code=200, json=lambda: {"query_status": "hash_not_found"})
        with mock.patch("blotter.keys.get", return_value="secret"), \
             mock.patch("requests.request", return_value=response) as post:
            [finding] = malwarebazaar.scan(temp_file(b""))
        self.assertEqual(finding.level, CLEAR)
        kwargs = post.call_args.kwargs
        self.assertEqual(kwargs["data"]["query"], "get_info")
        self.assertEqual(kwargs["headers"]["Auth-Key"], "secret")
        self.assertIsNotNone(kwargs["timeout"])

    def test_no_key_is_skipped(self):
        with mock.patch("blotter.keys.get", return_value=None):
            [finding] = malwarebazaar.scan(temp_file())
        self.assertEqual(finding.level, SKIPPED)

    def test_http_401(self):
        with mock.patch("blotter.keys.get", return_value="k"), \
             mock.patch("requests.request", return_value=mock.Mock(status_code=401)):
            [finding] = malwarebazaar.scan(temp_file())
        self.assertIn("rejected", finding.text)


EICAR_OUTPUT = """Scan starting...
Scan finished.
Found 1 threats.

----------------------------- Threat information ------------------------------
Threat                  : Virus:DOS/EICAR_Test_File
Resources               : 1 total
    file                : C:\\Users\\x\\AppData\\Local\\Blotter\\incoming\\abc.blotter
-------------------------------------------------------------------------------
"""
CLEAN_OUTPUT = "Scan starting...\nScan finished.\nScanning C:\\x\\abc.blotter found no threats.\n"


class DefenderTests(unittest.TestCase):
    def test_threat_and_quarantine(self):
        [finding] = defender.interpret(2, EICAR_OUTPUT, still_there=False)
        self.assertEqual(finding.level, MALICIOUS)
        self.assertEqual(finding.text,
                         "Microsoft Defender detected Virus:DOS/EICAR_Test_File in this file and quarantined Blotter's copy.")
        self.assertEqual(finding.details["threats"], ["Virus:DOS/EICAR_Test_File"])

    def test_threat_without_quarantine(self):
        [finding] = defender.interpret(2, EICAR_OUTPUT, still_there=True)
        self.assertEqual(finding.level, MALICIOUS)
        self.assertNotIn("quarantined", finding.text)

    def test_clean(self):
        [finding] = defender.interpret(0, CLEAN_OUTPUT, still_there=True)
        self.assertEqual(finding.level, CLEAR)

    def test_service_off(self):
        [finding] = defender.interpret(2147549370, "CmdTool: Failed with hr = 0x800106BA.", still_there=True)
        self.assertEqual(finding.level, ERROR)
        self.assertIn("isn't running", finding.text)

    def test_removed_before_scan_is_a_detection(self):
        [finding] = defender.scan(Path(tempfile.mkdtemp()) / "gone.blotter")
        self.assertEqual(finding.level, MALICIOUS)
        self.assertIn("the moment it was saved", finding.text)

    def test_scanner_missing(self):
        [finding] = defender.scan(temp_file())  # tests point BLOTTER_DEFENDER_EXE at nothing
        self.assertEqual(finding.level, ERROR)
        self.assertIn("wasn't found", finding.text)

    def test_command_line_and_timeout(self):
        path = temp_file()
        fake = path.parent / "fake.exe"
        fake.write_bytes(b"")
        done = subprocess.CompletedProcess([], 0, CLEAN_OUTPUT.encode(), b"")
        with mock.patch.dict("os.environ", {"BLOTTER_DEFENDER_EXE": str(fake)}), \
             mock.patch("subprocess.run", return_value=done) as run:
            [finding] = defender.scan(path)
        self.assertEqual(finding.level, CLEAR)
        self.assertEqual(run.call_args.args[0], [str(fake), "-Scan", "-ScanType", "3", "-File", str(path)])
        self.assertEqual(run.call_args.kwargs["timeout"], defender.SCAN_TIMEOUT)

    def test_scan_timeout(self):
        path = temp_file()
        fake = path.parent / "fake.exe"
        fake.write_bytes(b"")
        with mock.patch.dict("os.environ", {"BLOTTER_DEFENDER_EXE": str(fake)}), \
             mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("x", 1)):
            [finding] = defender.scan(path)
        self.assertEqual(finding.level, ERROR)
        self.assertIn("longer than", finding.text)

    def test_finds_newest_platform_folder(self):
        root = Path(tempfile.mkdtemp())
        for version in ("4.18.24090.11-0", "4.18.25090.3009-0", "4.18.9999.1-0"):
            (root / version).mkdir()
            (root / version / defender.EXE_NAME).write_bytes(b"")
        with mock.patch.dict("os.environ", {"BLOTTER_DEFENDER_EXE": ""}), \
             mock.patch.object(defender, "PLATFORM", root):
            self.assertEqual(defender.find_scanner(), root / "4.18.25090.3009-0" / defender.EXE_NAME)

    def test_utf16_output(self):
        self.assertEqual(defender._decode("Found 1 threats.".encode("utf-16-le")), "Found 1 threats.")


if __name__ == "__main__":
    unittest.main()
