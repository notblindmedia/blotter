import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import vt

from blotter.checks import defender, load_checks, malwarebazaar, virustotal
from blotter.findings import CLEAR, ERROR, MALICIOUS, SUSPICIOUS, UNKNOWN

SHA = "a" * 64


def temp_file(data=b"just some bytes"):
    folder = Path(tempfile.mkdtemp())
    path = folder / "sample.blotter"
    path.write_bytes(data)
    return path


class RegistryTests(unittest.TestCase):
    def test_three_checks_in_order(self):
        checks = load_checks()
        self.assertEqual([c.ID for c in checks], ["virustotal", "malwarebazaar", "defender"])
        for c in checks:
            self.assertTrue(c.TIMEOUT > 0)
            self.assertTrue(callable(c.scan))


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
        self.assertEqual(finding.level, ERROR)
        self.assertIn("no API key", finding.text)

    def test_not_found(self):
        with mock.patch("blotter.keys.get", return_value="k"), \
             mock.patch.object(virustotal, "_lookup", mock.AsyncMock(return_value=None)):
            [finding] = virustotal.scan(temp_file())
        self.assertEqual(finding.level, UNKNOWN)
        self.assertIn("no record", finding.text)

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
             mock.patch("requests.post", return_value=response) as post:
            [finding] = malwarebazaar.scan(temp_file(b""))
        self.assertEqual(finding.level, CLEAR)
        kwargs = post.call_args.kwargs
        self.assertEqual(kwargs["data"]["query"], "get_info")
        self.assertEqual(kwargs["headers"]["Auth-Key"], "secret")
        self.assertIsNotNone(kwargs["timeout"])

    def test_http_401(self):
        with mock.patch("blotter.keys.get", return_value="k"), \
             mock.patch("requests.post", return_value=mock.Mock(status_code=401)):
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
