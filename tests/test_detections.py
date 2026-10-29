"""Detections: trust never lowers them, and detections naming the same threat share one line on the card."""

import tempfile
import types
import unittest
from pathlib import Path

from blotter.analyze import yararules
from blotter.cache import Cache
from blotter.checks import capabilities, clamav, defender, malwarebazaar, virustotal
from blotter.findings import (CLEAR, HIDING, KNOWN_GOOD, MALICIOUS, NOTE, SUSPICIOUS, UNCHECKED, Finding, detected,
                              risky)
from blotter.runner import Runner
from blotter.trust import TrustList
from blotter.verdict import decide
from tests import samples
from tests.test_checks import EICAR_OUTPUT, vt_data
from tests.test_runner_app import wait_done

RAN = Finding("filetype", CLEAR, "It is a Windows program (EXE).")


FORGE_EICAR = b'''rule TRELLIX_ARC_Malw_Eicar {
  meta:
    description = "Rule to detect the EICAR pattern"
    score = 75
  strings:
    $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
  condition:
    $a
}
'''


def forge_rules():
    """A stand-in YARA Forge pack (the test folder has none), kept in the vault like the real one."""
    from unittest import mock
    from blotter import config, vault
    folder = Path(tempfile.mkdtemp())
    with mock.patch.object(config, "YARA_FORGE", folder / "forge.7z"), \
         mock.patch.object(config, "YARA_COMPILED", folder / "compiled.7z"):
        vault.write(config.YARA_FORGE, {yararules.FORGE_MEMBER: FORGE_EICAR})
        return yararules.load()


def eicar_findings():
    found = defender.interpret(2, EICAR_OUTPUT, still_there=False)
    found += clamav.interpret("stream: Win.Test.EICAR_HDB-1 FOUND")
    found += yararules.scan_target(forge_rules(), "yara", data=samples.eicar())  # in memory
    return found


class TrustNeverHidesDetectionsTests(unittest.TestCase):
    def test_each_engine_detection_survives_trust(self):
        engines = {
            "Defender": defender.interpret(2, EICAR_OUTPUT, still_there=True),
            "ClamAV": clamav.interpret("stream: Win.Trojan.Agent-1 FOUND"),
            "ClamAV heuristics": clamav.interpret("stream: Heuristics.Phishing.Email FOUND"),
            "YARA": yararules.scan_target(yararules.load(), "yara", data=samples.eicar()),
            "MalwareBazaar": malwarebazaar.interpret("a" * 64, {"query_status": "ok", "data": [{"signature": "AgentTesla"}]}),
            "VirusTotal, 3 engines": virustotal.interpret("a" * 64, vt_data({"malicious": 3, "undetected": 67})),
            "YARA broad rule": [yararules.classify("yara", types.SimpleNamespace(
                rule="ELASTIC_Windows_Generic_Threat_1", namespace="forge", meta={"score": 75}))],
            "capa malware family": capabilities.interpret(
                {"rules": {"match known PlugX module": {"meta": {"namespace": "malware-family/plugx"}}}}),
        }
        for name, found in engines.items():
            plain = decide([RAN, *found])
            trusted = decide([RAN, *found], trusted=True)
            self.assertIn(plain["verdict"], ("malicious", "suspicious"), name)
            self.assertEqual(trusted["verdict"], plain["verdict"], f"trust lowered a {name} detection")
            self.assertIn("You trusted this file before, but it is now", trusted["summary"], name)

    def test_trust_quiets_one_or_two_virustotal_engines(self):
        for engines, words in ((1, "1 VirusTotal engine flags it"), (2, "2 VirusTotal engines flag it")):
            found = virustotal.interpret("a" * 64, vt_data({"malicious": engines, "undetected": 70 - engines}))
            self.assertEqual(decide([RAN, *found])["verdict"], "suspicious")
            v = decide([RAN, *found], trusted=True)
            self.assertEqual(v["verdict"], "no_known_detections", engines)
            self.assertIn(f"You trusted this file; {words}.", v["summary"])
            self.assertTrue(any("VirusTotal" in r for r in v["reasons"]), "the engine line still shows")
        found = virustotal.interpret("a" * 64, vt_data({"suspicious": 1, "undetected": 69}))
        self.assertIn("1 VirusTotal engine calls it suspicious", decide([RAN, *found], trusted=True)["summary"])

    def test_weak_virustotal_plus_a_real_detection_is_not_lowered(self):
        found = [*virustotal.interpret("a" * 64, vt_data({"malicious": 1, "undetected": 69})),
                 *clamav.interpret("stream: Heuristics.Phishing.Email FOUND")]
        v = decide([RAN, *found], trusted=True)
        self.assertEqual(v["verdict"], "suspicious")
        self.assertIn("now flagged", v["summary"])

    def test_trust_never_turns_an_unfinished_check_into_no_known(self):
        found = [*virustotal.interpret("a" * 64, vt_data({"malicious": 1, "undetected": 69})),
                 Finding("capa", NOTE, "too big", {}, [UNCHECKED])]
        self.assertEqual(decide([RAN, *found], trusted=True)["verdict"], "couldnt_fully_check")
        found = [risky("capa", "inject", "x"), Finding("x", NOTE, "scrambled", {}, [HIDING]),
                 Finding("capa", NOTE, "too big", {}, [UNCHECKED])]
        self.assertEqual(decide([RAN, *found], trusted=True)["verdict"], "couldnt_fully_check")

    def test_malicious_wording(self):
        v = decide([RAN, *eicar_findings()], trusted=True)
        self.assertEqual(v["verdict"], "malicious")
        self.assertIn("You trusted this file before, but it is now detected.", v["summary"])

    def test_trust_still_quiets_ability_warnings(self):
        found = [RAN, risky("capa", "inject", "It can inject code."), Finding("x", NOTE, "scrambled", {}, [HIDING])]
        self.assertEqual(decide(found)["verdict"], "suspicious")
        self.assertEqual(decide(found, trusted=True)["verdict"], "no_known_detections")

    def test_known_good_doesnt_lower_an_engine_flag(self):
        found = [RAN, *virustotal.interpret("a" * 64, vt_data({"malicious": 1, "undetected": 69})),
                 risky("capa", "inject", "x"), Finding("x", NOTE, "scrambled", {}, [HIDING]),
                 Finding("hashlookup", CLEAR, "known", {}, [KNOWN_GOOD])]
        self.assertEqual(decide(found)["verdict"], "suspicious")

    def test_a_file_trusted_earlier_and_detected_now(self):
        trust = TrustList(Path(tempfile.mkdtemp()) / "t.sqlite3")
        sha = "b" * 64
        trust.add(sha, "old-mod.dll")

        def scan(path):
            return [detected(Finding("clamav", MALICIOUS, "ClamAV recognises it as malware: Win.Trojan.X."),
                             "ClamAV", "Win.Trojan.X")]

        engine = types.SimpleNamespace(ID="clamav", NAME="ClamAV", ORDER=1, TIMEOUT=5, CACHE=False,
                                       NEEDS_FILE=False, scan=scan)
        path = Path(tempfile.mkdtemp()) / "c.blotter"
        path.write_bytes(b"x")
        job = wait_done(Runner(Cache(Path(tempfile.mkdtemp()) / "c.sqlite3"), [engine], trust=trust)
                        .start(path, "old-mod.dll", 1, sha))
        self.assertEqual(job.verdict["verdict"], "malicious")
        self.assertTrue(job.trusted, "the trust stays")
        self.assertIn("now detected", job.verdict["summary"])
        self.assertIsNotNone(trust.get(sha))


class GroupingTests(unittest.TestCase):
    def test_eicar_is_one_line(self):
        v = decide([RAN, *eicar_findings()])
        self.assertEqual(v["reasons"][0], "Recognised as EICAR test file by Defender, ClamAV, YARA and Blotter.")
        self.assertFalse(any("EICAR" in r for r in v["reasons"][1:]), v["reasons"])

    def test_details_keep_every_line(self):
        found = eicar_findings()
        self.assertGreaterEqual(len([f for f in found if f.level == MALICIOUS]), 4, "each check's own finding stays")

    def test_different_threats_stay_apart(self):
        found = [*clamav.interpret("stream: Win.Trojan.Emotet-9 FOUND"),
                 *malwarebazaar.interpret("a" * 64, {"query_status": "ok", "data": [{"signature": "AgentTesla"}]})]
        v = decide([RAN, *found])
        self.assertEqual(len([r for r in v["reasons"] if "ClamAV" in r or "MalwareBazaar" in r]), 2)
        self.assertFalse(any(r.startswith("Recognised as") for r in v["reasons"]))

    def test_same_family_from_two_engines(self):
        found = [*malwarebazaar.interpret("a" * 64, {"query_status": "ok", "data": [{"signature": "AgentTesla"}]}),
                 *clamav.interpret("stream: Win.Trojan.Agenttesla-9876 FOUND")]
        v = decide([RAN, *found])
        self.assertEqual(v["reasons"][0], "Recognised as AgentTesla by ClamAV and MalwareBazaar.")

    def test_one_detection_keeps_its_own_words(self):
        [f] = clamav.interpret("stream: Win.Trojan.Emotet-9 FOUND")
        self.assertEqual(decide([RAN, f])["reasons"][0], f.text)

    def test_generic_words_never_merge_different_threats(self):
        found = [*defender.interpret(2, EICAR_OUTPUT.replace("Virus:DOS/EICAR_Test_File", "Trojan:Win32/Agent!ml"),
                                     still_there=True),
                 *clamav.interpret("stream: Win.Trojan.Agent-9 FOUND"),
                 *clamav.interpret("stream: Win.Malware.Heur-1 FOUND"),
                 *malwarebazaar.interpret("a" * 64, {"query_status": "ok", "data": [{"signature": "Generic Malware"}]}),
                 *virustotal.interpret("a" * 64, vt_data({"malicious": 5, "undetected": 65}, label="trojan.generic/win32"))]
        v = decide([RAN, *found])
        self.assertFalse(any(r.startswith("Recognised as") for r in v["reasons"]), v["reasons"])

    def test_type_words_dont_merge_but_family_names_do(self):
        found = [*defender.interpret(2, EICAR_OUTPUT.replace("Virus:DOS/EICAR_Test_File",
                                                             "TrojanDownloader:Win32/Emotet.A"), still_there=True),
                 *clamav.interpret("stream: Win.Trojan.Emotet-1 FOUND"),
                 *defender.interpret(2, EICAR_OUTPUT.replace("Virus:DOS/EICAR_Test_File",
                                                             "TrojanDownloader:Win32/Qakbot"), still_there=True)]
        v = decide([RAN, *found])
        self.assertIn("Recognised as Emotet by Defender and ClamAV.", v["reasons"])
        self.assertTrue(any("Qakbot" in r and not r.startswith("Recognised as") for r in v["reasons"]), v["reasons"])

    def test_warnings_group_separately_from_detections(self):
        found = [*clamav.interpret("stream: Heuristics.Phishing.Emotet FOUND"),
                 *virustotal.interpret("a" * 64, vt_data({"malicious": 1, "undetected": 69}, label="emotet")),
                 *clamav.interpret("stream: Win.Trojan.Agent-1 FOUND")]
        v = decide([RAN, *found])
        self.assertIn("Flagged as possibly Emotet by ClamAV and VirusTotal.", v["reasons"])
        self.assertEqual(v["verdict"], "malicious")
        self.assertTrue(all(f.level in (MALICIOUS, SUSPICIOUS) for f in found))


class CardTests(unittest.TestCase):
    def test_page_hides_trust_on_malicious(self):
        js = (Path(__file__).parent.parent / "blotter" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn('$("trust").hidden = !shown || (malicious && !job.trusted);', js)
        self.assertIn('const malicious = shown && job.verdict.verdict === "malicious";', js)


if __name__ == "__main__":
    unittest.main()
