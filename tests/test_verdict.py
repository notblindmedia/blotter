import re
import unittest

from blotter.findings import (CLEAR, DISGUISED, ERROR, HIDING, KNOWN_GOOD, LYING_NAME, MALICIOUS, NOTE, PACKED,
                              RISKY, SIGNED, SKIPPED, SUSPICIOUS, UNCHECKED, UNKNOWN, UNKNOWN_ONLINE, UNSIGNED,
                              Finding, risky, weak)
from blotter.verdict import VERDICTS, decide


def f(level, text="A sentence.", signals=(), **details):
    return Finding("x", level, text, details, list(signals))


INJECT = risky("capa", "inject", "It can inject code into other running programs.")


class VerdictTests(unittest.TestCase):
    def test_malicious_wins(self):
        self.assertEqual(decide([f(CLEAR), f(SUSPICIOUS), f(MALICIOUS), f(ERROR)])["verdict"], "malicious")

    def test_suspicious(self):
        self.assertEqual(decide([f(CLEAR), f(SUSPICIOUS)])["verdict"], "suspicious")

    def test_no_known_detections_even_with_some_errors(self):
        v = decide([f(CLEAR, "Ran fine."), f(ERROR, "Couldn't run.")])
        self.assertEqual(v["verdict"], "no_known_detections")
        self.assertEqual(v["reasons"], ["Ran fine.", "Couldn't run."])

    def test_unknown_counts_as_ran(self):
        self.assertEqual(decide([f(UNKNOWN), f(ERROR)])["verdict"], "no_known_detections")

    def test_all_errors(self):
        self.assertEqual(decide([f(ERROR), f(ERROR)])["verdict"], "couldnt_check")
        self.assertEqual(decide([])["verdict"], "couldnt_check")

    def test_reasons_put_detections_first(self):
        v = decide([f(ERROR, "e."), f(CLEAR, "c."), f(MALICIOUS, "m.")])
        self.assertEqual(v["reasons"][0], "m.")

    def test_never_says_safe(self):
        for title, summary in VERDICTS.values():
            self.assertNotRegex((title + summary).lower(), r"\bsafe")


class ScorerTests(unittest.TestCase):
    def verdict(self, *findings, trusted=False):
        return decide([f(CLEAR, "Something ran."), *findings], trusted=trusted)

    def test_risky_only_is_unusual(self):
        v = self.verdict(INJECT)
        self.assertEqual(v["verdict"], "unusual")
        self.assertIn("It can inject code", v["reasons"][0])

    def test_risky_plus_each_qualifier_is_suspicious(self):
        for extra, why in [(f(NOTE, "hides", [HIDING]), "hides"),
                           (f(NOTE, "lies", [LYING_NAME]), "name doesn't match"),
                           (f(NOTE, "packed", [PACKED]), "packed program without a valid signature"),
                           (f(UNKNOWN, "VT never saw it", [UNKNOWN_ONLINE]), "VirusTotal has never seen")]:
            v = self.verdict(INJECT, extra)
            self.assertEqual(v["verdict"], "suspicious", why)
            self.assertIn(why, v["summary"])

    def test_packed_but_signed_is_not_a_qualifier(self):
        v = self.verdict(INJECT, f(NOTE, "packed", [PACKED]), f(CLEAR, "signed", [SIGNED]))
        self.assertEqual(v["verdict"], "unusual")

    def test_hiding_alone_is_not_a_warning(self):
        self.assertEqual(self.verdict(f(NOTE, "anti-debug", [HIDING]))["verdict"], "no_known_detections")

    def test_disguised_program_is_suspicious_on_its_own(self):
        v = self.verdict(f(NOTE, "a program named .jpg", [DISGUISED, LYING_NAME]))
        self.assertEqual(v["verdict"], "suspicious")
        self.assertIn("dressed up", v["summary"])

    def test_signals_in_different_archive_files_dont_combine(self):
        v = self.verdict(risky("archive", "inject", "x", {"scope": "a.dll"}),
                         f(NOTE, "scrambled", [HIDING], scope="b.js"))
        self.assertEqual(v["verdict"], "unusual")
        v = self.verdict(risky("archive", "inject", "x", {"scope": "a.dll"}),
                         f(NOTE, "scrambled", [HIDING], scope="a.dll"))
        self.assertEqual(v["verdict"], "suspicious")

    def test_known_good_lowers_one_step(self):
        good = f(CLEAR, "CIRCL knows it", [KNOWN_GOOD])
        self.assertEqual(self.verdict(INJECT, good)["verdict"], "no_known_detections")
        v = self.verdict(INJECT, f(NOTE, "hides", [HIDING]), good)
        self.assertEqual(v["verdict"], "unusual")
        self.assertIn("lowered", v["summary"])

    def test_known_good_doesnt_hide_detections(self):
        good = f(CLEAR, "CIRCL knows it", [KNOWN_GOOD])
        self.assertEqual(self.verdict(f(SUSPICIOUS, "2 engines"), good)["verdict"], "suspicious")
        self.assertEqual(self.verdict(f(MALICIOUS, "malware"), good)["verdict"], "malicious")

    def test_known_good_cancels_unknown_everywhere(self):
        v = self.verdict(INJECT, f(UNKNOWN, "VT never saw it", [UNKNOWN_ONLINE]), f(CLEAR, "known", [KNOWN_GOOD]))
        self.assertNotEqual(v["verdict"], "suspicious")

    def test_trusted(self):
        v = self.verdict(INJECT, f(NOTE, "hides", [HIDING]), trusted=True)
        self.assertEqual(v["verdict"], "no_known_detections")
        self.assertIn("trusted", v["summary"])
        v = self.verdict(f(MALICIOUS, "malware"), trusted=True)
        self.assertEqual(v["verdict"], "malicious", "trust never hides a malware detection")
        self.assertIn("trusted", v["summary"])

    def test_locked_archive_couldnt_check(self):
        v = self.verdict(f(NOTE, "locked", [UNCHECKED]))
        self.assertEqual((v["verdict"], v["title"]), ("couldnt_fully_check", "Couldn't fully check"))
        self.assertEqual(self.verdict(f(NOTE, "locked", [UNCHECKED]), f(MALICIOUS, "m"))["verdict"], "malicious")

    def test_same_ability_said_once_and_skips_hidden(self):
        v = self.verdict(INJECT, risky("program", "inject", "Imports say it injects."), f(SKIPPED, "not a doc"))
        self.assertEqual(sum("inject" in r for r in v["reasons"]), 1)
        self.assertNotIn("not a doc", v["reasons"])

    def test_only_skipped_is_couldnt_check(self):
        self.assertEqual(decide([f(SKIPPED), f(ERROR)])["verdict"], "couldnt_check")


class WeakSignTests(unittest.TestCase):
    """Weak signs stay quiet alone but add up with unsigned, packed or unknown everywhere."""
    RWX = weak("capa", "memory", "It can make parts of its own memory runnable.")
    UNSIGNED_ = f(NOTE, "It isn't digitally signed.", [UNSIGNED])
    PACKED_ = f(NOTE, "It is packed.", [PACKED])
    UNKNOWN_ = f(UNKNOWN, "VirusTotal has no record of this file.", [UNKNOWN_ONLINE])
    SIGNED_ = f(CLEAR, "Signed by Example.", [SIGNED])

    def verdict(self, *findings):
        return decide([f(CLEAR, "Something ran."), *findings])

    def test_quiet_alone(self):
        v = self.verdict(self.RWX)
        self.assertEqual(v["verdict"], "no_known_detections")
        self.assertNotIn(self.RWX.text, v["reasons"], "a quiet weak sign stays in Details, not on the card")
        self.assertEqual(self.verdict(self.RWX, self.SIGNED_)["verdict"], "no_known_detections")
        self.assertEqual(self.verdict(self.RWX, f(NOTE, "anti-debug", [HIDING]))["verdict"], "no_known_detections")

    def test_one_context_sign_makes_unusual(self):
        for context in (self.UNSIGNED_, self.PACKED_, self.UNKNOWN_):
            v = self.verdict(self.RWX, context)
            self.assertEqual(v["verdict"], "unusual", context.text)
            self.assertIn(self.RWX.text, v["reasons"])
            self.assertIn("add up", v["summary"])

    def test_two_context_signs_or_hiding_make_suspicious(self):
        for extra in ((self.UNSIGNED_, self.PACKED_), (self.UNSIGNED_, self.UNKNOWN_), (self.PACKED_, self.UNKNOWN_),
                      (self.UNSIGNED_, f(NOTE, "scrambled", [HIDING])),
                      (self.UNSIGNED_, f(NOTE, "wrong ending", [LYING_NAME]))):
            v = self.verdict(self.RWX, *extra)
            self.assertEqual(v["verdict"], "suspicious", [e.text for e in extra])

    def test_without_weak_signs_context_alone_is_quiet(self):
        self.assertEqual(self.verdict(self.UNSIGNED_, self.UNKNOWN_)["verdict"], "no_known_detections")

    def test_known_good_cancels_unknown_everywhere(self):
        v = self.verdict(self.RWX, self.UNSIGNED_, self.UNKNOWN_, f(CLEAR, "CIRCL knows it", [KNOWN_GOOD]))
        self.assertEqual(v["verdict"], "no_known_detections",
                         "CIRCL cancels 'unknown everywhere' (Suspicious -> Unusual) and lowers one more step")

    def test_signs_in_different_archive_files_dont_combine(self):
        v = self.verdict(weak("archive", "memory", "x", {"scope": "a.exe"}),
                         f(NOTE, "unsigned", [UNSIGNED], scope="b.exe"))
        self.assertEqual(v["verdict"], "no_known_detections")

    def test_end_to_end_from_real_check_output(self):
        """Real capa and program-check code: each weak sign with an unsigned, packed or unknown program."""
        import random
        from unittest import mock

        from blotter.analyze import program
        from blotter.checks import capabilities
        from tests.test_layer2 import fake_pe

        weak_rules = {
            "allocate or change RWX memory": "host-interaction/process/inject",
            "interact with driver via IOCTL": "host-interaction/driver",
            "parse credit card information": "collection/credit-card",
            "load assembly via IAssembly": "load-code/dotnet",
        }
        noise = random.Random(3).randbytes(200_000)
        unsigned = {"status": "NotSigned", "signer": ""}

        def analyze(pe, sig):
            with mock.patch("pefile.PE", return_value=pe), mock.patch.object(program, "signature", return_value=sig):
                return program.analyze("program", "x.exe")

        vt_unknown = [f(UNKNOWN, "VirusTotal has no record.", [UNKNOWN_ONLINE])]
        for rule, namespace in weak_rules.items():
            capa = capabilities.interpret({"rules": {rule: {"meta": {"namespace": namespace}}}})
            plain_unsigned = analyze(fake_pe([(".text", b"\x90" * 100)], ["ExitProcess"]), unsigned)
            packed_unsigned = analyze(fake_pe([("UPX0", b""), ("UPX1", noise)], ["GetProcAddress"]), unsigned)
            self.assertEqual(decide(capa)["verdict"], "no_known_detections", rule)
            self.assertEqual(decide(capa + plain_unsigned)["verdict"], "unusual", rule)
            self.assertEqual(decide(capa + packed_unsigned)["verdict"], "suspicious", rule)
            self.assertEqual(decide(capa + plain_unsigned + vt_unknown)["verdict"], "suspicious", rule)

        # the fifth weak sign: a compressed .NET code section
        dotnet = analyze(fake_pe([(".text", noise)], ["_CorDllMain"], dotnet=True), unsigned)
        self.assertEqual(decide(dotnet)["verdict"], "unusual")
        signed = analyze(fake_pe([(".text", noise)], ["_CorDllMain"], dotnet=True),
                         {"status": "Valid", "signer": "Example"})
        self.assertEqual(decide(signed)["verdict"], "no_known_detections")
        self.assertEqual(decide(signed + vt_unknown)["verdict"], "unusual")


class NoSafeWordInSourceTests(unittest.TestCase):
    """No sentence a person can read may call a file safe."""

    def test_sources(self):
        from pathlib import Path
        root = Path(__file__).parent.parent / "blotter"
        for path in list(root.rglob("*.py")) + list(root.rglob("*.html")) + list(root.rglob("*.js")):
            text = path.read_text(encoding="utf-8").lower()
            self.assertIsNone(re.search(r"\bsafe\b|100%", text), f"'safe' or '100%' found in {path.name}")


if __name__ == "__main__":
    unittest.main()
